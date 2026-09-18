"""Evaluation Service（§10 Orchestrator + §6 stages）— v1 同步串行单跑。

create(request) → 冻结 snapshot + 建 evaluation。
run(evaluation_id) → VALIDATE→...→FINALIZE 同步执行，落库。
run() 使用短连接：慢操作（trace 解析、LLM 调用）期间不持有 MySQL 连接。
"""
from __future__ import annotations
import json
import os
import sys
import time
import threading
from dataclasses import dataclass, field
from ..infrastructure.database import connect
from ..persistence.repositories import fact_repo
from ..workers.turing_trace_parser import TuringTraceParser
from ..workers.resolvers import (
    OutcomeResolverImpl, KnowledgeResolverImpl, ToolActionResolverImpl, ResourceResolverImpl,
)
from ..workers.ai_matcher import match_alert_center_to_findings
from ..workers.sink_matcher import sink_match_baselines
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log, set_eval_ctx, clear_eval_ctx
from ..workers.pairing import TaskPairMatcherImpl, PairDerivedFactComputer
from ..domain.metrics import PairView, run_all_metrics
from ..domain.diagnostics import diagnose
from .report_assembler import (assemble, render_json,
                               ai_per_case_kg_analysis, rule_based_per_case_kg_analysis)
from .fpr_analysis import run_fpr_analysis, derive_fpr_from_subset
from ..domain.task_run import TaskRun, BenchmarkItem
from ..domain.enums import Condition, ConditionSource, ExpectedLabel, PairMatchStatus
from ..orchestration.state_machine import PIPELINE, assert_transition
from ..application import platform_service as ps

def _extract_source_task_id(entry: dict) -> str:
    """从 entry 的 source_uri 提取平台任务 UUID（漏洞中心 API 需要，非 benchmark task_id）。

    source_uri 格式: /data/files/{project_id}/tasks/{task_uuid}/session/...
    无法提取时返回空字符串。
    """
    import re
    src = entry.get("source_uri", "") or ""
    m = re.search(r'/tasks/([^/]+)', src)
    return m.group(1) if m else ""


# 协作取消：force retry 时在 DB 设 CANCEL_REQUESTED，run() 在阶段边界检查并退出
# 跨 worker 生效（--workers 2 时不同 worker 共享同一 DB）

# 运行时可调并发参数
_runtime_workers = {"parse": 4, "kg_analysis": 4}


def get_runtime_workers() -> dict:
    return dict(_runtime_workers)


def set_runtime_workers(**kwargs):
    for k, v in kwargs.items():
        if k in _runtime_workers:
            _runtime_workers[k] = max(1, min(v, 50))

# 进度文本：AI 匹配等慢阶段向前端报告进度（内存字典，pod 重启后重跑无需持久化）
# 两层：_progress_phase 存阶段级文本（解析/写入/配对等），_progress_tasks 存任务级文本（多 task_run 并行各自独立）
_progress_phase: dict[str, str] = {}
_progress_tasks: dict[str, dict[str, str]] = {}
_progress_lock = threading.Lock()


def set_progress(evaluation_id: str, text: str):
    """设置阶段级进度（覆盖任务级进度）。"""
    with _progress_lock:
        _progress_phase[evaluation_id] = text
        _progress_tasks.pop(evaluation_id, None)


def set_task_progress(evaluation_id: str, task_run_id: str, text: str):
    """设置任务级进度（多任务并行时各自独立，互不覆盖）。"""
    with _progress_lock:
        _progress_tasks.setdefault(evaluation_id, {})[task_run_id] = text


def get_progress(evaluation_id: str) -> str:
    with _progress_lock:
        tasks = _progress_tasks.get(evaluation_id, {})
        if tasks:
            return " | ".join(tasks.values())
        return _progress_phase.get(evaluation_id, "")


def clear_progress(evaluation_id: str):
    with _progress_lock:
        _progress_phase.pop(evaluation_id, None)
        _progress_tasks.pop(evaluation_id, None)


def set_cancel(evaluation_id: str):
    """标记一个评测任务为取消（force retry 时调用，通知旧线程退出）。
    跨 worker 生效：写 DB cancel_requested=1，独立于 status，不会被新线程覆盖。
    """
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("UPDATE evaluation SET cancel_requested=1 WHERE evaluation_id=%s",
                    (evaluation_id,))
        conn.commit()
    finally:
        conn.close()
    log("CANCEL", f"{evaluation_id} 收到取消信号")


def clear_cancel(evaluation_id: str):
    """清除取消标记（新线程启动时调用）。"""
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("UPDATE evaluation SET cancel_requested=0 WHERE evaluation_id=%s",
                    (evaluation_id,))
        conn.commit()
    finally:
        conn.close()


def is_cancelled(evaluation_id: str) -> bool:
    """检查评测任务是否被取消（读 DB cancel_requested）。"""
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT cancel_requested FROM evaluation WHERE evaluation_id=%s",
                    (evaluation_id,))
        row = cur.fetchone()
        return row is not None and row[0] == 1
    finally:
        conn.close()


class TaskCancelledError(Exception):
    """评测任务被取消（force retry 替换了旧线程）。"""
    pass


def _check_cancel(evaluation_id: str, phase: str):
    """在阶段边界检查取消信号。"""
    if is_cancelled(evaluation_id):
        raise TaskCancelledError(f"{evaluation_id} 在 {phase} 阶段被取消（force retry）")

LOCAL_TRACE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tests", "fixtures", "fetched")


def _resolve_trace_path(source_uri: str, project_id: str = "", task_id: str = "") -> str:
    """source_uri 可能是 k8s pod 上的 /data/... 路径；本地开发时拉到本地。"""
    if os.path.exists(source_uri):
        return source_uri
    if source_uri.startswith("/data/") or source_uri.startswith("data/"):
        return ps.fetch_trace_to_local(project_id, task_id, source_uri, LOCAL_TRACE_DIR)
    raise FileNotFoundError(f"trace 不可读且非 /data 路径：{source_uri}")


EVAL_CONFIG = {
    "access_rules": {
        "skill_names": [],
        "path_patterns": [],
        "command_patterns": [r"athena", r"athena\.py"],
        "text_patterns": [],
        "kg_tools": [],
    },
    "delivery_rules": {
        "path_patterns": [],
        "reject_patterns": [r"^404", r"404\s*Not Found", r"unreachable", r"Connection refused",
                           r"service.*not.*running", r"^$", r"^\[\]$", r'^{"result":""}',
                           "知识库暂无此类知识",
                           "Terminated", "timeout", "超时",
                           "command not found", "not found",
                           "unavailable",
                           # API 调用失败模式（athena_ask HTTP API 不可达 / 超时）
                           r"Execution error", r"Failed to poll", r"error sending request",
                           r"Failed to.*Athena"],
        "kg_success_patterns": ["knowledge persisted", "Success: knowledge", "知识已", r'"result":"Success"'],
    },
    "token_schema": {"reasoning_in_output": True, "cache_excluded": True},
}


@dataclass
class CreateRequest:
    evaluation_id: str
    evaluation_name: str | None = None
    benchmark_set_id: str = "BS001"
    vbench_project_name: str | None = None
    benchmark_source: str = "vbench_zip"  # "vbench_zip" | "vuln_center"
    vc_source_task_id: str | None = None  # 漏洞中心模式下的 source_task_id（项目用 benchmark_set_id）
    vc_source_project_name: str | None = None  # 漏洞中心项目名
    vc_source_task_name: str | None = None  # 漏洞中心任务名
    entries: list = field(default_factory=list)  # [{task_id, condition, source_uri, benchmark_item_id}]


def _set_status(cur, evaluation_id, status):
    if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "CANCELLED"):
        cur.execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
    elif status == "FAILED":
        cur.execute("UPDATE evaluation SET evaluation_status=%s, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
    else:
        cur.execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL WHERE evaluation_id=%s", (status, evaluation_id))


def _set_status_short(evaluation_id, status):
    """短连接设状态，用于 run() 各阶段更新进度。走 _db_query 重试 2006/2013。"""
    def _do(cur):
        if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "CANCELLED"):
            cur.execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
        elif status == "FAILED":
            cur.execute("UPDATE evaluation SET evaluation_status=%s, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
        else:
            cur.execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL WHERE evaluation_id=%s", (status, evaluation_id))
    try:
        _db_query(_do)
    except Exception as e:
        # CHECK 约束可能不含新状态（如 AI_MATCHING）→ 自动修复约束后重试
        if "Check constraint" in str(e) or "3819" in str(e):
            log("DB", f"CHECK 约束阻止设状态 {status}，自动修复...")
            def _fix_and_set(cur):
                for stmt in (
                    "ALTER TABLE evaluation DROP CHECK evaluation_chk_1",
                    "ALTER TABLE evaluation DROP CONSTRAINT evaluation_chk_1",
                    "ALTER TABLE evaluation DROP CHECK evaluation_status_chk",
                    "ALTER TABLE evaluation DROP CONSTRAINT evaluation_status_chk",
                ):
                    try: cur.execute(stmt)
                    except Exception: pass
                try:
                    cur.execute(
                        "ALTER TABLE evaluation ADD CONSTRAINT evaluation_status_chk CHECK (evaluation_status IN "
                        "('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING','PARSING','AI_MATCHING','RESOLVING','PAIRING',"
                        "'CALCULATING','STATISTICAL_ANALYSIS','DIAGNOSING','REPORTING','FINALIZING',"
                        "'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCEL_REQUESTED','CANCELLING','CANCELLED'))"
                    )
                except Exception: pass
                cur.execute("UPDATE evaluation SET evaluation_status=%s WHERE evaluation_id=%s", (status, evaluation_id))
            try:
                _db_query(_fix_and_set)
                log("DB", f"CHECK 约束已修复，重试设状态 {status} 成功")
            except Exception as e2:
                log("DB", f"CHECK 约束修复后仍失败: {e2}")
                raise
        else:
            raise


def _ai_extract_source_info(description: str, vulnerability_type: str = "") -> tuple[str, str, str]:
    """用 LLM 从漏洞描述中提取 source_file、source_function 和 source_line（行号）。

    当结构化数据（V-Bench traces 或漏洞中心 subject.locator）无法提取时作为 fallback。
    """
    from ..infrastructure import llm as llm_mod
    if not description or not llm_mod.is_enabled():
        return "", "", ""
    prompt = [
        {"role": "system", "content": (
            "从漏洞描述中提取漏洞所在的源文件路径、函数/方法名和行号。\n"
            "只返回 JSON: {\"source_file\": \"文件路径\", \"source_function\": \"函数名\", \"source_line\": \"行号\"}\n"
            "行号只填数字，如 872。如果无法确定，对应字段返回空字符串。不要输出其他内容。"
        )},
        {"role": "user", "content": f"漏洞类型: {vulnerability_type}\n漏洞描述: {description}"},
    ]
    try:
        result = llm_mod.chat_json(prompt, temperature=0, max_tokens=500)
        return result.get("source_file", ""), result.get("source_function", ""), str(result.get("source_line", ""))
    except Exception as e:
        log("CREATE", f"AI 提取 source_file/source_function/source_line 失败: {e}")
        return "", "", ""


def _fill_missing_source(case: dict) -> None:
    """如果 case 的 source_file、source_function 或 source_line 为空，用 AI 从 description 补提取。"""
    if not case.get("source_file") or not case.get("source_function") or not case.get("source_line"):
        sf, sfn, sln = _ai_extract_source_info(case.get("description", ""), case.get("vulnerability_type", ""))
        if not case.get("source_file"):
            case["source_file"] = sf
        if not case.get("source_function"):
            case["source_function"] = sfn
        if not case.get("source_line"):
            case["source_line"] = sln


def create(req: CreateRequest):
    """Stage 0：建 evaluation + snapshot（冻结）。每步用独立连接避免远程防火墙重置。"""
    # ===== 自动发现 trace =====
    # 1. 挖掘 trace：自动判断 trace_kind（用户只选了 task_id，不选 trace_kind）
    for e in req.entries:
        if not e.get("trace_kind") and e.get("task_id") and e.get("project_id"):
            try:
                kind = ps.discover_mining_trace_kind(e["project_id"], e["task_id"])
                if kind:
                    e["trace_kind"] = kind
                    log("CREATE", f"自动发现挖掘 trace_kind={kind} task={e['task_id']}")
            except Exception as err:
                log("CREATE", f"⚠ 自动发现挖掘 trace_kind 失败: {err}")

    # 2. 验证 trace：自动扫描 app 目录，有数据就加入 entries
    _existing_kinds = {e.get("trace_kind") for e in req.entries}
    _project_id = req.entries[0].get("project_id") if req.entries else ""
    # 是否有 No-KG 条目（决定验证 trace 是否也创建 NOGK entry）
    _has_nogk_entries = any(e.get("condition") == "NOGK" for e in req.entries)
    if _project_id and not any(k in _existing_kinds for k in ("cvuln_verify", "webvulnverify")):
        try:
            verify_traces = ps.discover_verify_traces(_project_id)
            for vt in verify_traces:
                # 有 No-KG 时为每个验证 agent 创建 KG + NOGK 两个 entry；仅 KG 时只创建 KG
                _conds = ("KG", "NOGK") if _has_nogk_entries else ("KG",)
                for cond in _conds:
                    req.entries.append({
                        "task_id": f"verify-{vt['agent_name']}",
                        "condition": cond,
                        "source_uri": vt["source_uri"],
                        "trace_kind": vt["trace_kind"],
                        "category": "verify",
                        "project_id": _project_id,
                        "benchmark_item_id": None,
                        "benchmark_item_ids": [],
                    })
                log("CREATE", f"自动发现验证 trace: {vt['agent_name']} kind={vt['trace_kind']} conds={_conds}")
        except Exception as err:
            log("CREATE", f"⚠ 自动发现验证 trace 失败: {err}")

    # Step 1: evaluation
    eval_name = req.evaluation_name or f"eval-{req.evaluation_id}"
    conn = connect(autocommit=True)
    try:
        conn.cursor().execute(
            "INSERT INTO evaluation (evaluation_id, evaluation_name, benchmark_set_id, agent_name) "
            "VALUES (%s,%s,%s,'Turing')",
            (req.evaluation_id, eval_name, req.benchmark_set_id))
    finally:
        conn.close()

    # Step 2: evaluation_snapshot（独立连接）
    # 基线数据、告警中心数据在 run() 的 INGESTING 阶段获取，create() 只冻结 entries + 配置
    manifest = {"entries": req.entries, "manifest_hash": "mh",
                "vbench_project_name": req.vbench_project_name,
                "benchmark_source": req.benchmark_source,
                "benchmark_set_id": req.benchmark_set_id,
                "vc_source_task_id": req.vc_source_task_id,
                "vc_source_project_name": req.vc_source_project_name,
                "vc_source_task_name": req.vc_source_task_name}
    conn = connect(autocommit=True)
    try:
        conn.cursor().execute(
            "INSERT INTO evaluation_snapshot (snapshot_id, evaluation_id, parser_version, resolver_version, "
            "metric_profile_version, statistical_profile, canonical_action_schema, knowledge_rule_version, "
            "token_schema_version, experiment_fingerprint_json, code_hashes_json, config_json) "
            "VALUES (%s,%s,'1.0','1.0','1.0','1.0','1.0','1.0','1.0',%s,%s,%s)",
            (f"snap-{req.evaluation_id}", req.evaluation_id,
             json.dumps({"agent_hash": "a"}), json.dumps({}),
             json.dumps({"manifest": manifest, **EVAL_CONFIG})))
    finally:
        conn.close()

    return req.evaluation_id


def _db_query(fn, _retries=8):
    """从连接池取连接执行 DB 操作。ping 检测 + 断连重试双重保障。

    2006/2013 时强制关闭底层连接（pymysql._force_close 不设 _closed，
    导致 DBUtils 认为连接仍可用并放回池中，重试取到同一个坏连接）。
    """
    import pymysql
    from ..infrastructure.log_util import log_to_file
    last_err = None
    for attempt in range(_retries):
        conn = None
        try:
            conn = connect(autocommit=True)
            return fn(conn.cursor())
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
            last_err = e
            # 强制关闭底层 pymysql 连接，防止池复用坏连接
            if conn:
                try:
                    inner = getattr(conn, '_con', None)
                    if inner is not None and not getattr(inner, '_closed', True):
                        inner.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            if e.args and e.args[0] in (2013, 2006) and attempt < _retries - 1:
                _wait = min(2 * (attempt + 1), 30)  # 指数退避，上限 30s
                log("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]}, retry in {_wait}s...")
                log_to_file("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]} {e}, retry in {_wait}s...")
                import time; time.sleep(_wait)
                continue
            raise
        finally:
            if conn:
                try: conn.close()
                except: pass


def run(evaluation_id: str) -> dict:
    """跑完整管线。使用短连接：慢操作（trace 解析、LLM）期间不持有 MySQL 连接。"""
    set_eval_ctx(evaluation_id)
    clear_cancel(evaluation_id)  # 新线程启动，清除可能的旧取消标记

    # LLM 并发上限由 load_system_config() 从 DB 加载，不在 run() 中覆盖

    # ===== 重跑前清空所有历史数据（DB + 静态报告文件）=====
    def _clear_all_old_data(cur):
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for tbl in ("statistical_result", "metric_result", "pair_derived_fact", "task_pair",
                     "outcome_fact", "tool_action_fact", "resource_fact",
                     "knowledge_interaction_fact", "task_run", "trace_source",
                     "finding_benchmark_match", "extracted_finding", "session_graph",
                     "exclusion_record", "evaluation_report"):
            cur.execute(f"DELETE FROM {tbl} WHERE evaluation_id=%s", (evaluation_id,))
        # benchmark_item 按 benchmark_set_id 关联，不是 evaluation_id
        cur.execute("SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        _bs_row = cur.fetchone()
        if _bs_row and _bs_row[0]:
            cur.execute("DELETE FROM benchmark_item WHERE benchmark_set_id=%s", (_bs_row[0],))
        cur.execute("DELETE FROM evaluation_population_snapshot WHERE calculation_run_id LIKE %s",
                    (f"CR-{evaluation_id}%",))
        cur.execute("DELETE FROM evaluation_calculation_run WHERE calculation_run_id LIKE %s",
                    (f"CR-{evaluation_id}%",))
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
        log("RUN", f"清理旧数据（重跑）: evaluation_id={evaluation_id} 含 benchmark_item")
    _db_query(_clear_all_old_data)
    # 删除旧的静态报告 HTML 文件
    import os as _os_clear
    try:
        _reports_dir = _os_clear.environ.get("EVAL_REPORTS_DIR") or _os_clear.path.join(
            _os_clear.path.dirname(_os_clear.path.dirname(_os_clear.path.abspath(__file__))), "reports")
        _html_path = _os_clear.path.join(_reports_dir, f"{evaluation_id}.html")
        if _os_clear.path.isfile(_html_path):
            _os_clear.remove(_html_path)
            log("RUN", f"删除旧静态报告: {_html_path}")
    except Exception as _e:
        log("RUN", f"删除旧静态报告失败（不影响重跑）: {_e}")

    # ===== Phase 0: INGESTING — 取基线 + 告警中心数据 + 写 benchmark_items =====
    _set_status_short(evaluation_id, "INGESTING")
    set_progress(evaluation_id, "获取基线数据...")

    # 0a. 读 snapshot 配置 + benchmark_set_id（短连接）
    def _read_ingest_config(cur):
        cur.execute("SELECT config_json FROM evaluation_snapshot WHERE evaluation_id=%s", (evaluation_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"evaluation {evaluation_id} not found")
        cfg = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        cur.execute("SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        eval_row = cur.fetchone()
        benchmark_set_id = eval_row[0] if eval_row else "BS001"
        return cfg, benchmark_set_id
    _ingest_cfg, _ingest_bsid = _db_query(_read_ingest_config)
    _ingest_manifest = _ingest_cfg.get("manifest", {})
    _ingest_entries = _ingest_manifest.get("entries", [])
    _bm_source = _ingest_manifest.get("benchmark_source", "vbench_zip")
    _vc_task_id = _ingest_manifest.get("vc_source_task_id")

    # 0b. 获取基线 case 详情（含漏洞描述）。数据源二选一：
    #   vbench_zip   — 从 V-Bench benchmark.zip 读（测评集基线）
    #   vuln_center  — 从漏洞中心 Chimera 直接读人工确认 case（含漏洞与非漏洞两类）
    case_details = {}
    if _bm_source == "vuln_center" and not _vc_task_id:
        for e in _ingest_entries:
            tid_actual = e.get("task_id_actual") or _extract_source_task_id(e) or e.get("task_id")
            if tid_actual:
                _vc_task_id = tid_actual
                break
        if _vc_task_id:
            log("INGEST", f"vc_source_task_id 未指定，使用 entries 的 task_id_actual={_vc_task_id} 过滤")
    try:
        if _bm_source == "vuln_center":
            from ..infrastructure.vuln_center_client import get_vuln_center_benchmark
            log("INGEST", f"漏洞中心取基线: project={_ingest_bsid} task={_vc_task_id}")
            bm = get_vuln_center_benchmark(_ingest_bsid, _vc_task_id)
            n_cases = len(bm.get("cases") or [])
            log("INGEST", f"漏洞中心返回 {n_cases} 条 case")
            if n_cases == 0 and _vc_task_id:
                log("INGEST", f"task={_vc_task_id} 不是漏洞中心 source_task，不带 task 过滤重试")
                bm = get_vuln_center_benchmark(_ingest_bsid, None)
                n_cases = len(bm.get("cases") or [])
                log("INGEST", f"不带 task 过滤返回 {n_cases} 条 case")
            _total = len(bm.get("cases") or [])
            _done = 0
            for c in (bm.get("cases") or []):
                cid = c.get("case_id") or c.get("id") or ""
                if cid:
                    case_details[cid] = {
                        "description": c.get("description") or "",
                        "vulnerability_type": c.get("vulnerability_type") or "",
                        "target_finding_id": c.get("target_finding_id") or "",
                        "expected_label": c.get("expected_label") or "VULNERABLE",
                        "source_file": c.get("source_file") or "",
                        "source_function": c.get("source_function") or "",
                        "source_line": c.get("source_line") or "",
                    }
                    _fill_missing_source(case_details[cid])
                _done += 1
                if _done % 5 == 0 or _done == _total:
                    set_progress(evaluation_id, f"获取基线数据: {_done}/{_total} 条 case")
        else:
            from ..infrastructure.vbench_client import get_benchmark
            log("INGEST", f"V-Bench 取基线: set_id={_ingest_bsid}")
            bm = get_benchmark(_ingest_bsid)
            _all_cases = bm.get("cases") or []
            _vuln_n = sum(1 for c in _all_cases if (c.get("expected_label") or "VULNERABLE") == "VULNERABLE")
            _nonvuln_n = sum(1 for c in _all_cases if c.get("expected_label") == "NON_VULNERABLE")
            log("INGEST", f"V-Bench 返回 {len(_all_cases)} 条 case（漏洞={_vuln_n} 非漏洞={_nonvuln_n}）")
            if _nonvuln_n == 0:
                log("INGEST", "⚠ 非漏洞基线为 0 — 请确认 benchmark.zip 中包含 false_positives.json")
            _total = len(_all_cases)
            _done = 0
            for c in _all_cases:
                cid = c.get("case_id") or c.get("id") or ""
                if cid:
                    findings = c.get("findings") or []
                    desc = " ".join(f.get("explanation", "") for f in findings if f.get("explanation")) or c.get("vulnerability_type", "") or c.get("description") or ""
                    case_details[cid] = {
                        "description": desc,
                        "vulnerability_type": c.get("vulnerability_type") or c.get("category") or "",
                        "target_finding_id": c.get("target_finding_id") or "",
                        "expected_label": c.get("expected_label") or "VULNERABLE",
                        "source_file": c.get("source_file") or "",
                        "source_function": c.get("source_function") or "",
                        "source_line": c.get("source_line") or "",
                    }
                _done += 1
                if _done % 5 == 0 or _done == _total:
                    set_progress(evaluation_id, f"获取基线数据: {_done}/{_total} 条 case")
        log("INGEST", f"case_details 构建完成: {len(case_details)} 条")
    except Exception as e:
        import traceback as _tb
        log("INGEST", f"取基线数据失败: {e}")
        _tb.print_exc()
    if not case_details:
        raise ValueError("无法获取基线数据（case_details 为空），没有基线的评测无意义。"
                         "请检查 benchmark_source 配置、V-Bench/漏洞中心服务连通性后重试。")

    # 并行补提取缺失的 source 信息（每个 case 可能调一次 LLM）
    _need_fill = [cd for cd in case_details.values()
                  if not cd.get("source_file") or not cd.get("source_function") or not cd.get("source_line")]
    if _need_fill:
        from ..infrastructure import llm as llm_mod
        if llm_mod.is_enabled():
            from concurrent.futures import ThreadPoolExecutor, as_completed
            log("INGEST", f"并行补提取 source 信息: {len(_need_fill)} 条 case")
            _fill_done = [0]
            import threading as _th
            _fill_lock = _th.Lock()
            with ThreadPoolExecutor(max_workers=min(len(_need_fill), 8)) as pool:
                futures = [pool.submit(_fill_missing_source, cd) for cd in _need_fill]
                for fut in as_completed(futures):
                    fut.result()
                    with _fill_lock:
                        _fill_done[0] += 1
                        if _fill_done[0] % 5 == 0 or _fill_done[0] == len(_need_fill):
                            set_progress(evaluation_id, f"补提取 source: {_fill_done[0]}/{len(_need_fill)}")

    # 0c. 获取告警中心数据（T001 提交的漏洞 + T002 引擎判定结论）
    _ac_pairs: list[tuple[str, str]] = []
    _seen_pairs: set[tuple[str, str]] = set()
    for e in _ingest_entries:
        _pid = e.get("project_id") or ""
        _tid = e.get("task_id_actual") or _extract_source_task_id(e) or _vc_task_id or ""
        if _pid and _tid and (_pid, _tid) not in _seen_pairs:
            _ac_pairs.append((_pid, _tid))
            _seen_pairs.add((_pid, _tid))
    _alert_center_data = {}
    if _ac_pairs:
        try:
            from ..infrastructure.vuln_center_client import get_alert_center_summary
            _all_cases: list[dict] = []
            _merged_counts = {"vulnerable": 0, "not_vulnerable": 0, "inconclusive": 0, "pending": 0}
            for _ac_project, _ac_task in _ac_pairs:
                log("INGEST", f"告警中心取数据: project={_ac_project} task={_ac_task}")
                ac_summary = get_alert_center_summary(_ac_project, _ac_task)
                ac_total = ac_summary.get("total", 0)
                ac_counts = ac_summary.get("counts", {})
                log("INGEST", f"告警中心返回 {ac_total} 条 case: "
                    f"是漏洞={ac_counts.get('vulnerable', 0)} "
                    f"不是漏洞={ac_counts.get('not_vulnerable', 0)} "
                    f"无法判定={ac_counts.get('inconclusive', 0)} "
                    f"研判中={ac_counts.get('pending', 0)}")
                for k in _merged_counts:
                    _merged_counts[k] += ac_counts.get(k, 0)
                _all_cases.extend(
                    {
                        "case_id": c.get("id") or c.get("case_id") or "",
                        "title": c.get("title") or "",
                        "summary": c.get("summary") or "",
                        "validation_result": c.get("validation_result"),
                        "current_stage": c.get("current_stage"),
                        "current_status": c.get("current_status"),
                        "project_id": _ac_project,
                    }
                    for c in ac_summary.get("cases", [])
                )
            _alert_center_data = {
                "source_task_ids": [t for _, t in _ac_pairs],
                "project_ids": [p for p, _ in _ac_pairs],
                "total": len(_all_cases),
                "counts": _merged_counts,
                "cases": _all_cases,
            }
        except Exception as e:
            import traceback as _tb
            log("INGEST", f"⚠ 取告警中心数据失败: {e}")
            _tb.print_exc()
    else:
        log("INGEST", "⚠ 跳过告警中心数据获取: entries 中无 project_id/task_id_actual")

    # 0d. 写 benchmark_set + benchmark_items（短连接，幂等）
    conn = connect(autocommit=True)
    try:
        fact_repo.insert_benchmark_set(conn.cursor(), _ingest_bsid)
    finally:
        conn.close()

    _filter_by_case_details = _bm_source == "vuln_center" and case_details
    _inserted_ids: set[str] = set()
    for e in _ingest_entries:
        item_ids = e.get("benchmark_item_ids") or ([e["benchmark_item_id"]] if e.get("benchmark_item_id") else [])
        if _filter_by_case_details:
            _before = len(item_ids)
            item_ids = [bid for bid in item_ids if bid in case_details]
            if _before != len(item_ids):
                log("INGEST", f"task={e.get('task_id','')} 过滤掉 {_before - len(item_ids)} 条不属于当前任务的 case，"
                      f"剩余 {len(item_ids)} 条")
        for bid in item_ids:
            cd = case_details.get(bid) or {}
            if not cd:
                log("INGEST", f"⚠ benchmark_item {bid} 在 case_details 中未找到 → metadata 将为空")
            conn = connect(autocommit=True)
            try:
                fact_repo.insert_benchmark_item(conn.cursor(), bid, _ingest_bsid,
                                                e["task_id"], cd.get("expected_label") or e.get("expected_label", "VULNERABLE"),
                                                cd.get("target_finding_id") or e.get("target_finding_id"),
                                                cd)
            finally:
                conn.close()
            _inserted_ids.add(bid)

    # 插入非漏洞基线（来自 false_positives.json，不在 entries item_ids 中的）
    _supplemented = [cid for cid, cd in case_details.items()
                     if cd.get("expected_label") == "NON_VULNERABLE" and cid not in _inserted_ids]
    if _supplemented:
        _task_id = _ingest_entries[0]["task_id"] if _ingest_entries else ""
        for cid in _supplemented:
            cd = case_details[cid]
            conn = connect(autocommit=True)
            try:
                fact_repo.insert_benchmark_item(conn.cursor(), cid, _ingest_bsid,
                                                _task_id, "NON_VULNERABLE", "", cd)
            finally:
                conn.close()
        log("INGEST", f"插入 {len(_supplemented)} 条非漏洞基线到 DB（来自 false_positives.json）")

    if _alert_center_data:
        _ac_counts = _alert_center_data.get("counts", {})
        log("INGEST", f"基线数据就绪: case_details={len(case_details)} "
              f"告警中心={_alert_center_data.get('total', 0)} "
              f"(是漏洞={_ac_counts.get('vulnerable', 0)} "
              f"不是漏洞={_ac_counts.get('not_vulnerable', 0)})")
    else:
        log("INGEST", f"基线数据就绪: case_details={len(case_details)} 告警中心=0")

    # ===== Phase 1: 读配置（短连接）=====
    def _load_config(cur):
        cur.execute("SELECT config_json FROM evaluation_snapshot WHERE evaluation_id=%s", (evaluation_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"evaluation {evaluation_id} not found")
        cfg = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        entries = cfg.get("manifest", {}).get("entries", [])
        cur.execute("SELECT benchmark_item_id, task_id, expected_label, target_finding_id, metadata_json FROM benchmark_item "
                    "WHERE benchmark_set_id=(SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s)",
                    (evaluation_id,))
        bench_by_task = {}
        for bi_id, tid, label, tfid, meta in cur.fetchall():
            md = json.loads(meta) if isinstance(meta, str) else (meta or None)
            bench_by_task.setdefault(tid, []).append(
                BenchmarkItem(bi_id, "BS001", tid, ExpectedLabel(label) if label else None, tfid, md))
        # 基线是评测级共享的：benchmark_item 的 UNIQUE(set_id, item_id) 导致第二条
        # entry 的 INSERT IGNORE 被跳过 → 只有首个 task_id 拿到基线。把完整基线
        # 分配给所有 entry 的 task_id，避免 bench_by_task.get(tid) 为空。
        if bench_by_task and entries:
            # 收集所有 task_id 桶的全部基线（去重），而非每个桶只取第一条
            _seen_ids = set()
            _all_items = []
            for items in bench_by_task.values():
                for item in items:
                    if item.benchmark_item_id not in _seen_ids:
                        _seen_ids.add(item.benchmark_item_id)
                        _all_items.append(item)
            for e in entries:
                _tid = e.get("task_id", "")
                if _tid and _tid not in bench_by_task:
                    bench_by_task[_tid] = [BenchmarkItem(b.benchmark_item_id, "BS001", _tid,
                                                         b.expected_label, b.target_finding_id, b.metadata)
                                           for b in _all_items]
        # 漏洞中心模式：只保留人工确认 case（含漏洞与非漏洞）作为基线。
        # task_id_actual 不是有效的 source_task_id 时会返回 0 条，不带 task 过滤重试。
        _bm_src = cfg.get("manifest", {}).get("benchmark_source", "")
        _vc_tid = cfg.get("manifest", {}).get("vc_source_task_id")
        if _bm_src == "vuln_center" and not _vc_tid:
            for e in entries:
                _vc_tid = e.get("task_id_actual") or _extract_source_task_id(e) or e.get("task_id")
                if _vc_tid:
                    break
        if _bm_src == "vuln_center" and _vc_tid:
            try:
                from ..infrastructure.vuln_center_client import get_vuln_center_benchmark
                _vc_proj = cfg.get("manifest", {}).get("benchmark_set_id", "")
                _vc_bm = get_vuln_center_benchmark(_vc_proj, _vc_tid)
                _vc_cases = _vc_bm.get("cases") or []
                _vc_ids = {c.get("case_id") or c.get("id") or "" for c in _vc_cases}
                if not _vc_ids:
                    # task_id_actual 不是有效的 source_task_id，不带 task 过滤重试
                    log("LOAD", f"漏洞中心 task={_vc_tid} 返回 0 条，不带 task 过滤重试")
                    _vc_bm = get_vuln_center_benchmark(_vc_proj, None)
                    _vc_cases = _vc_bm.get("cases") or []
                    _vc_ids = {c.get("case_id") or c.get("id") or "" for c in _vc_cases}
                    log("LOAD", f"不带 task 过滤返回 {len(_vc_ids)} 条 case")
                if _vc_ids:
                    _before = sum(len(v) for v in bench_by_task.values())
                    for tid in list(bench_by_task.keys()):
                        bench_by_task[tid] = [b for b in bench_by_task[tid] if b.benchmark_item_id in _vc_ids]
                    _after = sum(len(v) for v in bench_by_task.values())
                    if _before != _after:
                        log("LOAD", f"漏洞中心过滤 benchmark: {_before} → {_after} 条（只保留 VULNERABLE）")
            except Exception as e:
                log("LOAD", f"漏洞中心校验失败（不影响评测）: {e}")
        return cfg, entries, bench_by_task
    cfg, entries, bench_by_task = _db_query(_load_config)

    # 告警中心数据已在 Phase 0 (INGESTING) 获取，直接使用 _alert_center_data

    # ===== Phase 2: 解析 trace + 提取 facts（无 DB 连接 — 慢操作）=====
    facts_already_exist = False

    def _is_webvulnverify_trace(path):
        """检测 JSONL 是否为 WebVulnVerify 格式（含 session_meta 行类型）。"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    import json as _json
                    d = _json.loads(line)
                    return d.get("type") == "session_meta"
        except Exception:
            pass
        return False

    def _get_parser(uri, trace_kind: str | None = None):
        import os as _os
        if trace_kind == "webvulnverify":
            from ..workers.webvulnverify_trace_parser import WebVulnVerifyTraceParser
            return WebVulnVerifyTraceParser()
        if trace_kind == "cvuln_verify":
            from ..workers.cvuln_verify_trace_parser import CVulnVerifyTraceParser
            return CVulnVerifyTraceParser()
        if trace_kind == "argo":
            from ..workers.argo_trace_parser import ArgoTraceParser
            from ..infrastructure import llm as _llm_mod
            return ArgoTraceParser(llm_module=_llm_mod)
        if trace_kind == "turing":
            from ..workers.turing_trace_parser import TuringTraceParser
            return TuringTraceParser()
        if trace_kind == "dataflow":
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        if trace_kind == "secmate":
            from ..workers.secmate_trace_parser import SecMateTraceParser
            return SecMateTraceParser()
        # 兼容：无 trace_kind 时按路径推断
        p = _os.path.normpath(uri)
        cvuln_suffix = _os.path.join("tasks", "c_vuln_verify")
        argo_suffix = _os.path.join("session", "argo")
        dataflow_suffix = _os.path.join("session", "dataflow_vuln_scan")
        if p.replace("\\", "/").endswith("/session/secmate"):
            from ..workers.secmate_trace_parser import SecMateTraceParser
            return SecMateTraceParser()
        if _os.path.isdir(p) and p.endswith(cvuln_suffix):
            from ..workers.cvuln_verify_trace_parser import CVulnVerifyTraceParser
            return CVulnVerifyTraceParser()
        if _os.path.isdir(p) and p.endswith(argo_suffix):
            from ..workers.argo_trace_parser import ArgoTraceParser
            from ..infrastructure import llm as _llm_mod
            return ArgoTraceParser(llm_module=_llm_mod)
        if _os.path.isdir(p) and (p.endswith(dataflow_suffix) or "dataflow_vuln_scan" in p):
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        # 单个 dataflow jsonl 文件（路径含 dataflow_vuln_scan）也用 dataflow 解析器
        if "dataflow_vuln_scan" in p and (p.endswith(".jsonl") or _os.path.isdir(p)):
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        if p.endswith("opencode.db"):
            from ..workers.turing_trace_parser import TuringTraceParser
            return TuringTraceParser()
        if _os.path.isdir(p) or p.endswith(".jsonl"):
            from ..workers.secmate_trace_parser import is_secmate_trace
            if is_secmate_trace(p):
                from ..workers.secmate_trace_parser import SecMateTraceParser
                return SecMateTraceParser()
            # Check WebVulnVerify format (has session_meta line type)
            _check_path = p
            if _os.path.isdir(p):
                import glob as _glob
                _jfiles = sorted(_glob.glob(_os.path.join(p, "*.jsonl")))
                _check_path = _jfiles[0] if _jfiles else ""
            if _check_path and _is_webvulnverify_trace(_check_path):
                from ..workers.webvulnverify_trace_parser import WebVulnVerifyTraceParser
                return WebVulnVerifyTraceParser()
            from ..workers.argo_trace_parser import ArgoTraceParser
            from ..infrastructure import llm as _llm_mod
            return ArgoTraceParser(llm_module=_llm_mod)
        from ..workers.turing_trace_parser import TuringTraceParser
        return TuringTraceParser()

    task_runs: list[TaskRun] = []
    facts: dict[str, dict] = {}
    if facts_already_exist:
        # 重试：从 DB 加载已有 facts，跳过解析
        _set_status_short(evaluation_id, "CALCULATING")
        def _load_facts(cur):
            cur.execute("SELECT task_run_id, task_id, `condition`, benchmark_item_id, trace_valid, runtime_valid FROM task_run WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                tr = TaskRun(task_run_id=r[0], evaluation_id=evaluation_id, task_id=r[1],
                            trace_id=r[0].replace("tr-", "ts-"),
                            condition=Condition[r[2]], condition_source=ConditionSource.MANIFEST,
                            trace_valid=bool(r[4]), runtime_valid=bool(r[5]), benchmark_item_id=r[3])
                task_runs.append(tr)
        _db_query(_load_facts)
        # 加载 outcomes + tool + resource facts
        def _load_facts_from_db(cur):
            for t in task_runs:
                facts[t.task_run_id] = {"_task_id": t.task_id}
            # outcomes（含 confusion_label + case_results from evidence_json）
            cur.execute("SELECT task_run_id, outcome, prediction, resolver_status, validation_result, "
                        "confusion_label, benchmark_item_id, target_finding_id, gt_label, evidence_json "
                        "FROM outcome_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                from ..domain.enums import Outcome, Prediction, Confusion
                _ev = json.loads(r[9]) if r[9] and isinstance(r[9], str) else (r[9] or {})
                # case_results 存文件时从文件读
                _cr_uri = _ev.get("case_results_uri") if isinstance(_ev, dict) else None
                if _cr_uri and os.path.isfile(_cr_uri):
                    with open(_cr_uri, "r", encoding="utf-8") as _f:
                        _cr = json.loads(_f.read()).get("case_results", [])
                else:
                    _cr = _ev.get("case_results", []) if isinstance(_ev, dict) else []
                _oc = type('OC', (), {
                    'task_run_id': r[0], 'outcome_fact_id': f"ocf-{r[0]}",
                    'outcome': Outcome(r[1]) if r[1] else Outcome.UNDETERMINED,
                    'prediction': Prediction(r[2]) if r[2] else Prediction.UNDETERMINED,
                    'resolver_status': r[3], 'validation_result': r[4],
                    'confusion_label': Confusion(r[5]) if r[5] else None,
                    'benchmark_item_id': r[6], 'target_finding_id': r[7],
                    'gt_label': ExpectedLabel(r[8]) if r[8] else None,
                    'case_results': _cr,
                })()
                facts[r[0]] = {"outcome": _oc, "case_results": _cr, "_task_id": facts.get(r[0], {}).get("_task_id", "")}
            # tool action facts
            cur.execute("SELECT task_run_id, kg_count, finding_count, code_count, shell_count, other_count, total_tool_calls, action_distribution FROM tool_action_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                if r[0] in facts:
                    _ad = json.loads(r[7]) if r[7] and isinstance(r[7], str) else (r[7] or {})
                    facts[r[0]]["tool"] = type('TA', (), {
                        'kg_count': r[1], 'finding_count': r[2], 'code_count': r[3],
                        'shell_count': r[4], 'other_count': r[5], 'total_tool_calls': r[6],
                        'tool_action_fact_id': r[0],
                        'action_distribution': _ad if isinstance(_ad, dict) else {},
                    })()
            # resource facts
            cur.execute("SELECT task_run_id, effective_tokens, steps, duration_ms, time_valid FROM resource_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                if r[0] in facts:
                    facts[r[0]]["resource"] = type('RS', (), {
                        'resource_fact_id': f"rsf-{r[0]}",
                        'effective_tokens': r[1], 'tokens': r[1], 'steps': r[2],
                        'duration': r[3], 'duration_ms': r[3], 'time_valid': bool(r[4]),
                    })()
            # knowledge facts
            cur.execute("SELECT task_run_id, access, delivery, mount_status, access_event_count, "
                        "read_event_count, successful_read_count, evidence_json "
                        "FROM knowledge_interaction_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                if r[0] in facts:
                    ev = json.loads(r[7]) if r[7] and isinstance(r[7], str) else (r[7] or {})
                    _interactions = ev.get("interactions", []) if isinstance(ev, dict) else []
                    facts[r[0]]["knowledge"] = type('KN', (), {
                        'access': bool(r[1]), 'delivery': bool(r[2]), 'mount_status': r[3],
                        'access_event_count': r[4] or 0,
                        'read_event_count': r[5] or 0,
                        'successful_read_count': r[6] or 0,
                        'interactions': _interactions,
                    })()
        _db_query(_load_facts_from_db)
    else:
        set_progress(evaluation_id, "解析 Trace: 准备中...")
        _set_status_short(evaluation_id, "PARSING")
        _check_cancel(evaluation_id, "PARSING")
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _parse_trace(e):
            """Phase 1: 解析 trace → events + session（无 LLM，快）。"""
            cond = Condition.KG if e["condition"] == "KG" else Condition.NOGK
            biid = e.get("benchmark_item_id") or None
            tr = TaskRun(
                task_run_id=f"tr-{evaluation_id}-{e['task_id']}-{cond.value}",
                evaluation_id=evaluation_id, task_id=e["task_id"],
                trace_id=f"ts-{evaluation_id}-{e['task_id']}-{cond.value}",
                condition=cond, condition_source=ConditionSource.MANIFEST,
                trace_valid=True, runtime_valid=True, benchmark_item_id=biid,
            )
            src = e["source_uri"]
            local_path = _local_paths.get(src) or _resolve_trace_path(src, e.get("project_id", ""), e["task_id"])
            import os as _os
            exists = _os.path.exists(local_path)
            is_dir = _os.path.isdir(local_path) if exists else False
            size = 0
            if exists and not is_dir:
                try: size = _os.path.getsize(local_path)
                except: pass
            elif exists and is_dir:
                try:
                    files_in_dir = [f for f in _os.listdir(local_path) if f.endswith((".jsonl", ".db"))]
                    if not files_in_dir:
                        for sub in _os.listdir(local_path):
                            sub_path = _os.path.join(local_path, sub)
                            if _os.path.isdir(sub_path):
                                files_in_dir += [f"{sub}/{f}" for f in _os.listdir(sub_path) if f.endswith((".jsonl", ".db"))]
                    size = sum(_os.path.getsize(_os.path.join(local_path, f)) for f in files_in_dir) if files_in_dir else 0
                except: files_in_dir = []
            log("PARSE", f"{cond.value} task={e['task_id']} kind={e.get('trace_kind')} "
                  f"path={local_path} exists={exists} is_dir={is_dir} size={size}B")
            if not exists:
                log("PARSE", f"⚠ trace 文件不存在: {local_path} (source_uri={src})")
            parser = _get_parser(local_path, e.get("trace_kind"))
            bench = list(bench_by_task.get(e["task_id"], []))
            trace_source = {"trace_id": tr.trace_id, "source_uri": local_path}
            # CVulnVerify 的目录由多个平台任务共享，解析时必须只保留本次选择
            # 的原始平台任务所关联、且属于当前 benchmark 的 case 文件。
            if e.get("trace_kind") == "cvuln_verify":
                task_id_actual = e.get("task_id_actual", "") or _extract_source_task_id(e)
                trace_case_ids = [str(c) for c in e.get("trace_case_ids", []) if c]
                # CVulnVerify 的 JSONL 文件在项目目录下（非任务目录），
                # 需要任务 ID 来过滤出本次评测的文件。
                # 优先用 manifest 的 task_id_actual；缺失时从告警中心
                # 按 trace_case_ids 搜索获取 source_task.task_id。
                if not task_id_actual and trace_case_ids:
                    try:
                        from ..infrastructure.vuln_center_client import get_task_id_by_case_id
                        _proj = e.get("project_id", "")
                        task_id_actual = get_task_id_by_case_id(_proj, trace_case_ids[0]) or ""
                        log("CVULN", f"manifest 无 task_id_actual，从告警中心搜索获取: "
                              f"{task_id_actual}")
                    except Exception as err:
                        log("CVULN", f"从告警中心获取 task_id 失败: {err}")
                trace_source["source_task_id"] = task_id_actual
                # trace_case_ids 与 benchmark_item_id 属于不同命名空间，
                # 不能用它过滤基线。它只传给 parser 做 JSONL 文件过滤。
                trace_source["source_case_ids"] = trace_case_ids
                if trace_case_ids:
                    log("CVULN", f"task={task_id_actual} "
                          f"benchmark={len(bench)} trace_case_ids={len(trace_case_ids)}")
                else:
                    log("CVULN", f"未提供 trace_case_ids，parser 将不过滤文件")
            log("PARSE", f"{cond.value} parser={parser.__class__.__name__}")
            events = list(parser.parse(trace_source))
            log("PARSE", f"{cond.value} events={len(events)}")
            if not events:
                log("PARSE", f"⚠ {cond.value} 解析出 0 个事件！path={local_path}")
            # 跨 JSONL 文件时按时间戳排序，确保事件顺序正确
            events.sort(key=lambda e: (e.timestamp_ms or 0, e.event_id))
            session = parser.load_session(trace_source)
            session["_events_ts"] = [ev.timestamp_ms for ev in events]
            if not bench:
                bench = [BenchmarkItem(None, "BS001", e["task_id"], None, e.get("target_finding_id"))]
            return {"tr": tr, "events": events, "session": session, "bench": bench, "src": src,
                    "cond": cond, "parser": parser,
                    "trace_kind": e.get("trace_kind"), "category": e.get("category", ""),
                    "project_id": e.get("project_id", "")}

        def _resolve_trace(parsed):
            """Phase 2: 漏洞匹配 + resolve（含 LLM，慢）。

            三方匹配方案（finding 为锚点）：
            1. parser 提取 trace findings
            2. 告警中心 case ↔ finding AI 匹配（跟基线一样的方案，告警中心为锚点）
            3. 匹配上的 finding 用告警中心 validation_result 更新 verdict
            4. 未匹配上 finding 的告警中心 case 作为兜底 finding（直接参与 finding↔基线匹配）
            5. sink_match_baselines 做 sink 点匹配 + session 链 LLM 分析 → TP/FP/FN/TN
            """
            from concurrent.futures import ThreadPoolExecutor
            tr = parsed["tr"]; events = parsed["events"]; session = parsed["session"]
            bench = parsed["bench"]; cond = parsed["cond"]; parser = parsed["parser"]
            trace_kind = parsed.get("trace_kind")
            category = parsed.get("category", "")
            _trace_project_id = parsed.get("project_id", "")
            is_verify = category == "verify" or trace_kind in ("cvuln_verify", "webvulnverify")
            _trid = tr.task_run_id

            log("MATCH", f"[{_trid}] {cond.value} bench_items={len(bench)} events={len(events)} starting ai_match + resolve...")
            _trace_start = time.time()
            _TRACE_TIMEOUT = 7200  # 单条 trace 超时上限 2 小时
            # 提前构建 session_graph，sink_match_baselines 和返回值共用，避免重复遍历百万级 events
            log("MATCH", f"[{_trid}] {cond.value} build_session_graph start (events={len(events)})")
            session_graph = parser.build_session_graph(events) if parser else {}
            log("MATCH", f"[{_trid}] {cond.value} session_graph built ({len(session_graph.get('sessions',{}))} sessions) "
                  f"in {int(time.time()-_trace_start)}s")
            inner_pool = ThreadPoolExecutor(max_workers=50)
            try:
                # KN/TA/RS 不依赖告警中心匹配，先提交并行跑
                fut_kn = inner_pool.submit(KnowledgeResolverImpl(EVAL_CONFIG).resolve, tr, events)
                fut_ta = inner_pool.submit(ToolActionResolverImpl(EVAL_CONFIG).resolve, tr, events, "1.0")
                fut_rs = inner_pool.submit(ResourceResolverImpl(EVAL_CONFIG).resolve, tr, session)
                log("MATCH", f"[{_trid}] {cond.value} KN/TA/RS resolvers submitted")

                # 三方匹配（主线程跑，KN/TA/RS 在后台并行）
                _findings_override = None
                _ac_confirmed = 0
                _ac_fp = 0
                _ac_cases = []  # 按项目过滤后的告警中心 case
                if _alert_center_data and _alert_center_data.get("cases"):
                    _ac_cases = list(_alert_center_data["cases"])
                    # 按项目过滤：只匹配当前 trace 所属项目的告警中心 case
                    if _trace_project_id:
                        _ac_cases = [c for c in _ac_cases if c.get("project_id") == _trace_project_id]
                    # Step 1: 提取 parser findings
                    _parser_findings = parser.extract_findings(events)
                    log("MATCH", f"[{_trid}] {cond.value} parser findings={len(_parser_findings)} ac_cases={len(_ac_cases)} "
                          f"(is_verify={is_verify})")

                    # Step 2: 告警中心 case ↔ finding AI 匹配（告警中心为锚点，跟基线一样）
                    _matched, _unmatched_ac = match_alert_center_to_findings(
                        _ac_cases, _parser_findings,
                        progress_cb=lambda text: set_task_progress(
                            evaluation_id, tr.task_run_id,
                            f"[{tr.condition.value}] {text}"))

                    # Step 3: 匹配上的 finding 用告警中心 validation_result 更新
                    for fi, ai in _matched.items():
                        ac = _ac_cases[ai]
                        vr = ac.get("validation_result")
                        _parser_findings[fi]["ac_case_id"] = ac.get("case_id", "")
                        if is_verify:
                            # T002: validation_result 映射
                            _parser_findings[fi]["validation_result"] = (
                                "CONFIRMED" if vr == "vulnerable" else "FALSE_POSITIVE")
                        else:
                            # T001: 告警中心全部 = agent 认为是漏洞
                            _parser_findings[fi]["validation_result"] = "CONFIRMED"
                        log("MATCH", f"[{_trid}] {cond.value} finding[{fi}] ← ac_case={ac.get('case_id','')} "
                              f"vr={vr} → {_parser_findings[fi]['validation_result']}")

                    # Step 4: 未匹配上 finding 的告警中心 case 作为兜底 finding
                    for ai in _unmatched_ac:
                        ac = _ac_cases[ai]
                        vr = ac.get("validation_result")
                        if is_verify:
                            finding_vr = "CONFIRMED" if vr == "vulnerable" else "FALSE_POSITIVE"
                        else:
                            finding_vr = "CONFIRMED"
                        _parser_findings.append({
                            "validation_result": finding_vr,
                            "title": ac.get("title") or "",
                            "vuln_type": "",
                            "description": ac.get("summary") or "",
                            "source": "",
                            "sink": "",
                            "display_id": ac.get("case_id", ""),
                            "finding_id": ac.get("case_id", ""),
                            "ac_case_id": ac.get("case_id", ""),
                        })

                    _findings_override = _parser_findings
                    _ac_confirmed = sum(1 for f in _parser_findings if f.get("validation_result") == "CONFIRMED")
                    _ac_fp = sum(1 for f in _parser_findings if f.get("validation_result") == "FALSE_POSITIVE")
                    log("MATCH", f"[{_trid}] {cond.value} 三方匹配完成: findings={len(_parser_findings)} "
                          f"matched={len(_matched)} unmatched_ac={len(_unmatched_ac)} "
                          f"confirmed={_ac_confirmed} fp={_ac_fp}")

                # sink_match_baselines: sink 点匹配 + session 链 LLM 分析 → TP/FP/FN/TN
                try:
                    fut_outcome = inner_pool.submit(sink_match_baselines, tr, bench, events, parser,
                                                    progress_cb=lambda text, tr=tr: set_task_progress(
                                                        evaluation_id, tr.task_run_id,
                                                        f"[{tr.condition.value}] {text}"),
                                                    findings_override=_findings_override,
                                                    session_graph=session_graph)
                    log("MATCH", f"[{_trid}] {cond.value} sink_match_baselines submitted (findings_override={'yes' if _findings_override is not None else 'no'})")
                except RuntimeError:
                    raise RuntimeError("线程池已关闭（Pod 可能正在重启）")
                _elapsed = time.time() - _trace_start
                _remaining = max(1, _TRACE_TIMEOUT - _elapsed)
                log("MATCH", f"[{_trid}] {cond.value} waiting for results (elapsed={int(_elapsed)}s, timeout={int(_remaining)}s)...")
                oc, case_results = fut_outcome.result(timeout=_remaining)
                log("MATCH", f"[{_trid}] {cond.value} sink_match done (elapsed={int(time.time()-_trace_start)}s)")
                _remaining = max(1, _TRACE_TIMEOUT - (time.time() - _trace_start))
                kn = fut_kn.result(timeout=_remaining)
                log("MATCH", f"[{_trid}] {cond.value} KN resolver done (elapsed={int(time.time()-_trace_start)}s)")
                _remaining = max(1, _TRACE_TIMEOUT - (time.time() - _trace_start))
                ta = fut_ta.result(timeout=_remaining)
                log("MATCH", f"[{_trid}] {cond.value} TA resolver done (elapsed={int(time.time()-_trace_start)}s)")
                _remaining = max(1, _TRACE_TIMEOUT - (time.time() - _trace_start))
                rs = fut_rs.result(timeout=_remaining)
                log("MATCH", f"[{_trid}] {cond.value} RS resolver done (elapsed={int(time.time()-_trace_start)}s)")
            except TimeoutError:
                log("MATCH", f"[{_trid}] {cond.value} TIMEOUT after {int(time.time()-_trace_start)}s "
                      f"(events={len(events)}), aborting trace")
                inner_pool.shutdown(wait=False, cancel_futures=True)
                raise RuntimeError(f"trace 超时（{int(time.time()-_trace_start)}s, events={len(events)}）")
            except Exception:
                inner_pool.shutdown(wait=False, cancel_futures=True)
                raise
            else:
                inner_pool.shutdown(wait=True)
            log("MATCH", f"[{_trid}] {cond.value} DONE outcome={oc.outcome.value} confusion={oc.confusion_label.value if oc.confusion_label else 'NA'} "
                  f"prediction={oc.prediction.value if oc.prediction else 'NA'} resolver={oc.resolver_status} "
                  f"knowledge={len(kn.interactions)} tool_calls={ta.total_tool_calls} "
                  f"tokens_in={rs.input_tokens} tokens_out={rs.output_tokens} steps={rs.steps}")
            # finding_count 保持工具调用数（JSD 用），CONFIRMED/FP 数存 action_distribution
            if _findings_override is not None:
                _findings = _findings_override
                _confirmed = _ac_confirmed
                _fp = _ac_fp
                _analyze_count = len(_ac_cases) if _alert_center_data else (_ac_confirmed + _ac_fp)
            else:
                log("MATCH", f"[{_trid}] {cond.value} extract_findings start (events={len(events)})")
                _findings = parser.extract_findings(events)
                log("MATCH", f"[{_trid}] {cond.value} extract_findings done: {len(_findings)} findings (elapsed={int(time.time()-_trace_start)}s)")
                _confirmed = sum(1 for f in _findings if f.get('validation_result') == 'CONFIRMED')
                _fp = sum(1 for f in _findings if f.get('validation_result') == 'FALSE_POSITIVE')
                # WebVulnVerify: 验证接收总数 = vulnerability_analyze + vulnerability_verify 的唯一 vulnerability_id 数
                _analyze_vids = set()
                for _e in events:
                    if _e.is_tool_call() and (_e.tool_name or "") in ("vulnerability_analyze", "vulnerability_verify"):
                        _vid = str((_e.input_json or {}).get("vulnerability_id", ""))
                        if _vid and _vid != "?":
                            _analyze_vids.add(_vid)
                _analyze_count = len(_analyze_vids) if _analyze_vids else (_confirmed + _fp)
            log("MATCH", f"[{_trid}] {cond.value} findings={len(_findings)} confirmed={_confirmed} fp={_fp} analyze_recv={_analyze_count}")
            ta.action_distribution["confirmed_finding_count"] = _confirmed
            ta.action_distribution["false_positive_finding_count"] = _fp
            ta.action_distribution["analyze_received_count"] = _analyze_count
            ta.action_distribution["alert_center_total"] = len(_ac_cases) if _ac_cases else 0
            ta.action_distribution["alert_center_counts"] = (
                {"vulnerable": sum(1 for c in _ac_cases if c.get("validation_result") == "vulnerable"),
                 "not_vulnerable": sum(1 for c in _ac_cases if c.get("validation_result") == "not_vulnerable"),
                 "inconclusive": sum(1 for c in _ac_cases if c.get("validation_result") == "inconclusive"),
                 "pending": sum(1 for c in _ac_cases if not c.get("validation_result"))}
            ) if _ac_cases else {}
            oc.case_results = case_results
            # session_graph 已在 resolve 开头构建，sink_match_baselines 复用，无需重复遍历
            return tr, {"outcome": oc, "knowledge": kn, "tool": ta, "resource": rs, "case_results": case_results, "session_graph": session_graph, "findings": _findings, "events": events, "_task_id": tr.task_id, "parser": parser, "_is_verify": is_verify}, parsed["src"]

        # 预取所有 trace 到本地（串行，避免并发写同一文件 WinError 32）
        _local_paths = {}
        for e in entries:
            key = e["source_uri"]
            if key not in _local_paths:
                _local_paths[key] = _resolve_trace_path(key, e.get("project_id", ""), e["task_id"])
        # Phase PARSING: 并行解析所有 trace → events（无 LLM，快）
        set_progress(evaluation_id, f"解析 Trace: 0/{len(entries)} 完成")
        with ThreadPoolExecutor(max_workers=max(1, min(len(entries), _runtime_workers["parse"]))) as pool:
            _parse_futures = {pool.submit(_parse_trace, e): i for i, e in enumerate(entries)}
            parsed = [None] * len(entries)
            _parse_done = 0
            for _fut in as_completed(_parse_futures):
                parsed[_parse_futures[_fut]] = _fut.result()
                _parse_done += 1
                set_progress(evaluation_id, f"解析 Trace: {_parse_done}/{len(entries)} 完成")
        # Phase AI_MATCHING: 漏洞匹配 + resolve（含 LLM，慢）
        # 所有 trace 同时启动；LLM 并发由 llm.py 全局信号量控制（上限 50）
        # 非 LLM 的 resolver 不占信号量，KG trace 的 resolver 先跑完 → LLM 槽位立刻给 No-KG
        llm_mod.reset_token_usage()
        set_progress(evaluation_id, "漏洞匹配: 准备中...")
        _set_status_short(evaluation_id, "AI_MATCHING")
        _check_cancel(evaluation_id, "AI_MATCHING")
        log("EVAL", f"漏洞匹配 + resolve 开始（{len(parsed)} 条 trace，LLM 并发上限 50）")
        _pool = ThreadPoolExecutor(max_workers=max(1, len(parsed)))
        _match_start = time.time()
        log("MATCH", f"pool.map start: {len(parsed)} traces, max_workers={max(1, len(parsed))}")
        try:
            results = list(_pool.map(_resolve_trace, parsed))
        except Exception as e:
            _pool.shutdown(wait=False, cancel_futures=True)
            log("MATCH", f"pool.map FAILED after {int(time.time()-_match_start)}s: {str(e)[:200]}")
            raise
        else:
            log("MATCH", f"pool.map all done, shutting down pool (elapsed={int(time.time()-_match_start)}s)")
            _pool.shutdown(wait=True)
            log("MATCH", f"pool.shutdown(wait=True) done (total={int(time.time()-_match_start)}s)")
        for tr, f, src in results:
            task_runs.append(tr)
            facts[tr.task_run_id] = f
            facts[tr.task_run_id]["_source_uri"] = src

        log("MATCH", f"all {len(results)} traces resolved, entering RESOLVING (total={int(time.time()-_match_start)}s)")
        # Phase 3: 写入 facts（每 task_run 一个短连接，避免长连接被防火墙断开）
        set_progress(evaluation_id, "写入事实数据...")
        _set_status_short(evaluation_id, "RESOLVING")
        # ALTER TABLE 只需执行一次（独立短连接）
        def _alter_tables(cur):
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            for col in ("vuln_type", "title", "description"):
                try:
                    cur.execute(f"ALTER TABLE extracted_finding MODIFY COLUMN {col} MEDIUMTEXT")
                except Exception:
                    pass  # 可能已是 MEDIUMTEXT
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        _db_query(_alter_tables)
        # 每个 task_run 独立短连接写入（幂等，断开可重试）
        _total_tr = len(task_runs)
        for _idx, tr in enumerate(task_runs):
            f = facts[tr.task_run_id]
            _src_uri = f.get("_source_uri", "")
            _findings = f.get("findings", [])
            _session_graph = f.get("session_graph", {})
            def _insert_one(cur):
                fact_repo.insert_trace_source(cur, tr.trace_id, evaluation_id, _src_uri)
                fact_repo.insert_task_run(cur, tr)
                fact_repo.insert_outcome_fact(cur, f["outcome"])
                fact_repo.insert_knowledge_fact(cur, f["knowledge"])
                fact_repo.insert_tool_action_fact(cur, f["tool"])
                fact_repo.insert_resource_fact(cur, f["resource"])
                fact_repo.insert_extracted_findings(cur, tr.task_run_id, evaluation_id, _findings)
                fact_repo.insert_session_graph(cur, tr.task_run_id, evaluation_id, _session_graph)
            _db_query(_insert_one)
            if (_idx + 1) % 5 == 0 or (_idx + 1) == _total_tr:
                set_progress(evaluation_id, f"写入事实数据: {_idx + 1}/{_total_tr}")

    # ===== Phase 4: 配对 + 计算指标（纯内存，无 DB）=====
    set_progress(evaluation_id, "任务配对...")
    _set_status_short(evaluation_id, "PAIRING")
    _check_cancel(evaluation_id, "PAIRING")
    pairs = TaskPairMatcherImpl().match(task_runs)
    has_nogk = any(tr.condition == Condition.NOGK for tr in task_runs)
    valid_pairs = [p for p in pairs if p.pair_match_status == PairMatchStatus.VALID_PAIR]
    # 有 No-KG trace 但配对全部失败时，退化为 KG-only 模式（避免假 PairView 产生误导指标）
    if has_nogk and not valid_pairs:
        has_nogk = False
        log("EVAL", f"⚠ 有 No-KG trace 但无有效配对，退化为 KG-only 模式")
    log("EVAL", f"配对完成: {len(pairs)} 对 (valid={len(valid_pairs)}, has_nogk={has_nogk}, task_runs={len(task_runs)})")
    pair_views: list[PairView] = []
    kg_access = kg_valid = kg_delivery = access = 0
    kg_access_events = kg_successful_reads = 0  # 交互级计数（M6 KDR 用）
    kg_tool_calls = total_tool_calls = 0  # 交互级计数（M5 KAR 用）
    mem_read_count = mem_successful_reads = 0  # 记忆计数（M11/M12 用）

    def _accumulate_kg_metrics(kg_f, kg_f_run):
        """累加 KG 侧的知识/工具/记忆指标（KG-only 和配对模式共用）。"""
        nonlocal kg_valid, access, kg_delivery, kg_access_events, kg_successful_reads
        nonlocal mem_read_count, mem_successful_reads, kg_tool_calls, total_tool_calls
        if kg_f_run and kg_f_run.condition == Condition.KG and kg_f_run.trace_valid and kg_f_run.runtime_valid:
            kg_valid += 1
            kn = kg_f["knowledge"]
            if kn.access: access += 1
            if kn.access and kn.delivery: kg_delivery += 1
            kg_access_events += kn.access_event_count
            kg_successful_reads += kn.successful_read_count
            mem_read_count += getattr(kn, 'memory_access_event_count', 0)
            mem_successful_reads += getattr(kn, 'memory_successful_read_count', 0)
            ta = kg_f["tool"]
            kg_tool_calls += ta.kg_count
            total_tool_calls += ta.total_tool_calls

    if has_nogk and valid_pairs:
        # 正常模式：KG + No-KG 配对
        for pair in valid_pairs:
            kg_f = facts[pair.kg_task_run_id]; nogk_f = facts[pair.nogk_task_run_id]
            derived = PairDerivedFactComputer().compute(
                pair, kg_f["outcome"], nogk_f["outcome"], kg_f["tool"], nogk_f["tool"],
                kg_f["resource"], nogk_f["resource"])
            kg_f_run = next(t for t in task_runs if t.task_run_id == pair.kg_task_run_id)
            _accumulate_kg_metrics(kg_f, kg_f_run)
            j = next((d.value_numeric for d in derived if d.derived_fact_type == "JSD"), None)
            dt = next((d.value_numeric for d in derived if d.derived_fact_type == "DELTA_TOKEN"), None)
            ds = next((d.value_numeric for d in derived if d.derived_fact_type == "DELTA_STEPS"), None)
            dtm = next((d.value_numeric for d in derived if d.derived_fact_type == "DELTA_TIME"), None)
            bench = bench_by_task.get(pair.task_id) or [BenchmarkItem(pair.benchmark_item_id, "BS001", pair.task_id, None)]
            bench_item = bench[0] if bench else BenchmarkItem(pair.benchmark_item_id, "BS001", pair.task_id, None)
            has_vuln = any(b.expected_label and b.expected_label.value == "VULNERABLE" for b in bench)
            pair_views.append(PairView(
                kg_success=kg_f["outcome"].outcome.value == "SUCCESS",
                nogk_success=nogk_f["outcome"].outcome.value == "SUCCESS",
                gt="VULNERABLE" if has_vuln else (bench_item.expected_label.value if bench_item and bench_item.expected_label else "NA"),
                kg_outcome=kg_f["outcome"].outcome.value, nogk_outcome=nogk_f["outcome"].outcome.value,
                jsd=j, delta_token=dt, delta_steps=ds, delta_time=dtm))
    else:
        # KG-only 模式：无 No-KG，从 KG case_results 构造 PairViews
        for tr in task_runs:
            if tr.condition != Condition.KG:
                continue
            f = facts.get(tr.task_run_id, {})
            _accumulate_kg_metrics(f, tr)
            kg_cr = f.get("case_results", [])
            bench = bench_by_task.get(tr.task_id, [])
            has_vuln = any(b.expected_label and b.expected_label.value == "VULNERABLE" for b in bench)
            for kc in kg_cr:
                kg_conf = kc.get("confusion", "")
                kg_ok = kg_conf in ("TP", "FP")
                pair_views.append(PairView(
                    kg_success=kg_ok, nogk_success=False,
                    gt=kc.get("expected_label", "VULNERABLE" if has_vuln else "NA"),
                    kg_outcome="SUCCESS" if kg_ok else "FAIL",
                    nogk_outcome="FAIL",
                    jsd=None, delta_token=None, delta_steps=None, delta_time=None,
                    kg_confusion=kg_conf, nogk_confusion="",
                    kg_mined=kc.get("mined", False), nogk_mined=False,
                    kg_sink_hit=kc.get("sink_hit", False), nogk_sink_hit=False))
        log("EVAL", f"KG-only 模式: 从 case_results 构造 {len(pair_views)} 个 pair_view")

    # 按 benchmark_item 展开 pair_views，供 M1-M4 混淆矩阵使用
    item_pair_views: list[PairView] = []
    _item_pv_task_ids: list[str] = []
    if has_nogk and valid_pairs:
        for i, pair in enumerate(valid_pairs):
            pv = pair_views[i]
            kg_cr = facts[pair.kg_task_run_id].get("case_results", [])
            nogk_cr = facts[pair.nogk_task_run_id].get("case_results", [])
            if not kg_cr or not nogk_cr:
                continue
            nogk_by_id = {c.get("case_id"): c for c in nogk_cr}
            for kc in kg_cr:
                nc = nogk_by_id.get(kc.get("case_id"))
                if not nc:
                    continue
                kg_conf = kc.get("confusion", "")
                nogk_conf = nc.get("confusion", "")
                kg_ok = kg_conf in ("TP", "FP")
                nogk_ok = nogk_conf in ("TP", "FP")
                item_pair_views.append(PairView(
                    kg_success=kg_ok, nogk_success=nogk_ok,
                    gt=kc.get("expected_label", "NA"),
                    kg_outcome="SUCCESS" if kg_ok else "FAIL",
                    nogk_outcome="SUCCESS" if nogk_ok else "FAIL",
                    jsd=pv.jsd, delta_token=pv.delta_token,
                    delta_steps=pv.delta_steps, delta_time=pv.delta_time,
                    kg_confusion=kg_conf, nogk_confusion=nogk_conf,
                    kg_mined=kc.get("mined", False), nogk_mined=nc.get("mined", False),
                    kg_sink_hit=kc.get("sink_hit", False), nogk_sink_hit=nc.get("sink_hit", False)))
                _item_pv_task_ids.append(pair.task_id)
    else:
        # KG-only: item_pair_views = pair_views（已从 case_results 构造）
        item_pair_views = list(pair_views)
        _item_pv_task_ids = [tr.task_id for tr in task_runs if tr.condition == Condition.KG
                             for _ in range(len(facts.get(tr.task_run_id, {}).get("case_results", [])))]
    log("EVAL", f"item 级 pair_views: {len(item_pair_views)} 个 (任务级 {len(pair_views)})")

    # 存配对数据（短连接）— KG-only 模式跳过（无配对）
    if has_nogk and valid_pairs:
        pair_derived = []
        for pair in valid_pairs:
            kg_f = facts[pair.kg_task_run_id]; nogk_f = facts[pair.nogk_task_run_id]
            derived = PairDerivedFactComputer().compute(
                pair, kg_f["outcome"], nogk_f["outcome"], kg_f["tool"], nogk_f["tool"],
                kg_f["resource"], nogk_f["resource"])
            pair_derived.append((pair, derived))
        for pair, derived in pair_derived:
            def _insert_one_pair(cur, _pair=pair, _derived=derived):
                fact_repo.insert_task_pair(cur, _pair)
                for d in _derived:
                    fact_repo.insert_pair_derived_fact(cur, d)
            _db_query(_insert_one_pair)

    set_progress(evaluation_id, "计算指标...")
    _set_status_short(evaluation_id, "CALCULATING")
    _check_cancel(evaluation_id, "CALCULATING")
    log("EVAL", f"开始计算指标: {len(pair_views)} 个 pair_view, kg_access={access} kg_valid={kg_valid} kg_tool_calls={kg_tool_calls}/{total_tool_calls}")
    out = run_all_metrics(pair_views, confusion_pairs=item_pair_views or None,
                          kg_access=access, kg_valid=kg_valid,
                          kg_delivery=kg_delivery, access=access,
                          kg_access_events=kg_access_events, kg_successful_reads=kg_successful_reads,
                          mem_read_count=mem_read_count, mem_successful_reads=mem_successful_reads,
                          kg_tool_calls=kg_tool_calls, total_tool_calls=total_tool_calls,
                          seed=42)
    log("EVAL", f"主指标计算完成: {len(out.get('metric_results',[]))} 条")

    # ===== Phase 4b: 分组计算指标（挖掘/验证各自独立）=====
    # 按 task_id 分组 pair_views，每组独立算指标
    from collections import defaultdict as _dd2
    # 建立 pair_view → task_id 的映射
    _pv_task_ids: list[str] = []
    if has_nogk and valid_pairs:
        for pair in valid_pairs:
            _pv_task_ids.append(pair.task_id)
    else:
        # KG-only: pair_views 从 case_results 构造，按 KG task_run 展开
        for tr in task_runs:
            if tr.condition != Condition.KG:
                continue
            n_cases = len(facts.get(tr.task_run_id, {}).get("case_results", []))
            _pv_task_ids.extend([tr.task_id] * n_cases)
    _groups_pv: dict[str, list[PairView]] = _dd2(list)
    for i, pv in enumerate(pair_views):
        tid = _pv_task_ids[i] if i < len(_pv_task_ids) else "T001"
        _groups_pv[tid].append(pv)
    _groups_item_pv: dict[str, list[PairView]] = _dd2(list)
    for i, pv in enumerate(item_pair_views):
        tid = _item_pv_task_ids[i] if i < len(_item_pv_task_ids) else "T001"
        _groups_item_pv[tid].append(pv)
    # 为每组计算指标
    _metric_groups: list[dict] = []
    _group_kg_inputs: dict[str, tuple[list[dict], list[dict], object, list[dict], list, list[dict], object]] = {}
    for tid, gvs in _groups_pv.items():
        if not gvs:
            continue
        # 计算 group 级别的 kg_access 等
        _g_kg_valid = _g_access = _g_kg_delivery = 0
        _g_kg_access_events = _g_kg_successful_reads = 0
        _g_kg_tool_calls = _g_total_tool_calls = 0
        _g_mem_read = _g_mem_success = 0
        if has_nogk and valid_pairs:
            for pair in valid_pairs:
                if pair.task_id != tid:
                    continue
                kg_f = facts[pair.kg_task_run_id]
                kg_f_run = next(t for t in task_runs if t.task_run_id == pair.kg_task_run_id)
                if kg_f_run and kg_f_run.condition == Condition.KG and kg_f_run.trace_valid and kg_f_run.runtime_valid:
                    _g_kg_valid += 1
                    kn = kg_f["knowledge"]
                    if kn.access: _g_access += 1
                    if kn.access and kn.delivery: _g_kg_delivery += 1
                    _g_kg_access_events += kn.access_event_count
                    _g_kg_successful_reads += kn.successful_read_count
                    _g_mem_read += getattr(kn, 'memory_access_event_count', 0)
                    _g_mem_success += getattr(kn, 'memory_successful_read_count', 0)
                    ta = kg_f["tool"]
                    _g_kg_tool_calls += ta.kg_count
                    _g_total_tool_calls += ta.total_tool_calls
        else:
            # KG-only: 从 KG task_runs 累加
            for tr in task_runs:
                if tr.condition != Condition.KG or tr.task_id != tid:
                    continue
                kg_f = facts.get(tr.task_run_id, {})
                if tr.trace_valid and tr.runtime_valid:
                    _g_kg_valid += 1
                    kn = kg_f["knowledge"]
                    if kn.access: _g_access += 1
                    if kn.access and kn.delivery: _g_kg_delivery += 1
                    _g_kg_access_events += kn.access_event_count
                    _g_kg_successful_reads += kn.successful_read_count
                    _g_mem_read += getattr(kn, 'memory_access_event_count', 0)
                    _g_mem_success += getattr(kn, 'memory_successful_read_count', 0)
                    ta = kg_f["tool"]
                    _g_kg_tool_calls += ta.kg_count
                    _g_total_tool_calls += ta.total_tool_calls
        g_out = run_all_metrics(gvs, confusion_pairs=_groups_item_pv.get(tid) or None,
                                kg_access=_g_access, kg_valid=_g_kg_valid,
                                  kg_delivery=_g_kg_delivery, access=_g_access,
                                  kg_access_events=_g_kg_access_events, kg_successful_reads=_g_kg_successful_reads,
                                  mem_read_count=_g_mem_read, mem_successful_reads=_g_mem_success,
                                  kg_tool_calls=_g_kg_tool_calls, total_tool_calls=_g_total_tool_calls,
                                  seed=42)
        g_hits = diagnose(g_out["metric_results"], g_out["statistical_results"])
        g_report = assemble(evaluation_id, g_out["metric_results"], g_out["statistical_results"], g_hits,
                            pair_views=gvs, has_nogk=has_nogk)
        # 找到这个 task_id 对应的 category 和 agent_name
        _g_category = ""
        _g_agent_name = ""
        for e in entries:
            if e.get("task_id") == tid:
                _g_category = e.get("category", "")
                _g_agent_name = e.get("agent_name", "")
                break
        _g_kg_run = next((tr for tr in task_runs
                          if tr.task_id == tid and tr.condition == Condition.KG), None)
        _g_nogk_run = next((tr for tr in task_runs
                            if tr.task_id == tid and tr.condition == Condition.NOGK), None)
        _g_kg_facts = facts.get(_g_kg_run.task_run_id, {}) if _g_kg_run else {}
        _g_nogk_facts = facts.get(_g_nogk_run.task_run_id, {}) if _g_nogk_run else {}
        _g_kg_cases = _g_kg_facts.get("case_results", [])
        _g_nogk_by_case = {c.get("case_id"): c for c in _g_nogk_facts.get("case_results", [])}
        _g_bench_by_case = {b.benchmark_item_id: b for b in bench_by_task.get(tid, [])}
        _g_case_results = []
        for _g_case in _g_kg_cases:
            _g_case_id = _g_case.get("case_id")
            _g_bench = _g_bench_by_case.get(_g_case_id)
            _g_meta = (_g_bench.metadata or {}) if _g_bench else {}
            _g_nogk_case = _g_nogk_by_case.get(_g_case_id, {})
            _g_case_results.append({
                **_g_case,
                "expected_label": _g_case.get("expected_label") or (_g_bench.expected_label.value if _g_bench and _g_bench.expected_label else "NA"),
                "description": _g_meta.get("description", ""),
                "vulnerability_type": _g_meta.get("vulnerability_type", ""),
                "source_file": _g_meta.get("source_file", ""),
                "source_function": _g_meta.get("source_function", ""),
                "source_line": _g_meta.get("source_line", ""),
                "nogk_matched": _g_nogk_case.get("matched", False),
                "nogk_mined": _g_nogk_case.get("mined", False),
                "nogk_sink_hit": _g_nogk_case.get("sink_hit", False),
                "nogk_confusion": _g_nogk_case.get("confusion", "NA"),
                "nogk_finding_title": _g_nogk_case.get("finding_title", ""),
                "nogk_ac_case_id": _g_nogk_case.get("ac_case_id", ""),
                "nogk_session_id": _g_nogk_case.get("session_id", ""),
                "nogk_sink_sessions": _g_nogk_case.get("sink_sessions", []),
                "nogk_sink_hit_sessions": _g_nogk_case.get("sink_hit_sessions", []),
                "nogk_finding_session": _g_nogk_case.get("finding_session", ""),
                "nogk_session_chain": _g_nogk_case.get("session_chain", []),
                "nogk_candidate_findings": _g_nogk_case.get("candidate_findings", []),
                "nogk_sink_info": _g_nogk_case.get("sink_info", ""),
                "nogk_sink_analysis": _g_nogk_case.get("sink_analysis", ""),
                "nogk_no_finding_reason": _g_nogk_case.get("no_finding_reason", ""),
                "nogk_knowledge_intervention": _g_nogk_case.get("knowledge_intervention"),
                "kg_source_uri": _g_kg_facts.get("_source_uri", ""),
                "nogk_source_uri": _g_nogk_facts.get("_source_uri", ""),
            })
        _g_knowledge = _g_kg_facts.get("knowledge")
        _group_kg_inputs[tid] = (
            _g_case_results,
            list(_g_knowledge.interactions) if _g_knowledge and _g_knowledge.interactions else [],
            _g_kg_facts.get("session_graph"),
            list(_g_nogk_facts.get("case_results", [])),
            list(_g_kg_facts.get("events", [])),
            list(_g_knowledge.memory_interactions) if _g_knowledge and _g_knowledge.memory_interactions else [],
            _g_kg_facts.get("parser"),
        )
        _g_kg_ta = _g_kg_facts.get("tool")
        _g_nogk_ta = _g_nogk_facts.get("tool")
        _g_kg_ad = _g_kg_ta.action_distribution if _g_kg_ta else {}
        _g_nogk_ad = _g_nogk_ta.action_distribution if _g_nogk_ta else {}
        _metric_groups.append({
            "task_id": tid,
            "category": _g_category,
            "label": f"漏洞验证-{_g_agent_name}" if _g_category == "verify" and _g_agent_name
                     else ("漏洞验证" if _g_category == "verify" else "漏洞挖掘"),
            "agent_name": _g_agent_name,
            "p0": g_report.p0, "p1": g_report.p1, "p2": g_report.p2,
            "diagnostic_hits": g_report.diagnostic_hits,
            "case_results": _g_case_results,
            "pair_count": len(gvs),
            "alert_center": {
                "kg": {
                    "total": _g_kg_ad.get("alert_center_total", 0),
                    "counts": _g_kg_ad.get("alert_center_counts", {}),
                },
                "nogk": {
                    "total": _g_nogk_ad.get("alert_center_total", 0),
                    "counts": _g_nogk_ad.get("alert_center_counts", {}),
                },
            } if _alert_center_data else None,
        })

    # ===== Phase 5: 写入指标（短连接）=====
    cr_id = f"CR-{evaluation_id}"; pop_id = f"PS-{evaluation_id}"
    def _insert_metrics(cur):
        cur.execute("INSERT IGNORE INTO evaluation_calculation_run (calculation_run_id, evaluation_id, run_type, config_snapshot_id) "
                    "VALUES (%s,%s,'INITIAL',%s)", (cr_id, evaluation_id, f"snap-{evaluation_id}"))
        cur.execute("INSERT IGNORE INTO evaluation_population_snapshot (population_snapshot_id, calculation_run_id, "
                    "population_type, population_entity_type, task_count, estimator_version, population_ids_uri, population_ids_hash) "
                    "VALUES (%s,%s,'primary_analysis','TASK_PAIR',%s,'1.0','uri','hash')", (pop_id, cr_id, len(pair_views)))
        # 修复 metric_result 的 metric_id CHECK 约束（加 M13/M14，删 M2/M3）
        try:
            cur.execute("ALTER TABLE metric_result DROP CHECK metric_result_metric_id_chk")
        except Exception:
            try: cur.execute("ALTER TABLE metric_result DROP CONSTRAINT metric_result_metric_id_chk")
            except Exception: pass
        try:
            cur.execute("ALTER TABLE metric_result ADD CONSTRAINT metric_result_metric_id_chk CHECK (metric_id IN "
                        "('M5','M6','M7','M8','M9','M10','M11','M12','M13'))")
        except Exception: pass  # 可能已存在
        # calculation_method 列从 VARCHAR(128) 改为 TEXT（method 字典含 KG/No-KG 绝对值，JSON 超长）
        try:
            cur.execute("ALTER TABLE metric_result MODIFY COLUMN calculation_method TEXT")
        except Exception: pass  # 可能已是 TEXT
        for m in out["metric_results"]:
            fact_repo.insert_metric_result(cur, cr_id, pop_id, m, evaluation_id)
        for s in out["statistical_results"]:
            fact_repo.insert_statistical_result(cur, cr_id, pop_id, s, evaluation_id)
    _db_query(_insert_metrics)

    # ===== Phase 6: AI 分析 + 生成报告（慢操作，无 DB 连接）=====
    # 排空连接池空闲连接：LLM 调用期间空闲连接会被网络层关闭，
    # 但 ping 检测（小包）无法发现半断连，导致后续大 INSERT 失败
    from ..infrastructure.database import drain_idle_connections
    drain_idle_connections()
    set_progress(evaluation_id, "诊断中...")
    _set_status_short(evaluation_id, "REPORTING")
    _check_cancel(evaluation_id, "REPORTING")
    log("EVAL", f"开始 AI 分析 + 生成报告...")
    hits = diagnose(out["metric_results"], out["statistical_results"])
    log("EVAL", f"诊断完成: {len(hits)} 条告警")
    report = assemble(evaluation_id, out["metric_results"], out["statistical_results"], hits,
                      pair_views=pair_views, has_nogk=has_nogk)
    report.metric_groups = _metric_groups

    from ..infrastructure.llm import is_enabled as _llm_enabled
    if _llm_enabled():
        from concurrent.futures import ThreadPoolExecutor as _TP
        # ── Phase 6: 知识与记忆介入分析（逐漏洞 KG 归因）──
        log("EVAL", f"知识与记忆介入分析: 分类 per_case_kg...")
        set_progress(evaluation_id, "知识与记忆介入分析: 准备中...")
        with _TP(max_workers=max(1, len(_metric_groups))) as kg_pool:
            fut_group_pcka = {}
            for group in _metric_groups:
                (_g_cases, _g_interactions, _g_session_graph,
                 _g_nogk_cases, _g_events, _g_mem_interactions,
                 _g_parser) = _group_kg_inputs[group["task_id"]]
                _g_label = group.get("label", group["task_id"])
                def _cb(done, total, _label=_g_label):
                    set_task_progress(evaluation_id, _label, f"知识与记忆 {done}/{total}")
                fut_group_pcka[group["task_id"]] = kg_pool.submit(
                    ai_per_case_kg_analysis, _g_cases, _g_interactions,
                    bench_by_task, _g_session_graph, _g_nogk_cases, _g_events,
                    _g_mem_interactions, group["category"], _g_parser, _cb,
                    has_nogk=has_nogk)
            for group in _metric_groups:
                group["per_case_kg_analysis"] = fut_group_pcka[group["task_id"]].result()
                _group_kg_inputs.pop(group["task_id"], None)
        log("EVAL", f"知识与记忆介入分析完成")
        set_progress(evaluation_id, "知识与记忆介入分析完成，生成报告中...")
    else:
        log("EVAL", f"LLM 未启用，跳过 AI 请求并使用规则化报告")
        set_progress(evaluation_id, "知识与记忆介入分析: 规则化分析...")
        for group in _metric_groups:
            _g_nogk_cases = _group_kg_inputs[group["task_id"]][3] if group["task_id"] in _group_kg_inputs else None
            group["per_case_kg_analysis"] = rule_based_per_case_kg_analysis(
                group["case_results"], group["category"], _g_nogk_cases)
        set_progress(evaluation_id, "知识与记忆介入分析完成，生成报告中...")
    # per_case_kg_analysis 已在 metric_groups 中，顶层不再重复（避免 report JSON 体积翻倍导致 max_allowed_packet 溢出）
    for group in _metric_groups:
        for item in group["per_case_kg_analysis"]:
            item.setdefault("task_id", group["task_id"])
            item.setdefault("category", group["category"])

    # ===== Phase 6b+6c: FPR 分析（统一：告警中心匹配 → 派生漏洞中心 FPR）=====
    # 跑一次告警中心匹配，按 case ID 筛选派生漏洞中心 FPR，保证一致性。
    # 漏洞中心 case ID 是告警中心的真子集（128/158），无需独立 LLM 匹配。
    _e2e_fpr_kg = None       # 漏洞中心 FPR（E2E，派生）
    _e2e_fpr_nogk = None
    _ac_fpr_kg = None        # 告警中心 FPR（挖掘，直接）
    _ac_fpr_nogk = None
    _fpr_cache: dict = {}   # (project_id, task_id) → (alert_result, vc_ids)

    def _run_fpr_for_cond(cond_label, cond_val):
        """单个条件的 FPR 分析（可并行调用）。"""
        _mining_entry = next((e for e in entries
                              if e.get("category", "") != "verify"
                              and e.get("condition") == cond_val
                              and e.get("project_id")), None)
        if not _mining_entry:
            return cond_val, None, None
        _fpr_pid = _mining_entry["project_id"]
        _fpr_tid = _extract_source_task_id(_mining_entry) or _mining_entry.get("task_id", "")
        if not _fpr_tid or _fpr_tid == _mining_entry.get("task_id"):
            _fpr_tid = _mining_entry.get("task_id", "")

        log("EVAL", f"FPR 分析 ({cond_label}): project={_fpr_pid}, task={_fpr_tid}")
        set_progress(evaluation_id, f"FPR 分析 ({cond_label}): 基线 vs 告警中心数据匹配中...")
        try:
            def _fpr_cb(done, total, _cl=cond_label):
                set_task_progress(evaluation_id, f"FPR分析{_cl}", f"FPR匹配 {done}/{total}")
            _ac_result = run_fpr_analysis(_fpr_pid, _fpr_tid, progress_cb=_fpr_cb,
                                           source="alert_center", case_details=case_details)
        except Exception as _fpr_err:
            log("FPR", f"FPR 分析失败 ({cond_label}): {_fpr_err}")
            _ac_result = None

        # 获取漏洞中心 case ID 集合（用于派生子集）
        _vc_ids: set[str] = set()
        if _ac_result:
            try:
                from ..infrastructure.vuln_center_client import list_vuln_cases
                _vc_cases = list_vuln_cases(project_id=_fpr_pid, source_task_id=_fpr_tid)
                _vc_ids = {c.get("id", "") for c in _vc_cases if c.get("id")}
                log("FPR", f"漏洞中心 {len(_vc_ids)} 条 case (用于派生验证 FPR)")
            except Exception as _vc_err:
                log("FPR", f"获取漏洞中心 case ID 失败: {_vc_err}")

        return cond_val, _ac_result, _vc_ids

    # KG/NOGK 并行 FPR 分析
    from concurrent.futures import ThreadPoolExecutor as _FPR_TP
    with _FPR_TP(max_workers=2) as _fpr_pool:
        _fpr_futures = {
            _fpr_pool.submit(_run_fpr_for_cond, label, val): val
            for label, val in (("KG", "KG"), ("NOGK", "NOGK"))
        }
        for _fut in _fpr_futures:
            _cond_val, _ac_result, _vc_ids = _fut.result()
            if _ac_result:
                # 派生漏洞中心 FPR（从告警中心结果按 case ID 筛选）
                if _vc_ids:
                    _vc_result = derive_fpr_from_subset(_ac_result, _vc_ids)
                else:
                    _vc_result = None
                    log("FPR", "漏洞中心 case ID 为空，无法派生验证 FPR")

                _cond_label = "KG" if _cond_val == "KG" else "NOGK"
                log("EVAL", f"FPR ({_cond_label}): 挖掘 FPR={_ac_result['fpr']:.1%} "
                    f"(匹配 {_ac_result['matched']}/{_ac_result['total_findings']}), "
                    f"验证 FPR={_vc_result['fpr']:.1%} "
                    f"(匹配 {_vc_result['matched']}/{_vc_result['total_findings']})"
                    if _vc_result else
                    f"FPR ({_cond_label}): 挖掘 FPR={_ac_result['fpr']:.1%}, 验证 FPR 未能派生")

                if _cond_val == "KG":
                    _ac_fpr_kg = _ac_result
                    _e2e_fpr_kg = _vc_result
                else:
                    _ac_fpr_nogk = _ac_result
                    _e2e_fpr_nogk = _vc_result
            else:
                _cond_label = "KG" if _cond_val == "KG" else "NOGK"
                log("EVAL", f"FPR ({_cond_label}) 无结果（基线未配置或告警中心无数据）")

    # 将 E2E FPR 结果挂到 verify metric_group
    if _e2e_fpr_kg or _e2e_fpr_nogk:
        for _mg in _metric_groups:
            if _mg.get("category") == "verify":
                _mg["e2e_fpr_kg"] = _e2e_fpr_kg
                _mg["e2e_fpr_nogk"] = _e2e_fpr_nogk

    # 漏洞挖掘误报率 metric_group
    if _ac_fpr_kg or _ac_fpr_nogk:
        _metric_groups.append({
            "task_id": "",
            "category": "mining_fpr",
            "label": "漏洞挖掘误报率",
            "agent_name": "",
            "p0": {}, "p1": {}, "p2": {},
            "diagnostic_hits": [],
            "case_results": [],
            "pair_count": 0,
            "e2e_fpr_kg": _ac_fpr_kg,
            "e2e_fpr_nogk": _ac_fpr_nogk,
        })
        set_progress(evaluation_id, "FPR 分析完成，生成报告中...")
    else:
        log("EVAL", "FPR 分析无结果（告警中心无数据），跳过误报率 tab")
        set_progress(evaluation_id, "生成报告中...")

    # ===== 更新 M13 指标：用 LLM 匹配 FPR 替换 sink-point 匹配 FPR =====
    # 公式：FPR = FP / (FP + TP)，以基线 label 为准
    def _update_m13_fpr(m13, fpr_kg_result, fpr_nogk_result, label=""):
        """用 run_fpr_analysis 的结果更新 M13 指标。FPR 分析失败则标记 NA + 报错。"""
        if not m13:
            return
        if not fpr_kg_result and not fpr_nogk_result:
            m13["estimate"] = None
            m13["calculation_status"] = "NA"
            m13["reason_code"] = "FPR_ANALYSIS_FAILED"
            m13["ci_lower"] = None
            m13["ci_upper"] = None
            m = m13.get("method", {})
            m["formula"] = "FP / (FP + TP)"
            log("EVAL", f"⚠ M13 ({label}) FPR 分析失败，标记 NA")
            return
        fpr_kg = fpr_kg_result["fpr"] if fpr_kg_result else 0.0
        fpr_nogk = fpr_nogk_result["fpr"] if fpr_nogk_result else 0.0
        tp_kg = fpr_kg_result["tp"] if fpr_kg_result else 0
        fp_kg = fpr_kg_result["fp"] if fpr_kg_result else 0
        tp_n = fpr_nogk_result["tp"] if fpr_nogk_result else 0
        fp_n = fpr_nogk_result["fp"] if fpr_nogk_result else 0
        n_kg = fpr_kg_result["total_findings"] if fpr_kg_result else 0
        m13["estimate"] = fpr_kg - fpr_nogk
        m13["calculation_status"] = "CALCULATED"
        m13["reason_code"] = None
        m = m13.get("method", {})
        m["fpr_kg"] = fpr_kg
        m["fpr_nogk"] = fpr_nogk
        m["tp_kg"] = tp_kg
        m["fp_kg"] = fp_kg
        m["fn_kg"] = 0
        m["tn_kg"] = 0
        m["tp_n"] = tp_n
        m["fp_n"] = fp_n
        m["fn_n"] = 0
        m["tn_n"] = 0
        m["formula"] = "FP / (FP + TP)"
        m["uncertainty"] = None
        m13["n"] = n_kg
        m13["ci_lower"] = None
        m13["ci_upper"] = None

    # 顶层 M13：用挖掘 FPR（告警中心，超集）
    _update_m13_fpr(report.p0.get("M13"), _ac_fpr_kg, _ac_fpr_nogk, label="顶层")
    # 分组 M13：挖掘用告警中心 FPR，验证用漏洞中心 FPR
    for _mg in _metric_groups:
        _cat = _mg.get("category", "")
        if _cat == "mining":
            _update_m13_fpr(_mg.get("p0", {}).get("M13"), _ac_fpr_kg, _ac_fpr_nogk, label=f"挖掘({_mg.get('task_id','')})")
        elif _cat == "verify":
            _update_m13_fpr(_mg.get("p0", {}).get("M13"), _e2e_fpr_kg, _e2e_fpr_nogk, label=f"验证({_mg.get('task_id','')})")
    if _ac_fpr_kg or _e2e_fpr_kg:
        _parts = []
        if _ac_fpr_kg: _parts.append(f"mining KG={_ac_fpr_kg['fpr']:.1%}")
        if _e2e_fpr_kg: _parts.append(f"verify KG={_e2e_fpr_kg['fpr']:.1%}")
        log("EVAL", f"M13 已更新为 LLM 匹配 FPR: {', '.join(_parts)}")

    # AI 评测摘要
    outcomes_list = [{"task_run_id": tr.task_run_id,
                      "outcome": facts[tr.task_run_id]["outcome"].outcome.value,
                      "prediction": facts[tr.task_run_id]["outcome"].prediction.value if facts[tr.task_run_id]["outcome"].prediction else None,
                      "resolver_status": facts[tr.task_run_id]["outcome"].resolver_status,
                      "validation": facts[tr.task_run_id]["outcome"].validation_result}
                     for tr in task_runs]
    # 报告 JSON 瘦身：删除 renderer 不使用的大字段，避免 100MB+ HTML
    _STRIP_FIELDS = ("chain_actions", "kg_source_uri", "nogk_source_uri",
                      "nogk_session_id", "finding_ts")
    for group in _metric_groups:
        for cr in group.get("case_results", []):
            for _f in _STRIP_FIELDS:
                cr.pop(_f, None)
            # sink_sessions 截断到前 20 个（renderer 只展示，不需要 1560 个）
            if cr.get("sink_sessions") and len(cr["sink_sessions"]) > 20:
                cr["sink_sessions"] = cr["sink_sessions"][:20]
    report.llm_token_usage = llm_mod.get_token_usage()
    log("EVAL", f"LLM token 用量: {report.llm_token_usage}")
    rj = render_json(report)

    # 判断是否需要标记 COMPLETED_WITH_WARNINGS
    _warnings = []
    # 指标 NA（KG-only 模式下 M7-M10 是结构性不可计算，无对照组，不算告警）
    _delta_metrics = {"M7", "M8", "M9", "M10"}
    na_metrics = [m.metric_id for m in out["metric_results"] if m.calculation_status == "NA"
                  and not (not has_nogk and m.metric_id in _delta_metrics)]
    if na_metrics:
        _warnings.append(f"指标不可计算(NA)：{','.join(na_metrics)}，这些指标缺少必要数据")
    report.warnings = _warnings
    final_status = "COMPLETED_WITH_WARNINGS" if _warnings else "COMPLETED"
    if _warnings:
        log("EVAL", f"评测完成（带警告）: {', '.join(_warnings)}")
    else:
        log("EVAL", f"评测完成")

    # ===== Phase 7: 写入报告 JSON 文件 + 标记完成 =====
    # 报告 JSON 存文件（PVC），不存 DB — 避免 26MB INSERT 导致 BrokenPipe/max_allowed_packet
    set_progress(evaluation_id, "生成报告中...")
    rj = render_json(report)  # rj 在写入 warnings 后重新序列化
    log("EVAL", f"报告 JSON 大小: {len(rj):,} 字节")
    import os as _os
    _reports_dir = _os.environ.get("EVAL_REPORTS_DIR") or "/app/reports"
    _os.makedirs(_reports_dir, exist_ok=True)
    _json_path = _os.path.join(_reports_dir, f"{evaluation_id}.json")
    with open(_json_path, "w", encoding="utf-8") as _f:
        _f.write(rj)
    log("EVAL", f"报告 JSON 已写入文件: {_json_path}")
    # DB 只存状态（小 SQL，不走连接池）
    def _finalize(cur):
        cur.execute("INSERT IGNORE INTO evaluation_report (report_id, evaluation_id, calculation_run_id, snapshot_id, "
                    "report_version, json_uri, status) VALUES (%s,%s,%s,%s,'1.0',%s,'READY')",
                    (f"rp-{evaluation_id}", evaluation_id, cr_id, f"snap-{evaluation_id}", _json_path))
        _set_status(cur, evaluation_id, final_status)
    _db_query(_finalize)

    # ===== Phase 8: 固化静态报告 HTML（打开时零计算）=====
    _html_ok = False
    try:
        from ..api.routes.evaluations import render_static_report
        render_static_report(evaluation_id)
        _html_ok = True
    except Exception as e:
        log("REPORT", f"⚠ 固化 HTML 失败（不影响评测结果）: {e}")

    # ===== Phase 9: 报告 JSON 瘦身 + 清理临时文件 =====
    # HTML 生成成功后，剥离 dashboard 不使用的大字段（candidate_findings 等），
    # 并删除临时 _cr.json 文件。JSON 从 250MB 降到 ~5MB。
    if _html_ok:
        import json as _json_slim
        try:
            with open(_json_path, "r", encoding="utf-8") as _f:
                _rj_data = _json_slim.loads(_f.read())
            # dashboard 需要的 case_results 字段白名单
            _KEEP_FIELDS = {"case_id", "expected_label", "confusion", "nogk_confusion",
                             "description", "vulnerability_type", "source_file",
                             "source_function", "session_id"}
            for _mg in _rj_data.get("metric_groups", []):
                for _cr in _mg.get("case_results", []):
                    _strip_keys = set(_cr.keys()) - _KEEP_FIELDS
                    for _k in _strip_keys:
                        _cr.pop(_k, None)
            _rj_slim = _json_slim.dumps(_rj_data, ensure_ascii=False)
            with open(_json_path, "w", encoding="utf-8") as _f:
                _f.write(_rj_slim)
            log("EVAL", f"报告 JSON 瘦身后: {len(_rj_slim):,} 字节")
        except Exception as e:
            log("EVAL", f"⚠ 报告 JSON 瘦身失败: {e}")

        # 删除临时 case_results 文件
        for _tr in task_runs:
            _cr_file = _os.path.join(_reports_dir, f"{evaluation_id}_{_tr.task_run_id}_cr.json")
            if _os.path.isfile(_cr_file):
                _os.remove(_cr_file)
        log("EVAL", f"已清理 {len(task_runs)} 个临时 _cr.json 文件")

    clear_eval_ctx()
    return {"status": final_status, "metrics": len(out["metric_results"]),
            "statistical_results": len(out["statistical_results"]),
            "report_uri": f"report/{evaluation_id}", "pair_count": len(pair_views)}


def get_status(evaluation_id: str) -> dict:
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT evaluation_status, evaluation_name, error_message, started_at "
                    "FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        r = cur.fetchone()
        if not r:
            return {"error": "not found"}
        cur.execute("SELECT COUNT(*) FROM metric_result WHERE evaluation_id=%s", (evaluation_id,))
        n_metrics = cur.fetchone()[0]
        # MySQL NOW(3) 返回 UTC，前端统一转北京时间
        return {"evaluation_id": evaluation_id, "status": r[0], "name": r[1], "metrics": n_metrics,
                "error_message": r[2],
                "started_at": r[3].isoformat() if r[3] else None,
                "progress": get_progress(evaluation_id)}
    finally:
        conn.close()


def get_report(evaluation_id: str) -> dict:
    # 优先从文件读取（新方式），回退到 DB report_config_json（旧数据兼容）
    import os as _os
    _reports_dir = _os.environ.get("EVAL_REPORTS_DIR") or "/app/reports"
    _json_path = _os.path.join(_reports_dir, f"{evaluation_id}.json")
    if _os.path.isfile(_json_path):
        with open(_json_path, "r", encoding="utf-8") as _f:
            return {"evaluation_id": evaluation_id, "status": "READY",
                    "report": json.loads(_f.read())}
    # 回退：从 DB 读旧数据
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT report_config_json, status FROM evaluation_report WHERE evaluation_id=%s", (evaluation_id,))
        r = cur.fetchone()
        if not r:
            return {"error": "report not found"}
        return {"evaluation_id": evaluation_id, "status": r[1],
                "report": json.loads(r[0]) if r[0] else None}
    finally:
        conn.close()
