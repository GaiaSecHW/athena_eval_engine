"""Evaluation Service（§10 Orchestrator + §6 stages）— v1 同步串行单跑。

create(request) → 冻结 snapshot + 建 evaluation。
run(evaluation_id) → VALIDATE→...→FINALIZE 同步执行，落库。
run() 使用短连接：慢操作（trace 解析、LLM 调用）期间不持有 MySQL 连接。
"""
from __future__ import annotations
import json
import os
import sys
import threading
from dataclasses import dataclass, field
from ..infrastructure.database import connect
from ..persistence.repositories import fact_repo
from ..workers.turing_trace_parser import TuringTraceParser
from ..workers.resolvers import (
    OutcomeResolverImpl, KnowledgeResolverImpl, ToolActionResolverImpl, ResourceResolverImpl,
)
from ..workers.ai_matcher import ai_match_outcome, match_alert_center_to_findings
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log, set_eval_ctx, clear_eval_ctx
from ..workers.pairing import TaskPairMatcherImpl, PairDerivedFactComputer
from ..domain.metrics import PairView, run_all_metrics
from ..domain.diagnostics import diagnose
from .report_assembler import (assemble, render_json, ai_narrative, ai_vuln_analysis,
                               ai_per_case_kg_analysis, rule_based_per_case_kg_analysis)
from ..domain.task_run import TaskRun, BenchmarkItem
from ..domain.enums import Condition, ConditionSource, ExpectedLabel, PairMatchStatus
from ..orchestration.state_machine import PIPELINE, assert_transition
from ..application import platform_service as ps

# 协作取消：force retry 时设置 cancel event，run() 在阶段边界检查并退出
_cancel_events: dict[str, threading.Event] = {}
_cancel_lock = threading.Lock()

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
    """标记一个评测任务为取消（force retry 时调用，通知旧线程退出）。"""
    with _cancel_lock:
        ev = _cancel_events.get(evaluation_id)
        if ev is None:
            ev = threading.Event()
            _cancel_events[evaluation_id] = ev
        ev.set()
        log("CANCEL", f"{evaluation_id} 收到取消信号")


def clear_cancel(evaluation_id: str):
    """清除取消标记（新线程启动时调用）。"""
    with _cancel_lock:
        _cancel_events.pop(evaluation_id, None)


def is_cancelled(evaluation_id: str) -> bool:
    """检查评测任务是否被取消。"""
    ev = _cancel_events.get(evaluation_id)
    return ev is not None and ev.is_set()


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
    entries: list = field(default_factory=list)  # [{task_id, condition, source_uri, benchmark_item_id}]


def _set_status(cur, evaluation_id, status):
    if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "CANCELLED"):
        cur.execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
    elif status == "FAILED":
        cur.execute("UPDATE evaluation SET evaluation_status=%s, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
    else:
        cur.execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL WHERE evaluation_id=%s", (status, evaluation_id))


def _set_status_short(evaluation_id, status):
    """短连接设状态，用于 run() 各阶段更新进度。"""
    conn = connect(autocommit=True)
    try:
        try:
            if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "CANCELLED"):
                conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
            elif status == "FAILED":
                conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s, finished_at=NOW(3) WHERE evaluation_id=%s", (status, evaluation_id))
            else:
                conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s, error_message=NULL WHERE evaluation_id=%s", (status, evaluation_id))
        except Exception as e:
            # CHECK 约束可能不含新状态（如 AI_MATCHING）→ 自动修复约束后重试
            if "Check constraint" in str(e) or "3819" in str(e):
                log("DB", f"CHECK 约束阻止设状态 {status}，自动修复...")
                cur = conn.cursor()
                # 1) DROP 所有可能的旧约束（忽略所有错误）
                for stmt in (
                    "ALTER TABLE evaluation DROP CHECK evaluation_chk_1",
                    "ALTER TABLE evaluation DROP CONSTRAINT evaluation_chk_1",
                    "ALTER TABLE evaluation DROP CHECK evaluation_status_chk",
                    "ALTER TABLE evaluation DROP CONSTRAINT evaluation_status_chk",
                ):
                    try: cur.execute(stmt)
                    except Exception: pass
                # 2) ADD 新约束（可能已存在，忽略错误）
                try:
                    cur.execute(
                        "ALTER TABLE evaluation ADD CONSTRAINT evaluation_status_chk CHECK (evaluation_status IN "
                        "('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING','PARSING','AI_MATCHING','RESOLVING','PAIRING',"
                        "'CALCULATING','STATISTICAL_ANALYSIS','DIAGNOSING','REPORTING','FINALIZING',"
                        "'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCEL_REQUESTED','CANCELLING','CANCELLED'))"
                    )
                except Exception: pass
                log("DB", f"CHECK 约束已修复，重试设状态 {status}")
                conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s WHERE evaluation_id=%s", (status, evaluation_id))
            else:
                raise
    finally:
        conn.close()


def _ai_extract_source_info(description: str, vulnerability_type: str = "") -> tuple[str, str]:
    """用 LLM 从漏洞描述中提取 source_file 和 source_function。

    当结构化数据（V-Bench traces 或漏洞中心 subject.locator）无法提取时作为 fallback。
    """
    from ..infrastructure import llm as llm_mod
    if not description or not llm_mod.is_enabled():
        return "", ""
    prompt = [
        {"role": "system", "content": (
            "从漏洞描述中提取漏洞所在的源文件路径和函数/方法名。\n"
            "只返回 JSON: {\"source_file\": \"文件路径\", \"source_function\": \"函数名\"}\n"
            "如果无法确定，对应字段返回空字符串。不要输出其他内容。"
        )},
        {"role": "user", "content": f"漏洞类型: {vulnerability_type}\n漏洞描述: {description}"},
    ]
    try:
        result = llm_mod.chat_json(prompt, temperature=0, max_tokens=500)
        return result.get("source_file", ""), result.get("source_function", "")
    except Exception as e:
        log("CREATE", f"AI 提取 source_file/source_function 失败: {e}")
        return "", ""


def _fill_missing_source(case: dict) -> None:
    """如果 case 的 source_file 或 source_function 为空，用 AI 从 description 补提取。"""
    if not case.get("source_file") or not case.get("source_function"):
        sf, sfn = _ai_extract_source_info(case.get("description", ""), case.get("vulnerability_type", ""))
        if not case.get("source_file"):
            case["source_file"] = sf
        if not case.get("source_function"):
            case["source_function"] = sfn


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

    # 获取基线 case 详情（含漏洞描述）。数据源二选一：
    #   vbench_zip   — 从 V-Bench benchmark.zip 读（测评集基线）
    #   vuln_center  — 从漏洞中心 Chimera 直接读人工确认 case（含漏洞与非漏洞两类）
    case_details = {}
    # 漏洞中心模式下，如果未指定 vc_source_task_id，用 entries 的 task_id_actual 补取
    effective_vc_task = req.vc_source_task_id
    if req.benchmark_source == "vuln_center" and not effective_vc_task:
        for e in req.entries:
            tid_actual = e.get("task_id_actual") or e.get("task_id")
            if tid_actual:
                effective_vc_task = tid_actual
                break
        if effective_vc_task:
            log("CREATE", f"vc_source_task_id 未指定，使用 entries 的 task_id_actual={effective_vc_task} 过滤")
    try:
        if req.benchmark_source == "vuln_center":
            from ..infrastructure.vuln_center_client import get_vuln_center_benchmark
            log("CREATE", f"漏洞中心取基线: project={req.benchmark_set_id} task={effective_vc_task}")
            bm = get_vuln_center_benchmark(req.benchmark_set_id, effective_vc_task)
            n_cases = len(bm.get("cases") or [])
            log("CREATE", f"漏洞中心返回 {n_cases} 条 case")
            # task_id_actual 不是有效的 source_task_id 时会返回 0 条。
            # 不带 task 过滤重试，拿到整个项目的人工确认 case（含漏洞与非漏洞）。
            if n_cases == 0 and effective_vc_task:
                log("CREATE", f"task={effective_vc_task} 不是漏洞中心 source_task，不带 task 过滤重试")
                bm = get_vuln_center_benchmark(req.benchmark_set_id, None)
                n_cases = len(bm.get("cases") or [])
                log("CREATE", f"不带 task 过滤返回 {n_cases} 条 case")
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
                    }
                    _fill_missing_source(case_details[cid])
        else:
            from ..infrastructure.vbench_client import get_benchmark
            log("CREATE", f"V-Bench 取基线: set_id={req.benchmark_set_id}")
            bm = get_benchmark(req.benchmark_set_id)
            n_cases = len(bm.get("cases") or [])
            log("CREATE", f"V-Bench 返回 {n_cases} 条 case")
            for c in (bm.get("cases") or []):
                cid = c.get("case_id") or c.get("id") or ""
                if cid:
                    findings = c.get("findings") or []
                    desc = " ".join(f.get("explanation", "") for f in findings if f.get("explanation")) or c.get("vulnerability_type", "") or c.get("description") or ""
                    case_details[cid] = {
                        "description": desc,
                        "vulnerability_type": c.get("vulnerability_type") or c.get("category") or "",
                        "target_finding_id": c.get("target_finding_id") or "",
                        "source_file": c.get("source_file") or "",
                        "source_function": c.get("source_function") or "",
                    }
                    _fill_missing_source(case_details[cid])
        log("CREATE", f"case_details 构建完成: {len(case_details)} 条")
    except Exception as e:
        import traceback as _tb
        log("CREATE", f"⚠ 取基线数据失败: {e}")
        _tb.print_exc()
        log("CREATE", f"case_details 将为空 → metadata_json=NULL, expected_label 退化 VULNERABLE")

    # 获取告警中心数据（T001 提交的漏洞 + T002 引擎判定结论）
    # 从 entries 提取所有 (project_id, source_task_id) 对，可能有多个项目
    _ac_pairs: list[tuple[str, str]] = []
    _seen_pairs: set[tuple[str, str]] = set()
    for e in req.entries:
        _pid = e.get("project_id") or ""
        _tid = e.get("task_id_actual") or effective_vc_task or ""
        if _pid and _tid and (_pid, _tid) not in _seen_pairs:
            _ac_pairs.append((_pid, _tid))
            _seen_pairs.add((_pid, _tid))
    alert_center_data = {}
    if _ac_pairs:
        try:
            from ..infrastructure.vuln_center_client import get_alert_center_summary
            _all_cases: list[dict] = []
            _merged_counts = {"vulnerable": 0, "not_vulnerable": 0, "inconclusive": 0, "pending": 0}
            for _ac_project, _ac_task in _ac_pairs:
                log("CREATE", f"告警中心取数据: project={_ac_project} task={_ac_task}")
                ac_summary = get_alert_center_summary(_ac_project, _ac_task)
                ac_total = ac_summary.get("total", 0)
                ac_counts = ac_summary.get("counts", {})
                log("CREATE", f"告警中心返回 {ac_total} 条 case: "
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
            alert_center_data = {
                "source_task_ids": [t for _, t in _ac_pairs],
                "project_ids": [p for p, _ in _ac_pairs],
                "total": len(_all_cases),
                "counts": _merged_counts,
                "cases": _all_cases,
            }
        except Exception as e:
            import traceback as _tb
            log("CREATE", f"⚠ 取告警中心数据失败: {e}")
            _tb.print_exc()
    else:
        log("CREATE", "⚠ 跳过告警中心数据获取: entries 中无 project_id/task_id_actual")

    # Step 1: benchmark_set
    conn = connect(autocommit=True)
    try:
        fact_repo.insert_benchmark_set(conn.cursor(), req.benchmark_set_id)
    finally:
        conn.close()

    # Step 2: benchmark_items（含 case 描述存入 metadata_json）
    # expected_label 优先取 case_details 里的（漏洞中心逐 case 标注），否则取 entry 级
    # 漏洞中心模式下，只插入 case_details 里有的 case（过滤掉不属于当前任务的 case）
    _filter_by_case_details = req.benchmark_source == "vuln_center" and case_details
    for e in req.entries:
        item_ids = e.get("benchmark_item_ids") or ([e["benchmark_item_id"]] if e.get("benchmark_item_id") else [])
        if _filter_by_case_details:
            _before = len(item_ids)
            item_ids = [bid for bid in item_ids if bid in case_details]
            if _before != len(item_ids):
                log("CREATE", f"task={e.get('task_id','')} 过滤掉 {_before - len(item_ids)} 条不属于当前任务的 case，"
                      f"剩余 {len(item_ids)} 条")
        for bid in item_ids:
            cd = case_details.get(bid) or {}
            if not cd:
                log("CREATE", f"⚠ benchmark_item {bid} 在 case_details 中未找到 → metadata 将为空")
            conn = connect(autocommit=True)
            try:
                fact_repo.insert_benchmark_item(conn.cursor(), bid, req.benchmark_set_id,
                                                e["task_id"], cd.get("expected_label") or e.get("expected_label", "VULNERABLE"),
                                                cd.get("target_finding_id") or e.get("target_finding_id"),
                                                cd)
            finally:
                conn.close()

    # Step 3: evaluation
    eval_name = req.evaluation_name or f"eval-{req.evaluation_id}"
    conn = connect(autocommit=True)
    try:
        conn.cursor().execute(
            "INSERT INTO evaluation (evaluation_id, evaluation_name, benchmark_set_id, agent_name) "
            "VALUES (%s,%s,%s,'Turing')",
            (req.evaluation_id, eval_name, req.benchmark_set_id))
    finally:
        conn.close()

    # Step 4: evaluation_snapshot（独立连接）
    manifest = {"entries": req.entries, "manifest_hash": "mh",
                "vbench_project_name": req.vbench_project_name,
                "benchmark_source": req.benchmark_source,
                "vc_source_task_id": req.vc_source_task_id,
                "vc_source_project_name": req.vc_source_project_name,
                "vc_source_task_name": req.vc_source_task_name,
                "alert_center_data": alert_center_data}
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


def _db_query(fn, _retries=5):
    """短连接执行 DB 操作。连接断开时重连重试。"""
    import pymysql
    last_err = None
    for attempt in range(_retries):
        conn = None
        try:
            conn = connect(autocommit=True)
            return fn(conn.cursor())
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
            last_err = e
            if e.args and e.args[0] in (2013, 2006) and attempt < _retries - 1:
                log("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]}, retry...")
                import time; time.sleep(2 * (attempt + 1))  # 指数退避
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

    # 设置全局 LLM 并发上限（3 评测 × 8 并发 = 24，仅首次调用生效）
    from ..infrastructure.llm import set_max_concurrency
    set_max_concurrency(24)

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
                _vc_tid = e.get("task_id_actual") or e.get("task_id")
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

    # 从 snapshot 加载告警中心数据（指标计算的权威数据来源）
    _alert_center_data = cfg.get("manifest", {}).get("alert_center_data", {})
    if _alert_center_data:
        _ac_counts = _alert_center_data.get("counts", {})
        log("EVAL", f"告警中心数据已加载: total={_alert_center_data.get('total', 0)} "
              f"是漏洞={_ac_counts.get('vulnerable', 0)} "
              f"不是漏洞={_ac_counts.get('not_vulnerable', 0)} "
              f"无法判定={_ac_counts.get('inconclusive', 0)} "
              f"研判中={_ac_counts.get('pending', 0)}")
    else:
        log("EVAL", "⚠ 告警中心数据为空，指标计算将回退到 parser 提取")

    # ===== Phase 2: 解析 trace + 提取 facts（无 DB 连接 — 慢操作）=====
    # 重跑时清理旧 facts，确保用最新 benchmark_item 标签重新计算
    def _clear_old_facts(cur):
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for tbl in ("statistical_result", "metric_result", "pair_derived_fact", "task_pair",
                     "outcome_fact", "tool_action_fact", "resource_fact",
                     "knowledge_interaction_fact", "task_run", "trace_source",
                     "evaluation_report"):
            cur.execute(f"DELETE FROM {tbl} WHERE evaluation_id=%s", (evaluation_id,))
        # population_snapshot / calculation_run 用 calculation_run_id 关联
        cur.execute("DELETE FROM evaluation_population_snapshot WHERE calculation_run_id LIKE %s",
                    (f"CR-{evaluation_id}%",))
        cur.execute("DELETE FROM evaluation_calculation_run WHERE calculation_run_id LIKE %s",
                    (f"CR-{evaluation_id}%",))
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
        log("RUN", f"清理旧 facts（重跑）: evaluation_id={evaluation_id}")
    _db_query(_clear_old_facts)
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
            return ArgoTraceParser()
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
            return ArgoTraceParser()
        if _os.path.isdir(p) and (p.endswith(dataflow_suffix) or "dataflow_vuln_scan" in p):
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        # 单个 dataflow jsonl 文件（路径含 dataflow_vuln_scan）也用 dataflow 解析器
        if "dataflow_vuln_scan" in p and (p.endswith(".jsonl") or _os.path.isdir(p)):
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        if p.endswith("opencode.db") or p.endswith("findings.db"):
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
            return ArgoTraceParser()
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
                task_id_actual = e.get("task_id_actual", "")
                trace_case_ids = [str(c) for c in e.get("trace_case_ids", []) if c]
                # CVulnVerify 的 JSONL 文件在项目目录下（非任务目录），
                # 需要任务 ID 来过滤出本次评测的文件。
                # 优先用 manifest 的 task_id_actual；缺失时从漏洞中心
                # 按 trace_case_ids 搜索获取 source_task.task_id。
                if not task_id_actual and trace_case_ids:
                    try:
                        from ..infrastructure.vuln_center_client import get_task_id_by_case_id
                        _proj = e.get("project_id", "")
                        task_id_actual = get_task_id_by_case_id(_proj, trace_case_ids[0]) or ""
                        log("CVULN", f"manifest 无 task_id_actual，从漏洞中心搜索获取: "
                              f"{task_id_actual}")
                    except Exception as err:
                        log("CVULN", f"从漏洞中心获取 task_id 失败: {err}")
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
            5. ai_match_outcome 做 finding↔基线匹配 → TP/FP/FN/TN
            """
            from concurrent.futures import ThreadPoolExecutor
            tr = parsed["tr"]; events = parsed["events"]; session = parsed["session"]
            bench = parsed["bench"]; cond = parsed["cond"]; parser = parsed["parser"]
            trace_kind = parsed.get("trace_kind")
            category = parsed.get("category", "")
            _trace_project_id = parsed.get("project_id", "")
            is_verify = category == "verify" or trace_kind in ("cvuln_verify", "webvulnverify")

            log("MATCH", f"{cond.value} bench_items={len(bench)} starting ai_match + resolve...")
            with ThreadPoolExecutor(max_workers=24) as inner_pool:
                # KN/TA/RS 不依赖告警中心匹配，先提交并行跑
                fut_kn = inner_pool.submit(KnowledgeResolverImpl(EVAL_CONFIG).resolve, tr, events)
                fut_ta = inner_pool.submit(ToolActionResolverImpl(EVAL_CONFIG).resolve, tr, events, "1.0")
                fut_rs = inner_pool.submit(ResourceResolverImpl(EVAL_CONFIG).resolve, tr, session)

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
                    log("MATCH", f"{cond.value} parser findings={len(_parser_findings)} ac_cases={len(_ac_cases)} "
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
                        log("MATCH", f"{cond.value} finding[{fi}] ← ac_case={ac.get('case_id','')} "
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
                    log("MATCH", f"{cond.value} 三方匹配完成: findings={len(_parser_findings)} "
                          f"matched={len(_matched)} unmatched_ac={len(_unmatched_ac)} "
                          f"confirmed={_ac_confirmed} fp={_ac_fp}")

                # ai_match_outcome 依赖三方匹配结果，最后提交
                fut_outcome = inner_pool.submit(ai_match_outcome, tr, bench, events, parser,
                                                progress_cb=lambda text, tr=tr: set_task_progress(
                                                    evaluation_id, tr.task_run_id,
                                                    f"[{tr.condition.value}] {text}"),
                                                findings_override=_findings_override)
                oc, case_results = fut_outcome.result()
                kn = fut_kn.result()
                ta = fut_ta.result()
                rs = fut_rs.result()
            log("MATCH", f"{cond.value} DONE outcome={oc.outcome.value} confusion={oc.confusion_label.value if oc.confusion_label else 'NA'} "
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
                _findings = parser.extract_findings(events)
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
            log("MATCH", f"{cond.value} findings={len(_findings)} confirmed={_confirmed} fp={_fp} analyze_recv={_analyze_count}")
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
            # session_graph 由 parser 构建（基类有通用实现，各子类可覆盖）
            session_graph = parser.build_session_graph(events)
            return tr, {"outcome": oc, "knowledge": kn, "tool": ta, "resource": rs, "case_results": case_results, "session_graph": session_graph, "findings": _findings, "events": events, "_task_id": tr.task_id, "parser": parser, "_is_verify": is_verify}, parsed["src"]

        # 预取所有 trace 到本地（串行，避免并发写同一文件 WinError 32）
        _local_paths = {}
        for e in entries:
            key = e["source_uri"]
            if key not in _local_paths:
                _local_paths[key] = _resolve_trace_path(key, e.get("project_id", ""), e["task_id"])
        # Phase PARSING: 并行解析所有 trace → events（无 LLM，快）
        set_progress(evaluation_id, f"解析 Trace: 0/{len(entries)} 完成")
        with ThreadPoolExecutor(max_workers=max(1, min(len(entries), 4))) as pool:
            _parse_futures = {pool.submit(_parse_trace, e): i for i, e in enumerate(entries)}
            parsed = [None] * len(entries)
            _parse_done = 0
            for _fut in as_completed(_parse_futures):
                parsed[_parse_futures[_fut]] = _fut.result()
                _parse_done += 1
                set_progress(evaluation_id, f"解析 Trace: {_parse_done}/{len(entries)} 完成")
        # Phase AI_MATCHING: 漏洞匹配 + resolve（含 LLM，慢）
        # 所有 trace 同时启动；LLM 并发由 llm.py 全局信号量控制（上限 24）
        # 非 LLM 的 resolver 不占信号量，KG trace 的 resolver 先跑完 → LLM 槽位立刻给 No-KG
        llm_mod.reset_token_usage()
        set_progress(evaluation_id, "漏洞匹配: 准备中...")
        _set_status_short(evaluation_id, "AI_MATCHING")
        _check_cancel(evaluation_id, "AI_MATCHING")
        log("EVAL", f"漏洞匹配 + resolve 开始（{len(parsed)} 条 trace，LLM 并发上限 24）")
        with ThreadPoolExecutor(max_workers=max(1, len(parsed))) as pool:
            results = list(pool.map(_resolve_trace, parsed))
        for tr, f, src in results:
            task_runs.append(tr)
            facts[tr.task_run_id] = f
            facts[tr.task_run_id]["_source_uri"] = src

        # Phase 3: 写入 facts（单连接批量，重试整体幂等）
        set_progress(evaluation_id, "写入事实数据...")
        def _insert_facts(cur):
            cur.execute("UPDATE evaluation SET evaluation_status=%s WHERE evaluation_id=%s", ("RESOLVING", evaluation_id))
            for tr in task_runs:
                f = facts[tr.task_run_id]
                cur.execute("SET FOREIGN_KEY_CHECKS=0")
                # vuln_type/title/description 列从 VARCHAR 改为 MEDIUMTEXT（超长 finding 数据）
                for col in ("vuln_type", "title", "description"):
                    try:
                        cur.execute(f"ALTER TABLE extracted_finding MODIFY COLUMN {col} MEDIUMTEXT")
                    except Exception:
                        pass  # 可能已是 MEDIUMTEXT
                fact_repo.insert_trace_source(cur, tr.trace_id, evaluation_id, f.get("_source_uri", ""))
                fact_repo.insert_task_run(cur, tr)
                fact_repo.insert_outcome_fact(cur, f["outcome"])
                fact_repo.insert_knowledge_fact(cur, f["knowledge"])
                fact_repo.insert_tool_action_fact(cur, f["tool"])
                fact_repo.insert_resource_fact(cur, f["resource"])
                fact_repo.insert_extracted_findings(cur, tr.task_run_id, evaluation_id, f.get("findings", []))
                fact_repo.insert_session_graph(cur, tr.task_run_id, evaluation_id, f.get("session_graph", {}))
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        _db_query(_insert_facts)

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
                    jsd=None, delta_token=None, delta_steps=None, delta_time=None))
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
                    delta_steps=pv.delta_steps, delta_time=pv.delta_time))
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
        def _insert_pairs(cur):
            for pair, derived in pair_derived:
                fact_repo.insert_task_pair(cur, pair)
                for d in derived:
                    fact_repo.insert_pair_derived_fact(cur, d)
        _db_query(_insert_pairs)

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
                "nogk_matched": _g_nogk_case.get("matched", False),
                "nogk_confusion": _g_nogk_case.get("confusion", "NA"),
                "nogk_finding_title": _g_nogk_case.get("finding_title", ""),
                "nogk_ac_case_id": _g_nogk_case.get("ac_case_id", ""),
                "nogk_session_id": _g_nogk_case.get("session_id", ""),
                "nogk_candidate_findings": _g_nogk_case.get("candidate_findings", []),
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
                        "('M1','M4','M5','M6','M7','M8','M9','M10','M11','M12','M13','M14'))")
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
    set_progress(evaluation_id, "诊断中...")
    _set_status_short(evaluation_id, "REPORTING")
    _check_cancel(evaluation_id, "REPORTING")
    log("EVAL", f"开始 AI 分析 + 生成报告...")
    hits = diagnose(out["metric_results"], out["statistical_results"])
    log("EVAL", f"诊断完成: {len(hits)} 条告警")
    report = assemble(evaluation_id, out["metric_results"], out["statistical_results"], hits,
                      pair_views=pair_views, has_nogk=has_nogk)
    report.metric_groups = _metric_groups

    # tool_stats_list 供 ai_narrative 引用漏洞流转数据
    tool_stats_list = [{"task_run_id": tr.task_run_id,
                        "task_id": tr.task_id,
                        "condition": tr.condition,
                        "finding_count": facts[tr.task_run_id]["tool"].action_distribution.get("confirmed_finding_count", 0),
                        "false_positive_count": facts[tr.task_run_id]["tool"].action_distribution.get("false_positive_finding_count", 0),
                        "analyze_received_count": facts[tr.task_run_id]["tool"].action_distribution.get("analyze_received_count", 0),
                        "total_tools": facts[tr.task_run_id]["tool"].total_tool_calls}
                       for tr in task_runs]

    from ..infrastructure.llm import is_enabled as _llm_enabled
    if _llm_enabled():
        from concurrent.futures import ThreadPoolExecutor as _TP
        # ── Phase 6a: 报告生成（叙述性结论 + 漏洞流转分析）──
        log("EVAL", f"AI 综合分析: ai_narrative + ai_vuln_analysis...")
        set_progress(evaluation_id, "AI 综合分析中...")
        with _TP(max_workers=2) as llm_pool:
            fut_narr = llm_pool.submit(ai_narrative, out["metric_results"], out["statistical_results"], hits,
                                        metric_groups=_metric_groups, tool_stats=tool_stats_list, has_nogk=has_nogk)
            fut_vuln = llm_pool.submit(ai_vuln_analysis, facts, bench_by_task)
            report.narrative = fut_narr.result()
            report.vuln_analysis = fut_vuln.result()
        log("EVAL", f"AI 综合分析完成")

        # ── Phase 6b: 知识与记忆介入分析（逐漏洞 KG 归因）──
        log("EVAL", f"知识与记忆介入分析: 分类 per_case_kg...")
        set_progress(evaluation_id, "知识与记忆介入分析: 准备中...")
        with _TP(max_workers=2) as kg_pool:
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
        log("EVAL", f"知识与记忆介入分析完成")
        set_progress(evaluation_id, "知识与记忆介入分析完成，生成报告中...")
    else:
        log("EVAL", f"LLM 未启用，跳过 AI 请求并使用规则化报告")
        set_progress(evaluation_id, "知识与记忆介入分析: 规则化分析...")
        for group in _metric_groups:
            _g_nogk_cases = _group_kg_inputs[group["task_id"]][3] if group["task_id"] in _group_kg_inputs else None
            group["per_case_kg_analysis"] = rule_based_per_case_kg_analysis(
                group["case_results"], group["category"], _g_nogk_cases)
        report.vuln_analysis = ai_vuln_analysis(facts, bench_by_task)
        set_progress(evaluation_id, "知识与记忆介入分析完成，生成报告中...")
    # 保留全局字段以兼容既有消费者，同时标明来源类别，避免相同 case_id 混淆。
    for group in _metric_groups:
        for item in group["per_case_kg_analysis"]:
            item.setdefault("task_id", group["task_id"])
            item.setdefault("category", group["category"])
    report.per_case_kg_analysis = [item for group in _metric_groups
                                   for item in group["per_case_kg_analysis"]]
    # AI 评测摘要
    outcomes_list = [{"task_run_id": tr.task_run_id,
                      "outcome": facts[tr.task_run_id]["outcome"].outcome.value,
                      "prediction": facts[tr.task_run_id]["outcome"].prediction.value if facts[tr.task_run_id]["outcome"].prediction else None,
                      "resolver_status": facts[tr.task_run_id]["outcome"].resolver_status,
                      "validation": facts[tr.task_run_id]["outcome"].validation_result}
                     for tr in task_runs]
    report.llm_token_usage = llm_mod.get_token_usage()
    log("EVAL", f"LLM token 用量: {report.llm_token_usage}")
    rj = render_json(report)

    # 判断是否需要标记 COMPLETED_WITH_WARNINGS
    _warnings = []
    # LLM 不可用
    if "LLM 不可用" in (report.narrative.get("conclusion") or "") or "LLM unavailable" in (report.narrative.get("summary") or ""):
        _warnings.append("LLM 不可用：AI 分析部分或全部失败，报告结论可能不完整")
    # 指标 NA
    na_metrics = [m.metric_id for m in out["metric_results"] if m.calculation_status == "NA"]
    if na_metrics:
        _warnings.append(f"指标不可计算(NA)：{','.join(na_metrics)}，这些指标缺少必要数据")
    report.warnings = _warnings
    final_status = "COMPLETED_WITH_WARNINGS" if _warnings else "COMPLETED"
    if _warnings:
        log("EVAL", f"评测完成（带警告）: {', '.join(_warnings)}")
    else:
        log("EVAL", f"评测完成")

    # ===== Phase 7: 写入报告 + 标记完成（短连接）=====
    set_progress(evaluation_id, "生成报告中...")
    rj = render_json(report)  # rj 在写入 warnings 后重新序列化
    def _finalize(cur):
        cur.execute("INSERT IGNORE INTO evaluation_report (report_id, evaluation_id, calculation_run_id, snapshot_id, "
                    "report_version, report_config_json, status) VALUES (%s,%s,%s,%s,'1.0',%s,'READY')",
                    (f"rp-{evaluation_id}", evaluation_id, cr_id, f"snap-{evaluation_id}", rj))
        _set_status(cur, evaluation_id, final_status)
    _db_query(_finalize)

    # ===== Phase 8: 固化静态报告 HTML（打开时零计算）=====
    try:
        from ..api.routes.evaluations import render_static_report
        render_static_report(evaluation_id)
    except Exception as e:
        log("REPORT", f"⚠ 固化 HTML 失败（不影响评测结果）: {e}")

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
        return {"evaluation_id": evaluation_id, "status": r[0], "name": r[1], "metrics": n_metrics,
                "error_message": r[2], "started_at": r[3].isoformat() if r[3] else None,
                "progress": get_progress(evaluation_id)}
    finally:
        conn.close()


def get_report(evaluation_id: str) -> dict:
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
