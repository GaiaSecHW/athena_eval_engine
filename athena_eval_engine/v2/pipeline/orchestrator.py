"""v2 Pipeline 编排器。

阶段流程：
    INGESTING → PARSING → RESOLVING → CALCULATING
        → INVENTORY → LIFECYCLE_ANALYSIS → CAUSAL_CHAIN → REPORTING → FINALIZE

方案不含 No-KG 对照组，不执行 KG/No-KG 配对。
M7-M10（JSD/ΔToken/ΔSteps/ΔTime）需要配对数据，返回 NA。

协作取消：
- 每个阶段入口检查 ``_check_cancel(evaluation_id)``
- ``cancel_cb`` 穿透到 LLM 密集内循环

重试路径：
- knowledge_access_detail 表已有记录 → 跳过 LIFECYCLE_ANALYSIS
- lifecycle report 已存在 → 跳过 REPORTING
"""
from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pymysql

from ..infra.database import connect
from ..infra.concurrency import get as _conc_get
from ..infra.parallel import iter_completed
from ...infrastructure.log_util import (
    log, set_eval_ctx, clear_eval_ctx, with_eval_ctx, log_error,
)
from .state_machine import assert_transition
from . import stages

# ── 报告目录 ──────────────────────────────────────────


def _get_reports_dir() -> str:
    """获取报告输出目录（EVAL_REPORTS_DIR 或默认 /app/reports）。"""
    return os.environ.get("EVAL_REPORTS_DIR") or "/app/reports"


# ── 取消异常 ──────────────────────────────────────────


class TaskCancelledError(Exception):
    """评测任务被取消（cancel_requested flag 被 set）。"""
    pass


# ── DB 短连接 + 重试 ──────────────────────────────────


def _db_query(fn, _retries: int = 8):
    """短连接 + 重试包装器。

    2006/2013（连接丢失）时指数退避重试，其他错误直接抛出。
    与老代码 evaluation_service._db_query 同模式——拷贝而非 import。
    """
    from ...infrastructure.log_util import log_to_file
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
                    inner = getattr(conn, "_con", None)
                    if inner is not None and not getattr(inner, "_closed", True):
                        inner.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            if e.args and e.args[0] in (2013, 2006) and attempt < _retries - 1:
                _wait = min(2 * (attempt + 1), 30)
                log("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]}, retry in {_wait}s...")
                log_to_file("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]} {e}, retry in {_wait}s...")
                time.sleep(_wait)
                continue
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    raise last_err  # type: ignore[misc]


# ── 进度追踪（内存，pod 重启后重跑不需要持久化）──

_progress: dict[str, str] = {}
_progress_lock = threading.Lock()


def _set_progress(evaluation_id: str, text: str):
    with _progress_lock:
        _progress[evaluation_id] = text


def _get_progress(evaluation_id: str) -> str:
    with _progress_lock:
        return _progress.get(evaluation_id, "")


def _clear_progress(evaluation_id: str):
    with _progress_lock:
        _progress.pop(evaluation_id, None)


# ── 取消信号 ──────────────────────────────────────────


def _is_cancelled(evaluation_id: str) -> bool:
    """检查 DB 中的 cancel_requested flag。"""
    conn = None
    try:
        conn = connect(autocommit=True)
        cur = conn.cursor()
        cur.execute(
            "SELECT cancel_requested FROM evaluation WHERE evaluation_id=%s",
            (evaluation_id,),
        )
        row = cur.fetchone()
        return row is not None and row[0] == 1
    except Exception as e:
        log("CANCEL", f"检查取消信号失败: {e}")
        return False
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _check_cancel(evaluation_id: str, phase: str = ""):
    """在阶段边界检查取消信号。"""
    if _is_cancelled(evaluation_id):
        raise TaskCancelledError(
            f"{evaluation_id} 在 {phase} 阶段被取消"
        )


def _make_cancel_cb(evaluation_id: str, phase: str = ""):
    """创建 cancel_cb 闭包，穿透到 LLM 密集内循环。"""
    def _cb():
        _check_cancel(evaluation_id, phase)
    return _cb


# ── 状态更新 ──────────────────────────────────────────


def _set_status(evaluation_id: str, status: str):
    """短连接更新 evaluation 状态。"""

    def _do(cur):
        if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "CANCELLED"):
            cur.execute(
                "UPDATE evaluation SET evaluation_status=%s, "
                "error_message=NULL, finished_at=NOW(3) "
                "WHERE evaluation_id=%s",
                (status, evaluation_id),
            )
        elif status == "FAILED":
            cur.execute(
                "UPDATE evaluation SET evaluation_status=%s, "
                "finished_at=NOW(3) WHERE evaluation_id=%s",
                (status, evaluation_id),
            )
        else:
            cur.execute(
                "UPDATE evaluation SET evaluation_status=%s, "
                "error_message=NULL WHERE evaluation_id=%s",
                (status, evaluation_id),
            )

    try:
        _db_query(_do)
    except Exception as e:
        log("STATUS", f"设状态 {status} 失败: {e}")
        raise


def _set_failed(evaluation_id: str, error_msg: str):
    """标记评测失败，写入 error_message。"""

    def _do(cur):
        cur.execute(
            "UPDATE evaluation SET evaluation_status='FAILED', "
            "error_message=%s, finished_at=NOW(3) WHERE evaluation_id=%s",
            (error_msg[:2000], evaluation_id),
        )

    try:
        _db_query(_do)
    except Exception as e:
        log("STATUS", f"设 FAILED 状态失败: {e}")


# ── 重试路径幂等检查 ──────────────────────────────────


def _has_knowledge_access_details(evaluation_id: str) -> bool:
    """检查 knowledge_access_detail 表是否已有该 evaluation_id 的记录。"""
    def _do(cur):
        cur.execute(
            "SELECT 1 FROM knowledge_access_detail "
            "WHERE evaluation_id=%s LIMIT 1",
            (evaluation_id,),
        )
        return cur.fetchone() is not None

    try:
        return _db_query(_do)
    except Exception as e:
        log("RETRY_CHECK", f"检查 knowledge_access_detail 失败: {e}")
        return False


def _has_lifecycle_report(evaluation_id: str, reports_dir: str) -> bool:
    """检查 lifecycle report 是否已存在。"""
    return os.path.isfile(
        os.path.join(reports_dir, f"{evaluation_id}_lifecycle.json")
    )


def _load_existing_access_details(evaluation_id: str) -> list[dict]:
    """从 DB 加载已有的 knowledge_access_detail 记录（重试路径用）。"""
    def _do(cur):
        cur.execute(
            "SELECT access_id, evaluation_id, task_run_id, task_id, event_idx, "
            "source_system, l0_origin, business_phase, "
            "l1_need_knowledge, l2_initiated, l3_query_accurate, l4_knowledge_exists, "
            "l5_retrieved, l6_used, l7_influenced, l7_method, "
            "effect_label, cause_code, "
            "query_content, returned_content, reasoning_ref, judgment_conclusion, "
            "evidence_json, evidence_file "
            "FROM knowledge_access_detail WHERE evaluation_id=%s",
            (evaluation_id,),
        )
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        return [dict(zip(cols, row)) for row in rows]

    try:
        return _db_query(_do)
    except Exception as e:
        log("RETRY_LOAD", f"加载 knowledge_access_detail 失败: {e}")
        return []


# ── 编排器 ────────────────────────────────────────────


class Orchestrator:
    """v2 Pipeline 编排器。

    替代老代码 ``evaluation_service.run()``，串联全部 v2 模块。

    用法::

        from athena_eval_engine.v2.pipeline.orchestrator import Orchestrator
        Orchestrator().run("EV-20261011120000-xxxx")
    """

    def __init__(self):
        """初始化编排器，延迟 import 所有 v2 模块。"""
        # 延迟 import 在各方法中执行，避免模块加载时的循环依赖

    def run(self, evaluation_id: str, cancel_cb=None):
        """主编排逻辑。

        阶段流程：
        1. INGESTING — 取基线 case 详情 + 告警中心数据
        2. PARSING — 并行 trace 解析，每个 trace 调用 parser.build_data_pack()
        3. RESOLVING — 持久化 findings + session_graph 到 DB
        4. CALCULATING — 指标计算（M5-M13）
        5. INVENTORY — 知识盘点
        6. LIFECYCLE_ANALYSIS — L0-L7 全链路分析
        7. CAUSAL_CHAIN — 因果链分析
        8. REPORTING — 报告组装 + 改进建议生成
        9. FINALIZE — 写入 evaluation_report 表，状态设为 COMPLETED

        Args:
            evaluation_id: 评测 ID。
            cancel_cb: 外部传入的取消检查回调（可选）。编排器内部会创建
                       绑定到 evaluation_id 的 cancel_cb 穿透到内循环。
        """
        set_eval_ctx(evaluation_id)
        reports_dir = _get_reports_dir()
        os.makedirs(reports_dir, exist_ok=True)

        # 统一 cancel_cb：外部传入的优先，否则用内部创建的
        _cancel_cb = cancel_cb or _make_cancel_cb(evaluation_id, "ORCHESTRATOR")

        log("ORCH", f"启动 v2 pipeline: evaluation_id={evaluation_id} "
              f"reports_dir={reports_dir}")

        try:
            # ── INGESTING ──
            assert_transition("VALIDATING", stages.INGESTING)
            self._set_status_safe(evaluation_id, "VALIDATING")
            self._set_status_safe(evaluation_id, stages.INGESTING)
            _set_progress(evaluation_id, "获取基线数据...")
            benchmark_items, case_details, alert_center_data, entries, cfg = \
                self._ingest(evaluation_id)
            eval_mode = cfg.get("manifest", {}).get("eval_mode", "dev")
            log("ORCH", f"INGESTING done: {len(benchmark_items)} benchmark_items, "
                  f"{len(case_details)} case_details, eval_mode={eval_mode}")

            # ── PARSING ──
            _check_cancel(evaluation_id, stages.PARSING)
            assert_transition(stages.INGESTING, stages.PARSING)
            self._set_status_safe(evaluation_id, stages.PARSING)
            _set_progress(evaluation_id, "并行 trace 解析...")
            data_packs = self._parse_traces(
                evaluation_id, entries, benchmark_items, case_details, cfg,
                cancel_cb=_cancel_cb,
            )
            log("ORCH", f"PARSING done: {len(data_packs)} data_packs")

            # ── RESOLVING ──
            # 持久化 findings + session_graph 到 DB（CaseFilter 依赖 extracted_finding 表）
            _check_cancel(evaluation_id, stages.RESOLVING)
            assert_transition(stages.PARSING, stages.RESOLVING)
            self._set_status_safe(evaluation_id, stages.RESOLVING)
            _set_progress(evaluation_id, "持久化解析结果...")
            self._persist_findings(evaluation_id, data_packs)

            # ── CALCULATING ──
            _check_cancel(evaluation_id, stages.CALCULATING)
            assert_transition(stages.RESOLVING, stages.CALCULATING)
            self._set_status_safe(evaluation_id, stages.CALCULATING)
            _set_progress(evaluation_id, "指标计算...")
            metrics = self._calculate_metrics(data_packs, alert_center_data)
            log("ORCH", f"CALCULATING done: {len(metrics.get('metric_results', []))} "
                  f"metric_results")

            # ── INVENTORY ──
            _check_cancel(evaluation_id, stages.INVENTORY)
            assert_transition(stages.CALCULATING, stages.INVENTORY)
            self._set_status_safe(evaluation_id, stages.INVENTORY)
            _set_progress(evaluation_id, "知识盘点...")
            inventory = self._run_inventory(
                evaluation_id, data_packs, reports_dir,
            )
            log("ORCH", f"INVENTORY done: coverage_rate="
                  f"{inventory.get('coverage', {}).get('coverage_rate', 'N/A')}")

            # ── LIFECYCLE_ANALYSIS ──
            # 重试路径：knowledge_access_detail 表已有记录 → 跳过
            _check_cancel(evaluation_id, stages.LIFECYCLE_ANALYSIS)
            assert_transition(stages.INVENTORY, stages.LIFECYCLE_ANALYSIS)
            self._set_status_safe(evaluation_id, stages.LIFECYCLE_ANALYSIS)
            if _has_knowledge_access_details(evaluation_id):
                log("ORCH", "LIFECYCLE_ANALYSIS skipped: "
                      "knowledge_access_detail 已有记录（重试路径）")
                _set_progress(evaluation_id, "生命周期分析（已有记录，跳过）")
                access_details = _load_existing_access_details(evaluation_id)
            else:
                _set_progress(evaluation_id, "L0-L7 全链路分析...")
                access_details = self._run_lifecycle(
                    data_packs, evaluation_id, reports_dir,
                    cancel_cb=_cancel_cb, eval_mode=eval_mode,
                )
                log("ORCH", f"LIFECYCLE_ANALYSIS done: "
                      f"{len(access_details)} access_details")

            # ── CAUSAL_CHAIN ──
            _check_cancel(evaluation_id, stages.CAUSAL_CHAIN)
            assert_transition(
                stages.LIFECYCLE_ANALYSIS, stages.CAUSAL_CHAIN,
            )
            self._set_status_safe(evaluation_id, stages.CAUSAL_CHAIN)
            _set_progress(evaluation_id, "因果链分析...")
            causal_chain = self._run_causal_chain(access_details)
            log("ORCH", f"CAUSAL_CHAIN done: "
                  f"{len(causal_chain.get('per_case_breakpoints', []))} "
                  f"cases with breakpoints")

            # ── REPORTING ──
            _check_cancel(evaluation_id, stages.REPORTING)
            assert_transition(stages.CAUSAL_CHAIN, stages.REPORTING)
            self._set_status_safe(evaluation_id, stages.REPORTING)

            # 重试路径：lifecycle report 已存在 → 跳过报告组装
            if _has_lifecycle_report(evaluation_id, reports_dir):
                log("ORCH", "REPORTING skipped: lifecycle report 已存在"
                      "（重试路径）")
                _set_progress(evaluation_id, "报告组装（已有，跳过）")
                suggestions: list[dict] = []
            else:
                _set_progress(evaluation_id, "生成改进建议...")
                suggestions = self._generate_suggestions(
                    evaluation_id, causal_chain, cancel_cb=_cancel_cb,
                )
                _set_progress(evaluation_id, "报告组装...")
                self._assemble_report(
                    evaluation_id, metrics, inventory,
                    access_details, causal_chain,
                    metrics.get("lifecycle_metrics", []),
                    suggestions, reports_dir,
                )
                log("ORCH", f"REPORTING done: {len(suggestions)} suggestions")

            # ── FINALIZE ──
            _check_cancel(evaluation_id, stages.FINALIZE)
            assert_transition(stages.REPORTING, "FINALIZING")
            self._set_status_safe(evaluation_id, "FINALIZING")
            _set_progress(evaluation_id, "完成...")
            self._finalize(evaluation_id, reports_dir, metrics, inventory,
                           causal_chain, suggestions)
            self._set_status_safe(evaluation_id, "COMPLETED")
            _set_progress(evaluation_id, "评测完成")
            log("ORCH", f"v2 pipeline 完成: {evaluation_id}")

        except TaskCancelledError as e:
            log("ORCH", f"评测被取消: {e}")
            self._set_status_safe(evaluation_id, "CANCELLED")
            raise
        except Exception as e:
            log_error(evaluation_id, "ORCH", e)
            _set_failed(evaluation_id, str(e))
            raise
        finally:
            clear_eval_ctx()
            _clear_progress(evaluation_id)

    # ── INGESTING ────────────────────────────────────

    def _ingest(self, evaluation_id: str) -> tuple:
        """取基线 case 详情 + 告警中心数据。

        从 evaluation_snapshot 表读 manifest（entries + benchmark_source），
        按数据源（vuln_center 或 vbench_zip）取基线 case 详情，
        并从告警中心获取 AC case 数据。

        返回:
            (benchmark_items, case_details, alert_center_data, entries, cfg)
        """
        # 读 snapshot 配置
        def _read_config(cur):
            cur.execute(
                "SELECT config_json FROM evaluation_snapshot "
                "WHERE evaluation_id=%s",
                (evaluation_id,),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError(
                    f"evaluation {evaluation_id} snapshot not found"
                )
            cfg = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            cur.execute(
                "SELECT benchmark_set_id FROM evaluation "
                "WHERE evaluation_id=%s",
                (evaluation_id,),
            )
            eval_row = cur.fetchone()
            bsid = eval_row[0] if eval_row else "BS001"
            return cfg, bsid

        cfg, benchmark_set_id = _db_query(_read_config)
        manifest = cfg.get("manifest", {})
        entries = manifest.get("entries", [])
        bm_source = manifest.get("benchmark_source", "vbench_zip")
        vc_task_id = manifest.get("vc_source_task_id")

        case_details: dict[str, dict] = {}
        alert_center_data: dict = {}

        # 取基线 case 详情
        if bm_source == "vuln_center":
            # 从 entries 提取 source_task_id（如果未指定）
            if not vc_task_id:
                for e in entries:
                    src = e.get("source_uri", "") or ""
                    import re
                    m = re.search(r"/tasks/([^/]+)", src)
                    if m:
                        vc_task_id = m.group(1)
                        break

            from ...infrastructure.vuln_center_client import (
                get_vuln_center_benchmark,
            )
            log("INGEST", f"漏洞中心取基线: project={benchmark_set_id} "
                  f"task={vc_task_id}")
            bm = get_vuln_center_benchmark(benchmark_set_id, vc_task_id)
            n_cases = len(bm.get("cases") or [])
            log("INGEST", f"漏洞中心返回 {n_cases} 条 case")

            if n_cases == 0 and vc_task_id:
                log("INGEST", "不带 task 过滤重试")
                bm = get_vuln_center_benchmark(benchmark_set_id, None)
                n_cases = len(bm.get("cases") or [])
                log("INGEST", f"不带 task 过滤返回 {n_cases} 条 case")

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
                        "locator": c.get("locator") or "",
                    }

        elif bm_source == "vbench_zip":
            from ...infrastructure.vbench_client import get_benchmark
            log("INGEST", f"V-Bench 取基线: set_id={benchmark_set_id}")
            bm = get_benchmark(benchmark_set_id)
            all_cases = bm.get("cases") or []
            for c in all_cases:
                cid = c.get("case_id") or c.get("id") or ""
                if cid:
                    findings = c.get("findings") or []
                    desc = (" ".join(
                        f.get("explanation", "")
                        for f in findings if f.get("explanation")
                    ) or c.get("description", "")
                     or c.get("vulnerability_type", "") or "")
                    case_details[cid] = {
                        "description": desc,
                        "vulnerability_type": c.get("vulnerability_type")
                        or c.get("category") or "",
                        "target_finding_id": c.get("target_finding_id") or "",
                        "expected_label": c.get("expected_label")
                        or "VULNERABLE",
                        "source_file": c.get("source_file") or "",
                        "source_function": c.get("source_function") or "",
                        "source_line": c.get("source_line") or "",
                    }

        if not case_details:
            raise ValueError(
                "无法获取基线数据（case_details 为空），"
                "没有基线的评测无意义。"
                "请检查 benchmark_source 配置、V-Bench/漏洞中心服务连通性后重试。"
            )

        # 获取告警中心数据
        _ac_pairs: list[tuple[str, str]] = []
        _seen: set[tuple[str, str]] = set()
        for e in entries:
            _pid = e.get("project_id") or ""
            _tid = e.get("task_id_actual") or ""
            # 从 source_uri 提取 task UUID
            src = e.get("source_uri", "") or ""
            if not _tid:
                import re
                m = re.search(r"/tasks/([^/]+)", src)
                if m:
                    _tid = m.group(1)
            if _pid and _tid and (_pid, _tid) not in _seen:
                _ac_pairs.append((_pid, _tid))
                _seen.add((_pid, _tid))

        if _ac_pairs:
            try:
                from ...infrastructure.vuln_center_client import (
                    get_alert_center_summary,
                )
                all_cases: list[dict] = []
                merged_counts = {
                    "vulnerable": 0, "not_vulnerable": 0,
                    "inconclusive": 0, "pending": 0,
                }
                ac_pool = ThreadPoolExecutor(
                    max_workers=min(len(_ac_pairs), _conc_get("ac_fetch_workers")),
                )
                try:
                    ac_futures = {
                        ac_pool.submit(
                            with_eval_ctx(self._fetch_ac), pair,
                        ): pair
                        for pair in _ac_pairs
                    }
                    for fut in ac_futures:
                        pair = ac_futures[fut]
                        ac_project, _ = pair
                        ac_summary = fut.result()
                        for k in merged_counts:
                            merged_counts[k] += ac_summary.get("counts", {}).get(k, 0)
                        for c in ac_summary.get("cases", []):
                            all_cases.append({
                                **c,
                                "project_id": ac_project,
                            })
                finally:
                    ac_pool.shutdown(wait=False)

                alert_center_data = {
                    "source_task_ids": [t for _, t in _ac_pairs],
                    "project_ids": [p for p, _ in _ac_pairs],
                    "total": len(all_cases),
                    "counts": merged_counts,
                    "cases": all_cases,
                }
                log("INGEST", f"告警中心: {len(all_cases)} 条 case "
                      f"(是漏洞={merged_counts['vulnerable']} "
                      f"不是漏洞={merged_counts['not_vulnerable']})")
            except Exception as e:
                log("INGEST", f"取告警中心数据失败: {e}")
                raise ValueError(
                    f"取告警中心数据失败: {e}"
                ) from e

        # 构建 benchmark_items（从 case_details）
        benchmark_items = list(case_details.keys())

        return benchmark_items, case_details, alert_center_data, entries, cfg

    def _fetch_ac(self, pair: tuple[str, str]) -> dict:
        """获取单个项目的告警中心数据（用于线程池并行）。"""
        from ...infrastructure.vuln_center_client import get_alert_center_summary
        project_id, task_id = pair
        return get_alert_center_summary(project_id, task_id)

    # ── PARSING ──────────────────────────────────────

    def _parse_traces(
        self,
        evaluation_id: str,
        entries: list[dict],
        benchmark_items: list[str],
        case_details: dict[str, dict],
        cfg: dict,
        cancel_cb=None,
    ) -> list:
        """并行 trace 解析，返回 DataPack 列表。

        对每个 entry 调用 parser.build_data_pack()，在内部完成
        parse → extract_findings → build_session_graph → load_session
        → label_session_phases → resolve → DataPack。

        使用 ThreadPoolExecutor 并行，受 parse_workers 并发控制。
        """
        from ..parsers import get_parser
        from ..core.task_run import TaskRun, BenchmarkItem
        from ..core.enums import Condition, ConditionSource, ExpectedLabel

        # 解析 trace 源路径
        def _resolve_path(source_uri: str, project_id: str = "",
                          task_id: str = "") -> str:
            if os.path.exists(source_uri):
                return source_uri
            # /data/ 路径 — 本地开发时从平台拉取
            if source_uri.startswith("/data/") or source_uri.startswith("data/"):
                from ...application import platform_service as ps
                return ps.fetch_trace_to_local(
                    project_id, task_id, source_uri,
                    os.path.join(
                        os.path.dirname(os.path.dirname(
                            os.path.dirname(os.path.dirname(__file__))
                        )), "tests", "fixtures", "fetched",
                    ),
                )
            raise FileNotFoundError(
                f"trace 不可读且非 /data 路径：{source_uri}"
            )

        # 预取所有 trace 到本地（串行，避免并发写同一文件）
        local_paths: dict[str, str] = {}
        for e in entries:
            key = e["source_uri"]
            if key not in local_paths:
                local_paths[key] = _resolve_path(
                    key, e.get("project_id", ""), e.get("task_id", ""),
                )

        # 构建解析任务
        tasks: list[dict] = []
        for e in entries:
            src_uri = e["source_uri"]
            local_path = local_paths[src_uri]
            cond = e.get("condition", "UNKNOWN")
            task_id = e.get("task_id", "")
            trace_kind = e.get("trace_kind")
            category = e.get("category", "")
            project_id = e.get("project_id", "")

            # 为每个 entry 创建 TaskRun + benchmark_items
            bench = []
            for bid in benchmark_items:
                cd = case_details.get(bid, {})
                exp_label = cd.get("expected_label", "VULNERABLE")
                bench.append(BenchmarkItem(
                    benchmark_item_id=bid,
                    benchmark_set_id=cfg.get("manifest", {}).get(
                        "benchmark_set_id", "BS001",
                    ),
                    task_id=task_id,
                    expected_label=ExpectedLabel(exp_label)
                    if exp_label else None,
                    target_finding_id=cd.get("target_finding_id"),
                    metadata=cd,
                ))

            tr = TaskRun(
                task_run_id=f"{evaluation_id}_{task_id}_{cond}",
                evaluation_id=evaluation_id,
                task_id=task_id,
                trace_id=src_uri,
                condition=Condition.KG if cond == "KG"
                else Condition.UNKNOWN,
                condition_source=ConditionSource.MANIFEST,
                benchmark_item_id=bench[0].benchmark_item_id if bench else None,
            )

            tasks.append({
                "task_run": tr,
                "source_uri": local_path,
                "trace_kind": trace_kind,
                "benchmark_items": bench,
                "category": category,
                "project_id": project_id,
            })

        # 并行解析
        n_workers = min(len(tasks), _conc_get("parse_workers"))
        data_packs: list = []
        if not tasks:
            return data_packs

        pool = ThreadPoolExecutor(max_workers=max(1, n_workers))
        try:
            futures = {
                pool.submit(
                    with_eval_ctx(self._parse_one_trace),
                    task, cancel_cb,
                ): i
                for i, task in enumerate(tasks)
            }
            results: list = [None] * len(futures)
            for fut, _ in iter_completed(futures, cancel_cb=cancel_cb):
                i = futures[fut]
                try:
                    results[i] = fut.result()
                except TaskCancelledError:
                    raise
                except Exception as e:
                    log("PARSE", f"trace 解析失败 "
                          f"task={tasks[i]['task_run'].task_run_id}: {e}")
                    raise  # 禁止降级跳过
            for r in results:
                if r is not None:
                    data_packs.append(r)
        finally:
            pool.shutdown(wait=False)

        log("PARSE", f"解析完成: {len(data_packs)}/{len(tasks)} data_packs")
        return data_packs

    def _parse_one_trace(self, task: dict, cancel_cb=None):
        """解析单个 trace，返回 DataPack。"""
        from ..parsers import get_parser

        tr = task["task_run"]
        source_uri = task["source_uri"]
        trace_kind = task.get("trace_kind")
        bench = task.get("benchmark_items", [])

        if cancel_cb:
            cancel_cb()

        parser = get_parser(trace_kind, source_uri)
        log("PARSE", f"[{tr.task_run_id}] parser={parser.__class__.__name__} "
              f"source={source_uri}")

        # TaskRun 的 benchmark_item 只取第一个，build_data_pack 内部用
        if bench:
            tr.benchmark_item_id = bench[0].benchmark_item_id

        # 构造 trace_source dict（所有 parser 的 parse()/load_session() 都期望 dict）
        trace_source = {
            "source_uri": source_uri,
            "trace_id": tr.trace_id or source_uri,
        }
        dp = parser.build_data_pack(trace_source, tr)

        # 将 benchmark_item 附加到 DataPack
        if bench:
            dp.benchmark_item = bench[0]

        # 将 project_id 写入 session_meta，供 inventory 使用
        project_id = task.get("project_id", "")
        if project_id and isinstance(dp.session_meta, dict):
            dp.session_meta.setdefault("project_id", project_id)

        return dp

    # ── RESOLVING ───────────────────────────────────

    def _persist_findings(self, evaluation_id: str, data_packs: list):
        """持久化 findings + session_graph 到 DB。

        CaseFilter 依赖 extracted_finding 表判断 finding 是否匹配基线。
        """
        from ...persistence.repositories.fact_repo import (
            insert_extracted_findings, insert_session_graph,
        )

        def _do(cur):
            for dp in data_packs:
                insert_extracted_findings(
                    cur, dp.task_run_id, evaluation_id, dp.findings or [],
                )
                insert_session_graph(
                    cur, dp.task_run_id, evaluation_id, dp.session_graph or {},
                )

        try:
            _db_query(_do)
            log("RESOLVE", f"持久化 {len(data_packs)} data_packs 的 findings + session_graph")
        except Exception as e:
            log("RESOLVE", f"持久化 findings 失败: {e}")

    # ── CALCULATING ─────────────────────────────────

    def _calculate_metrics(
        self, data_packs: list,
        alert_center_data: dict,
    ) -> dict:
        """指标计算（M5-M13 + M15-M26）。

        调用 run_all_metrics()，从 data_packs 和 alert_center_data
        提取计数参数。
        """
        from ..metrics.calculator import run_all_metrics

        # 从 data_packs 提取计数
        kg_access_events = 0
        kg_successful_reads = 0
        mem_read_count = 0
        mem_successful_reads = 0
        kg_tool_calls = 0
        total_tool_calls = 0

        for dp in data_packs:
            kf = dp.knowledge_fact
            taf = dp.tool_action_fact

            if kf:
                kg_access_events += len(kf.interactions or [])
                kg_successful_reads += sum(
                    1 for i in (kf.interactions or [])
                    if i.get("output_preview")
                )
                mem_read_count += len(kf.memory_interactions or [])
                mem_successful_reads += sum(
                    1 for i in (kf.memory_interactions or [])
                    if i.get("output_preview")
                )

            if taf:
                total_tool_calls += taf.total_tool_calls or 0
                dist = taf.action_distribution or {}
                kg_tool_calls += dist.get("KG", 0)

        return run_all_metrics(
            kg_access_events=kg_access_events,
            kg_successful_reads=kg_successful_reads,
            mem_read_count=mem_read_count,
            mem_successful_reads=mem_successful_reads,
            kg_tool_calls=kg_tool_calls,
            total_tool_calls=total_tool_calls,
        )

    # ── INVENTORY ───────────────────────────────────

    def _run_inventory(
        self, evaluation_id: str, data_packs: list,
        reports_dir: str,
    ) -> dict:
        """知识盘点。

        调用 KnowledgeInventory.run_inventory()，输出
        {evaluation_id}_inventory.json。
        """
        from ..knowledge_inventory.inventory import KnowledgeInventory

        inv = KnowledgeInventory()
        return inv.run_inventory(evaluation_id, data_packs, reports_dir)

    # ── LIFECYCLE_ANALYSIS ──────────────────────────

    def _run_lifecycle(
        self, data_packs: list, evaluation_id: str,
        reports_dir: str, cancel_cb=None, eval_mode: str = "dev",
    ) -> list[dict]:
        """L0-L7 全链路分析。

        调用 LifecycleAnalyzer.analyze()，对有效 case 的每次知识访问
        执行 L0-L7 逐级判定，写入 knowledge_access_detail 表。

        cancel_cb 穿透到 LLM 密集内循环。
        eval_mode: "dev"（开发态，分析 FP+FN）| "runtime"（运行态，只分析 FP）
        """
        from ..lifecycle.analyzer import LifecycleAnalyzer

        analyzer = LifecycleAnalyzer()
        return analyzer.analyze(
            evaluation_id, data_packs, reports_dir,
            cancel_cb=cancel_cb, eval_mode=eval_mode,
        )

    # ── CAUSAL_CHAIN ─────────────────────────────────

    def _run_causal_chain(self, access_details: list[dict]) -> dict:
        """因果链分析。

        调用 CausalChainAnalyzer.analyze()，基于 knowledge_access_detail
        的判定结果按业务阶段聚合误报归因。
        """
        from ..causal_chain.analyzer import CausalChainAnalyzer

        analyzer = CausalChainAnalyzer()
        # access_details 需要包含 evaluation_id（从第一条记录取）
        evaluation_id = ""
        if access_details:
            evaluation_id = access_details[0].get("evaluation_id", "")
        return analyzer.analyze(evaluation_id, access_details)

    # ── SUGGESTION GENERATION ────────────────────────

    def _generate_suggestions(
        self, evaluation_id: str, causal_chain: dict,
        cancel_cb=None,
    ) -> list[dict]:
        """生成改进建议。

        调用 SuggestionGenerator.generate()，从断点生成结构化改进建议。
        cancel_cb 穿透到 LLM 内循环。
        """
        from ..report.suggestion_generator import SuggestionGenerator

        gen = SuggestionGenerator()
        return gen.generate(evaluation_id, causal_chain, cancel_cb=cancel_cb)

    # ── REPORTING ────────────────────────────────────

    def _assemble_report(
        self, evaluation_id: str, metrics: dict,
        inventory: dict, access_details: list,
        causal_chain: dict, lifecycle_metrics: list,
        suggestions: list, reports_dir: str,
    ):
        """报告组装。

        调用 ReportAssembler 组装生命周期分析段 + 知识盘点段报告，
        写入 {evaluation_id}_lifecycle.json + {evaluation_id}_inventory.json。
        """
        from ..report.assembler import ReportAssembler

        assembler = ReportAssembler()

        # 组装生命周期分析段报告
        assembler.assemble_lifecycle_report(
            evaluation_id,
            access_details,
            causal_chain,
            lifecycle_metrics,
            suggestions,
            reports_dir,
        )

        # 组装知识盘点段报告（inventory 已由 run_inventory 生成，
        # 这里补充报告元数据）
        assembler.assemble_inventory_report(
            evaluation_id,
            inventory,
            reports_dir,
        )

        # 写入基础报告段（metrics + 汇总）
        base_report = {
            "evaluation_id": evaluation_id,
            "metrics": {
                "metric_results": metrics.get("metric_results", []),
                "statistical_results": metrics.get("statistical_results", []),
            },
            "inventory_summary": {
                "coverage_rate": inventory.get("coverage", {}).get(
                    "coverage_rate", 0,
                ),
                "total_vuln_types": inventory.get("coverage", {}).get(
                    "total_vuln_types", 0,
                ),
                "covered_vuln_types": inventory.get("coverage", {}).get(
                    "covered_vuln_types", 0,
                ),
            },
            "causal_chain_summary": {
                "cause_summary": causal_chain.get("cause_summary", {}),
                "effect_label_distribution": causal_chain.get(
                    "effect_label_distribution", {},
                ),
            },
        }
        base_path = os.path.join(reports_dir, f"{evaluation_id}.json")
        with open(base_path, "w", encoding="utf-8") as f:
            json.dump(base_report, f, ensure_ascii=False, indent=2,
                      default=str)
        log("REPORT", f"基础报告写入 {base_path}")

    # ── FINALIZE ─────────────────────────────────────

    def _finalize(
        self, evaluation_id: str, reports_dir: str,
        metrics: dict, inventory: dict,
        causal_chain: dict, suggestions: list,
    ):
        """写入 evaluation_report 表，状态设为 COMPLETED。

        将报告 JSON 路径写入 evaluation_report 表，
        供 /report/status 和 /report/lifecycle 端点查询。
        """
        # 检查 lifecycle report 是否存在
        lifecycle_path = os.path.join(
            reports_dir, f"{evaluation_id}_lifecycle.json",
        )
        inventory_path = os.path.join(
            reports_dir, f"{evaluation_id}_inventory.json",
        )
        base_path = os.path.join(reports_dir, f"{evaluation_id}.json")

        report_data = {
            "evaluation_id": evaluation_id,
            "base_report_path": base_path,
            "lifecycle_report_path": lifecycle_path,
            "inventory_report_path": inventory_path,
            "metrics_count": len(metrics.get("metric_results", [])),
            "lifecycle_metrics_count": len(
                metrics.get("lifecycle_metrics", []),
            ),
            "suggestions_count": len(suggestions),
            "coverage_rate": inventory.get("coverage", {}).get(
                "coverage_rate", 0,
            ),
            "cause_summary": causal_chain.get("cause_summary", {}),
        }

        def _do(cur):
            # 适配 evaluation_report 表 schema（与老代码一致）
            cur.execute(
                "INSERT INTO evaluation_report "
                "(report_id, evaluation_id, calculation_run_id, snapshot_id, "
                "report_version, json_uri, report_config_json, status) "
                "VALUES (%s, %s, %s, %s, '1.0', %s, %s, 'READY') "
                "ON DUPLICATE KEY UPDATE "
                "json_uri=VALUES(json_uri), "
                "report_config_json=VALUES(report_config_json), "
                "status='READY'",
                (
                    f"rp-{evaluation_id}",
                    evaluation_id,
                    f"cr-{evaluation_id}",
                    f"snap-{evaluation_id}",
                    base_path,
                    json.dumps(report_data, ensure_ascii=False),
                ),
            )

        try:
            _db_query(_do)
            log("FINALIZE", f"evaluation_report 已写入: {evaluation_id}")
        except Exception as e:
            # evaluation_report 表可能不存在（未迁移），不阻断完成
            log("FINALIZE", f"写入 evaluation_report 表失败（不阻断）: {e}")

    # ── 辅助方法 ─────────────────────────────────────

    def _set_status_safe(self, evaluation_id: str, status: str):
        """安全设状态（CHECK 约束自动修复）。"""
        try:
            _set_status(evaluation_id, status)
        except Exception as e:
            # CHECK 约束可能不含新状态 → 自动修复约束后重试
            if "Check constraint" in str(e) or "3819" in str(e):
                log("DB", f"CHECK 约束阻止设状态 {status}，自动修复...")
                self._fix_check_constraint(evaluation_id, status)
            else:
                raise

    def _fix_check_constraint(self, evaluation_id: str, status: str):
        """修复 evaluation 表的 CHECK 约束以包含 v2 新状态。"""
        def _fix_and_set(cur):
            for stmt in (
                "ALTER TABLE evaluation DROP CHECK evaluation_chk_1",
                "ALTER TABLE evaluation DROP CONSTRAINT evaluation_chk_1",
                "ALTER TABLE evaluation DROP CHECK evaluation_status_chk",
                "ALTER TABLE evaluation DROP CONSTRAINT evaluation_status_chk",
            ):
                try:
                    cur.execute(stmt)
                except Exception:
                    pass
            try:
                cur.execute(
                    "ALTER TABLE evaluation ADD CONSTRAINT evaluation_status_chk "
                    "CHECK (evaluation_status IN "
                    "('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING',"
                    "'PARSING','RESOLVING','PAIRING','CALCULATING',"
                    "'INVENTORY','LIFECYCLE_ANALYSIS','CAUSAL_CHAIN',"
                    "'REPORTING','FINALIZING',"
                    "'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED',"
                    "'CANCEL_REQUESTED','CANCELLING','CANCELLED'))"
                )
            except Exception:
                pass
            cur.execute(
                "UPDATE evaluation SET evaluation_status=%s "
                "WHERE evaluation_id=%s",
                (status, evaluation_id),
            )

        try:
            _db_query(_fix_and_set)
            log("DB", f"CHECK 约束已修复，重试设状态 {status} 成功")
        except Exception as e2:
            log("DB", f"CHECK 约束修复后仍失败: {e2}")
            raise
