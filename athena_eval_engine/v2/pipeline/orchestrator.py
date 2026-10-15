"""v2 Pipeline 编排器。

阶段流程：
    INGESTING → PARSING → CASE_MATCHING → ROOT_CAUSE_ANALYSIS
        → RESOLVING → LIFECYCLE_ANALYSIS → CAUSAL_CHAIN → REPORTING → FINALIZE

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

import dataclasses
import json
import os
import sys
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


def _json_default(obj):
    """json.dump default — dataclass → dict，numpy → Python 原生类型。"""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    # numpy 标量
    for mod_name, convs in (
        ("numpy", (
            ("float64", float), ("float32", float),
            ("int64", int), ("int32", int),
            ("float_", float), ("int_", int),
        )),
    ):
        mod = sys.modules.get(mod_name)
        if mod is not None and isinstance(obj, mod.ndarray):
            return obj.tolist()
        if mod is not None:
            for attr, conv in convs:
                t = getattr(mod, attr, None)
                if t is not None and isinstance(obj, t):
                    return conv(obj)
    if isinstance(obj, (set, tuple)):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _json_dump(obj, f, **kw):
    """json.dump 包装：用 _json_default 替代 default=str。"""
    kw.setdefault("ensure_ascii", False)
    kw.setdefault("indent", 2)
    json.dump(obj, f, default=_json_default, **kw)


def _json_dumps(obj, **kw):
    """json.dumps 包装：用 _json_default 替代 default=str。"""
    kw.setdefault("ensure_ascii", False)
    return json.dumps(obj, default=_json_default, **kw)


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
            "source_system, l0_origin, "
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
        3. CASE_MATCHING — 基线 case ↔ trace session 精确匹配，判定 TP/FP/FN/TN
        4. ROOT_CAUSE_ANALYSIS — FP case 挖掘链+验证链各自滚动压缩根因分析
        5. RESOLVING — 持久化 session_graph + 4 种 fact 到 DB
        6. LIFECYCLE_ANALYSIS — L0-L7 全链路分析
        7. CAUSAL_CHAIN — 因果链分析 + DTS 问题单生成
        8. REPORTING — 报告组装（含召回率/准确率计算）
        9. FINALIZE — 写入 evaluation_report 表，状态设为 COMPLETED

        Args:
            evaluation_id: 评测 ID。
            cancel_cb: 外部传入的取消检查回调（可选）。编排器内部会创建
                       绑定到 evaluation_id 的 cancel_cb 穿透到内循环。
        """
        set_eval_ctx(evaluation_id)
        reports_dir = _get_reports_dir()
        os.makedirs(reports_dir, exist_ok=True)

        # 清除旧的 debug 数据文件（重试时避免残留历史数据）
        self._clear_debug_files(reports_dir, evaluation_id)

        # 统一 cancel_cb：外部传入的优先，否则用内部创建的
        _cancel_cb = cancel_cb or _make_cancel_cb(evaluation_id, "ORCHESTRATOR")

        log("ORCH", f"启动 v2 pipeline: evaluation_id={evaluation_id} "
              f"reports_dir={reports_dir}")

        try:
            # ── INGESTING（拆分：config+entries 立即返回，数据采集并行） ──
            assert_transition("VALIDATING", stages.INGESTING)
            self._set_status_safe(evaluation_id, "VALIDATING")
            self._set_status_safe(evaluation_id, stages.INGESTING)

            # 1. 读 config + entries（快，纯 DB 读）
            cfg = self._read_config(evaluation_id)
            entries = cfg.get("manifest", {}).get("entries", [])
            eval_mode = cfg.get("manifest", {}).get("eval_mode", "dev")
            benchmark_source = cfg.get("manifest", {}).get(
                "benchmark_source", "vbench_zip")
            log("ORCH", f"INGESTING: {len(entries)} entries, eval_mode={eval_mode}, "
                  f"benchmark_source={benchmark_source}")

            # 2. 并行启动：trace 解析 + 数据采集（基线/原始数据/LLM 匹配）
            _set_progress(evaluation_id, "并行：trace 解析 + 数据采集...")

            # ── PARSING 线程 ──
            _check_cancel(evaluation_id, stages.PARSING)
            assert_transition(stages.INGESTING, stages.PARSING)
            self._set_status_safe(evaluation_id, stages.PARSING)

            parse_pool = ThreadPoolExecutor(max_workers=1)
            parse_future = parse_pool.submit(
                with_eval_ctx(self._parse_traces),
                evaluation_id, entries, [], {}, cfg,
                cancel_cb=_cancel_cb,
            )

            # ── 数据采集线程 ──
            def _collect_data():
                return with_eval_ctx(self._collect_baseline_and_raw)(
                    evaluation_id, cfg,
                )
            data_pool = ThreadPoolExecutor(max_workers=1)
            data_future = data_pool.submit(_collect_data)

            # 等待数据采集完成
            benchmark_items, case_details, alert_center_data, case_matches = \
                data_future.result()
            data_pool.shutdown(wait=False)
            log("ORCH", f"数据采集 done: {len(benchmark_items)} benchmark_items, "
                  f"{len(case_details)} case_details")

            # ── 开发态 LLM 语义匹配 ──
            # （已在 _collect_baseline_and_raw 内完成，case_matches 直接返回）

            # debug dump：INGESTING 中间数据明细
            self._dump_debug(reports_dir, evaluation_id, "ingesting", {
                "benchmark_source": benchmark_source,
                "eval_mode": eval_mode,
                "benchmark_set_id": cfg.get("manifest", {}).get("benchmark_set_id"),
                "vc_source_task_id": cfg.get("manifest", {}).get("vc_source_task_id"),
                "entries": [
                    {
                        "condition": e.get("condition"),
                        "project_id": e.get("project_id"),
                        "task_id": e.get("task_id_actual"),
                        "project_name": e.get("project_name"),
                        "task_name": e.get("task_name"),
                        "category": e.get("category"),
                        "source_uri": e.get("source_uri"),
                    }
                    for e in entries
                ],
                "raw_data": {
                    "source_task_ids": alert_center_data.get("source_task_ids", []),
                    "project_ids": alert_center_data.get("project_ids", []),
                    "total": alert_center_data.get("total", 0),
                    "counts": alert_center_data.get("counts", {}),
                    "cases": [
                        {
                            "case_id": c.get("id"),
                            "title": c.get("title"),
                            "validation_result": c.get("validation_result"),
                            "current_stage": c.get("current_stage"),
                            "false_positive_reason": c.get("false_positive_reason"),
                            "false_positive_group": c.get("false_positive_group"),
                            "project_id": c.get("project_id"),
                        }
                        for c in alert_center_data.get("cases", [])
                    ],
                },
                "baseline": {
                    "total": len(case_details),
                    "cases": [
                        {
                            "case_id": cid,
                            **detail,
                        }
                        for cid, detail in case_details.items()
                    ],
                },
                "case_matches": case_matches,
            })

            # debug 断点
            debug_stop = cfg.get("manifest", {}).get("debug_stop_after")
            if debug_stop == "ingesting":
                log("ORCH", f"DEBUG 断点：停在 INGESTING 之后（debug_stop_after=ingesting）")
                self._set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
                _set_progress(evaluation_id, "调试断点：INGESTING 完成")
                _set_failed(evaluation_id, "调试断点：debug_stop_after=ingesting")
                return

            # 等待 trace 解析完成
            data_packs = parse_future.result()
            parse_pool.shutdown(wait=False)
            log("ORCH", f"PARSING done: {len(data_packs)} data_packs")

            # 将 benchmark_items 附加到每个 DataPack（并行解析时未传入）
            if benchmark_items:
                from ..core.task_run import BenchmarkItem
                from ..core.enums import ExpectedLabel
                for dp in data_packs:
                    bench = []
                    for bid in benchmark_items:
                        cd = case_details.get(bid, {})
                        exp_label = cd.get("expected_label", "VULNERABLE")
                        bench.append(BenchmarkItem(
                            benchmark_item_id=bid,
                            benchmark_set_id=cfg.get("manifest", {}).get(
                                "benchmark_set_id", "BS001",
                            ),
                            task_id=dp.task_id,
                            expected_label=ExpectedLabel(exp_label)
                            if exp_label else None,
                            metadata=cd,
                        ))
                    dp.benchmark_item = bench[0] if bench else None

            # debug dump：PARSING 中间数据 — 所有 session 关系图
            self._dump_debug(reports_dir, evaluation_id, "parsing", {
                "data_packs": [
                    self._summarize_data_pack(dp)
                    for dp in data_packs
                ],
            })

            # ── CASE_MATCHING（基线 case ↔ trace session）──
            _check_cancel(evaluation_id, stages.CASE_MATCHING)
            assert_transition(stages.PARSING, stages.CASE_MATCHING)
            self._set_status_safe(evaluation_id, stages.CASE_MATCHING)
            _set_progress(evaluation_id, "case-session 匹配...")
            from ..lifecycle.case_session_matcher import CaseSessionMatcher
            matcher = CaseSessionMatcher()
            case_session_matches = matcher.match(
                evaluation_id, data_packs, case_details,
                case_matches=case_matches,
                eval_mode=eval_mode,
            )

            # debug dump：CASE_MATCHING 中间数据
            self._dump_debug(reports_dir, evaluation_id, "case_matching", {
                "eval_mode": eval_mode,
                "total_cases": len(case_session_matches),
                "matched": sum(1 for r in case_session_matches
                               if r["match_method"] != "unmatched"),
                "unmatched": sum(1 for r in case_session_matches
                                 if r["match_method"] == "unmatched"),
                "outcomes": {
                    "TP": sum(1 for r in case_session_matches if r["outcome"] == "TP"),
                    "FP": sum(1 for r in case_session_matches if r["outcome"] == "FP"),
                    "FN": sum(1 for r in case_session_matches if r["outcome"] == "FN"),
                    "TN": sum(1 for r in case_session_matches if r["outcome"] == "TN"),
                },
                "matches": case_session_matches,
            })

            # debug 断点
            if cfg.get("manifest", {}).get("debug_stop_after") == "case_matching":
                log("ORCH", "DEBUG 断点：停在 CASE_MATCHING 之后")
                self._set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
                _set_progress(evaluation_id, "调试断点：CASE_MATCHING 完成")
                _set_failed(evaluation_id, "调试断点：debug_stop_after=case_matching")
                return

            # ── ROOT_CAUSE_ANALYSIS（FP case 滚动压缩根因分析）──
            _check_cancel(evaluation_id, stages.ROOT_CAUSE_ANALYSIS)
            assert_transition(stages.CASE_MATCHING, stages.ROOT_CAUSE_ANALYSIS)
            self._set_status_safe(evaluation_id, stages.ROOT_CAUSE_ANALYSIS)
            fp_cases = [r for r in case_session_matches if r["outcome"] == "FP"]
            if fp_cases:
                _set_progress(evaluation_id,
                              f"根因分析中... {len(fp_cases)} 个 FP case")
                from ..lifecycle.root_cause_analyzer import RootCauseAnalyzer
                rca = RootCauseAnalyzer()
                root_cause_results = rca.analyze(
                    evaluation_id, fp_cases, data_packs,
                    cancel_cb=_cancel_cb,
                )

                # debug dump：ROOT_CAUSE 中间数据
                self._dump_debug(reports_dir, evaluation_id, "root_cause", {
                    "total_fp": len(fp_cases),
                    "analyzed": len(root_cause_results),
                    "results": root_cause_results,
                })

                # debug 断点
                if cfg.get("manifest", {}).get("debug_stop_after") == "root_cause":
                    log("ORCH", "DEBUG 断点：停在 ROOT_CAUSE 之后")
                    self._set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
                    _set_progress(evaluation_id, "调试断点：ROOT_CAUSE 完成")
                    _set_failed(evaluation_id, "调试断点：debug_stop_after=root_cause")
                    return
            else:
                root_cause_results = []
                log("ORCH", "无 FP case，跳过根因分析")

            # 清理 /tmp trace 缓存（NFS 拷贝到本地的临时文件）
            try:
                from ...application.evaluation_service import _cleanup_trace_cache
                _cleanup_trace_cache(evaluation_id)
            except Exception:
                pass

            # ── RESOLVING ──
            # 持久化 session_graph + 4 种 fact 到 DB
            _check_cancel(evaluation_id, stages.RESOLVING)
            assert_transition(stages.ROOT_CAUSE_ANALYSIS, stages.RESOLVING)
            self._set_status_safe(evaluation_id, stages.RESOLVING)
            _set_progress(evaluation_id, "持久化解析结果...")
            self._persist_data(evaluation_id, data_packs)

            # ── LIFECYCLE_ANALYSIS ──
            # 重试路径：knowledge_access_detail 表已有记录 → 跳过
            _check_cancel(evaluation_id, stages.LIFECYCLE_ANALYSIS)
            assert_transition(stages.RESOLVING, stages.LIFECYCLE_ANALYSIS)
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
                    benchmark_source=benchmark_source,
                    alert_center_data=alert_center_data,
                    case_details=case_details,
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
            causal_chain = self._run_causal_chain(
                access_details, evaluation_id, reports_dir,
            )
            log("ORCH", f"CAUSAL_CHAIN done: "
                  f"{len(causal_chain.get('per_case_breakpoints', []))} "
                  f"cases with breakpoints")

            # ── REPORTING ──
            _check_cancel(evaluation_id, stages.REPORTING)
            assert_transition(stages.CAUSAL_CHAIN, stages.REPORTING)
            self._set_status_safe(evaluation_id, stages.REPORTING)

            # 重试路径：lifecycle report 已存在 → 跳过报告组装
            if _has_lifecycle_report(evaluation_id, reports_dir) and \
                    os.path.isfile(os.path.join(reports_dir, f"{evaluation_id}.json")):
                log("ORCH", "REPORTING skipped: lifecycle + base report 已存在"
                      "（重试路径）")
                _set_progress(evaluation_id, "报告组装（已有，跳过）")
            else:
                _set_progress(evaluation_id, "计算召回率/准确率...")
                recall_precision = self._calc_recall_precision(
                    evaluation_id, case_details, alert_center_data,
                    benchmark_source,
                )
                _set_progress(evaluation_id, "报告组装...")
                self._assemble_report(
                    evaluation_id,
                    access_details, causal_chain,
                    recall_precision, reports_dir,
                )
                log("ORCH", f"REPORTING done: recall={recall_precision.get('recall_rate')}, "
                      f"precision={recall_precision.get('precision_rate')}")

            # ── FINALIZE ──
            _check_cancel(evaluation_id, stages.FINALIZE)
            assert_transition(stages.REPORTING, "FINALIZING")
            self._set_status_safe(evaluation_id, "FINALIZING")
            _set_progress(evaluation_id, "完成...")
            self._finalize(evaluation_id, reports_dir,
                           causal_chain)
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

    def _read_config(self, evaluation_id: str) -> dict:
        """读 evaluation_snapshot 配置（纯 DB 读，快速）。"""
        def _read(cur):
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
            cfg.setdefault("manifest", {})["benchmark_set_id"] = \
                cfg.get("manifest", {}).get("benchmark_set_id") or bsid
            return cfg
        return _db_query(_read)

    def _collect_baseline_and_raw(
        self, evaluation_id: str, cfg: dict,
    ) -> tuple[list, dict, dict, list]:
        """采集基线 + 原始数据 + LLM 匹配（并行于 trace 解析）。

        返回:
            (benchmark_items, case_details, alert_center_data, case_matches)
        """
        manifest = cfg.get("manifest", {})
        entries = manifest.get("entries", [])
        bm_source = manifest.get("benchmark_source", "vbench_zip")
        benchmark_set_id = manifest.get("benchmark_set_id", "BS001")
        vc_source_task_id = manifest.get("vc_source_task_id")
        eval_mode = manifest.get("eval_mode", "dev")

        case_details: dict[str, dict] = {}
        alert_center_data: dict = {}
        case_matches: list[dict] = []

        # ── 获取原始数据：从告警中心取挖掘 agent 上报的 case ──
        _ac_pairs: list[tuple[str, str]] = []
        _seen: set[tuple[str, str]] = set()
        for e in entries:
            if e.get("category") != "mining":
                continue
            _pid = e.get("project_id") or ""
            _tid = e.get("task_id_actual") or ""
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
                log("INGEST", f"原始数据(告警中心): {len(all_cases)} 条 case "
                      f"(是漏洞={merged_counts['vulnerable']} "
                      f"不是漏洞={merged_counts['not_vulnerable']})")
            except Exception as e:
                log("INGEST", f"取告警中心数据失败: {e}")
                raise ValueError(
                    f"取告警中心数据失败: {e}"
                ) from e

        # ── 取基线 case 详情 ──
        if bm_source == "vuln_center":
            from ...infrastructure.vuln_center_client import (
                _case_to_benchmark, get_alert_center_summary,
            )
            log("INGEST", f"基线数据(告警中心): project={benchmark_set_id} "
                  f"task={vc_source_task_id or '(未指定)'}")
            baseline_summary = get_alert_center_summary(
                benchmark_set_id, vc_source_task_id,
            )
            baseline_cases = baseline_summary.get("cases", [])
            log("INGEST", f"基线告警中心返回 {len(baseline_cases)} 条 case")

            for c in baseline_cases:
                if c.get("current_stage") != "finished":
                    continue
                vr = c.get("validation_result")
                if vr not in ("vulnerable", "not_vulnerable"):
                    continue
                expected_label = "VULNERABLE" if vr == "vulnerable" else "NON_VULNERABLE"
                bm = _case_to_benchmark(c, expected_label)
                cid = bm.get("case_id") or ""
                if cid:
                    case_details[cid] = {
                        "description": bm.get("description") or "",
                        "vulnerability_type": bm.get("vulnerability_type") or "",
                        "expected_label": expected_label,
                        "source_file": bm.get("source_file") or "",
                        "source_function": bm.get("source_function") or "",
                        "source_line": bm.get("source_line") or "",
                        "locator": bm.get("locator") or "",
                        "false_positive_group": bm.get("false_positive_group") or "",
                        "false_positive_reason": bm.get("false_positive_reason") or "",
                        "human_confirmation_summary": bm.get("human_confirmation_summary") or "",
                    }

        elif bm_source == "vbench_zip":
            from ...infrastructure.vbench_client import get_benchmark
            log("INGEST", f"基线数据(V-Bench): set_id={benchmark_set_id}")
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
                "请检查 benchmark_source 配置、V-Bench/告警中心服务连通性后重试。"
            )

        benchmark_items = list(case_details.keys())

        # ── 开发态 LLM 语义匹配 ──
        if eval_mode == "dev" and alert_center_data.get("cases"):
            raw_project_ids = set(alert_center_data.get("project_ids", []))
            baseline_project = benchmark_set_id
            needs_match = baseline_project and \
                baseline_project not in raw_project_ids
            if needs_match:
                log("ORCH", f"开发态：原始数据 project={raw_project_ids} "
                      f"≠ 基线 project={baseline_project}，启动 LLM 匹配")
                _set_progress(evaluation_id, "LLM 语义匹配原始数据与基线...")
                from ..lifecycle.case_matcher import match_cases
                raw_cases_for_match = alert_center_data.get("cases", [])
                baseline_cases_for_match = [
                    {
                        "case_id": cid,
                        "title": detail.get("vulnerability_type") or "",
                        "description": detail.get("description") or "",
                        "vulnerability_type": detail.get(
                            "vulnerability_type") or "",
                    }
                    for cid, detail in case_details.items()
                ]

                def _match_progress(done, total, matched):
                    _set_progress(evaluation_id,
                        f"LLM 匹配中... {done}/{total} "
                        f"({matched} 条已匹配)")

                case_matches = match_cases(
                    raw_cases_for_match,
                    baseline_cases_for_match,
                    evaluation_id,
                    cancel_cb=_make_cancel_cb(evaluation_id, "MATCH"),
                    progress_cb=_match_progress,
                )
                matched = sum(
                    1 for m in case_matches
                    if m.get("matched_baseline_case_id")
                )
                log("ORCH", f"LLM 匹配完成: {matched}/{len(case_matches)} "
                      f"条原始数据找到基线匹配")
            else:
                log("ORCH", "开发态：原始数据与基线同项目，跳过 LLM 匹配")

        return benchmark_items, case_details, alert_center_data, case_matches

    def _ingest(self, evaluation_id: str) -> tuple:
        """取原始数据 + 基线数据。

        原始数据：从 entries 的 project_id + task_id 取告警中心引擎上报数据。
        基线数据：标准答案，来源二选一：
          - vuln_center：从告警中心取人工标注数据（benchmark_set_id + vc_source_task_id 指定基线项目）
          - vbench_zip：从 V-Bench 测评数据集取

        运行态时原始数据和基线是同一个项目；开发态时可能是不同项目。

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
        vc_source_task_id = manifest.get("vc_source_task_id")

        case_details: dict[str, dict] = {}
        alert_center_data: dict = {}

        # ── 获取原始数据：从告警中心取挖掘 agent 上报的 case ──
        # 只取 category=mining 的 entry，验证 agent 不上报新漏洞
        _ac_pairs: list[tuple[str, str]] = []
        _seen: set[tuple[str, str]] = set()
        for e in entries:
            if e.get("category") != "mining":
                continue
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
                log("INGEST", f"原始数据(告警中心): {len(all_cases)} 条 case "
                      f"(是漏洞={merged_counts['vulnerable']} "
                      f"不是漏洞={merged_counts['not_vulnerable']})")
            except Exception as e:
                log("INGEST", f"取告警中心数据失败: {e}")
                raise ValueError(
                    f"取告警中心数据失败: {e}"
                ) from e

        # ── 取基线 case 详情 ──
        if bm_source == "vuln_center":
            # 从告警中心取基线数据（人工标注的标准答案）
            # 用 vc_source_task_id 按 task 取，与原始数据同范围
            from ...infrastructure.vuln_center_client import (
                _case_to_benchmark, get_alert_center_summary,
            )
            log("INGEST", f"基线数据(告警中心): project={benchmark_set_id} "
                  f"task={vc_source_task_id or '(未指定)'}")
            baseline_summary = get_alert_center_summary(
                benchmark_set_id, vc_source_task_id,
            )
            baseline_cases = baseline_summary.get("cases", [])
            log("INGEST", f"基线告警中心返回 {len(baseline_cases)} 条 case")

            for c in baseline_cases:
                # 基线 = 人工标注的数据：只取 current_stage=finished 的 case
                if c.get("current_stage") != "finished":
                    continue
                vr = c.get("validation_result")
                # 只取人工已判定的 case（vulnerable / not_vulnerable）
                if vr not in ("vulnerable", "not_vulnerable"):
                    continue
                expected_label = "VULNERABLE" if vr == "vulnerable" else "NON_VULNERABLE"
                bm = _case_to_benchmark(c, expected_label)
                cid = bm.get("case_id") or ""
                if cid:
                    case_details[cid] = {
                        "description": bm.get("description") or "",
                        "vulnerability_type": bm.get("vulnerability_type") or "",
                        "expected_label": expected_label,
                        "source_file": bm.get("source_file") or "",
                        "source_function": bm.get("source_function") or "",
                        "source_line": bm.get("source_line") or "",
                        "locator": bm.get("locator") or "",
                        "false_positive_group": bm.get("false_positive_group") or "",
                        "false_positive_reason": bm.get("false_positive_reason") or "",
                        "human_confirmation_summary": bm.get("human_confirmation_summary") or "",
                    }

        elif bm_source == "vbench_zip":
            # 开发态：从 V-Bench 测评数据集取基线
            from ...infrastructure.vbench_client import get_benchmark
            log("INGEST", f"基线数据(V-Bench): set_id={benchmark_set_id}")
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
                "请检查 benchmark_source 配置、V-Bench/告警中心服务连通性后重试。"
            )

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
        parse → build_session_graph → load_session
        → resolve → DataPack。

        使用 ThreadPoolExecutor 并行，受 parse_workers 并发控制。
        """
        from ..parsers import get_parser
        from ..core.task_run import TaskRun, BenchmarkItem
        from ..core.enums import Condition, ConditionSource, ExpectedLabel

        # 解析 trace 源路径
        def _resolve_path(source_uri: str, project_id: str = "",
                          task_id: str = "") -> str:
            if os.path.exists(source_uri):
                # k8s 模式：/data 在 NFS-backed PVC 上，SQLite 随机读极慢，
                # 拷贝到 pod 本地 /tmp 加速解析，解析完删除
                if source_uri.startswith("/data/"):
                    from ...application.evaluation_service import (
                        _copy_trace_to_local,
                    )
                    return _copy_trace_to_local(
                        source_uri, evaluation_id=evaluation_id)
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
            key = e.get("source_uri", "")
            if not key:
                continue
            if key not in local_paths:
                local_paths[key] = _resolve_path(
                    key, e.get("project_id", ""), e.get("task_id", ""),
                )

        # 构建解析任务
        tasks: list[dict] = []
        for e in entries:
            src_uri = e.get("source_uri", "")
            local_path = local_paths[src_uri]
            cond = e.get("condition", "UNKNOWN")
            task_id = e.get("task_id", "")
            trace_kind = e.get("trace_kind")
            category = e.get("category", "")
            project_id = e.get("project_id", "")

            # 为每个 entry 创建 TaskRun + benchmark_items
            # benchmark_items 可能为空（并行模式下数据采集尚未完成）
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

    def _persist_data(self, evaluation_id: str, data_packs: list):
        """持久化 task_run + session_graph + 4 种 fact 到 DB。

        task_run 记录必须先写入，因为 knowledge_interaction_fact 等
        fact 表有 FK 约束引用 task_run(evaluation_id, task_run_id)。
        _calculate_metrics 和 _get_packs_with_knowledge 依赖
        knowledge_interaction_fact 和 tool_action_fact。
        """
        from ...persistence.repositories.fact_repo import (
            insert_session_graph,
            insert_knowledge_fact, insert_tool_action_fact,
            insert_outcome_fact, insert_resource_fact,
            insert_task_run, insert_trace_source,
        )
        from ..core.task_run import TaskRun
        from ..core.enums import Condition, ConditionSource

        def _do(cur):
            for dp in data_packs:
                trace_id = (dp.session_meta.get("trace_id", "")
                            if isinstance(dp.session_meta, dict) else "")
                if not trace_id:
                    trace_id = dp.task_run_id  # 回退用 task_run_id

                # 先写 trace_source（FK 约束：task_run.trace_id 引用 trace_source）
                insert_trace_source(
                    cur, trace_id, evaluation_id,
                    dp.session_meta.get("source_uri", "")
                    if isinstance(dp.session_meta, dict) else "",
                )

                # 再写 task_run（FK 约束：fact 表引用 task_run）
                tr = TaskRun(
                    task_run_id=dp.task_run_id,
                    evaluation_id=evaluation_id,
                    task_id=dp.task_id,
                    trace_id=trace_id,
                    condition=Condition.KG if dp.condition == "KG"
                    else Condition.UNKNOWN,
                    condition_source=ConditionSource.MANIFEST,
                    trace_valid=True,
                    runtime_valid=True,
                    parser_version="2.0",
                )
                # agent_name 不在 TaskRun dataclass 中，但 insert_task_run
                # 用 hasattr 检查，动态设置
                tr.agent_name = dp.agent_type
                insert_task_run(cur, tr)

                insert_session_graph(
                    cur, dp.task_run_id, evaluation_id, dp.session_graph or {},
                )
                # 持久化 4 种 fact
                if dp.knowledge_fact:
                    insert_knowledge_fact(cur, dp.knowledge_fact)
                if dp.tool_action_fact:
                    insert_tool_action_fact(cur, dp.tool_action_fact)
                if dp.outcome_fact:
                    insert_outcome_fact(cur, dp.outcome_fact)
                if dp.resource_fact:
                    insert_resource_fact(cur, dp.resource_fact)

        try:
            _db_query(_do)
            log("RESOLVE", f"持久化 {len(data_packs)} data_packs 的 "
                  f"session_graph + 4 种 fact")
        except Exception as e:
            log("RESOLVE", f"持久化失败: {e}")
            raise

    # ── LIFECYCLE_ANALYSIS ──────────────────────────

    def _run_lifecycle(
        self, data_packs: list, evaluation_id: str,
        reports_dir: str, cancel_cb=None, eval_mode: str = "dev",
        benchmark_source: str = "vbench_zip",
        alert_center_data: dict | None = None,
        case_details: dict | None = None,
    ) -> list[dict]:
        """L0-L7 全链路分析。

        调用 LifecycleAnalyzer.analyze()，对有效 case 的每次知识访问
        执行 L0-L7 逐级判定，写入 knowledge_access_detail 表。

        cancel_cb 穿透到 LLM 密集内循环。
        eval_mode: "dev"（开发态，分析 FP+FN）| "runtime"（运行态，只分析 FP）
        benchmark_source: "vuln_center"（漏洞中心，纯代码匹配）|
                          "vbench_zip"（V-Bench 测评集，LLM 匹配）
        alert_center_data: 告警中心数据，用于 FN 判定（基线漏洞与告警中心对比，
                          匹配上的不是漏报，没匹配上的是漏报）
        """
        from ..lifecycle.analyzer import LifecycleAnalyzer

        analyzer = LifecycleAnalyzer()
        records = analyzer.analyze(
            evaluation_id, data_packs, reports_dir,
            cancel_cb=cancel_cb, eval_mode=eval_mode,
            benchmark_source=benchmark_source,
            alert_center_data=alert_center_data,
            case_details=case_details,
        )
        # 将 FPR 统计存到实例，供 run() 计算 M13
        self._lifecycle_fpr_stats = getattr(analyzer, "case_filter_stats", None)
        return records

    # ── CAUSAL_CHAIN ─────────────────────────────────

    def _run_causal_chain(
        self, access_details: list[dict],
        evaluation_id: str = "", reports_dir: str = "",
    ) -> dict:
        """因果链分析 + DTS 问题单生成。

        调用 CausalChainAnalyzer.analyze()，基于 knowledge_access_detail
        的判定结果按 Agent 类型聚合误报归因。
        分析完成后，从 per_case_breakpoints 自动生成 DTS 问题单并持久化。
        """
        from ..causal_chain.analyzer import CausalChainAnalyzer

        analyzer = CausalChainAnalyzer()
        # access_details 需要包含 evaluation_id（从第一条记录取）
        if not evaluation_id and access_details:
            evaluation_id = access_details[0].get("evaluation_id", "")
        result = analyzer.analyze(evaluation_id, access_details)

        # 从断点生成 DTS 问题单
        from ..dts.issue import generate_dts_issues
        from ..persistence.dts_repo import upsert_dts_issues

        case_filter_stats = getattr(self, "_lifecycle_fpr_stats", None) or {}
        dts_issues = generate_dts_issues(
            evaluation_id, result, access_details, case_filter_stats,
        )
        if dts_issues:
            upsert_dts_issues(dts_issues, evaluation_id, reports_dir)
            log("CAUSAL_CHAIN", f"Generated {len(dts_issues)} DTS issues")

        return result

    def _calc_recall_precision(
        self, evaluation_id: str, case_details: dict,
        alert_center_data: dict, benchmark_source: str,
    ) -> dict:
        """计算召回率和准确率。

        从基线 case_details 和告警中心数据计算：
        - 召回率 = TP / (TP + FN)
        - 准确率 = TP / (TP + FP)

        TP = 基线 VULNERABLE + 告警中心有匹配（agent 上报了）
        FN = 基线 VULNERABLE + 告警中心无匹配（agent 漏报）
        FP = 基线 NON_VULNERABLE + trace 有 finding 且 CONFIRMED（agent 误报）
        TN = 基线 NON_VULNERABLE + 无匹配 finding 或 finding 非 CONFIRMED

        FP/TN 从 CaseFilter 的 FPR 统计获取（lifecycle 阶段已计算），
        TP/FN 从告警中心数据与基线对比获取。
        """
        # TP/FN: 从告警中心数据计算
        tp_count = 0
        fn_count = 0

        # 告警中心有匹配的基线 VULNERABLE case → TP
        ac_cases = alert_center_data.get("cases", [])
        ac_case_ids = set()
        for ac in ac_cases:
            ac_id = ac.get("case_id") or ac.get("id") or ""
            if ac_id:
                ac_case_ids.add(ac_id)

        for cid, cd in case_details.items():
            expected = cd.get("expected_label", "VULNERABLE").upper()
            if expected == "VULNERABLE":
                if cid in ac_case_ids:
                    tp_count += 1
                else:
                    fn_count += 1

        # FP: 从 lifecycle FPR 统计获取
        fpr_stats = getattr(self, "_lifecycle_fpr_stats", None) or {}
        fp_count = fpr_stats.get("fp_count", 0)
        tn_count = fpr_stats.get("tn_count", 0)

        # 召回率 = TP / (TP + FN)
        recall_denom = tp_count + fn_count
        recall_rate = (tp_count / recall_denom) if recall_denom > 0 else None

        # 准确率 = TP / (TP + FP)
        precision_denom = tp_count + fp_count
        precision_rate = (tp_count / precision_denom) if precision_denom > 0 else None

        result = {
            "recall_rate": round(recall_rate, 4) if recall_rate is not None else None,
            "precision_rate": round(precision_rate, 4) if precision_rate is not None else None,
            "tp_count": tp_count,
            "fn_count": fn_count,
            "fp_count": fp_count,
            "tn_count": tn_count,
        }
        log("REPORT", f"召回率={result['recall_rate']}, "
              f"准确率={result['precision_rate']}, "
              f"TP={tp_count}, FN={fn_count}, FP={fp_count}, TN={tn_count}")
        return result

    # ── REPORTING ────────────────────────────────────

    def _assemble_report(
        self, evaluation_id: str,
        access_details: list, causal_chain: dict,
        recall_precision: dict, reports_dir: str,
    ):
        """报告组装。

        调用 ReportAssembler 组装生命周期分析段报告，
        写入 {evaluation_id}_lifecycle.json。
        """
        from ..report.assembler import ReportAssembler

        assembler = ReportAssembler()

        # 组装生命周期分析段报告
        assembler.assemble_lifecycle_report(
            evaluation_id,
            access_details,
            causal_chain,
            recall_precision,
            reports_dir,
        )

        # 写入基础报告段
        base_report = {
            "evaluation_id": evaluation_id,
            "recall_precision": {
                "recall_rate": recall_precision.get("recall_rate"),
                "precision_rate": recall_precision.get("precision_rate"),
                "tp_count": recall_precision.get("tp_count", 0),
                "fn_count": recall_precision.get("fn_count", 0),
                "fp_count": recall_precision.get("fp_count", 0),
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
            _json_dump(base_report, f)
        log("REPORT", f"基础报告写入 {base_path}")

    # ── FINALIZE ─────────────────────────────────────

    def _finalize(
        self, evaluation_id: str, reports_dir: str,
        causal_chain: dict,
    ):
        """写入 evaluation_report 表，状态设为 COMPLETED。

        将报告 JSON 路径写入 evaluation_report 表，
        供 /report/status 和 /report/lifecycle 端点查询。
        """
        # 检查 lifecycle report 是否存在
        lifecycle_path = os.path.join(
            reports_dir, f"{evaluation_id}_lifecycle.json",
        )
        base_path = os.path.join(reports_dir, f"{evaluation_id}.json")

        report_data = {
            "evaluation_id": evaluation_id,
            "base_report_path": base_path,
            "lifecycle_report_path": lifecycle_path,
            "cause_summary": causal_chain.get("cause_summary", {}),
        }

        def _do(cur):
            # 先创建 evaluation_calculation_run 记录（FK 约束要求）
            # v2 不需要 calculation_run，但 evaluation_report 表有 FK 约束
            cur.execute(
                "INSERT IGNORE INTO evaluation_calculation_run "
                "(calculation_run_id, evaluation_id, run_type, "
                "config_snapshot_id) "
                "VALUES (%s, %s, 'v2_pipeline', %s)",
                (
                    f"cr-{evaluation_id}",
                    evaluation_id,
                    f"snap-{evaluation_id}",
                ),
            )
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
                    _json_dumps(report_data),
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

    def _clear_debug_files(self, reports_dir: str, evaluation_id: str):
        """清除该评测的所有 debug 数据文件（重试时清理历史数据）。"""
        import glob
        pattern = os.path.join(reports_dir, f"{evaluation_id}_debug_*.json")
        for f in glob.glob(pattern):
            try:
                os.remove(f)
            except Exception:
                pass

    def _dump_debug(self, reports_dir: str, evaluation_id: str,
                    step: str, data: dict):
        """将步骤中间数据 dump 到 {eid}_debug_{step}.json，供调试界面查看。"""
        path = os.path.join(reports_dir, f"{evaluation_id}_debug_{step}.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                _json_dump(data, f)
            log("DEBUG", f"dump {step}: {path}")
        except Exception as e:
            log("DEBUG", f"dump {step} 失败: {e}")

    def _summarize_data_pack(self, dp) -> dict:
        """将 DataPack 序列化为 debug 可展示的摘要（含 session 关系图）。"""
        sg = dp.session_graph or {}
        sessions = sg.get("sessions", {})
        edges = sg.get("edges", {})
        parent_map = sg.get("parent_map", {})

        # session 列表（含 agent、phase、parent + task 信息）
        session_list = []
        db_columns = []
        for sid, info in sessions.items():
            info_d = info if isinstance(info, dict) else {}
            db_row = info_d.get("db_row", {})
            if db_row and not db_columns:
                db_columns = sorted(db_row.keys())
            session_list.append({
                "session_id": sid,
                "agent": info_d.get("agent", ""),
                "session_type": info_d.get("session_type", ""),
                "task_type": info_d.get("task_type", ""),
                "task_id": info_d.get("task_id", ""),
                "status": info_d.get("status", ""),
                "is_failed_task": info_d.get("is_failed_task", False),
                "parent_id": parent_map.get(sid, ""),
                "phase": (dp.session_phase_labels or {}).get(sid, ""),
                "files": sorted(info_d.get("files", set()) if isinstance(info_d.get("files"), set) else info_d.get("files", [])),
                "facts": sorted(info_d.get("facts", set()) if isinstance(info_d.get("facts"), set) else info_d.get("facts", [])),
                "db_row": db_row,
            })

        # 边列表
        edge_list = []
        for src, targets in edges.items():
            if isinstance(targets, set):
                targets = sorted(targets)
            elif not isinstance(targets, list):
                targets = list(targets)
            for tgt in targets:
                edge_list.append({"from": src, "to": tgt})

        return {
            "task_run_id": dp.task_run_id,
            "task_id": dp.task_id,
            "agent_type": dp.agent_type,
            "condition": dp.condition,
            "session_count": len(sessions),
            "edge_count": len(edge_list),
            "event_count": len(dp.events or []),
            "db_columns": db_columns,
            "sessions": session_list,
            "edges": edge_list,
        }

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
                    "'PARSING','CASE_MATCHING','ROOT_CAUSE_ANALYSIS',"
                    "'RESOLVING','PAIRING',"
                    "'LIFECYCLE_ANALYSIS','CAUSAL_CHAIN',"
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
