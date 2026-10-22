"""v2 Pipeline 编排器。

阶段流程：
    INGESTING → PARSING → CASE_MATCHING → ROOT_CAUSE_ANALYSIS
        → RESOLVING → REPORTING → FINALIZE

RESOLVING 阶段内完成 fact 持久化 + 因果链分析 + 问题单生成
（从根因分析结果的 l0_l7_breakpoints 构建，不再有独立的 L0-L7 逐条分析）。

协作取消：
- 每个阶段入口检查 ``_check_cancel(evaluation_id)``
- ``cancel_cb`` 穿透到 LLM 密集内循环

重试路径：
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


# ── 编排器 ────────────────────────────────────────────


def _has_lifecycle_report(evaluation_id: str, reports_dir: str) -> bool:
    """检查 lifecycle report 是否已存在。"""
    return os.path.isfile(
        os.path.join(reports_dir, f"{evaluation_id}_lifecycle.json")
    )


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
        5. RESOLVING — 持久化 session_graph + 4 种 fact 到 DB；
           随后完成因果链分析 + 问题单生成（从根因分析结果构建）
        6. REPORTING — 报告组装（含召回率/准确率计算）
        7. FINALIZE — 写入 evaluation_report 表，状态设为 COMPLETED

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
                            "summary": c.get("summary") or "",
                            "validation_result": c.get("validation_result"),
                            "current_stage": c.get("current_stage"),
                            "false_positive_reason": c.get("false_positive_reason"),
                            "false_positive_group": c.get("false_positive_group"),
                            "human_confirmation_summary": (c.get("human_confirmation") or {}).get("summary") or "",
                            "project_id": c.get("project_id"),
                            "source_file": (c.get("subject") or {}).get("locator") or "",
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
                alert_center_data=alert_center_data,
            )

            # case_matching 只处理 FP（误报）和 FN（漏报）case
            # TP（真阳性，正确报了）和 TN（真阴性，正确没报）不需要根因分析/问题单
            fp_fn_matches = [r for r in case_session_matches
                             if r["outcome"] in ("FP", "FN")]

            # ── FN 漏报匹配结果（开发态）──
            # LLM 未匹配的 VULNERABLE 基线在 case_session_matches 里被 sink
            # 文件扫描判为 TP，但 agent 实际未上报漏洞——评测上是漏报。
            # 这里的漏报匹配结果是**精确匹配**：只有 sink 函数/行号级命中
            # （且读取型工具）的 session 才算匹配上——agent 确实读到过
            # 疑似 sink 点。文件级命中（grep/glob 结果列表碰巧含路径）
            # 不算匹配。FnMissAnalyzer 一次完成：sink 提取 + 精确匹配 +
            # 细分漏报成因，结果在 CASE_MATCHING 展示匹配、在
            # ROOT_CAUSE_ANALYSIS 展示漏报原因（避免重复 LLM 调用）。
            fn_miss_results: list[dict] = []
            fn_miss_match_cases: list[dict] = []
            if eval_mode == "dev":
                _set_progress(evaluation_id, "FN 漏报原因分析...")
                from ..lifecycle.fn_miss_analyzer import FnMissAnalyzer
                fn_analyzer = FnMissAnalyzer()
                fn_miss_results = fn_analyzer.analyze(
                    evaluation_id, case_details, case_matches,
                    data_packs, eval_mode=eval_mode,
                    cancel_cb=_cancel_cb,
                )
                for r in fn_miss_results:
                    precise_sessions = r.get("precise_sessions", {}) or {}
                    mining_sessions: list[str] = []
                    for at, sids in precise_sessions.items():
                        for sid in sids:
                            if sid not in mining_sessions:
                                mining_sessions.append(sid)
                    fn_miss_match_cases.append({
                        "case_id": r.get("case_id", ""),
                        "ac_case_id": "",
                        "vuln_title": r.get("vuln_title", ""),
                        "summary": r.get("summary", ""),
                        "description": r.get("description", ""),
                        "expected_label": "VULNERABLE",
                        "mining_sessions": mining_sessions,
                        "verify_sessions": [],
                        "outcome": "FN",
                        "match_method": "unmatched" if not mining_sessions
                        else "matched",
                        "match_detail": (
                            f"{len(mining_sessions)} 个 session 精确命中 sink 点"
                            f"（函数/行号级），LLM 未匹配原始数据，漏报"
                            if mining_sessions else
                            "LLM 未匹配原始数据且 trace 未精确命中 sink 点，漏报"),
                    })

            # debug dump：CASE_MATCHING 中间数据（FP/FN 匹配判定 + 漏报匹配结果，
            # 不含漏报原因——漏报原因分析在 ROOT_CAUSE_ANALYSIS 阶段展示）
            fn_match_cases = fp_fn_matches + fn_miss_match_cases
            case_matching_debug: dict = {
                "eval_mode": eval_mode,
                "total_cases": len(fn_match_cases),
                "matched": sum(1 for r in fn_match_cases
                               if r["match_method"] != "unmatched"),
                "unmatched": sum(1 for r in fn_match_cases
                                 if r["match_method"] == "unmatched"),
                "outcomes": {
                    "FP": sum(1 for r in fn_match_cases if r["outcome"] == "FP"),
                    "FN": sum(1 for r in fn_match_cases if r["outcome"] == "FN"),
                },
                "matches": fn_match_cases,
            }
            self._dump_debug(reports_dir, evaluation_id, "case_matching",
                             case_matching_debug)

            # debug 断点
            if cfg.get("manifest", {}).get("debug_stop_after") == "case_matching":
                log("ORCH", "DEBUG 断点：停在 CASE_MATCHING 之后")
                self._set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
                _set_progress(evaluation_id, "调试断点：CASE_MATCHING 完成")
                _set_failed(evaluation_id, "调试断点：debug_stop_after=case_matching")
                return

            # ── ROOT_CAUSE_ANALYSIS（FP + FN case 独立压缩 + 合并输出根因分析）──
            # FN 漏报原因分析（sink 精确命中 + 细分漏报成因）已在
            # CASE_MATCHING 阶段完成（fn_miss_results），此处直接复用，
            # 不重复调 LLM。
            _check_cancel(evaluation_id, stages.ROOT_CAUSE_ANALYSIS)
            assert_transition(stages.CASE_MATCHING, stages.ROOT_CAUSE_ANALYSIS)
            self._set_status_safe(evaluation_id, stages.ROOT_CAUSE_ANALYSIS)
            fp_cases = [r for r in case_session_matches if r["outcome"] == "FP"]
            fn_cases = [r for r in case_session_matches if r["outcome"] == "FN"]

            # 补充人工标注误报原因到 fp_cases/fn_cases，供根因分析使用
            for fc in fp_cases + fn_cases:
                cd = case_details.get(fc.get("case_id", ""), {})
                fc["human_confirmation_summary"] = cd.get(
                    "human_confirmation_summary", "")
                fc["summary"] = cd.get("summary", "")
            # FN 漏报原因分析结果按 case_id 附加到对应 case 上
            fn_miss_by_case: dict[str, dict] = {
                r["case_id"]: r for r in fn_miss_results
            }
            for fc in fn_cases:
                fc["fn_miss"] = fn_miss_by_case.get(fc.get("case_id", ""))

            # LLM 未匹配的 VULNERABLE 基线（agent 实际未上报的真漏洞）——
            # 不在 case_session_matches 里（sink 文件扫描使其判为 TP），
            # 但作为评测漏报必须进入根因分析。从 fn_miss_results 构建
            # 根因分析 case：outcome=FN，session 用精确命中的 session，
            # fn_miss 字段带 sink 漏报原因分析结果。
            existing_fn_ids = {fc.get("case_id", "") for fc in fn_cases}
            for r in fn_miss_results:
                cid = r.get("case_id", "")
                if cid in existing_fn_ids:
                    continue
                # 漏报原因分析的精确命中 session（函数/行号级）作为根因分析链
                all_precise_sids: list[str] = []
                for at, sids in (r.get("precise_sessions", {}) or {}).items():
                    for sid in sids:
                        if sid not in all_precise_sids:
                            all_precise_sids.append(sid)
                fn_cases.append({
                    "case_id": cid,
                    "ac_case_id": "",
                    "vuln_title": r.get("vuln_title", ""),
                    "summary": r.get("summary", ""),
                    "description": r.get("description", ""),
                    "expected_label": "VULNERABLE",
                    "mining_sessions": all_precise_sids,
                    "verify_sessions": [],
                    "outcome": "FN",
                    "match_method": "unmatched",
                    "match_detail": "LLM 未匹配原始数据，按漏报进入根因分析",
                    "fn_miss": r,
                })
                existing_fn_ids.add(cid)

            root_cause_cases = fp_cases + fn_cases
            if root_cause_cases or fn_miss_results:
                _set_progress(evaluation_id,
                              f"根因分析中... {len(fp_cases)} FP + "
                              f"{len(fn_cases)} FN case"
                              + (f" + {len(fn_miss_results)} 漏报原因分析"
                                 if fn_miss_results else ""))
                from ..lifecycle.root_cause_analyzer import RootCauseAnalyzer
                rca = RootCauseAnalyzer()
                # 从 manifest 取 project_id（知识库主动验证用）
                project_ids = [
                    e.get("project_id") for e in entries
                    if e.get("project_id")
                ]
                root_cause_project_id = project_ids[0] if project_ids else ""
                root_cause_results = rca.analyze(
                    evaluation_id, root_cause_cases, data_packs,
                    cancel_cb=_cancel_cb,
                    project_id=root_cause_project_id,
                )

                # debug dump：ROOT_CAUSE 中间数据（含 FN 漏报原因分析）
                self._dump_debug(reports_dir, evaluation_id, "root_cause", {
                    "total_fp": len(fp_cases),
                    "total_fn": len(fn_cases),
                    "analyzed": len(root_cause_results),
                    "fn_miss_analysis": {
                        "total": len(fn_miss_results),
                        "sink_found": sum(1 for r in fn_miss_results
                                          if r.get("sink_found")),
                        "sink_not_found": sum(1 for r in fn_miss_results
                                              if not r.get("sink_found")),
                        "results": fn_miss_results,
                    } if fn_miss_results else None,
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
                log("ORCH", "无 FP/FN case，跳过根因分析")

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

            # ── 因果链分析 + 问题单生成（从根因分析结果构建）──
            _set_progress(evaluation_id, "因果链分析 + 问题单生成...")
            # 从 manifest 取原始数据 task_id，写入问题单供按任务查询
            _task_id = cfg.get("manifest", {}).get("kg_task_id", "")
            causal_chain = self._run_causal_chain(
                root_cause_results, evaluation_id, reports_dir,
                task_id=_task_id,
            )
            log("ORCH", f"因果链分析 done: "
                  f"{len(causal_chain.get('per_case_breakpoints', []))} "
                  f"cases with breakpoints")

            # debug dump：因果链分析结果
            self._dump_debug(reports_dir, evaluation_id, "resolving", {
                "causal_chain": causal_chain,
            })

            # ── REPORTING ──
            _check_cancel(evaluation_id, stages.REPORTING)
            assert_transition(stages.RESOLVING, stages.REPORTING)
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
                    benchmark_source, case_session_matches,
                )
                _set_progress(evaluation_id, "报告组装...")
                self._assemble_report(
                    evaluation_id,
                    root_cause_results, causal_chain,
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

        采集策略：
        - 运行态（prod）：原始数据与基线同项目，一次请求拉全量，
          基线从原始数据中按 engine_confirmed_vulnerable=True 提取。
        - 开发态（dev）：原始数据与基线不同项目，分别请求。
          原始数据拉全量，基线用 final_result=vulnerable 拉引擎判定为漏洞的 case。
        """
        manifest = cfg.get("manifest", {})
        entries = manifest.get("entries", [])
        kg_project_id = manifest.get("kg_project_id", "")
        kg_task_id = manifest.get("kg_task_id", "")
        bm_source = manifest.get("benchmark_source", "vbench_zip")
        benchmark_set_id = manifest.get("benchmark_set_id", "BS001")
        vc_source_task_id = manifest.get("vc_source_task_id")
        eval_mode = manifest.get("eval_mode", "dev")

        case_details: dict[str, dict] = {}
        alert_center_data: dict = {}
        case_matches: list[dict] = []

        # ── 获取原始数据：从告警中心取挖掘 agent 上报的全部 case ──
        if kg_project_id and kg_task_id:
            try:
                from ...infrastructure.vuln_center_client import (
                    get_alert_center_summary,
                )
                ac_summary = with_eval_ctx(self._fetch_ac)(
                    (kg_project_id, kg_task_id),
                )
                all_cases = ac_summary.get("cases", [])
                merged_counts = ac_summary.get("counts", {})

                alert_center_data = {
                    "source_task_ids": [kg_task_id],
                    "project_ids": [kg_project_id],
                    "total": len(all_cases),
                    "counts": merged_counts,
                    "cases": all_cases,
                }
                log("INGEST", f"原始数据(告警中心): {len(all_cases)} 条 case "
                      f"(是漏洞={merged_counts.get('vulnerable', 0)} "
                      f"不是漏洞={merged_counts.get('not_vulnerable', 0)})")
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

            # 判断运行态：原始数据与基线同项目 → 从原始数据提取基线
            raw_project_ids = set(alert_center_data.get("project_ids", []))
            same_project = benchmark_set_id in raw_project_ids

            if same_project and alert_center_data.get("cases"):
                # 运行态：基线从原始数据中提取（engine_confirmed_vulnerable=True）
                baseline_cases = [
                    c for c in alert_center_data.get("cases", [])
                    if c.get("engine_confirmed_vulnerable") is True
                ]
                log("INGEST", f"基线数据(运行态从原始数据提取): "
                      f"{len(baseline_cases)} 条 engine_confirmed_vulnerable=True")
            else:
                # 开发态：基线不同项目，单独请求
                log("INGEST", f"基线数据(告警中心): project={benchmark_set_id} "
                      f"task={vc_source_task_id or '(未指定)'}")
                baseline_summary = get_alert_center_summary(
                    benchmark_set_id, vc_source_task_id,
                    final_result="vulnerable",
                )
                baseline_cases = baseline_summary.get("cases", [])
                log("INGEST", f"基线告警中心返回 {len(baseline_cases)} 条 case")

            from ...infrastructure.vuln_center_client import get_case_raw_report
            for c in baseline_cases:
                if c.get("current_stage") != "finished":
                    continue
                vr = c.get("validation_result")
                if vr not in ("vulnerable", "not_vulnerable"):
                    continue
                # 排除 non_fp：人工判定不是漏洞但理由不属于误报分类，不参与分析
                if c.get("false_positive_group") == "non_fp":
                    continue
                expected_label = "VULNERABLE" if vr == "vulnerable" else "NON_VULNERABLE"
                bm = _case_to_benchmark(c, expected_label)
                cid = bm.get("case_id") or ""
                if cid:
                    case_details[cid] = {
                        "description": get_case_raw_report(cid) or bm.get("description") or "",
                        "summary": c.get("summary") or "",
                        "vuln_title": bm.get("vuln_title") or "",
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
                     or c.get("vuln_title", "") or "")
                    case_details[cid] = {
                        "description": desc,
                        "vuln_title": c.get("vuln_title")
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
                # 原始数据 case 归一化：和基线走同一个 _case_to_benchmark 路径，
                # 产出 title/description/vuln_title/source_file/locator 等同构字段。
                # 修复：之前直接用 alert_center_data["cases"] 原始 42 字段结构，
                # 没有 description 字段（API 返回 summary），LLM 只看到 91 字符 title，
                # 与基线 5730 字符 description 严重不对称，导致匹配率低。
                from ...infrastructure.vuln_center_client import _case_to_benchmark
                raw_cases_for_match = [
                    _case_to_benchmark(c, expected_label="")
                    for c in alert_center_data.get("cases", [])
                ]
                # 基线与原始数据取相同字段（基线来源为漏洞中心时）。
                # case_details 的 description 是 get_case_raw_report 增强版（4207字符），
                # 但两边字段必须对称，基线也用 _case_to_benchmark 的 description
                # （_normalize_case_description 拼的 title+summary+display_summary，约1400字符）。
                # raw_report 在下游根因分析等环节仍可用，匹配阶段用 summary 级别足够。
                if bm_source == "vuln_center":
                    # 基线 case 用与 case_details 相同的过滤条件
                    # （current_stage=finished + validation_result + 排除 non_fp）
                    baseline_cases_for_match = [
                        _case_to_benchmark(c, expected_label="")
                        for c in baseline_cases
                        if c.get("current_stage") == "finished"
                        and c.get("validation_result") in (
                            "vulnerable", "not_vulnerable")
                        and c.get("false_positive_group") != "non_fp"
                    ]
                else:
                    baseline_cases_for_match = [
                        {
                            "case_id": cid,
                            "title": detail.get("vuln_title") or "",
                            "description": detail.get("description") or "",
                            "vuln_title": detail.get(
                                "vuln_title") or "",
                            "source_file": detail.get("source_file") or "",
                            "locator": detail.get("locator") or "",
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
                # 补充漏洞状态字段（debug 展示用）：
                # - raw_validation_result: 告警中心漏洞状态（vulnerable/not_vulnerable）
                # - baseline_expected_label: 基线漏洞状态（VULNERABLE/NON_VULNERABLE）
                raw_status_map: dict[str, str] = {}
                for c in alert_center_data.get("cases", []):
                    cid = str(c.get("case_id") or c.get("id") or "")
                    vr = c.get("validation_result", "")
                    if cid and vr:
                        raw_status_map[cid] = vr
                baseline_status_map: dict[str, str] = {
                    cid: detail.get("expected_label", "")
                    for cid, detail in case_details.items()
                }
                for m in case_matches:
                    rid = str(m.get("raw_case_id", ""))
                    m["raw_validation_result"] = raw_status_map.get(rid, "")
                    bid = m.get("matched_baseline_case_id", "") or ""
                    m["baseline_expected_label"] = (
                        baseline_status_map.get(bid, "")
                        if bid else "")
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
        kg_project_id = manifest.get("kg_project_id", "")
        kg_task_id = manifest.get("kg_task_id", "")
        bm_source = manifest.get("benchmark_source", "vbench_zip")
        vc_source_task_id = manifest.get("vc_source_task_id")

        case_details: dict[str, dict] = {}
        alert_center_data: dict = {}

        # ── 获取原始数据：从告警中心取挖掘 agent 上报的全部 case ──
        if kg_project_id and kg_task_id:
            try:
                from ...infrastructure.vuln_center_client import (
                    get_alert_center_summary,
                )
                ac_summary = with_eval_ctx(self._fetch_ac)(
                    (kg_project_id, kg_task_id),
                )
                all_cases = ac_summary.get("cases", [])
                merged_counts = ac_summary.get("counts", {})

                alert_center_data = {
                    "source_task_ids": [kg_task_id],
                    "project_ids": [kg_project_id],
                    "total": len(all_cases),
                    "counts": merged_counts,
                    "cases": all_cases,
                }
                log("INGEST", f"原始数据(告警中心): {len(all_cases)} 条 case "
                      f"(是漏洞={merged_counts.get('vulnerable', 0)} "
                      f"不是漏洞={merged_counts.get('not_vulnerable', 0)})")
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

            # 判断运行态：原始数据与基线同项目 → 从原始数据提取基线
            raw_project_ids = set(alert_center_data.get("project_ids", []))
            same_project = benchmark_set_id in raw_project_ids

            if same_project and alert_center_data.get("cases"):
                # 运行态：基线从原始数据中提取（engine_confirmed_vulnerable=True）
                baseline_cases = [
                    c for c in alert_center_data.get("cases", [])
                    if c.get("engine_confirmed_vulnerable") is True
                ]
                log("INGEST", f"基线数据(运行态从原始数据提取): "
                      f"{len(baseline_cases)} 条 engine_confirmed_vulnerable=True")
            else:
                # 开发态：基线不同项目，单独请求
                log("INGEST", f"基线数据(告警中心): project={benchmark_set_id} "
                      f"task={vc_source_task_id or '(未指定)'}")
                baseline_summary = get_alert_center_summary(
                    benchmark_set_id, vc_source_task_id,
                    final_result="vulnerable",
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
                # 排除 non_fp：人工判定不是漏洞但理由不属于误报分类，不参与分析
                if c.get("false_positive_group") == "non_fp":
                    continue
                expected_label = "VULNERABLE" if vr == "vulnerable" else "NON_VULNERABLE"
                bm = _case_to_benchmark(c, expected_label)
                cid = bm.get("case_id") or ""
                if cid:
                    from ...infrastructure.vuln_center_client import get_case_raw_report
                    case_details[cid] = {
                        "description": get_case_raw_report(cid) or bm.get("description") or "",
                        "summary": c.get("summary") or "",
                        "vuln_title": bm.get("vuln_title") or "",
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
                     or c.get("vuln_title", "") or "")
                    case_details[cid] = {
                        "description": desc,
                        "vuln_title": c.get("vuln_title")
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
                "original_source_uri": src_uri,
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
        original_source_uri = task.get("original_source_uri", source_uri)

        if cancel_cb:
            cancel_cb()

        parser = get_parser(trace_kind, source_uri)
        log("PARSE", f"[{tr.task_run_id}] parser={parser.__class__.__name__} "
              f"source={source_uri}")

        # TaskRun 的 benchmark_item 只取第一个，build_data_pack 内部用
        if bench:
            tr.benchmark_item_id = bench[0].benchmark_item_id

        # 构造 trace_source dict（所有 parser 的 parse()/load_session() 都期望 dict）
        # original_source_uri 保留原始 /data/files/{pid}/tasks/{tid}/ 路径，
        # 供 argo parser 解析原始数据 project_id/task_id（本地拷贝路径格式不同）
        trace_source = {
            "source_uri": source_uri,
            "original_source_uri": original_source_uri,
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

    # ── L0-L7 全链路分析 ─────────────────────────────

    # ── 因果链分析 + 问题单生成 ─────────────────────

    def _run_causal_chain(
        self, root_cause_results: list[dict],
        evaluation_id: str = "", reports_dir: str = "",
        task_id: str = "",
    ) -> dict:
        """因果链分析 + 问题单生成。

        调用 CausalChainAnalyzer.analyze()，基于根因分析结果的
        l0_l7_breakpoints 按 Agent 类型聚合误报归因。
        分析完成后，从 per_case_breakpoints 自动生成问题单并持久化。
        """
        from ..causal_chain.analyzer import CausalChainAnalyzer

        analyzer = CausalChainAnalyzer()
        result = analyzer.analyze(evaluation_id, root_cause_results)

        # 从断点生成问题单
        from ..dts.issue import generate_dts_issues
        from ..persistence.dts_repo import upsert_dts_issues

        dts_issues = generate_dts_issues(
            evaluation_id, result, root_cause_results,
            task_id=task_id,
            reports_dir=reports_dir,
        )
        if dts_issues:
            upsert_dts_issues(dts_issues, evaluation_id, reports_dir)
            log("DTS", f"Generated {len(dts_issues)} issues")

        return result

    def _calc_recall_precision(
        self, evaluation_id: str, case_details: dict,
        alert_center_data: dict, benchmark_source: str,
        case_session_matches: list[dict] = None,
    ) -> dict:
        """计算召回率和准确率。

        从基线 case_details 和告警中心数据计算：
        - 召回率 = TP / (TP + FN)
        - 准确率 = TP / (TP + FP)
        - 误报率 = FP / (TP + FP)（Agent 上报总数中误报占比）

        TP = 基线 VULNERABLE + 告警中心有匹配（agent 上报了）
        FN = 基线 VULNERABLE + 告警中心无匹配（agent 漏报）
        FP = 基线 NON_VULNERABLE + trace 有 finding 且 CONFIRMED（agent 误报）
        TN = 基线 NON_VULNERABLE + 无匹配 finding 或 finding 非 CONFIRMED

        TP/FN 从告警中心数据与基线对比获取。
        FP/TN 从 case_session_matches 获取（case_session_matcher 已计算）。
        """
        # TP/FN/FP/TN: 从 case_session_matches 获取（case_session_matcher 已判定）
        tp_count = sum(1 for r in case_session_matches if r.get("outcome") == "TP")
        fn_count = sum(1 for r in case_session_matches if r.get("outcome") == "FN")
        fp_count = sum(1 for r in case_session_matches if r.get("outcome") == "FP")
        tn_count = sum(1 for r in case_session_matches if r.get("outcome") == "TN")

        # 召回率 = TP / (TP + FN)
        recall_denom = tp_count + fn_count
        recall_rate = (tp_count / recall_denom) if recall_denom > 0 else None

        # 准确率 = TP / (TP + FP)
        precision_denom = tp_count + fp_count
        precision_rate = (tp_count / precision_denom) if precision_denom > 0 else None

        # 误报率 = FP / (TP + FP)（Agent 上报总数中误报占比）
        # 原公式 FP/(FP+TN) 依赖基线 NON_VULNERABLE 样本量，样本少且全命中时
        # TN=0 导致误报率虚高到 100%；C 口径只依赖 agent 上报行为，更稳健。
        fpr_denom = tp_count + fp_count
        fpr_rate = (fp_count / fpr_denom) if fpr_denom > 0 else None

        result = {
            "recall_rate": round(recall_rate, 4) if recall_rate is not None else None,
            "precision_rate": round(precision_rate, 4) if precision_rate is not None else None,
            "fpr_rate": round(fpr_rate, 4) if fpr_rate is not None else None,
            "tp_count": tp_count,
            "fn_count": fn_count,
            "fp_count": fp_count,
            "tn_count": tn_count,
        }
        log("REPORT", f"召回率={result['recall_rate']}, "
              f"准确率={result['precision_rate']}, "
              f"误报率={result['fpr_rate']}, "
              f"TP={tp_count}, FN={fn_count}, FP={fp_count}, TN={tn_count}")
        return result

    # ── REPORTING ────────────────────────────────────

    def _assemble_report(
        self, evaluation_id: str,
        root_cause_results: list, causal_chain: dict,
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
            root_cause_results,
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
                "fpr_rate": recall_precision.get("fpr_rate"),
                "tp_count": recall_precision.get("tp_count", 0),
                "fn_count": recall_precision.get("fn_count", 0),
                "fp_count": recall_precision.get("fp_count", 0),
                "tn_count": recall_precision.get("tn_count", 0),
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
        for sid, info in sessions.items():
            info_d = info if isinstance(info, dict) else {}
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
            "sessions": session_list,
            "edges": edge_list,
            "fact_deps": sg.get("fact_deps", []),  # 多对多 fact 依赖（investigate→fact→verify），turing 为空
            "vuln_id_to_sessions": {
                str(k): sorted(list(v)) if isinstance(v, (set, list)) else list(v)
                for k, v in (sg.get("vuln_id_to_sessions", {}) or {}).items()
            },
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
                    "'RESOLVING',"
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
