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

import json
import os
from concurrent.futures import ThreadPoolExecutor

from ..infra.concurrency import get as _conc_get
from ..infra.parallel import iter_completed
from ..infra.log_util import (
    log, set_eval_ctx, clear_eval_ctx, with_eval_ctx, log_error,
)
from .state_machine import assert_transition
from . import stages
from ..core.agents import MINING_AGENT_SET
from .status_manager import (
    TaskCancelledError, _is_cancelled, _check_cancel, _make_cancel_cb,
    _set_failed, _set_status_safe,
)
from .debug_dumper import (
    clear_debug_files as _clear_debug_files,
    dump_debug as _dump_debug,
    calc_agent_outcomes as _calc_agent_outcomes,
    summarize_data_pack as _summarize_data_pack,
)

# ── 报告目录 ──────────────────────────────────────────


from ..infra.json_utils import json_default as _json_default, json_dump as _json_dump, json_dumps as _json_dumps
from ..infra import pipeline_warnings as _pw


def _get_reports_dir() -> str:
    """获取报告输出目录（统一从 config_loader 读取）。"""
    from ...config_loader import get_reports_dir
    return get_reports_dir()


def _mining_agent_type(data_packs: list) -> str:
    """推导该评测实际运行的挖掘 agent 类型。

    sink_not_found 漏报 case 的 mining_sessions 为空（trace 无精确命中），
    root_cause_analyzer 无法从 session 反查 agent_type。此处从 data_packs
    的 agent_type 推导唯一的挖掘 agent 类型，供漏报断点归因兜底。
    多个挖掘 agent 并存时（少见）返回空，交由下游保持现状。
    """
    mining_types: set[str] = set()
    for dp in (data_packs or []):
        at = getattr(dp, "agent_type", "") or ""
        if at and at in MINING_AGENT_SET:
            mining_types.add(at)
    if len(mining_types) == 1:
        return next(iter(mining_types))
    return ""


# ── DB 短连接 + 重试 ──────────────────────────────────

from ..infra.db_utils import db_query as _db_query


# ── 进度追踪（内存，pod 重启后重跑不需要持久化）──

from ..infra.progress import set_progress as _set_progress
from ..infra.progress import get_progress as _get_progress
from ..infra.progress import clear_progress as _clear_progress


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
        _clear_debug_files(reports_dir, evaluation_id)
        _pw.reset(evaluation_id)
        _cancel_cb = cancel_cb or _make_cancel_cb(evaluation_id, "ORCHESTRATOR")

        log("ORCH", f"启动 v2 pipeline: evaluation_id={evaluation_id} "
              f"reports_dir={reports_dir}")

        try:
            # ── INGESTING + PARSING（并行启动） ──
            cfg, entries, eval_mode, benchmark_source, \
                benchmark_items, case_details, alert_center_data, case_matches, \
                parse_pool, parse_future = self._stage_ingesting(
                    evaluation_id, reports_dir, _cancel_cb,
                )

            debug_stop = cfg.get("manifest", {}).get("debug_stop_after")
            if debug_stop == "ingesting":
                log("ORCH", "DEBUG 断点：停在 INGESTING 之后")
                parse_pool.shutdown(wait=False)
                _set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
                _set_progress(evaluation_id, "调试断点：INGESTING 完成")
                _set_failed(evaluation_id, "调试断点：debug_stop_after=ingesting")
                return

            # ── PARSING（join + post-process） ──
            data_packs = self._stage_parsing_join(
                evaluation_id, reports_dir, parse_pool, parse_future,
                benchmark_items, case_details, cfg,
            )

            # ── CASE_MATCHING ──
            case_session_matches, fn_miss_results = self._stage_case_matching(
                evaluation_id, reports_dir, _cancel_cb,
                data_packs, case_details, case_matches,
                alert_center_data, eval_mode, cfg,
            )
            if cfg.get("manifest", {}).get("debug_stop_after") == "case_matching":
                return

            # ── ROOT_CAUSE_ANALYSIS ──
            root_cause_results = self._stage_root_cause(
                evaluation_id, reports_dir, _cancel_cb,
                case_session_matches, fn_miss_results,
                case_details, data_packs, entries, cfg,
            )
            if cfg.get("manifest", {}).get("debug_stop_after") == "root_cause":
                return

            # ── RESOLVING ──
            _check_cancel(evaluation_id, stages.RESOLVING)
            assert_transition(stages.ROOT_CAUSE_ANALYSIS, stages.RESOLVING)
            _set_status_safe(evaluation_id, stages.RESOLVING)
            _set_progress(evaluation_id, "持久化解析结果...")
            self._persist_data(evaluation_id, data_packs)

            _set_progress(evaluation_id, "因果链分析 + 问题单生成...")
            _task_id = cfg.get("manifest", {}).get("kg_task_id", "")
            causal_chain = self._run_causal_chain(
                root_cause_results, evaluation_id, reports_dir,
                task_id=_task_id,
            )
            log("ORCH", f"因果链分析 done: "
                  f"{len(causal_chain.get('per_case_breakpoints', []))} "
                  f"cases with breakpoints")
            _dump_debug(reports_dir, evaluation_id, "resolving", {
                "causal_chain": causal_chain,
            })

            # ── REPORTING ──
            _check_cancel(evaluation_id, stages.REPORTING)
            assert_transition(stages.RESOLVING, stages.REPORTING)
            _set_status_safe(evaluation_id, stages.REPORTING)

            # 分析对象告警：无 FP/FN、全部 case 匹配不到 session 等。
            # 「跑完了但没有任何可分析对象」必须显式提示，不能与正常空报告混同。
            case_outcome_summary = self._build_case_outcome_summary(
                case_session_matches, eval_mode)
            self._add_analysis_warnings(evaluation_id, case_outcome_summary)

            # 收集 pipeline 执行中的数据质量告警（drain 清空，后续 has_warnings 用本地变量）
            data_quality_warnings = _pw.drain(evaluation_id)

            recall_precision = None
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
                    eval_mode=eval_mode,
                )
                _set_progress(evaluation_id, "报告组装...")
                self._assemble_report(
                    evaluation_id,
                    root_cause_results, causal_chain,
                    recall_precision, reports_dir,
                    data_quality_warnings=data_quality_warnings,
                    case_outcome_summary=case_outcome_summary,
                    case_session_matches=case_session_matches,
                    eval_mode=eval_mode,
                )
                log("ORCH", f"REPORTING done: recall={recall_precision.get('recall_rate')}, "
                      f"precision={recall_precision.get('precision_rate')}")

            # ── FINALIZE ──
            _check_cancel(evaluation_id, stages.FINALIZE)
            assert_transition(stages.REPORTING, "FINALIZING")
            _set_status_safe(evaluation_id, "FINALIZING")
            _set_progress(evaluation_id, "完成...")
            self._finalize(
                evaluation_id, reports_dir, causal_chain,
                recall_precision=recall_precision,
                eval_mode=eval_mode,
                agent_outcomes=_calc_agent_outcomes(
                    case_session_matches, data_packs),
            )
            # 有数据质量告警时标记为 COMPLETED_WITH_WARNINGS
            if data_quality_warnings:
                _set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
                _set_progress(evaluation_id, "评测完成（含数据质量告警）")
                log("ORCH", f"v2 pipeline 完成（含 {len(data_quality_warnings)} 条告警）: {evaluation_id}")
            else:
                _set_status_safe(evaluation_id, "COMPLETED")
                _set_progress(evaluation_id, "评测完成")
                log("ORCH", f"v2 pipeline 完成: {evaluation_id}")

        except TaskCancelledError as e:
            log("ORCH", f"评测被取消: {e}")
            _set_status_safe(evaluation_id, "CANCELLED")
            raise
        except Exception as e:
            log_error(evaluation_id, "ORCH", e)
            _set_failed(evaluation_id, str(e))
            raise
        finally:
            clear_eval_ctx()
            _clear_progress(evaluation_id)

    # ── 阶段方法 ───────────────────────────────────────

    def _stage_ingesting(
        self, evaluation_id: str, reports_dir: str, _cancel_cb,
    ):
        """INGESTING：读 config + 并行启动 trace 解析 + 数据采集。

        PARSING 线程在此阶段启动（与数据采集并行），但 join 在调用方执行。
        返回 (cfg, entries, eval_mode, benchmark_source,
              benchmark_items, case_details, alert_center_data, case_matches,
              parse_pool, parse_future)。
        """
        assert_transition("VALIDATING", stages.INGESTING)
        _set_status_safe(evaluation_id, "VALIDATING")
        _set_status_safe(evaluation_id, stages.INGESTING)

        cfg = self._read_config(evaluation_id)
        entries = cfg.get("manifest", {}).get("entries", [])
        eval_mode = cfg.get("manifest", {}).get("eval_mode", "dev")
        benchmark_source = cfg.get("manifest", {}).get(
            "benchmark_source", "vbench_zip")
        log("ORCH", f"INGESTING: {len(entries)} entries, eval_mode={eval_mode}, "
              f"benchmark_source={benchmark_source}")

        _set_progress(evaluation_id, "并行：trace 解析 + 数据采集...")

        # PARSING 线程（与数据采集并行启动）
        _check_cancel(evaluation_id, stages.PARSING)
        assert_transition(stages.INGESTING, stages.PARSING)
        _set_status_safe(evaluation_id, stages.PARSING)

        parse_pool = ThreadPoolExecutor(max_workers=1)
        parse_future = parse_pool.submit(
            with_eval_ctx(self._parse_traces),
            evaluation_id, entries, [], {}, cfg,
            cancel_cb=_cancel_cb,
        )

        # 数据采集线程
        def _collect_data():
            return with_eval_ctx(self._collect_baseline_and_raw)(
                evaluation_id, cfg,
            )
        data_pool = ThreadPoolExecutor(max_workers=1)
        data_future = data_pool.submit(_collect_data)

        try:
            benchmark_items, case_details, alert_center_data, case_matches = \
                data_future.result()
        finally:
            data_pool.shutdown(wait=False)
        log("ORCH", f"数据采集 done: {len(benchmark_items)} benchmark_items, "
              f"{len(case_details)} case_details")

        _dump_debug(reports_dir, evaluation_id, "ingesting", {
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
                    {"case_id": cid, **detail}
                    for cid, detail in case_details.items()
                ],
            },
            "case_matches": case_matches,
        })

        return (cfg, entries, eval_mode, benchmark_source,
                benchmark_items, case_details, alert_center_data, case_matches,
                parse_pool, parse_future)

    def _stage_parsing_join(
        self, evaluation_id: str, reports_dir: str,
        parse_pool, parse_future,
        benchmark_items: list, case_details: dict, cfg: dict,
    ) -> list:
        """PARSING：等待解析完成 + 附加 benchmark_items + debug dump。"""
        try:
            data_packs = parse_future.result()
        finally:
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

        _dump_debug(reports_dir, evaluation_id, "parsing", {
            "data_packs": [_summarize_data_pack(dp) for dp in data_packs],
        })
        return data_packs

    def _stage_case_matching(
        self, evaluation_id: str, reports_dir: str, _cancel_cb,
        data_packs: list, case_details: dict, case_matches: list,
        alert_center_data: dict, eval_mode: str, cfg: dict,
    ):
        """CASE_MATCHING：基线 case ↔ trace session 精确匹配 + FN 漏报分析。

        返回 (case_session_matches, fn_miss_results)。
        """
        _check_cancel(evaluation_id, stages.CASE_MATCHING)
        assert_transition(stages.PARSING, stages.CASE_MATCHING)
        _set_status_safe(evaluation_id, stages.CASE_MATCHING)
        _set_progress(evaluation_id, "case-session 匹配...")
        from ..lifecycle.case_session_matcher import CaseSessionMatcher
        matcher = CaseSessionMatcher()
        case_session_matches = matcher.match(
            evaluation_id, data_packs, case_details,
            case_matches=case_matches,
            eval_mode=eval_mode,
            alert_center_data=alert_center_data,
        )

        fp_fn_matches = [r for r in case_session_matches
                         if r["outcome"] in ("FP", "FN")]

        # FN 漏报匹配结果（开发态）
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
                    "agent_type": _mining_agent_type(data_packs),
                    "outcome": "FN",
                    "match_method": "unmatched" if not mining_sessions
                    else "matched",
                    "match_detail": (
                        f"{len(mining_sessions)} 个 session 精确命中 sink 点"
                        f"（函数/行号级），LLM 未匹配原始数据，漏报"
                        if mining_sessions else
                        "LLM 未匹配原始数据且 trace 未精确命中 sink 点，漏报"),
                })

        # debug dump
        fn_match_cases = fp_fn_matches + fn_miss_match_cases
        _outcome_counts = {
            o: sum(1 for r in case_session_matches
                   if r.get("outcome") == o)
            for o in ("TP", "TN", "FP", "FN")
        }
        _unmatched_cases = [
            {
                "case_id": r.get("case_id", ""),
                "ac_case_id": r.get("ac_case_id", ""),
                "vuln_title": (r.get("vuln_title") or "")[:120],
                "expected_label": r.get("expected_label", ""),
            }
            for r in case_session_matches
            if r.get("match_method") == "unmatched"
        ]
        case_matching_debug: dict = {
            "eval_mode": eval_mode,
            "baseline_total": len(case_details),
            "outcome_counts": _outcome_counts,
            "unmatched_cases": _unmatched_cases,
            "total_cases": len(fn_match_cases),
            "matched": sum(1 for r in fn_match_cases
                           if r["match_method"] != "unmatched"),
            "unmatched": sum(1 for r in fn_match_cases
                             if r["match_method"] == "unmatched"),
            "outcomes": {
                "FP": sum(1 for r in fn_match_cases if r["outcome"] == "FP"),
                "FN": sum(1 for r in fn_match_cases if r["outcome"] == "FN"),
            },
            "agent_outcomes": _calc_agent_outcomes(
                case_session_matches, data_packs),
            "matches": fn_match_cases,
        }
        _dump_debug(reports_dir, evaluation_id, "case_matching",
                         case_matching_debug)

        if cfg.get("manifest", {}).get("debug_stop_after") == "case_matching":
            log("ORCH", "DEBUG 断点：停在 CASE_MATCHING 之后")
            _set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
            _set_progress(evaluation_id, "调试断点：CASE_MATCHING 完成")
            _set_failed(evaluation_id, "调试断点：debug_stop_after=case_matching")

        return case_session_matches, fn_miss_results

    def _stage_root_cause(
        self, evaluation_id: str, reports_dir: str, _cancel_cb,
        case_session_matches: list, fn_miss_results: list,
        case_details: dict, data_packs: list, entries: list, cfg: dict,
    ) -> list:
        """ROOT_CAUSE_ANALYSIS：FP + FN case 根因分析。

        返回 root_cause_results。
        """
        _check_cancel(evaluation_id, stages.ROOT_CAUSE_ANALYSIS)
        assert_transition(stages.CASE_MATCHING, stages.ROOT_CAUSE_ANALYSIS)
        _set_status_safe(evaluation_id, stages.ROOT_CAUSE_ANALYSIS)
        fp_cases = [r for r in case_session_matches if r["outcome"] == "FP"]
        # 运行态只分析误报：运行态基线是已确认漏洞（不存在"未被上报的基线漏洞"），
        # 因此不产生漏报分析；FN 仅来自开发态基线集。
        eval_mode = ((cfg.get("manifest") or {}).get("eval_mode", "dev")
                     if isinstance(cfg, dict) else "dev")
        fn_cases = ([r for r in case_session_matches if r["outcome"] == "FN"]
                    if eval_mode == "dev" else [])

        # 补充人工标注误报原因
        for fc in fp_cases + fn_cases:
            cd = case_details.get(fc.get("case_id", ""), {})
            fc["human_confirmation_summary"] = cd.get(
                "human_confirmation_summary", "")
            fc["summary"] = cd.get("summary", "")
        # FN 漏报原因分析结果按 case_id 附加
        fn_miss_by_case: dict[str, dict] = {
            r["case_id"]: r for r in fn_miss_results
        }
        for fc in fn_cases:
            fc["fn_miss"] = fn_miss_by_case.get(fc.get("case_id", ""))

        # LLM 未匹配的 VULNERABLE 基线作为漏报进入根因分析
        existing_fn_ids = {fc.get("case_id", "") for fc in fn_cases}
        for r in fn_miss_results:
            cid = r.get("case_id", "")
            if cid in existing_fn_ids:
                continue
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
                "agent_type": _mining_agent_type(data_packs),
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

            _dump_debug(reports_dir, evaluation_id, "root_cause", {
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

            if cfg.get("manifest", {}).get("debug_stop_after") == "root_cause":
                log("ORCH", "DEBUG 断点：停在 ROOT_CAUSE 之后")
                _set_status_safe(evaluation_id, "COMPLETED_WITH_WARNINGS")
                _set_progress(evaluation_id, "调试断点：ROOT_CAUSE 完成")
                _set_failed(evaluation_id, "调试断点：debug_stop_after=root_cause")
        else:
            root_cause_results = []
            log("ORCH", "无 FP/FN case，跳过根因分析")

        # 清理 /tmp trace 缓存
        try:
            from ..infra.trace_cache import cleanup_trace_cache
            cleanup_trace_cache(evaluation_id)
        except Exception:
            pass

        return root_cause_results

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
          基线从原始数据中按**人工确认结论**（validation_result）提取。
          不能用 engine_confirmed_vulnerable：未经过引擎研判的 case 该字段
          恒为 False，会把人工确认的 confirmed_fp 一起过滤掉，导致基线为空。
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
                from ..infra.vuln_center_client import (
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
            from ..infra.vuln_center_client import (
                _case_to_benchmark, get_alert_center_summary,
            )

            # 判断运行态：原始数据与基线同项目 → 从原始数据提取基线
            raw_project_ids = set(alert_center_data.get("project_ids", []))
            same_project = benchmark_set_id in raw_project_ids

            runtime_baseline = bool(
                same_project and alert_center_data.get("cases"))
            if runtime_baseline:
                # 运行态：基线从原始数据中提取，按人工确认结论（validation_result）
                # 筛选（下面循环统一过滤 finished / vulnerable|not_vulnerable / non_fp）。
                # 不能用 engine_confirmed_vulnerable：未经过引擎研判的 case 该字段
                # 恒为 False，会把人工确认的 confirmed_fp 一起过滤掉，导致基线为空。
                baseline_cases = list(alert_center_data.get("cases", []))
                log("INGEST", f"基线数据(运行态从原始数据提取): "
                      f"{len(baseline_cases)} 条（人工确认筛选前）")
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

            from ..infra.vuln_center_client import get_case_raw_report
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
                        "description": get_case_raw_report(cid, evaluation_id=evaluation_id) or bm.get("description") or "",
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
            if runtime_baseline:
                log("INGEST", f"运行态基线(人工确认 finished 且非 non_fp): "
                      f"{len(case_details)} 条")

        elif bm_source == "vbench_zip":
            from ..infra.vbench_client import get_benchmark
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
                from ..infra.vuln_center_client import _case_to_benchmark
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

    def _fetch_ac(self, pair: tuple[str, str]) -> dict:
        """获取单个项目的告警中心数据（用于线程池并行）。"""
        from ..infra.vuln_center_client import get_alert_center_summary
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
                    from ..infra.trace_cache import copy_trace_to_local
                    return copy_trace_to_local(
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
            parse_failures: list[str] = []
            for fut, _ in iter_completed(futures, cancel_cb=cancel_cb):
                i = futures[fut]
                task = tasks[i]
                try:
                    results[i] = fut.result()
                except TaskCancelledError:
                    raise
                except Exception as e:
                    # 单个 agent 的 trace 缺失/不可读不阻断整次评测：
                    # 跳过该 trace 并写入数据质量告警，其余 trace 继续解析。
                    src = (task.get("original_source_uri")
                           or task.get("source_uri") or "")
                    kind = task.get("trace_kind") or "trace"
                    msg = f"{kind} trace 解析失败，已跳过：{src}（{e}）"
                    log("PARSE", msg)
                    parse_failures.append(msg)
                    _pw.add(task["task_run"].evaluation_id, kind,
                            "trace_parse_skipped", "warning", msg)
                    results[i] = None
            # 全部 trace 都失败时也继续：报告会标记「未匹配到 trace session」，
            # 数据质量问题在 data_quality_warnings 中可见，不阻断评测。
            if results and all(r is None for r in results):
                all_fail_msg = ("所有 trace 解析失败，本次评测无任何可用 session："
                                + "；".join(parse_failures[:3]))
                log("PARSE", all_fail_msg, eval_id=evaluation_id)
                _pw.add(evaluation_id, "parse", "all_traces_failed",
                        "warning", all_fail_msg)
            for r in results:
                if r is not None:
                    data_packs.append(r)
                    if not getattr(r, "events", None):
                        _pw.add(evaluation_id,
                                getattr(r, "agent_type", "") or "trace",
                                "trace_empty", "warning",
                                f"{getattr(r, 'agent_type', '') or 'trace'} "
                                f"trace 未解析出任何事件")
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
        from ..persistence.fact_repo import (
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

        # 实际生成问题单的 case 集合：报告据此保证「每个 FP/FN 要么有单、
        # 要么说明原因」，不依赖对断点/线索的推断。
        result["dts_case_ids"] = [
            str(i.get("case_id")) for i in dts_issues if i.get("case_id")]

        return result

    def _calc_recall_precision(
        self, evaluation_id: str, case_details: dict,
        alert_center_data: dict, benchmark_source: str,
        case_session_matches: list[dict] = None,
        eval_mode: str = "dev",
    ) -> dict:
        """计算召回率和准确率。

        运行态（runtime）没有漏报基线：只统计误报相关指标，
        召回率 / 漏报率 / FN 一律为 None / 0。
        """
        runtime = str(eval_mode or "dev").lower() == "runtime"
        # TP/FN/FP/TN: 从 case_session_matches 获取（case_session_matcher 已判定）
        tp_count = sum(1 for r in case_session_matches if r.get("outcome") == "TP")
        fn_count = 0 if runtime else sum(
            1 for r in case_session_matches if r.get("outcome") == "FN")
        fp_count = sum(1 for r in case_session_matches if r.get("outcome") == "FP")
        tn_count = sum(1 for r in case_session_matches if r.get("outcome") == "TN")

        # 召回率 = TP / (TP + FN)；运行态不计算
        recall_denom = tp_count + fn_count
        recall_rate = (tp_count / recall_denom) if recall_denom > 0 else None
        fnr_rate = (fn_count / recall_denom) if recall_denom > 0 else None

        # 准确率 = TP / (TP + FP)
        precision_denom = tp_count + fp_count
        precision_rate = (tp_count / precision_denom) if precision_denom > 0 else None

        # 误报率 = FP / (TP + FP)（Agent 上报总数中误报占比）
        # 原公式 FP/(FP+TN) 依赖基线 NON_VULNERABLE 样本量，样本少且全命中时
        # TN=0 导致误报率虚高到 100%；C 口径只依赖 agent 上报行为，更稳健。
        fpr_denom = tp_count + fp_count
        fpr_rate = (fp_count / fpr_denom) if fpr_denom > 0 else None

        result = {
            "recall_rate": (round(recall_rate, 4)
                            if recall_rate is not None and not runtime else None),
            "fnr_rate": (round(fnr_rate, 4)
                         if fnr_rate is not None and not runtime else None),
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

    @staticmethod
    def _build_case_outcome_summary(matches: list[dict],
                                    eval_mode: str = "dev") -> dict:
        """汇总 case 匹配结果，供报告展示与告警判断。

        运行态没有漏报基线：FN 不参与统计，避免报告出现运行态漏报。
        """
        runtime = str(eval_mode or "dev").lower() == "runtime"
        effective = [m for m in (matches or [])
                     if not (runtime and str(m.get("outcome") or "") == "FN")]
        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        unmatched = 0
        unmatched_non_tn = 0
        for m in effective:
            outcome = str(m.get("outcome") or "")
            if outcome in counts:
                counts[outcome] += 1
            if m.get("match_method") == "unmatched":
                unmatched += 1
                if outcome != "TN":
                    unmatched_non_tn += 1
        total = len(effective)
        return {
            "total": total,
            "tp": counts["TP"], "fp": counts["FP"],
            "tn": counts["TN"], "fn": counts["FN"],
            "matched": total - unmatched,
            "unmatched": unmatched,
            "unmatched_non_tn": unmatched_non_tn,
        }

    @staticmethod
    def _add_analysis_warnings(evaluation_id: str, summary: dict) -> None:
        """记录「该分析却分析不了」的数据质量告警。

        FP/FN=0 时根因分析本来就没有对象，属于正常结果（不是失败、也不是
        数据问题），不告警；只有数据缺失导致本该分析却定位不到断点时才告警。
        """
        total = summary.get("total", 0)
        if total == 0:
            _pw.add(evaluation_id, "analysis", "no_cases", "warning",
                    "本次评测没有任何 case，报告仅含空指标")
            return

        fp, fn = summary.get("fp", 0), summary.get("fn", 0)
        has_targets = (fp + fn) > 0

        if has_targets and summary.get("matched", 0) == 0:
            _pw.add(evaluation_id, "analysis", "no_matched_sessions", "warning",
                    f"{total} 个 case 均未匹配到 trace session，无法定位断点")
        else:
            # TN 未上报本就没有 trace，未匹配属正常；只统计本应有 session 的 case
            non_tn = total - summary.get("tn", 0)
            bad = summary.get("unmatched_non_tn", 0)
            if non_tn > 0 and bad / non_tn > 0.8:
                _pw.add(
                    evaluation_id, "analysis", "high_unmatched_ratio", "warning",
                    f"{bad}/{non_tn} 个非 TN case 未匹配到 session（阈值 80%），"
                    f"请确认 trace 是否完整")

    # ── REPORTING ────────────────────────────────────

    def _assemble_report(
        self, evaluation_id: str,
        root_cause_results: list, causal_chain: dict,
        recall_precision: dict, reports_dir: str,
        data_quality_warnings: list[dict] | None = None,
        case_outcome_summary: dict | None = None,
        case_session_matches: list[dict] | None = None,
        eval_mode: str = "dev",
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
            data_quality_warnings=data_quality_warnings or [],
            case_outcome_summary=case_outcome_summary or {},
            case_session_matches=case_session_matches or [],
            eval_mode=eval_mode,
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
        recall_precision: dict | None = None,
        eval_mode: str = "dev",
        agent_outcomes: dict | None = None,
    ):
        """写入 evaluation_report 表，状态设为 COMPLETED。

        将报告 JSON 路径写入 evaluation_report 表，
        供 /report/status 和 /report/lifecycle 端点查询。

        同时写入 evaluation_summary 小索引表：首页看板只需一次 SQL 聚合，
        不再逐个读取 {eid}.json / _debug_case_matching.json / _lifecycle.json。
        """
        # 检查 lifecycle report 是否存在
        lifecycle_path = os.path.join(
            reports_dir, f"{evaluation_id}_lifecycle.json",
        )
        base_path = os.path.join(reports_dir, f"{evaluation_id}.json")

        # 重试路径跳过 REPORTING 时 recall_precision 未计算，从基础报告补读
        rp = recall_precision
        if not rp:
            try:
                with open(base_path, "r", encoding="utf-8") as f:
                    rp = (json.load(f) or {}).get("recall_precision") or {}
            except Exception:
                rp = {}

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
            # 小索引：看板聚合只读此表，不碰大报告文件
            cur.execute(
                "INSERT INTO evaluation_summary "
                "(evaluation_id, eval_mode, tp_count, fp_count, fn_count, tn_count, "
                " recall_rate, precision_rate, fpr_rate, agent_outcomes, "
                " breakpoint_distribution) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE "
                "eval_mode=VALUES(eval_mode), "
                "tp_count=VALUES(tp_count), fp_count=VALUES(fp_count), "
                "fn_count=VALUES(fn_count), tn_count=VALUES(tn_count), "
                "recall_rate=VALUES(recall_rate), "
                "precision_rate=VALUES(precision_rate), "
                "fpr_rate=VALUES(fpr_rate), "
                "agent_outcomes=VALUES(agent_outcomes), "
                "breakpoint_distribution=VALUES(breakpoint_distribution)",
                (
                    evaluation_id,
                    eval_mode or "",
                    int(rp.get("tp_count") or 0),
                    int(rp.get("fp_count") or 0),
                    int(rp.get("fn_count") or 0),
                    int(rp.get("tn_count") or 0),
                    rp.get("recall_rate"),
                    rp.get("precision_rate"),
                    rp.get("fpr_rate"),
                    _json_dumps(agent_outcomes or {}),
                    _json_dumps(causal_chain.get("cross_attribution_matrix") or {}),
                ),
            )

        try:
            _db_query(_do)
            log("FINALIZE", f"evaluation_report 已写入: {evaluation_id}")
        except Exception as e:
            # evaluation_report 表可能不存在（未迁移），不阻断完成
            log("FINALIZE", f"写入 evaluation_report 表失败（不阻断）: {e}")

    # 辅助方法已提取到 status_manager.py 和 debug_dumper.py
