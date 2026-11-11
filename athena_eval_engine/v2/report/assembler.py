"""报告组装扩展模块 — 生命周期分析段。

新增报告段（§4.6）：
- {eid}_lifecycle.json — 生命周期分析段（L0 原始来源分布 + L2-L7 断点分布 +
  成因汇总 + 召回率/准确率）

所有统计基于 session 级断点，不按假定线索的引用过滤，
与问题单明细口径一致。逐 case 断点明细由问题单详情页提供，不再在此重复。
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
from collections import Counter
from typing import Any

from ..infra.log_util import log
from ..infra.json_utils import json_default as _json_default
from ..core.causal_levels import ALL_CAUSES as _ALL_CAUSES
from ..core.causal_levels import ALL_LEVELS as _ALL_LEVELS
from ..core.agents import ALL_AGENT_TYPES as _ALL_AGENT_TYPES

# ── 常量 ──────────────────────────────────────────────

_LARGE_FIELD_THRESHOLD = 64 * 1024  # 64KB


class ReportAssembler:
    """报告组装器 — 组装生命周期分析段报告。

    不执行 L0-L7 判定或因果链分析（那是 RootCauseAnalyzer /
    CausalChainAnalyzer 的职责），只负责将已有结果组装为报告 JSON 并写入文件。

    所有统计口径基于 session 级断点，不按假定线索的引用过滤。
    """

    # ── 主入口 ──────────────────────────────────────────

    def assemble_lifecycle_report(
        self,
        evaluation_id: str,
        root_cause_results: list[dict],
        causal_chain_result: dict,
        recall_precision: dict,
        reports_dir: str,
        data_quality_warnings: list[dict] | None = None,
        case_outcome_summary: dict | None = None,
        case_session_matches: list[dict] | None = None,
        eval_mode: str = "dev",
    ) -> str:
        """组装生命周期分析段报告，写入 {reports_dir}/{evaluation_id}_lifecycle.json。

        Args:
            evaluation_id: 评测 ID。
            root_cause_results: RootCauseAnalyzer.analyze() 的输出，
                                含 mining/verification 的 l0_l7_breakpoints。
            causal_chain_result: CausalChainAnalyzer.analyze() 的输出 dict，
                                 含 cross_attribution_matrix、cause_summary、
                                 per_case_breakpoints。
            recall_precision: 召回率/准确率计算结果 dict，含 recall_rate、
                              precision_rate、tp_count、fn_count、fp_count。
            reports_dir: 报告输出目录。
            data_quality_warnings: pipeline 执行中收集的数据质量告警列表
                                   （外部数据源失败、LLM 降级等）。

        Returns:
            报告文件路径。
        """
        log(
            "REPORT_ASSEMBLER",
            f"assemble_lifecycle_report: eval={evaluation_id}, "
            f"{len(root_cause_results)} root cause results",
            eval_id=evaluation_id,
        )

        report: dict[str, Any] = {
            "evaluation_id": evaluation_id,
            "l0_origin_distribution": self._build_l0_distribution(
                causal_chain_result),
            "breakpoint_distribution": self._build_breakpoint_distribution(
                causal_chain_result
            ),
            "cause_summary": causal_chain_result.get(
                "cause_summary",
                {code: 0 for code in _ALL_CAUSES},
            ),
            "recall_precision": recall_precision,
            "skipped_cases": self._build_skipped_cases(
                root_cause_results, causal_chain_result, case_session_matches,
                eval_mode),
            # 证据不足、未生成问题单的 case，报告里必须说明原因
            "insufficient_cases": causal_chain_result.get(
                "insufficient_cases", []),
            # case 级 outcome 分布 + 匹配情况：FP/FN=0 时报告为空，必须说明原因
            "case_outcome_summary": case_outcome_summary or {},
        }
        if data_quality_warnings:
            report["data_quality_warnings"] = data_quality_warnings

        # 写入文件
        os.makedirs(reports_dir, exist_ok=True)
        out_path = os.path.join(reports_dir, f"{evaluation_id}_lifecycle.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=_json_default)

        log(
            "REPORT_ASSEMBLER",
            f"lifecycle report written to {out_path}",
            eval_id=evaluation_id,
        )

        return out_path

    # ── 私有方法 ────────────────────────────────────────

    @staticmethod
    def _build_skipped_cases(
        root_cause_results: list[dict],
        causal_chain_result: dict,
        case_session_matches: list[dict] | None = None,
        eval_mode: str = "dev",
    ) -> list[dict]:
        """列出「没有生成问题单」的 case 及原因。

        问题单由 per_case_breakpoints 驱动。若某 case 既没有假定线索、也没有
        可用的断点，就不会出现在问题单列表里——开发人员会疑惑「这个 case
        为什么没有单」。这里显式列出，说明原因。

        要求：每个误报/漏报要么生成问题单，要么在这里给出未生成的原因。
        TP/TN 不是问题单对象，不列出。
        「是否已生成」以 DTS 实际产出的 case_id 为准，不做推断。

        Returns:
            [{"case_id", "vuln_title", "outcome", "reason", "detail"}, ...]
        """
        # 已生成问题单的 case：优先用 DTS 实际生成的 case_id 集合，
        # 避免「有断点/线索但最终没出单」被误判为已覆盖。
        # 兼容旧数据（无该字段）时退回按 per_case_breakpoints 推断。
        actual = causal_chain_result.get("dts_case_ids")
        if actual is not None:
            covered = {str(c) for c in actual if c}
        else:
            covered = set()
            for entry in causal_chain_result.get("per_case_breakpoints", []):
                cid = entry.get("case_id", "")
                if not cid:
                    continue
                if entry.get("breakpoints") or entry.get("hypotheses"):
                    covered.add(cid)

        skipped: list[dict] = []
        # case_id → 匹配结果，用于把「没生成单」的原因定位到具体环节
        match_by_cid = {
            str(m.get("case_id")): m
            for m in (case_session_matches or []) if m.get("case_id")}

        for case in root_cause_results:
            cid = case.get("case_id", "")
            if not cid or cid in covered:
                continue
            mining = case.get("mining") or {}
            verify = case.get("verification") or {}
            has_hyp = bool(mining.get("hypotheses") or verify.get("hypotheses"))
            bp_count = len(mining.get("l0_l7_breakpoints") or []) + \
                len(verify.get("l0_l7_breakpoints") or [])
            fn = case.get("fn_miss") or {}
            m = match_by_cid.get(cid) or {}
            sessions = (m.get("mining_sessions") or []) + \
                (m.get("verify_sessions") or [])
            no_session = bool(m) and (
                str(m.get("match_method") or "") == "unmatched" or not sessions)

            insufficient = bool(
                mining.get("insufficient_evidence")
                or verify.get("insufficient_evidence"))
            if no_session:
                # 最可执行的原因：trace 里没有这个 case 的 session，
                # 后面所有分析都无从谈起。
                reason = "未匹配到 trace session，无法分析"
                detail = (str(m.get("match_detail") or "")
                          or "trace 中没有该 case 的 session")
            elif insufficient:
                reason = "证据不足，未生成结论"
                detail = (
                    (mining.get("root_cause") or {}).get("description")
                    or (verify.get("root_cause") or {}).get("description")
                    or "没有任何假定线索能关联到证据卡"
                )
            elif has_hyp:
                reason, detail = "有假定线索但未生成问题单", (
                    f"已产出假定线索，但问题单生成阶段未覆盖该 case")
            elif fn.get("miss_category"):
                reason, detail = "FN 快捷路径无断点", (
                    f"miss_category={fn.get('miss_category')}，"
                    f"程序判定漏报原因，无 L0-L7 断点")
            elif bp_count:
                reason, detail = "有断点但无假定线索", (
                    f"{bp_count} 条断点存在，但 merge 阶段未产出假定线索")
            else:
                if sessions:
                    reason, detail = "有 session 但根因分析未产出线索和断点", (
                        "session 已匹配，但压缩/合并阶段没有产出假定线索或断点")
                else:
                    reason, detail = "根因分析未产出假定线索和断点", (
                        "压缩/合并阶段没有产出假定线索或断点")

            skipped.append({
                "case_id": cid,
                "vuln_title": case.get("vuln_title", ""),
                "outcome": case.get("outcome", ""),
                "reason": reason,
                "detail": detail,
            })

        # 只列误报/漏报：每个 FP/FN 要么生成问题单（covered），要么在这里
        # 说明为什么没有单。TP/TN 不是问题单对象，不列。
        analyzed = {c.get("case_id", "") for c in root_cause_results}
        runtime = str(eval_mode or "dev").lower() == "runtime"
        for m in (case_session_matches or []):
            cid = str(m.get("case_id") or "")
            outcome = str(m.get("outcome") or "")
            if not cid or cid in covered or outcome not in ("FP", "FN"):
                continue
            # 运行态没有漏报基线：FN 不进入「未生成 DTS 单」清单
            if runtime and outcome == "FN":
                continue
            if cid in analyzed:
                # 已进入根因分析但没生成单的，上面循环已经给出原因
                continue
            method = str(m.get("match_method") or "")
            detail = str(m.get("match_detail") or "")
            if method == "unmatched":
                reason = ("误报，但未匹配到 trace session，无法分析"
                          if outcome == "FP"
                          else "漏报，但未匹配到 trace session，无法分析")
                detail = detail or "trace 中没有该 case 的 session"
            else:
                reason = ("误报但未进入根因分析" if outcome == "FP"
                          else "漏报但未进入根因分析")
            skipped.append({
                "case_id": cid,
                "vuln_title": m.get("vuln_title", ""),
                "outcome": outcome,
                "reason": reason,
                "detail": detail,
            })
        return skipped

    def _build_l0_distribution(
        self, causal_chain_result: dict,
    ) -> dict:
        """统计 L0 原始来源分布。

        **基于 session 级断点统计**——读因果链的 per_case_breakpoints，
        不按假定线索的引用过滤。这样汇总结论与问题单明细能对上。

        l0_source 为 None 或空字符串时归入 "未知"。
        """
        counter: Counter = Counter()
        for case_entry in causal_chain_result.get("per_case_breakpoints", []):
            for bp in case_entry.get("breakpoints", []):
                origin = bp.get("l0_source", "")
                if origin:
                    counter[str(origin)] += 1
                else:
                    counter["未知"] += 1
        return dict(counter)

    def _build_breakpoint_distribution(self, causal_chain_result: dict) -> dict:
        """从因果链结果提取断点分布（直接用 cross_attribution_matrix）。"""
        matrix = causal_chain_result.get("cross_attribution_matrix")
        if matrix and isinstance(matrix, dict):
            result: dict[str, dict[str, int]] = {}
            for agent_type in _ALL_AGENT_TYPES:
                agent_data = matrix.get(agent_type, {})
                if isinstance(agent_data, dict):
                    result[agent_type] = {
                        level: int(agent_data.get(level, 0))
                        for level in _ALL_LEVELS
                    }
                else:
                    result[agent_type] = {level: 0 for level in _ALL_LEVELS}
            return result

        return {
            agent_type: {level: 0 for level in _ALL_LEVELS}
            for agent_type in _ALL_AGENT_TYPES
        }

    def _handle_large_evidence(
        self,
        evaluation_id: str,
        case_id: str,
        bp_idx: int,
        evidence: str,
        reports_dir: str,
    ) -> str:
        """处理单个断点的 evidence 字段。"""
        if not evidence:
            return ""

        evidence_str = str(evidence)

        if len(evidence_str.encode("utf-8")) <= _LARGE_FIELD_THRESHOLD:
            return evidence_str

        field_dir = os.path.join(reports_dir, f"{evaluation_id}_lifecycle_data")
        os.makedirs(field_dir, exist_ok=True)

        safe_case_id = self._sanitize_filename(case_id or "unknown")
        file_name = f"{safe_case_id}_evidence_{bp_idx}.json"
        file_path = os.path.join(field_dir, file_name)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(evidence_str)

        log(
            "REPORT_ASSEMBLER",
            f"large evidence ({len(evidence_str.encode('utf-8'))} bytes) "
            f"written to {file_path}",
            eval_id=evaluation_id,
        )

        return file_path

    @staticmethod
    def _sanitize_filename(name: str) -> str:
        """清理文件名中的非法字符。"""
        for ch in ('\\', '/', ':', '*', '?', '"', '<', '>', '|'):
            name = name.replace(ch, '_')
        return name
