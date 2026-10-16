"""报告组装扩展模块 — 生命周期分析段。

新增报告段（§4.6）：
- {eid}_lifecycle.json — 生命周期分析段（L0 原始来源分布 + L2-L7 断点分布 +
  成因汇总 + 效果标签分布 + 召回率/准确率 + per_case_details）

大字段处理：per_case_details 中 evidence 字段可能很大，遵循"大 payload 存文件
DB 存路径"模式——超过 64KB 的 evidence 写入 {reports_dir}/{eid}_lifecycle_data/
目录，报告 JSON 中存文件路径而非完整内容。
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
from collections import Counter
from typing import Any

from ...infrastructure.log_util import log

# ── 常量 ──────────────────────────────────────────────


def _json_default(obj):
    """json.dump default — dataclass → dict，numpy → Python 原生类型。"""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    mod = sys.modules.get("numpy")
    if mod is not None and isinstance(obj, mod.ndarray):
        return obj.tolist()
    if mod is not None:
        for attr in ("float64", "float32", "float_"):
            t = getattr(mod, attr, None)
            if t is not None and isinstance(obj, t):
                return float(obj)
        for attr in ("int64", "int32", "int_"):
            t = getattr(mod, attr, None)
            if t is not None and isinstance(obj, t):
                return int(obj)
    if isinstance(obj, (set, tuple)):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

_LARGE_FIELD_THRESHOLD = 64 * 1024  # 64KB

# 所有 cause_code（A-G）
_ALL_CAUSES = ["A", "B", "C", "D", "E", "F", "G"]

# 所有 effect_label（含 NULL）
_ALL_EFFECTS = ["POSITIVE", "NEGATIVE", "NEUTRAL", "NULL"]

# 所有 L 级别（列头）
_ALL_LEVELS = ["L2", "L3", "L4", "L5", "L6", "L7"]

# 所有 Agent 类型（行头）
_ALL_AGENT_TYPES = [
    "turing", "argo", "secmate", "dataflow",
    "cvuln_verify", "webvuln_verify",
]


class ReportAssembler:
    """报告组装器 — 组装生命周期分析段报告。

    不执行 L0-L7 判定或因果链分析（那是 RootCauseAnalyzer /
    CausalChainAnalyzer 的职责），只负责将已有结果组装为报告 JSON 并写入文件。

    大字段处理：per_case_details 中超过 64KB 的 evidence 写入
    {reports_dir}/{eid}_lifecycle_data/ 目录，报告 JSON 中存文件路径。
    """

    # ── 主入口 ──────────────────────────────────────────

    def assemble_lifecycle_report(
        self,
        evaluation_id: str,
        root_cause_results: list[dict],
        causal_chain_result: dict,
        recall_precision: dict,
        reports_dir: str,
    ) -> str:
        """组装生命周期分析段报告，写入 {reports_dir}/{evaluation_id}_lifecycle.json。

        Args:
            evaluation_id: 评测 ID。
            root_cause_results: RootCauseAnalyzer.analyze() 的输出，
                                含 mining/verification 的 l0_l7_breakpoints。
            causal_chain_result: CausalChainAnalyzer.analyze() 的输出 dict，
                                 含 cross_attribution_matrix、cause_summary、
                                 effect_label_distribution、per_case_breakpoints。
            recall_precision: 召回率/准确率计算结果 dict，含 recall_rate、
                              precision_rate、tp_count、fn_count、fp_count。
            reports_dir: 报告输出目录。

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
                root_cause_results),
            "breakpoint_distribution": self._build_breakpoint_distribution(
                causal_chain_result
            ),
            "cause_summary": causal_chain_result.get(
                "cause_summary",
                {code: 0 for code in _ALL_CAUSES},
            ),
            "effect_label_distribution": causal_chain_result.get(
                "effect_label_distribution",
                {label: 0 for label in _ALL_EFFECTS},
            ),
            "recall_precision": recall_precision,
            "per_case_details": self._build_per_case_details(
                evaluation_id, root_cause_results, causal_chain_result,
                reports_dir,
            ),
        }

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

    def _build_l0_distribution(
        self, root_cause_results: list[dict],
    ) -> dict:
        """统计 L0 原始来源分布。

        从 root_cause_results 的 l0_l7_breakpoints 中 l0_source 字段统计。
        l0_source 为 None 或空字符串时归入 "未知"。
        """
        counter: Counter = Counter()
        for case in root_cause_results:
            for chain_type in ("mining", "verification"):
                chain_data = case.get(chain_type, {})
                if not chain_data or not isinstance(chain_data, dict):
                    continue
                for bp in chain_data.get("l0_l7_breakpoints", []):
                    if not isinstance(bp, dict):
                        continue
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

    def _build_per_case_details(
        self,
        evaluation_id: str,
        root_cause_results: list[dict],
        causal_chain_result: dict,
        reports_dir: str,
    ) -> list[dict]:
        """组装 per_case_details 列表。

        从 causal_chain_result.per_case_breakpoints 构建，为每个 case 附加：
        - vuln_type
        - root_cause
        - fix_suggestion
        - breakpoints（含 evidence，大字段写文件）
        """
        per_case_breakpoints = causal_chain_result.get("per_case_breakpoints", [])

        # 从 root_cause_results 获取每条 case 的根因和修复建议
        case_root_cause: dict[str, dict] = {}
        case_fix: dict[str, str] = {}
        for case in root_cause_results:
            cid = case.get("case_id", "")
            mining = case.get("mining", {}) or {}
            verify = case.get("verification", {}) or {}
            root_causes = {}
            fix_parts = []
            for chain_data in (mining, verify):
                rc = chain_data.get("root_cause", {})
                if rc:
                    cat = rc.get("category", "")
                    desc = rc.get("description", "")
                    if cat:
                        root_causes[cat] = desc
                fs = chain_data.get("fix_suggestion", "")
                if fs:
                    fix_parts.append(fs)
            case_root_cause[cid] = root_causes
            case_fix[cid] = " | ".join(fix_parts) if fix_parts else ""

        result: list[dict] = []
        for case_data in per_case_breakpoints:
            case_id = case_data.get("case_id", "")
            vuln_type = case_data.get("vuln_type", "")
            breakpoints_raw = case_data.get("breakpoints", [])

            processed_breakpoints: list[dict] = []
            for idx, bp in enumerate(breakpoints_raw):
                bp_processed = {
                    "agent_type": bp.get("agent_type", ""),
                    "chain_type": bp.get("chain_type", ""),
                    "break_level": bp.get("break_level", ""),
                    "cause_code": bp.get("cause_code", ""),
                    "evidence": self._handle_large_evidence(
                        evaluation_id, case_id, idx,
                        bp.get("evidence", ""),
                        reports_dir,
                    ),
                }
                processed_breakpoints.append(bp_processed)

            result.append({
                "case_id": case_id,
                "vuln_type": vuln_type,
                "root_cause": case_root_cause.get(case_id, {}),
                "fix_suggestion": case_fix.get(case_id, ""),
                "breakpoints": processed_breakpoints,
            })

        return result

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
