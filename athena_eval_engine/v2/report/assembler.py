"""报告组装扩展模块 — 生命周期分析段 + 知识盘点段。

新增两段报告（§4.6）：
- {eid}_lifecycle.json — 生命周期分析段（L0 原始来源分布 + L2-L7 断点分布 +
  成因汇总 + 效果标签分布 + M15-M21/M26 指标 + per_case_details + 改进建议汇总）
- {eid}_inventory.json — 知识盘点段（覆盖度清单 + 质量标注）

大字段处理：per_case_details 中 evidence 字段可能很大，遵循"大 payload 存文件
DB 存路径"模式——超过 64KB 的 evidence 写入 {reports_dir}/{eid}_lifecycle_data/
目录，报告 JSON 中存文件路径而非完整内容。
"""
from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

from ...infrastructure.log_util import log

# ── 常量 ──────────────────────────────────────────────

_LARGE_FIELD_THRESHOLD = 64 * 1024  # 64KB

# 所有 cause_code（A-H）
_ALL_CAUSES = ["A", "B", "C", "D", "E", "F", "G", "H"]

# 所有 effect_label（含 NULL）
_ALL_EFFECTS = ["POSITIVE", "NEGATIVE", "NEUTRAL", "NULL"]

# 所有 L 级别（列头）
_ALL_LEVELS = ["L2", "L3", "L4", "L5", "L6", "L7"]

# 所有业务阶段（中文显示名，按挖掘→验证顺序）
_ALL_PHASES_DISPLAY = [
    "入口识别", "数据流追踪", "漏洞模式识别", "Sink点定位", "漏洞判定与上报",
    "漏洞理解", "代码定位", "验证执行", "判定上报",
]


class ReportAssembler:
    """报告组装器 — 组装生命周期分析段和知识盘点段报告。

    不执行 L0-L7 判定或因果链分析（那是 LifecycleAnalyzer / CausalChainAnalyzer
    的职责），只负责将已有结果组装为报告 JSON 并写入文件。

    大字段处理：per_case_details 中超过 64KB 的 evidence 写入
    {reports_dir}/{eid}_lifecycle_data/ 目录，报告 JSON 中存文件路径。
    """

    # ── 主入口 ──────────────────────────────────────────

    def assemble_lifecycle_report(
        self,
        evaluation_id: str,
        access_details: list[dict],
        causal_chain_result: dict,
        lifecycle_metrics: list[dict],
        suggestions: list[dict],
        reports_dir: str,
    ) -> str:
        """组装生命周期分析段报告，写入 {reports_dir}/{evaluation_id}_lifecycle.json。

        Args:
            evaluation_id: 评测 ID。
            access_details: knowledge_access_detail 记录列表（dict），每条含
                            l0_origin、business_phase、cause_code、effect_label、
                            task_run_id、evidence_json 等字段。
            causal_chain_result: CausalChainAnalyzer.analyze() 的输出 dict，
                                 含 cross_attribution_matrix、cause_summary、
                                 effect_label_distribution、per_case_breakpoints。
            lifecycle_metrics: calc_all_lifecycle_metrics() 的输出 list[dict]，
                               M15-M21 + M26。
            suggestions: SuggestionGenerator.generate() 的输出 list[dict]。
            reports_dir: 报告输出目录。

        Returns:
            报告文件路径。
        """
        log(
            "REPORT_ASSEMBLER",
            f"assemble_lifecycle_report: eval={evaluation_id}, "
            f"{len(access_details)} access details, "
            f"{len(suggestions)} suggestions",
            eval_id=evaluation_id,
        )

        report: dict[str, Any] = {
            "evaluation_id": evaluation_id,
            "l0_origin_distribution": self._build_l0_distribution(access_details),
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
            "lifecycle_metrics": lifecycle_metrics,
            "per_case_details": self._build_per_case_details(
                evaluation_id, access_details, causal_chain_result,
                suggestions, reports_dir,
            ),
            "suggestions_summary": self._build_suggestions_summary(suggestions),
        }

        # 写入文件
        os.makedirs(reports_dir, exist_ok=True)
        out_path = os.path.join(reports_dir, f"{evaluation_id}_lifecycle.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)

        log(
            "REPORT_ASSEMBLER",
            f"lifecycle report written to {out_path}",
            eval_id=evaluation_id,
        )

        return out_path

    def assemble_inventory_report(
        self,
        evaluation_id: str,
        inventory_result: dict,
        reports_dir: str,
    ) -> str:
        """组装知识盘点段报告，写入 {reports_dir}/{evaluation_id}_inventory.json。

        inventory_result 已由 KnowledgeInventory.run_inventory() 生成，
        此方法负责补充报告元数据并写入文件。

        Args:
            evaluation_id: 评测 ID。
            inventory_result: KnowledgeInventory.run_inventory() 的输出 dict，
                              含 coverage、quality、memory_coverage、kb_stats。
            reports_dir: 报告输出目录。

        Returns:
            报告文件路径。
        """
        log(
            "REPORT_ASSEMBLER",
            f"assemble_inventory_report: eval={evaluation_id}",
            eval_id=evaluation_id,
        )

        # 补充报告元数据
        report: dict[str, Any] = {
            "evaluation_id": evaluation_id,
            "coverage": inventory_result.get("coverage", {}),
            "quality": inventory_result.get("quality", []),
            "memory_coverage": inventory_result.get("memory_coverage", {}),
            "kb_stats": inventory_result.get("kb_stats", {}),
        }

        # 写入文件
        os.makedirs(reports_dir, exist_ok=True)
        out_path = os.path.join(reports_dir, f"{evaluation_id}_inventory.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)

        log(
            "REPORT_ASSEMBLER",
            f"inventory report written to {out_path}",
            eval_id=evaluation_id,
        )

        return out_path

    # ── 私有方法 ────────────────────────────────────────

    def _build_l0_distribution(self, access_details: list[dict]) -> dict:
        """统计 L0 原始来源分布。

        从 access_details 的 l0_origin 字段统计各原始来源的出现次数。
        l0_origin 为 None 或空字符串时归入 "未知"。

        Returns:
            {"已有知识升华": 10, "历史漏洞经验": 5, "未知": 3, ...}
        """
        counter: Counter = Counter()
        for rec in access_details:
            origin = rec.get("l0_origin")
            if origin:
                counter[str(origin)] += 1
            else:
                counter["未知"] += 1
        return dict(counter)

    def _build_breakpoint_distribution(self, causal_chain_result: dict) -> dict:
        """从因果链结果提取断点分布（直接用 cross_attribution_matrix）。

        cross_attribution_matrix 结构：
        {"入口识别": {"L2": 3, "L3": 1, ...}, "漏洞判定与上报": {...}, ...}

        如果 causal_chain_result 中没有 cross_attribution_matrix，返回全零矩阵。

        Returns:
            {"入口识别": {"L2": 3, "L3": 1, "L4": 2, "L5": 0, "L6": 1, "L7": 0}, ...}
        """
        matrix = causal_chain_result.get("cross_attribution_matrix")
        if matrix and isinstance(matrix, dict):
            # 确保每个阶段都有完整的 L2-L7 键
            result: dict[str, dict[str, int]] = {}
            for phase in _ALL_PHASES_DISPLAY:
                phase_data = matrix.get(phase, {})
                if isinstance(phase_data, dict):
                    result[phase] = {
                        level: int(phase_data.get(level, 0))
                        for level in _ALL_LEVELS
                    }
                else:
                    result[phase] = {level: 0 for level in _ALL_LEVELS}
            return result

        # 无矩阵数据，返回全零
        return {
            phase: {level: 0 for level in _ALL_LEVELS}
            for phase in _ALL_PHASES_DISPLAY
        }

    def _build_suggestions_summary(self, suggestions: list[dict]) -> dict:
        """统计改进建议汇总（总数 + 按优先级分组）。

        Args:
            suggestions: SuggestionGenerator.generate() 的输出列表。

        Returns:
            {"total": N, "high": M, "medium": M, "low": M}
        """
        total = len(suggestions)
        high = sum(1 for s in suggestions if s.get("priority") == "high")
        medium = sum(1 for s in suggestions if s.get("priority") == "medium")
        low = sum(1 for s in suggestions if s.get("priority") == "low")
        return {
            "total": total,
            "high": high,
            "medium": medium,
            "low": low,
        }

    def _build_per_case_details(
        self,
        evaluation_id: str,
        access_details: list[dict],
        causal_chain_result: dict,
        suggestions: list[dict],
        reports_dir: str,
    ) -> list[dict]:
        """组装 per_case_details 列表。

        从 causal_chain_result.per_case_breakpoints 构建，为每个 case 附加：
        - vuln_type
        - breakpoints（含 evidence，大字段写文件）
        - suggestions（该 case 关联的改进建议）

        大字段处理：evidence 超过 64KB 时写入
        {reports_dir}/{eid}_lifecycle_data/{case_id}_evidence_{idx}.json，
        报告 JSON 中存文件路径。
        """
        per_case_breakpoints = causal_chain_result.get("per_case_breakpoints", [])

        # 按 case_id 索引建议（一个 case 可能有多个建议）
        case_suggestions: dict[str, list[dict]] = {}
        for s in suggestions:
            # 建议没有直接的 case_id 字段，但按 business_phase + cause_code 可关联
            # SuggestionGenerator 输出的建议不含 case_id
            # 这里不按 case 拆分建议，整体放入 per_case 的 suggestions 不合适
            # 需要从 per_case_breakpoints 的 breakpoints 匹配
            pass

        result: list[dict] = []
        for case_data in per_case_breakpoints:
            case_id = case_data.get("case_id", "")
            vuln_type = case_data.get("vuln_type", "")
            breakpoints_raw = case_data.get("breakpoints", [])

            # 处理每个 breakpoint 的 evidence（大字段写文件）
            processed_breakpoints: list[dict] = []
            for idx, bp in enumerate(breakpoints_raw):
                bp_processed = {
                    "business_phase": bp.get("business_phase", ""),
                    "break_level": bp.get("break_level", ""),
                    "cause_code": bp.get("cause_code", ""),
                    "evidence": self._handle_large_evidence(
                        evaluation_id, case_id, idx,
                        bp.get("evidence", ""),
                        reports_dir,
                    ),
                }
                processed_breakpoints.append(bp_processed)

            # 从 access_details 中提取该 case 的漏洞类型（如果 per_case_breakpoints 中没有）
            if not vuln_type:
                for rec in access_details:
                    if rec.get("task_run_id") == case_id:
                        vuln_type = self._extract_vuln_type(rec)
                        if vuln_type:
                            break

            # 匹配该 case 的建议（通过 business_phase + cause_code）
            case_matched_suggestions: list[dict] = []
            for bp in breakpoints_raw:
                bp_phase = bp.get("business_phase", "")
                bp_cause = bp.get("cause_code", "")
                for s in suggestions:
                    if (
                        s.get("business_phase") == bp_phase
                        and s.get("cause_code") == bp_cause
                    ):
                        # 避免重复添加同一建议
                        if s not in case_matched_suggestions:
                            case_matched_suggestions.append(s)

            result.append({
                "case_id": case_id,
                "vuln_type": vuln_type,
                "breakpoints": processed_breakpoints,
                "suggestions": case_matched_suggestions,
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
        """处理单个断点的 evidence 字段。

        如果 evidence 超过 64KB，写入文件并返回文件路径；
        否则原样返回 evidence 内容。

        文件路径格式：
        {reports_dir}/{eid}_lifecycle_data/{case_id}_evidence_{idx}.json
        """
        if not evidence:
            return ""

        evidence_str = str(evidence)

        # 判断是否超过阈值（按 UTF-8 字节数计算）
        if len(evidence_str.encode("utf-8")) <= _LARGE_FIELD_THRESHOLD:
            return evidence_str

        # 大字段写入文件
        field_dir = os.path.join(reports_dir, f"{evaluation_id}_lifecycle_data")
        os.makedirs(field_dir, exist_ok=True)

        # 清理 case_id 中的非法文件名字符
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
        # Windows 文件名非法字符：\ / : * ? " < > |
        for ch in ('\\', '/', ':', '*', '?', '"', '<', '>', '|'):
            name = name.replace(ch, '_')
        return name

    @staticmethod
    def _extract_vuln_type(rec: dict) -> str:
        """从 knowledge_access_detail 记录中提取漏洞类型。

        漏洞类型可能存在：
        - evidence_json 中的 vuln_type 字段
        - judgment_conclusion 中包含的漏洞类型描述
        """
        # 尝试从 evidence_json 提取
        evidence_json = rec.get("evidence_json")
        if evidence_json:
            try:
                if isinstance(evidence_json, str):
                    parsed = json.loads(evidence_json)
                else:
                    parsed = evidence_json
                if isinstance(parsed, dict):
                    vuln_type = parsed.get("vuln_type")
                    if vuln_type:
                        return str(vuln_type)
            except (json.JSONDecodeError, TypeError):
                pass

        # 尝试从 judgment_conclusion 提取
        judgment = rec.get("judgment_conclusion", "")
        if judgment:
            return str(judgment)[:100]

        return ""
