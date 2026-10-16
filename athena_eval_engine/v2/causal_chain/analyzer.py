"""因果链断点分析模块（§4.2）。

基于根因分析结果的 L0-L7 断点，按 Agent 类型聚合误报归因。
L0 不参与此模块逻辑——L0 仅标记知识原始来源 provenance，不产生断链。

输入：RootCauseAnalyzer.analyze() 的输出（root_cause_results）
输出：
  - 交叉归因矩阵：Agent 类型（行）× L2-L7 级别（列）
  - 成因汇总（cause_code A-G 计数）
  - 效果标签分布（POSITIVE/NEGATIVE/NEUTRAL/NULL）
  - 每 case 的断点清单
"""
from __future__ import annotations

from collections import Counter, defaultdict

from ...infrastructure.log_util import log

# ── 断点→级别映射（§4.1 断点→成因映射）──

CAUSE_TO_LEVEL = {
    "A": "L2",   # 该查没查——L2 断（需要知识但未发起访问）
    "B": "L3",   # 查询太泛——L3 断（查询不聚焦）
    "C": "L4",   # 查了没得——L4 断（知识不存在）
    "D": "L5",   # 链路问题——L5 断（工具失败/超时）
    "E": "L6",   # 查到没用——L6 断（召回了但推理没引用）
    "F": "L7",   # 用了没推动——L7 断（未影响结论）
    "G": "L7",   # 导致误判——L7 负向（知识推动了判定但方向错了）
}

# 所有 L 级别（列头）
_ALL_LEVELS = ["L2", "L3", "L4", "L5", "L6", "L7"]

# 所有 Agent 类型（行头）
_ALL_AGENT_TYPES = [
    "turing", "argo", "secmate", "dataflow",
    "cvuln_verify", "webvuln_verify",
]

# 所有 cause_code
_ALL_CAUSES = ["A", "B", "C", "D", "E", "F", "G"]

# 所有 effect_label（含 NULL——无 effect 时表示证据不足）
_ALL_EFFECTS = ["POSITIVE", "NEGATIVE", "NEUTRAL", "NULL"]

# ── 链类型→默认 agent_type 映射（回退用，优先从 chain_data.agent_type 取）──
_CHAIN_DEFAULT_AGENT_TYPE = {
    "mining": "turing",
    "verification": "",
}


class CausalChainAnalyzer:
    """因果链断点分析器。

    基于根因分析结果中的 l0_l7_breakpoints 聚合统计。
    不执行 L0-L7 判定（那是 RootCauseAnalyzer 的职责），只做聚合统计。
    """

    def analyze(self, evaluation_id: str,
                root_cause_results: list[dict]) -> dict:
        """基于根因分析结果的 L0-L7 断点，按 Agent 类型聚合误报归因。

        Args:
            evaluation_id: 评测 ID。
            root_cause_results: RootCauseAnalyzer.analyze() 的输出，每个 case 含
                case_id, vuln_title, mining{...}, verification{...}，
                其中 mining/verification 各含 l0_l7_breakpoints 列表。

        Returns:
            因果链分析结果 dict，结构见模块 docstring。
        """
        log("CAUSAL_CHAIN",
            f"analyze: {len(root_cause_results)} root cause results "
            f"for eval={evaluation_id}",
            eval_id=evaluation_id)

        if not root_cause_results:
            log("CAUSAL_CHAIN",
                f"no root cause results for eval={evaluation_id}, "
                f"returning empty result",
                eval_id=evaluation_id)
            return self._empty_result(evaluation_id)

        # 从 root_cause_results 提取扁平的断点记录列表
        flat_breakpoints = self._flatten_breakpoints(root_cause_results)

        cross_attribution_matrix = self._build_cross_attribution_matrix(
            flat_breakpoints)
        cause_summary = self._build_cause_summary(flat_breakpoints)
        effect_label_distribution = self._build_effect_label_distribution(
            flat_breakpoints)
        per_case_breakpoints = self._build_per_case_breakpoints(
            root_cause_results, flat_breakpoints)

        result = {
            "evaluation_id": evaluation_id,
            "cross_attribution_matrix": cross_attribution_matrix,
            "cause_summary": cause_summary,
            "effect_label_distribution": effect_label_distribution,
            "per_case_breakpoints": per_case_breakpoints,
        }

        log("CAUSAL_CHAIN",
            f"analyze done: {len(per_case_breakpoints)} cases with breakpoints, "
            f"{len(flat_breakpoints)} total breakpoints, "
            f"cause_summary={cause_summary}",
            eval_id=evaluation_id)

        return result

    # ── 扁平化断点 ──

    def _flatten_breakpoints(
        self, root_cause_results: list[dict],
    ) -> list[dict]:
        """从 root_cause_results 的嵌套结构提取扁平的断点记录列表。

        每个 root_cause_result 含 mining 和 verification 两段，
        每段含 l0_l7_breakpoints 列表。

        Returns:
            扁平断点记录列表，每条含：
            - case_id, vuln_title
            - chain_type: "mining" / "verification"
            - agent_type: 从 chain_type 推导
            - cause_code, breakpoint, l0_source
            - query_content, returned_content
            - l7_influenced (effect_label)
        """
        flat: list[dict] = []
        # 去重键：(case_id, chain_type, cause_code, breakpoint, query_content)
        # 同一断点可能在 session 级和 merge 级各出现一次，只保留一条
        seen_keys: set[tuple] = set()

        for case in root_cause_results:
            case_id = case.get("case_id", "")
            vuln_title = case.get("vuln_title", "")

            for chain_type in ("mining", "verification"):
                chain_data = case.get(chain_type, {})
                if not chain_data or not isinstance(chain_data, dict):
                    continue

                breakpoints = chain_data.get("l0_l7_breakpoints", [])
                for bp in breakpoints:
                    if not isinstance(bp, dict):
                        continue

                    cause_code = bp.get("cause_code")
                    # LLM 可能返回 "null" 字符串表示无断点
                    if not cause_code or cause_code == "null":
                        continue

                    dedup_key = (
                        case_id, chain_type,
                        cause_code, bp.get("breakpoint", ""),
                        bp.get("query_content", ""),
                    )
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    flat.append({
                        "case_id": case_id,
                        "vuln_title": vuln_title,
                        "chain_type": chain_type,
                        "agent_type": chain_data.get("agent_type") or
                            _CHAIN_DEFAULT_AGENT_TYPE.get(chain_type, ""),
                        "cause_code": cause_code,
                        "breakpoint": bp.get("breakpoint", ""),
                        "l0_source": bp.get("l0_source", ""),
                        "query_content": bp.get("query_content", ""),
                        "returned_content": bp.get("returned_content", ""),
                        "l7_influenced": bp.get("l7_influenced"),
                        "root_cause": chain_data.get("root_cause", {}),
                        "fix_suggestion": chain_data.get("fix_suggestion", ""),
                    })

        return flat

    # ── 交叉归因矩阵 ──

    def _build_cross_attribution_matrix(
        self, flat_breakpoints: list[dict],
    ) -> dict:
        """构建 Agent 类型 × L2-L7 级别的交叉归因矩阵。

        从扁平断点记录中按 agent_type 分组，统计每个 Agent 在各 L 级别的断点数。
        断点级别由 cause_code 反推（CAUSE_TO_LEVEL 映射）。
        """
        matrix: dict[str, dict[str, int]] = {
            agent_type: {level: 0 for level in _ALL_LEVELS}
            for agent_type in _ALL_AGENT_TYPES
        }

        for rec in flat_breakpoints:
            cause_code = rec.get("cause_code")
            if not cause_code:
                continue

            level = CAUSE_TO_LEVEL.get(cause_code)
            if level is None:
                continue

            agent_type = rec.get("agent_type", "")
            if agent_type in matrix:
                matrix[agent_type][level] += 1

        return matrix

    # ── 成因汇总 ──

    def _build_cause_summary(
        self, flat_breakpoints: list[dict],
    ) -> dict:
        """统计各 cause_code 的数量。

        Returns:
            {"A": 8, "B": 3, ...} — 所有 A-G 键都存在，值为计数。
        """
        counter: Counter = Counter()
        for rec in flat_breakpoints:
            cause_code = rec.get("cause_code")
            if cause_code:
                counter[cause_code] += 1

        return {code: counter.get(code, 0) for code in _ALL_CAUSES}

    # ── 效果标签分布 ──

    def _build_effect_label_distribution(
        self, flat_breakpoints: list[dict],
    ) -> dict:
        """统计 effect_label 的分布。

        effect_label 从 l7_influenced 字段映射：
        - "positive" → POSITIVE
        - "negative" → NEGATIVE
        - None/null → NULL（证据不足）
        """
        counter: Counter = Counter()
        for rec in flat_breakpoints:
            l7 = rec.get("l7_influenced")
            if l7 == "positive":
                counter["POSITIVE"] += 1
            elif l7 == "negative":
                counter["NEGATIVE"] += 1
            elif l7 == "neutral":
                counter["NEUTRAL"] += 1
            else:
                # None 或 "null" 字符串 → NULL（证据不足）
                counter["NULL"] += 1

        return {label: counter.get(label, 0) for label in _ALL_EFFECTS}

    # ── 每 case 断点清单 ──

    def _build_per_case_breakpoints(
        self,
        root_cause_results: list[dict],
        flat_breakpoints: list[dict],
    ) -> list[dict]:
        """按 case 分组，列出每个 case 的断点清单。

        一个 case 可能有多个断点（多次知识访问，每次可能有各自的断点）。
        只有 cause_code 非空的记录才产生断点条目。

        Returns:
            [{"case_id": ..., "vuln_title": ..., "breakpoints": [...]}, ...]
        """
        # 按 case_id 分组
        case_map: dict[str, list[dict]] = defaultdict(list)
        for rec in flat_breakpoints:
            case_id = rec.get("case_id", "")
            case_map[case_id].append(rec)

        # 从 root_cause_results 获取每条 case 的根因和修复建议
        case_root_cause: dict[str, dict] = {}
        case_fix: dict[str, str] = {}
        for case in root_cause_results:
            cid = case.get("case_id", "")
            mining = case.get("mining", {}) or {}
            verify = case.get("verification", {}) or {}
            # 合并 mining 和 verification 的根因
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
            case_fix[cid] = "\n".join(fix_parts) if fix_parts else ""

        result: list[dict] = []
        for case_id, records in case_map.items():
            vuln_title = ""
            breakpoints: list[dict] = []

            for rec in records:
                if not vuln_title:
                    vuln_title = rec.get("vuln_title", "")

                cause_code = rec.get("cause_code", "")
                level = CAUSE_TO_LEVEL.get(cause_code, "")

                evidence = self._build_evidence(rec)

                breakpoints.append({
                    "agent_type": rec.get("agent_type", ""),
                    "chain_type": rec.get("chain_type", ""),
                    "break_level": level,
                    "cause_code": cause_code,
                    "evidence": evidence,
                })

            result.append({
                "case_id": case_id,
                "vuln_title": vuln_title,
                "root_cause": case_root_cause.get(case_id, {}),
                "fix_suggestion": case_fix.get(case_id, ""),
                "breakpoints": breakpoints,
            })

        return result

    # ── 辅助方法 ──

    def _build_evidence(self, rec: dict) -> str:
        """从断点记录构建证据摘要。

        组合 query_content + returned_content + breakpoint 信息。
        """
        parts: list[str] = []

        cause_code = rec.get("cause_code", "")
        cause_desc = self._cause_description(cause_code)
        if cause_desc:
            parts.append(f"断点: {cause_desc}")

        query = rec.get("query_content", "")
        if query:
            parts.append(f"查询: {query}")

        returned = rec.get("returned_content", "")
        if returned:
            parts.append(f"返回: {returned}")

        l0 = rec.get("l0_source", "")
        if l0:
            parts.append(f"知识来源: {l0}")

        return "\n".join(parts) if parts else ""

    def _cause_description(self, cause_code: str) -> str:
        """cause_code → 中文描述。"""
        descriptions = {
            "A": "该查没查（召回意识不足）",
            "B": "查询太泛（查询不聚焦）",
            "C": "查了没得（知识覆盖度不足）",
            "D": "链路问题（工具失败/超时）",
            "E": "查到没用（死知识，推理未引用）",
            "F": "用了没推动（未影响结论）",
            "G": "导致误判（知识推动但方向错）",
        }
        return descriptions.get(cause_code, "")

    def _empty_result(self, evaluation_id: str) -> dict:
        """空结果（无 root_cause_results 时返回）。"""
        return {
            "evaluation_id": evaluation_id,
            "cross_attribution_matrix": {
                agent_type: {level: 0 for level in _ALL_LEVELS}
                for agent_type in _ALL_AGENT_TYPES
            },
            "cause_summary": {code: 0 for code in _ALL_CAUSES},
            "effect_label_distribution": {label: 0 for label in _ALL_EFFECTS},
            "per_case_breakpoints": [],
        }
