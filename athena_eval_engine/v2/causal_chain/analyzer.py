"""因果链断点分析模块（§4.2）。

基于根因分析结果的 L0-L7 断点，按 Agent 类型聚合误报归因。
L0 不参与此模块逻辑——L0 仅标记知识原始来源 provenance，不产生断链。

输入：RootCauseAnalyzer.analyze() 的输出（root_cause_results）
输出：
  - 交叉归因矩阵：Agent 类型（行）× L2-L7 级别（列）
  - 成因汇总（cause_code A-H 计数，断点维度）
  - 假设维度统计（hypothesis_summary，按 responsibility 分组）
  - 人工标注质量分布（label_quality_summary，precise/imprecise）
  - 每 case 的断点清单（含多假设）
"""
from __future__ import annotations

from collections import Counter, defaultdict

from ..core.agents import ALL_AGENT_TYPES
from ...infrastructure.log_util import log

# ── 断点→级别映射（§4.1 断点→成因映射）──

CAUSE_TO_LEVEL = {
    "A": "L2",   # 该查没查——L2 断（需要知识但未发起访问）
    "B": "L3",   # 查询太泛——L3 断（查询不聚焦）
    "C": "L4",   # 查了没得——L4 断（知识不存在）
    "D": "L5",   # 链路问题——L5 断（工具失败/超时）
    "E": "L6",   # 查到没用——L6 断（召回了但推理没引用）
    "F": "L7",   # 用了没推动——L7 断（未影响结论）
    "G": "L7",   # 知识误导——L7 负向（知识推动了判定但方向错了）
    "H": "L8",   # 挖掘方向偏差——L8 断（范围/路径未覆盖 sink 点）
    "I": "L8",   # 调用链中断——L8 断（找到 sink 未追踪到 source）
    "J": "L8",   # 模型幻觉——L8 断（虚构不存在的防护/漏洞逻辑）
    "K": "L8",   # 验证否定真漏洞——L8 断（挖掘 CONFIRMED 但验证否定）
}

# 所有 L 级别（列头）
_ALL_LEVELS = ["L2", "L3", "L4", "L5", "L6", "L7", "L8"]

# ── FN 细分漏报成因 → cause_code 映射（A-K 体系）──
# MissDetailAnalyzer 的 miss_sub_category → cause_code
_FN_SUB_TO_CAUSE = {
    "chain_break": "I",              # sink→source 调用链中断
    "params_uncontrollable": "I",    # 参数可控性误判（调用链未追完）
    "knowledge_mislead": "G",        # 知识/记忆误导
    "hallucination": "J",            # 模型幻觉
    "logic_jump": "H",               # 逻辑跳跃（agent 推理，归挖掘方向/其他）
    "evidence_ignored": "H",         # 忽略关键证据（agent 侧）
    "verify_dimension_missing": "K", # 验证维度遗漏（验证否定相关）
    "verify_standard_too_strict": "K", # 判定标准过严（验证否定相关）
    "context_loss": "H",             # 上下文压缩丢失（agent 侧）
    "vuln_confusion": "H",           # 多漏洞混淆（agent 侧）
    "other": "H",                    # 其他
}

# 所有 Agent 类型（行头，集中配置见 v2/core/agents.py）
_ALL_AGENT_TYPES = ALL_AGENT_TYPES

# 所有 cause_code
_ALL_CAUSES = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"]

# 所有 responsibility（假设维度）
_ALL_RESPONSIBILITIES = ["agent", "knowledge", "external_data_source", "eval_process"]

# ── 链类型→默认 agent_type 映射（回退用，优先从 chain_data.agent_type 取）──
# mining 无默认值——挖掘 agent 有多种（turing/argo/secmate/dataflow），
# 不应假设默认是 turing，缺数据时留空让下游处理
_CHAIN_DEFAULT_AGENT_TYPE = {
    "mining": "",
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
        hypothesis_summary = self._build_hypothesis_summary(
            root_cause_results)
        label_quality_summary = self._build_label_quality_summary(
            root_cause_results)
        per_case_breakpoints = self._build_per_case_breakpoints(
            root_cause_results, flat_breakpoints)

        result = {
            "evaluation_id": evaluation_id,
            "cross_attribution_matrix": cross_attribution_matrix,
            "cause_summary": cause_summary,
            "hypothesis_summary": hypothesis_summary,
            "label_quality_summary": label_quality_summary,
            "per_case_breakpoints": per_case_breakpoints,
        }

        log("CAUSAL_CHAIN",
            f"analyze done: {len(per_case_breakpoints)} cases with breakpoints, "
            f"{len(flat_breakpoints)} total breakpoints, "
            f"cause_summary={cause_summary}, "
            f"hypothesis_summary={hypothesis_summary}",
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

            # ── FN 漏报原因（sink 精确命中分析）→ 合成断点 ──
            # 漏报与误报走同一流程：FN case 的 fn_miss（sink 漏报原因）
            # 映射为合成断点进入因果链/问题单。
            #   sink_found_no_report（sink 精确命中但未上报）→ 细分漏报成因
            #     （LLM 判定：调用链中断/知识误导/幻觉/验证遗漏等）
            #   sink_not_found（sink 未命中）→ 挖掘方向问题（程序直接给结论）
            fn_miss = case.get("fn_miss") or {}
            if fn_miss:
                fn_category = fn_miss.get("miss_category", "")
                fn_reason = fn_miss.get("miss_reason", "")
                # 细分漏报成因（sink_found_no_report 时由 MissDetailAnalyzer
                # 判定；sink_not_found 直接给结论）
                fn_sub = (fn_miss.get("miss_detail") or {}).get(
                    "miss_sub_category", "")
                fn_sub_label = (fn_miss.get("miss_detail") or {}).get(
                    "miss_sub_category_label", "")
                fn_agent_type = ""
                for chain_type in ("mining", "verification"):
                    at = (case.get(chain_type) or {}).get("agent_type", "")
                    if at:
                        fn_agent_type = at
                        break
                if not fn_agent_type:
                    fn_agent_type = _CHAIN_DEFAULT_AGENT_TYPE["mining"]
                if fn_category:
                    # 细分漏报成因 → cause_code 映射（与 A-K 体系对齐）
                    # 挖掘方向偏差→H，调用链中断→I，知识误导→G，幻觉→J，
                    # 验证否定→K，其他 agent 侧问题→H
                    fn_cause_code = _FN_SUB_TO_CAUSE.get(
                        fn_sub, "H")
                    # query_content 带细分漏报成因（如有）
                    fn_query = fn_category
                    if fn_sub:
                        fn_query = f"{fn_category}:{fn_sub}"
                    fn_bp = {
                        "case_id": case_id,
                        "vuln_title": vuln_title,
                        "chain_type": "mining",
                        "agent_type": fn_agent_type,
                        "cause_code": fn_cause_code,
                        "breakpoint": "L8",
                        "l0_source": "",
                        "query_content": fn_query,
                        "returned_content": "",
                        "l7_influenced": None,
                        "root_cause": {
                            "category": fn_category,
                            "description": fn_reason,
                            "miss_sub_category": fn_sub,
                            "miss_sub_category_label": fn_sub_label,
                        },
                        "fix_suggestion": [],
                        "_fn_miss": True,
                    }
                    dedup_key = (
                        case_id, "mining", fn_cause_code, "L8", fn_query)
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        flat.append(fn_bp)

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
                        "session_id": bp.get("session_id", ""),
                        "root_cause": chain_data.get("root_cause", {}),
                        "fix_suggestion": chain_data.get("fix_suggestion") or [],
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

    # ── 假设维度统计 ──

    def _build_hypothesis_summary(
        self, root_cause_results: list[dict],
    ) -> dict:
        """统计多假设维度的分布。

        从 root_cause_results 的 mining/verification.hypotheses 中聚合：
        - by_responsibility: 按 responsibility 分组计数
        - by_cause_code: 按 cause_code 分组计数（假设维度）
        - by_agent_can_resolve: true/false 计数（agent 能否自行解决）
        - total: 假设总数

        Returns:
            {
                "by_responsibility": {"agent": N, "knowledge": N, ...},
                "by_cause_code": {"A": N, "B": N, ...},
                "by_agent_can_resolve": {"true": N, "false": N},
                "total": N,
            }
        """
        resp_counter: Counter = Counter()
        cause_counter: Counter = Counter()
        resolve_counter: Counter = Counter()
        total = 0

        for case in root_cause_results:
            for chain_type in ("mining", "verification"):
                chain_data = case.get(chain_type, {})
                if not chain_data or not isinstance(chain_data, dict):
                    continue
                for h in chain_data.get("hypotheses") or []:
                    if not isinstance(h, dict):
                        continue
                    total += 1
                    resp = h.get("responsibility", "")
                    if resp:
                        resp_counter[resp] += 1
                    cc = h.get("cause_code", "")
                    if cc:
                        cause_counter[cc] += 1
                    can_resolve = h.get("agent_can_resolve")
                    resolve_counter["true" if can_resolve else "false"] += 1

        return {
            "by_responsibility": {r: resp_counter.get(r, 0) for r in _ALL_RESPONSIBILITIES},
            "by_cause_code": {c: cause_counter.get(c, 0) for c in _ALL_CAUSES},
            "by_agent_can_resolve": {
                "true": resolve_counter.get("true", 0),
                "false": resolve_counter.get("false", 0),
            },
            "total": total,
        }

    # ── 人工标注质量分布 ──

    def _build_label_quality_summary(
        self, root_cause_results: list[dict],
    ) -> dict:
        """统计人工标注质量分布（precise/imprecise）。

        从 mining/verification.label_quality 中取 imprecise 优先合并。
        """
        precise_count = 0
        imprecise_count = 0
        imprecise_cases: list[str] = []

        for case in root_cause_results:
            cid = case.get("case_id", "")
            merged = {"precision": "precise"}
            for chain_type in ("mining", "verification"):
                chain_data = case.get(chain_type, {})
                if not chain_data or not isinstance(chain_data, dict):
                    continue
                lq = chain_data.get("label_quality") or {}
                if lq.get("precision") == "imprecise":
                    merged = lq
            if merged.get("precision") == "imprecise":
                imprecise_count += 1
                imprecise_cases.append(cid)
            else:
                precise_count += 1

        return {
            "precise": precise_count,
            "imprecise": imprecise_count,
            "imprecise_case_ids": imprecise_cases,
            "total": precise_count + imprecise_count,
        }

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

        # 从 root_cause_results 获取每条 case 的根因、修复建议、假设和标注质量
        case_root_cause: dict[str, dict] = {}
        case_fix: dict[str, str] = {}
        case_hypotheses: dict[str, list] = {}
        case_label_quality: dict[str, dict] = {}
        for case in root_cause_results:
            cid = case.get("case_id", "")
            mining = case.get("mining", {}) or {}
            verify = case.get("verification", {}) or {}
            root_causes = {}
            fix_parts = []
            all_hypotheses: list = []
            label_quality = {"precision": "precise", "reason": "", "follow_up_questions": []}
            for chain_type, chain_data in (("mining", mining), ("verification", verify)):
                chain_hypotheses = chain_data.get("hypotheses") or []
                if chain_hypotheses:
                    all_hypotheses.extend(chain_hypotheses)
                    for h in chain_hypotheses:
                        if not isinstance(h, dict):
                            continue
                        fs = h.get("fix_suggestion")
                        if isinstance(fs, dict):
                            parts = [f"[{chain_type}链]"]
                            if fs.get("target"):
                                parts.append(f"修复方: {fs['target']}")
                            if fs.get("location"):
                                parts.append(f"位置: {fs['location']}")
                            if fs.get("action"):
                                parts.append(f"修改: {fs['action']}")
                            if fs.get("expected_effect"):
                                parts.append(f"预期: {fs['expected_effect']}")
                            hyp_desc = h.get("hypothesis", "")
                            prob = h.get("probability", 0)
                            resp = h.get("responsibility", "")
                            if hyp_desc:
                                parts.append(f"假设(P={prob}, {resp}): {hyp_desc}")
                            if len(parts) > 1:
                                fix_parts.append(" | ".join(parts))
                else:
                    # 兼容旧格式
                    rc = chain_data.get("root_cause", {})
                    if rc:
                        cat = rc.get("category", "")
                        desc = rc.get("description", "")
                        if cat:
                            root_causes[cat] = desc
                    fs_list = chain_data.get("fix_suggestion") or []
                    if isinstance(fs_list, list):
                        for fs in fs_list:
                            if isinstance(fs, dict):
                                parts = []
                                if fs.get("target"): parts.append(fs["target"])
                                if fs.get("location"): parts.append(fs["location"])
                                if fs.get("action"): parts.append(fs["action"])
                                if fs.get("expected_effect"): parts.append(fs["expected_effect"])
                                if parts:
                                    fix_parts.append(" | ".join(parts))
                    elif isinstance(fs_list, str) and fs_list:
                        fix_parts.append(fs_list)
                lq = chain_data.get("label_quality") or {}
                if lq.get("precision") == "imprecise":
                    label_quality = lq
            case_hypotheses[cid] = all_hypotheses
            case_label_quality[cid] = label_quality
            if all_hypotheses:
                top = max(all_hypotheses, key=lambda h: h.get("probability", 0)) if all_hypotheses else None
                if top and isinstance(top, dict):
                    root_causes = {
                        "hypothesis": top.get("hypothesis", ""),
                        "probability": top.get("probability", 0),
                        "responsibility": top.get("responsibility", ""),
                        "evidence": top.get("evidence", ""),
                    }
            case_root_cause[cid] = root_causes
            case_fix[cid] = "\n".join(fix_parts) if fix_parts else ""

        # 从 root_cause_results 提取每条 case 的 outcome（FP/FN）
        case_outcomes: dict[str, str] = {}
        for case in root_cause_results:
            cid = case.get("case_id", "")
            outcome = case.get("outcome", "")
            if cid and outcome:
                case_outcomes[cid] = outcome

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

            case_entry = {
                "case_id": case_id,
                "vuln_title": vuln_title,
                "outcome": case_outcomes.get(case_id, "FP"),
                "root_cause": case_root_cause.get(case_id, {}),
                "fix_suggestion": case_fix.get(case_id, ""),
                "breakpoints": breakpoints,
            }
            hypotheses = case_hypotheses.get(case_id, [])
            if hypotheses:
                case_entry["hypotheses"] = hypotheses
            label_quality = case_label_quality.get(case_id, {})
            if label_quality and label_quality.get("precision") != "precise":
                case_entry["label_quality"] = label_quality
            result.append(case_entry)

        return result

    # ── 辅助方法 ──

    def _build_evidence(self, rec: dict) -> str:
        """从断点记录构建证据摘要。

        组合 query_content + returned_content + breakpoint 信息。
        FN 漏报合成断点（_fn_miss=True）输出漏报原因描述。
        """
        parts: list[str] = []

        # FN 漏报合成断点：query_content 即漏报原因分类，直接展示
        if rec.get("_fn_miss"):
            query = rec.get("query_content", "")
            root_cause = rec.get("root_cause") or {}
            desc = root_cause.get("description", "")
            # 细分漏报成因（sink_found_no_report 由 LLM 判定）
            sub_label = root_cause.get("miss_sub_category_label", "")
            sub_reason = root_cause.get("miss_sub_category", "")
            parts.append(f"漏报类型: {query.split(':')[0]}")
            if sub_label:
                parts.append(f"细分成因: {sub_label}")
            if desc:
                parts.append(f"漏报原因: {desc}")
            elif query:
                parts.append(f"漏报原因: {query}")
            return "\n".join(parts) if parts else "漏报（FN）"

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
            "H": "其他（知识访问链路无问题，其他原因导致误报/漏报）",
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
            "hypothesis_summary": {
                "by_responsibility": {r: 0 for r in _ALL_RESPONSIBILITIES},
                "by_cause_code": {c: 0 for c in _ALL_CAUSES},
                "by_agent_can_resolve": {"true": 0, "false": 0},
                "total": 0,
            },
            "label_quality_summary": {
                "precise": 0,
                "imprecise": 0,
                "imprecise_case_ids": [],
                "total": 0,
            },
            "per_case_breakpoints": [],
        }
