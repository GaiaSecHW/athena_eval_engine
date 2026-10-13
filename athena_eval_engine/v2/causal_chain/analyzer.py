"""因果链断点分析模块（§4.2）。

基于 knowledge_access_detail 的判定结果，按 Agent 类型聚合误报归因。
L0 不参与此模块逻辑——L0 仅标记知识原始来源 provenance，不产生断链。

输入：knowledge_access_detail 表中该 evaluation 的全部记录
输出：
  - 交叉归因矩阵：Agent 类型（行）× L2-L7 级别（列）
  - 成因汇总（cause_code A-G 计数）
  - 效果标签分布（POSITIVE/NEGATIVE/NEUTRAL/NULL）
  - 每 case 的断点清单
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from ..infra.database import connect
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

# 所有 effect_label（含 NULL——DB 中 effect_label 为 NULL 时表示证据不足）
_ALL_EFFECTS = ["POSITIVE", "NEGATIVE", "NEUTRAL", "NULL"]


class CausalChainAnalyzer:
    """因果链断点分析器。

    基于 knowledge_access_detail 已有的 L1-L7 判定结果聚合。
    不执行 L0-L7 判定（那是 LifecycleAnalyzer 的职责），只做聚合统计。
    """

    def analyze(self, evaluation_id: str, access_details: list[dict]) -> dict:
        """基于 knowledge_access_detail 的判定结果，按 Agent 类型聚合误报归因。

        Args:
            evaluation_id: 评测 ID。
            access_details: knowledge_access_detail 记录列表（dict），每条含
                            cause_code、effect_label、task_run_id 等字段。

        Returns:
            因果链分析结果 dict，结构见模块 docstring。
        """
        log("CAUSAL_CHAIN",
            f"analyze: {len(access_details)} access details for eval={evaluation_id}",
            eval_id=evaluation_id)

        if not access_details:
            log("CAUSAL_CHAIN",
                f"no access details for eval={evaluation_id}, returning empty result",
                eval_id=evaluation_id)
            return self._empty_result(evaluation_id)

        # 从 DB 补充 FP case 集合（outcome_fact 表中 validation_result='FALSE_POSITIVE'）
        fp_task_run_ids = self._load_fp_task_run_ids(evaluation_id)

        cross_attribution_matrix = self._build_cross_attribution_matrix(access_details)
        cause_summary = self._build_cause_summary(access_details)
        effect_label_distribution = self._build_effect_label_distribution(access_details)
        per_case_breakpoints = self._build_per_case_breakpoints(access_details)

        result = {
            "evaluation_id": evaluation_id,
            "cross_attribution_matrix": cross_attribution_matrix,
            "cause_summary": cause_summary,
            "effect_label_distribution": effect_label_distribution,
            "per_case_breakpoints": per_case_breakpoints,
        }

        log("CAUSAL_CHAIN",
            f"analyze done: {len(per_case_breakpoints)} cases with breakpoints, "
            f"{len(fp_task_run_ids)} FP cases, "
            f"cause_summary={cause_summary}",
            eval_id=evaluation_id)

        return result

    # ── 交叉归因矩阵 ──

    def _build_cross_attribution_matrix(self, access_details: list[dict]) -> dict:
        """构建 Agent 类型 × L2-L7 级别的交叉归因矩阵。

        从 access_details 中按 agent_type 分组，统计每个 Agent 在各 L 级别的断点数。
        断点级别由 cause_code 反推（CAUSE_TO_LEVEL 映射）。

        只有 cause_code 非空的记录才计入断点矩阵——cause_code 为 None 表示
        该访问无断点（L1=False 短路或 L6=True 待 L7 判定且 L7 正向）。
        """
        # 初始化矩阵：{agent_type: {L2: 0, L3: 0, ...}}
        matrix: dict[str, dict[str, int]] = {
            agent_type: {level: 0 for level in _ALL_LEVELS}
            for agent_type in _ALL_AGENT_TYPES
        }

        for rec in access_details:
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

    def _build_cause_summary(self, access_details: list[dict]) -> dict:
        """统计各 cause_code 的数量。

        Returns:
            {"A": 8, "B": 3, ...} — 所有 A-H 键都存在，值为计数。
        """
        counter: Counter = Counter()
        for rec in access_details:
            cause_code = rec.get("cause_code")
            if cause_code:
                counter[cause_code] += 1

        # 确保所有 cause_code 都在结果中
        return {code: counter.get(code, 0) for code in _ALL_CAUSES}

    # ── 效果标签分布 ──

    def _build_effect_label_distribution(self, access_details: list[dict]) -> dict:
        """统计 effect_label 的分布。

        effect_label 可为 POSITIVE / NEGATIVE / NEUTRAL / NULL（DB 中为 NULL）。
        """
        counter: Counter = Counter()
        for rec in access_details:
            effect = rec.get("effect_label")
            if effect:
                counter[effect] += 1
            else:
                # DB 中 NULL → 显示为 "NULL"
                counter["NULL"] += 1

        return {label: counter.get(label, 0) for label in _ALL_EFFECTS}

    # ── 每 case 断点清单 ──

    def _build_per_case_breakpoints(self, access_details: list[dict]) -> list[dict]:
        """按 case 分组，列出每个 case 的断点清单。

        一个 case 可能有多个断点（多次知识访问，每次可能有各自的断点）。
        只有 cause_code 非空的记录才产生断点条目。

        Returns:
            [{"case_id": ..., "vuln_type": ..., "breakpoints": [...]}, ...]
        """
        # 按 task_run_id 分组
        case_map: dict[str, list[dict]] = defaultdict(list)
        for rec in access_details:
            cause_code = rec.get("cause_code")
            if not cause_code:
                continue  # 无断点的记录不计入

            task_run_id = rec.get("task_run_id", "")
            case_map[task_run_id].append(rec)

        result: list[dict] = []
        for task_run_id, records in case_map.items():
            breakpoints: list[dict] = []
            vuln_type = ""

            for rec in records:
                cause_code = rec.get("cause_code", "")
                level = CAUSE_TO_LEVEL.get(cause_code, "")

                # 收集漏洞类型（从 evidence_json 或 judgment_conclusion 中提取）
                if not vuln_type:
                    vuln_type = self._extract_vuln_type(rec)

                # 构建证据摘要
                evidence = self._build_evidence(rec)

                breakpoints.append({
                    "agent_type": rec.get("agent_type", ""),
                    "break_level": level,
                    "cause_code": cause_code,
                    "evidence": evidence,
                })

            result.append({
                "case_id": task_run_id,
                "vuln_type": vuln_type,
                "breakpoints": breakpoints,
            })

        return result

    # ── 辅助方法 ──

    def _load_fp_task_run_ids(self, evaluation_id: str) -> set[str]:
        """从 outcome_fact 表加载 FP case 的 task_run_id 集合。

        FP case = validation_result = 'FALSE_POSITIVE' 的 task_run。
        """
        fp_ids: set[str] = set()

        conn = None
        try:
            conn = connect(autocommit=True)
            cur = conn.cursor()
            cur.execute(
                "SELECT task_run_id FROM outcome_fact "
                "WHERE evaluation_id = %s AND validation_result = 'FALSE_POSITIVE'",
                (evaluation_id,),
            )
            for row in cur.fetchall():
                fp_ids.add(row[0])
        except Exception as e:
            log("CAUSAL_CHAIN",
                f"load FP task_run_ids failed: {str(e)[:200]}",
                eval_id=evaluation_id)
            # 不跳过——向上抛出，遵循"禁止降级跳过"铁律
            raise
        finally:
            if conn is not None:
                conn.close()

        return fp_ids

    def _extract_vuln_type(self, rec: dict) -> str:
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

    def _build_evidence(self, rec: dict) -> str:
        """从 knowledge_access_detail 记录构建断点证据摘要。

        组合 query_content + returned_content + reasoning_ref + breakpoint 信息，
        截取关键部分作为证据。
        """
        parts: list[str] = []

        cause_code = rec.get("cause_code", "")
        cause_desc = self._cause_description(cause_code)
        if cause_desc:
            parts.append(f"断点: {cause_desc}")

        query = rec.get("query_content", "")
        if query:
            parts.append(f"查询: {str(query)[:200]}")

        returned = rec.get("returned_content", "")
        if returned:
            parts.append(f"返回: {str(returned)[:200]}")

        reasoning = rec.get("reasoning_ref", "")
        if reasoning:
            parts.append(f"引用: {str(reasoning)[:200]}")

        judgment = rec.get("judgment_conclusion", "")
        if judgment:
            parts.append(f"结论: {str(judgment)[:100]}")

        # 从 evidence_json 提取 breakpoint 描述
        evidence_json = rec.get("evidence_json")
        if evidence_json:
            try:
                if isinstance(evidence_json, str):
                    parsed = json.loads(evidence_json)
                else:
                    parsed = evidence_json
                if isinstance(parsed, dict):
                    bp = parsed.get("breakpoint")
                    cause = parsed.get("cause")
                    if bp and cause:
                        parts.append(f"L{bp}: {cause}")
            except (json.JSONDecodeError, TypeError):
                pass

        return " | ".join(parts) if parts else ""

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
        """空结果（无 access_details 时返回）。"""
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
