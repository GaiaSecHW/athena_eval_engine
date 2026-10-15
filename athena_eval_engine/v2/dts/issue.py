"""问题单生成模块。

从因果链分析结果的 per_case_breakpoints 生成问题单。
每个断点生成一条记录，映射到对应的责任方（Agent 或 knowledge_base）。
"""
from __future__ import annotations

from ...infrastructure.log_util import log

# ── 成因码→描述映射（§4.1 断点→成因映射）──

CAUSE_DESCRIPTIONS = {
    "A": "该查没查（召回意识不足）",
    "B": "查询太泛（查询不聚焦）",
    "C": "查了没得（知识覆盖度不足）",
    "D": "链路问题（工具失败/超时）",
    "E": "查到没用（死知识，推理未引用）",
    "F": "用了没推动（未影响结论）",
    "G": "导致误判（知识内容有误/过时/不适用）",
}

# ── 成因码→责任方映射 ──
# A/B/E/F → Agent 责任（召回意识、查询聚焦、推理引用、结论推动）
# C/D/G   → knowledge_base 责任（知识覆盖度、工具链路、知识内容准确性）

CAUSE_TO_RESPONSIBILITY = {
    "A": "agent",
    "B": "agent",
    "C": "knowledge_base",
    "D": "knowledge_base",
    "E": "agent",
    "F": "agent",
    "G": "knowledge_base",
}


def _build_breakpoint_desc(
    cause_code: str,
    break_level: str,
    evidence: str,
    vuln_type: str,
) -> str:
    """构建人类可读的断点描述。"""
    cause_desc = CAUSE_DESCRIPTIONS.get(cause_code, f"未知成因({cause_code})")
    parts: list[str] = [f"[{break_level}] {cause_desc}"]
    if vuln_type:
        parts.append(f"漏洞类型: {vuln_type}")
    if evidence:
        parts.append(f"证据: {evidence}")
    return " | ".join(parts)


def _determine_case_type(
    task_run_id: str,
    case_filter_stats: dict,
) -> str:
    """从 case_filter_stats 判断 case 类型（FP/FN）。

    case_filter_stats 包含 fp/fn case 的 task_run_id 集合。
    如果无法确定，默认 FP（因果链分析主要针对误报）。
    """
    if not case_filter_stats:
        return "FP"

    # case_filter_stats 可能有 fp_task_run_ids 或 fn_task_run_ids
    fp_ids = case_filter_stats.get("fp_task_run_ids", set())
    fn_ids = case_filter_stats.get("fn_task_run_ids", set())

    # 兼容 set 和 list
    if isinstance(fp_ids, (list, tuple)):
        fp_ids = set(fp_ids)
    if isinstance(fn_ids, (list, tuple)):
        fn_ids = set(fn_ids)

    if task_run_id in fp_ids:
        return "FP"
    if task_run_id in fn_ids:
        return "FN"

    # case_filter_stats 可能用 fp_cases/fn_cases 列表（每项含 case_id 或 task_run_id）
    fp_cases = case_filter_stats.get("fp_cases", [])
    fn_cases = case_filter_stats.get("fn_cases", [])
    for c in fp_cases:
        if isinstance(c, dict):
            if c.get("task_run_id") == task_run_id or c.get("case_id") == task_run_id:
                return "FP"
    for c in fn_cases:
        if isinstance(c, dict):
            if c.get("task_run_id") == task_run_id or c.get("case_id") == task_run_id:
                return "FN"

    return "FP"


def _lookup_fp_type(
    task_run_id: str,
    case_filter_stats: dict,
) -> str | None:
    """从 case_filter_stats 查找 fp_type（C1-C10）。

    如果 case_filter_stats 中包含 case→fp_type 映射，返回对应值；
    否则返回 None。
    """
    if not case_filter_stats:
        return None

    # 尝试从 fp_type_map 查找
    fp_type_map = case_filter_stats.get("fp_type_map", {})
    if fp_type_map and task_run_id in fp_type_map:
        return fp_type_map[task_run_id]

    # 尝试从 fp_cases 列表中查找
    fp_cases = case_filter_stats.get("fp_cases", [])
    for c in fp_cases:
        if isinstance(c, dict):
            cid = c.get("task_run_id") or c.get("case_id")
            if cid == task_run_id:
                return c.get("fp_type")

    return None


def _lookup_task_id(
    task_run_id: str,
    access_details: list[dict],
) -> str:
    """从 access_details 中查找 task_run_id 对应的 task_id。"""
    for rec in access_details:
        if rec.get("task_run_id") == task_run_id:
            return rec.get("task_id", "")
    return ""


def _lookup_access_id(
    task_run_id: str,
    cause_code: str,
    access_details: list[dict],
) -> str:
    """从 access_details 中查找对应断点的 access_id。

    按 task_run_id + cause_code 匹配，返回第一条匹配记录的 access_id。
    """
    for rec in access_details:
        if (rec.get("task_run_id") == task_run_id
                and rec.get("cause_code") == cause_code):
            return rec.get("access_id", "")
    return ""


def generate_dts_issues(
    evaluation_id: str,
    causal_chain_result: dict,
    access_details: list[dict],
    case_filter_stats: dict,
) -> list[dict]:
    """从因果链分析结果生成问题单。

    遍历 per_case_breakpoints，为每个断点生成一条记录。

    Args:
        evaluation_id: 评测 ID。
        causal_chain_result: CausalChainAnalyzer.analyze() 返回值，
            含 per_case_breakpoints 字段。
        access_details: knowledge_access_detail 记录列表，
            用于查找 task_id、access_id 等补充信息。
        case_filter_stats: CaseFilter 的 FPR 统计，
            含 fp/fn case 信息和 fp_type 映射。

    Returns:
        问题单 dict 列表，每条含 dts_id、evaluation_id、task_run_id、
        task_id、agent_type、case_type、fp_type、cause_code、
        breakpoint_level、access_id、breakpoint_desc、evidence_uri、status。
    """
    per_case_breakpoints = causal_chain_result.get("per_case_breakpoints", [])
    if not per_case_breakpoints:
        return []

    # 构建 task_run_id → access_details 的索引，加速查找
    _td_map: dict[str, list[dict]] = {}
    for rec in access_details:
        trid = rec.get("task_run_id", "")
        if trid:
            _td_map.setdefault(trid, []).append(rec)

    issues: list[dict] = []
    for case_entry in per_case_breakpoints:
        task_run_id = case_entry.get("case_id", "")
        vuln_type = case_entry.get("vuln_type", "")
        breakpoints = case_entry.get("breakpoints", [])

        case_type = _determine_case_type(task_run_id, case_filter_stats)
        fp_type = _lookup_fp_type(task_run_id, case_filter_stats)
        task_id = _lookup_task_id(task_run_id, access_details)

        for bp_idx, bp in enumerate(breakpoints):
            cause_code = bp.get("cause_code", "")
            if not cause_code:
                continue

            agent_type = bp.get("agent_type", "")
            break_level = bp.get("break_level", "")
            evidence = bp.get("evidence", "")

            access_id = _lookup_access_id(task_run_id, cause_code, access_details)
            responsibility = CAUSE_TO_RESPONSIBILITY.get(cause_code, "agent")

            dts_id = f"{evaluation_id}_{task_run_id}_{access_id}_{bp_idx}"
            breakpoint_desc = _build_breakpoint_desc(
                cause_code, break_level, evidence, vuln_type,
            )

            issues.append({
                "dts_id": dts_id,
                "evaluation_id": evaluation_id,
                "task_run_id": task_run_id,
                "task_id": task_id,
                "agent_type": agent_type,
                "case_type": case_type,
                "fp_type": fp_type,
                "cause_code": cause_code,
                "breakpoint_level": break_level,
                "access_id": access_id,
                "breakpoint_desc": breakpoint_desc,
                "evidence_uri": evidence[:512] if evidence else None,
                "root_cause": None,
                "solution": None,
                "replay_eval_id": None,
                "replay_result": None,
                "status": "unlocated",
                "responsibility": responsibility,
            })

    log("DTS", f"generated {len(issues)} DTS issues for eval={evaluation_id}")
    return issues
