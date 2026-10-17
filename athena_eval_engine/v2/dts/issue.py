"""问题单生成模块。

从因果链分析结果的 per_case_breakpoints 生成问题单。
每个断点生成一条记录，映射到对应的责任方（Agent 或 knowledge_base）。
完整根因分析数据（session_chain、compressed_summaries、l0_l7_breakpoints 等）
存到 {eid}_dts_{case_id}.json 文件，DTS issue 表只存路径。
"""
from __future__ import annotations

import json
import os

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
    "H": "其他（知识访问链路无问题，其他原因导致误报）",
}

# ── 成因码→责任方映射 ──
# A/B/E/F/H → Agent 责任（召回意识、查询聚焦、推理引用、结论推动、其他）
# C/D/G     → knowledge_base 责任（知识覆盖度、工具链路、知识内容准确性）

CAUSE_TO_RESPONSIBILITY = {
    "A": "agent",
    "B": "agent",
    "C": "knowledge_base",
    "D": "knowledge_base",
    "E": "agent",
    "F": "agent",
    "G": "knowledge_base",
    "H": "agent",
}


def _build_breakpoint_desc(
    cause_code: str,
    break_level: str,
    evidence: str,
    vuln_title: str,
) -> str:
    """构建人类可读的断点描述。"""
    cause_desc = CAUSE_DESCRIPTIONS.get(cause_code, f"未知成因({cause_code})")
    parts: list[str] = [f"[{break_level}] {cause_desc}"]
    if vuln_title:
        parts.append(f"漏洞标题: {vuln_title}")
    if evidence:
        parts.append(evidence)
    return "\n".join(parts)


# ── cause_code 严重度排序（G 最严重，A 最轻）──
_CAUSE_SEVERITY = {"G": 7, "H": 6, "F": 5, "E": 4, "D": 3, "C": 2, "B": 1, "A": 0}


def generate_dts_issues(
    evaluation_id: str,
    causal_chain_result: dict,
    root_cause_results: list[dict],
    task_id: str = "",
    reports_dir: str = "",
) -> list[dict]:
    """从因果链分析结果生成问题单。

    按 (case_id, agent_type) 分组——同一个 case 在同一个 agent 内只提一条单，
    所有断点全部列在 breakpoint_desc 中，供开发人员逐条排查。
    cause_code 和 breakpoint_level 取最严重的断点（严重度 G>F>...>A）。

    完整根因分析数据（mining + verification 的 session_chain、
    compressed_summaries、l0_l7_breakpoints、root_cause、fix_suggestion、
    merge_summary、l4_independent_verification、agent_type、vuln_title、
    summary、human_confirmation_summary、description）存到
    {eid}_dts_{case_id}.json 文件，DTS issue 表只存路径。

    Args:
        evaluation_id: 评测 ID。
        causal_chain_result: CausalChainAnalyzer.analyze() 返回值，
            含 per_case_breakpoints 字段。
        root_cause_results: RootCauseAnalyzer.analyze() 的输出，
            用于查找 case_id、vuln_title 等补充信息。
        task_id: 原始数据任务 ID（manifest 中的 task_id）。
        reports_dir: 报告目录，用于存储完整分析数据文件。

    Returns:
        问题单 dict 列表，每条含 dts_id、evaluation_id、task_id、case_id、
        agent_type、case_type、cause_code、breakpoint_level、
        breakpoint_desc、evidence_uri、root_cause、fix_suggestion、
        analysis_data_path、status、responsibility。
    """
    per_case_breakpoints = causal_chain_result.get("per_case_breakpoints", [])
    if not per_case_breakpoints:
        return []

    # 从 root_cause_results 构建 case_id → 完整根因分析数据 索引
    case_full_data: dict[str, dict] = {}
    case_root_cause: dict[str, dict] = {}
    case_fix: dict[str, str] = {}
    for case in root_cause_results:
        cid = case.get("case_id", "")
        if not cid:
            continue
        # 保存完整根因分析数据（供 DTS 详情页展示）
        case_full_data[cid] = case
        mining = case.get("mining", {}) or {}
        verify = case.get("verification", {}) or {}
        root_causes = {}
        fix_parts = []
        for chain_data in (mining, verify):
            rc = chain_data.get("root_cause", {})
            if rc:
                cat = rc.get("category", "")
                desc = rc.get("description", "")
                # 跳过无意义的占位根因
                if cat and cat not in ("no_session", "llm_error", "unknown"):
                    root_causes[cat] = desc
            fs = chain_data.get("fix_suggestion", "")
            if fs:
                fix_parts.append(fs)
        case_root_cause[cid] = root_causes
        case_fix[cid] = "\n".join(fix_parts) if fix_parts else ""

    # 按 (case_id, agent_type) 分组，所有断点合并到一条单
    grouped: dict[tuple[str, str], list[dict]] = {}
    for case_entry in per_case_breakpoints:
        case_id = case_entry.get("case_id", "")
        vuln_title = case_entry.get("vuln_title", "")
        breakpoints = case_entry.get("breakpoints", [])

        for bp in breakpoints:
            cause_code = bp.get("cause_code", "")
            if not cause_code:
                continue
            agent_type = bp.get("agent_type", "")
            key = (case_id, agent_type)
            bp["_vuln_title"] = vuln_title
            grouped.setdefault(key, []).append(bp)

    issues: list[dict] = []
    seq = 0
    for (case_id, agent_type), bps in grouped.items():
        # 按严重度排序，最严重的排前面
        bps.sort(key=lambda b: _CAUSE_SEVERITY.get(b.get("cause_code", ""), 0), reverse=True)
        primary = bps[0]
        vuln_title = primary.get("_vuln_title", "")
        cause_code = primary.get("cause_code", "")
        break_level = primary.get("break_level", "")

        # 所有断点逐条列出，供开发人员排查
        bp_lines = []
        for i, bp in enumerate(bps, 1):
            bp_cause = bp.get("cause_code", "")
            bp_level = bp.get("break_level", "")
            bp_evidence = bp.get("evidence", "")
            bp_lines.append(
                _build_breakpoint_desc(bp_cause, bp_level, bp_evidence, vuln_title)
            )
        breakpoint_desc = "\n".join(bp_lines)

        root_cause = case_root_cause.get(case_id, {})
        fix_suggestion = case_fix.get(case_id, "")
        responsibility = CAUSE_TO_RESPONSIBILITY.get(cause_code, "agent")

        seq += 1
        # DTS-{评测编号}-{序号}，评测编号取 evaluation_id 最后一段（7357）
        eval_seq = evaluation_id.split("-")[-1] if "-" in evaluation_id else evaluation_id[-4:]
        dts_id = f"DTS-{eval_seq}-{seq:02d}"

        # 完整根因分析数据存文件（遵循 Large Payload File Storage Over DB 原则）
        analysis_data_path = None
        full_data = case_full_data.get(case_id)
        if full_data and reports_dir:
            file_name = f"{evaluation_id}_dts_{case_id}.json"
            file_path = os.path.join(reports_dir, file_name)
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(full_data, f, ensure_ascii=False, indent=2)
                analysis_data_path = file_name
            except Exception as e:
                log("DTS", f"写入完整分析数据失败 case={case_id}: {str(e)[:200]}")

        issues.append({
            "dts_id": dts_id,
            "evaluation_id": evaluation_id,
            "task_id": task_id,
            "case_id": case_id,
            "vuln_title": vuln_title,
            "agent_type": agent_type,
            "case_type": "FP",
            "cause_code": cause_code,
            "breakpoint_level": break_level,
            "breakpoint_desc": breakpoint_desc,
            "evidence_uri": None,
            "root_cause": json.dumps(root_cause, ensure_ascii=False) if root_cause else None,
            "solution": fix_suggestion or None,
            "analysis_data_path": analysis_data_path,
            "replay_eval_id": None,
            "replay_result": None,
            "status": "unlocated",
            "responsibility": responsibility,
        })

    log("DTS", f"generated {len(issues)} DTS issues for eval={evaluation_id}")
    return issues
