"""问题单生成模块。

从因果链分析结果的 per_case_breakpoints 生成问题单。
每个断点生成一条记录，映射到对应的责任方（Agent 或 knowledge_base）。
完整根因分析数据（session_chain、compressed_summaries、l0_l7_breakpoints 等）
存到 {eid}_dts_{case_id}.json 文件，DTS issue 表只存路径。
"""
from __future__ import annotations

import json
import os
import uuid

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
# C/D/G     → knowledge 责任（知识覆盖度、工具链路、知识内容准确性）

CAUSE_TO_RESPONSIBILITY = {
    "A": "agent",
    "B": "agent",
    "C": "knowledge",
    "D": "knowledge",
    "E": "agent",
    "F": "agent",
    "G": "knowledge",
    "H": "agent",
}

# ── fix_suggestion.target → 中文标签 ──

_TARGET_LABELS = {
    "agent_prompt": "Agent提示词",
    "agent_code": "Agent代码",
    "knowledge": "知识库",
    "external_data_source": "外部数据源",
    "eval_process": "评测流程",
}


def _build_breakpoint_desc(
    cause_code: str,
    break_level: str,
    evidence: str,
) -> str:
    """构建人类可读的断点描述。

    漏洞标题已在问题单顶部展示，此处不再重复。
    """
    cause_desc = CAUSE_DESCRIPTIONS.get(cause_code, f"未知成因({cause_code})")
    parts: list[str] = [f"[{break_level}] {cause_desc}"]
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

    按 case_id 分组——一个误报 case 只提一条单，
    挖掘 agent 和验证 agent 的断点全部合并在同一条单里，
    agent_type 字段收集所有涉及的 agent（逗号分隔）。
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
        agent_type（逗号分隔多值）、case_type、cause_code、breakpoint_level、
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
    case_hypotheses: dict[str, list] = {}
    case_label_quality: dict[str, dict] = {}
    for case in root_cause_results:
        cid = case.get("case_id", "")
        if not cid:
            continue
        # 保存完整根因分析数据（供 DTS 详情页展示）
        case_full_data[cid] = case
        mining = case.get("mining", {}) or {}
        verify = case.get("verification", {}) or {}

        # ── 从多假设提取根因和修复建议 ──
        all_hypotheses = []
        root_causes = {}
        fix_parts = []
        label_quality = {"precision": "precise", "reason": "", "follow_up_questions": []}
        for chain_type, chain_data in (("挖掘", mining), ("验证", verify)):
            # 兼容旧格式：如果没有 hypotheses，从 root_cause 构建
            chain_hypotheses = chain_data.get("hypotheses") or []
            if chain_hypotheses:
                all_hypotheses.extend(chain_hypotheses)
                # 从假设提取 fix_suggestion
                for h in chain_hypotheses:
                    fs = h.get("fix_suggestion")
                    if isinstance(fs, dict):
                        target = fs.get("target", "")
                        location = fs.get("location", "")
                        action = fs.get("action", "")
                        expected = fs.get("expected_effect", "")
                        if not (target or location or action):
                            continue
                        parts = [f"[{chain_type}链]"]
                        if target:
                            parts.append(f"修复方: {_TARGET_LABELS.get(target, target)}")
                        if location:
                            parts.append(f"位置: {location}")
                        if action:
                            parts.append(f"修改: {action}")
                        if expected:
                            parts.append(f"预期: {expected}")
                        # 附加假设信息
                        hyp_desc = h.get("hypothesis", "")
                        prob = h.get("probability", 0)
                        resp = h.get("responsibility", "")
                        if hyp_desc:
                            parts.append(f"假设(P={prob}, {resp}): {hyp_desc}")
                        fix_parts.append(" | ".join(parts))
            else:
                # 兼容旧格式：从 root_cause + fix_suggestion 构建
                rc = chain_data.get("root_cause", {})
                if rc:
                    cat = rc.get("category", "")
                    desc = rc.get("description", "")
                    if cat and cat not in ("no_session", "llm_error", "unknown"):
                        root_causes[cat] = desc
                fs_list = chain_data.get("fix_suggestion") or []
                if isinstance(fs_list, list) and fs_list:
                    for fs in fs_list:
                        if not isinstance(fs, dict):
                            continue
                        target = fs.get("target", "")
                        location = fs.get("location", "")
                        action = fs.get("action", "")
                        expected = fs.get("expected_effect", "")
                        if not (target or location or action):
                            continue
                        parts = [f"[{chain_type}链]"]
                        if target:
                            parts.append(f"修复方: {_TARGET_LABELS.get(target, target)}")
                        if location:
                            parts.append(f"位置: {location}")
                        if action:
                            parts.append(f"修改: {action}")
                        if expected:
                            parts.append(f"预期: {expected}")
                        fix_parts.append(" | ".join(parts))
            # 合并 label_quality（取 imprecise 优先）
            lq = chain_data.get("label_quality") or {}
            if lq.get("precision") == "imprecise":
                label_quality = lq

        case_hypotheses[cid] = all_hypotheses
        case_label_quality[cid] = label_quality
        # 兼容旧格式：如果没有假设但有 root_causes
        if all_hypotheses:
            # 从最高概率假设提取 root_cause
            top = max(all_hypotheses, key=lambda h: h.get("probability", 0)) if all_hypotheses else None
            if top:
                root_causes = {
                    "hypothesis": top.get("hypothesis", ""),
                    "probability": top.get("probability", 0),
                    "responsibility": top.get("responsibility", ""),
                    "evidence": top.get("evidence", ""),
                }
        case_root_cause[cid] = root_causes
        case_fix[cid] = "\n".join(fix_parts) if fix_parts else ""

    # 按 case_id 分组，所有 agent 的断点合并到同一条单
    grouped: dict[str, list[dict]] = {}
    case_vuln_titles: dict[str, str] = {}
    for case_entry in per_case_breakpoints:
        case_id = case_entry.get("case_id", "")
        vuln_title = case_entry.get("vuln_title", "")
        if not case_id:
            continue
        if vuln_title and case_id not in case_vuln_titles:
            case_vuln_titles[case_id] = vuln_title
        breakpoints = case_entry.get("breakpoints", [])

        for bp in breakpoints:
            cause_code = bp.get("cause_code", "")
            if not cause_code:
                continue
            grouped.setdefault(case_id, []).append(bp)

    # 跨 agent 去重：同一 case 内 cause_code + break_level + evidence 完全相同的断点只保留一条
    # （mining 和 verification 可能各自产生相同的 L8 断点，内容一样无需重复展示）
    for case_id, bps in grouped.items():
        seen = set()
        deduped = []
        for bp in bps:
            key = (bp.get("cause_code", ""), bp.get("break_level", ""), bp.get("evidence", ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(bp)
        grouped[case_id] = deduped

    issues: list[dict] = []
    for case_id, bps in grouped.items():
        # 按严重度排序，最严重的排前面
        bps.sort(key=lambda b: _CAUSE_SEVERITY.get(b.get("cause_code", ""), 0), reverse=True)
        primary = bps[0]
        vuln_title = case_vuln_titles.get(case_id, "")
        primary_cause_code = primary.get("cause_code", "")
        break_level = primary.get("break_level", "")

        # 多假设：优先取最高概率假设的 cause_code 作为主 cause_code
        # 若无假设（旧格式），回退到断点的 primary cause_code
        hypotheses = case_hypotheses.get(case_id, [])
        label_quality = case_label_quality.get(case_id, {})
        if hypotheses:
            top_hyp = max(hypotheses, key=lambda h: h.get("probability", 0))
            cause_code = top_hyp.get("cause_code", "") or primary_cause_code
        else:
            cause_code = primary_cause_code

        # 所有断点逐条列出，供开发人员排查
        bp_lines = []
        for bp in bps:
            bp_cause = bp.get("cause_code", "")
            bp_level = bp.get("break_level", "")
            bp_evidence = bp.get("evidence", "")
            bp_lines.append(
                _build_breakpoint_desc(bp_cause, bp_level, bp_evidence)
            )
        breakpoint_desc = "\n".join(bp_lines)

        # 多假设描述追加到 breakpoint_desc 末尾
        # 让开发人员看到所有可能的根因假设及其概率、责任方
        if hypotheses:
            hyp_lines = ["", "─" * 40, "多假设根因分析："]
            for i, h in enumerate(hypotheses, 1):
                hyp_desc = h.get("hypothesis", "")
                prob = h.get("probability", 0)
                resp = h.get("responsibility", "")
                can_resolve = h.get("agent_can_resolve", True)
                hyp_lines.append(
                    f"  假设{i} (P={prob}, 责任={resp}, "
                    f"agent可解决={'是' if can_resolve else '否'}): {hyp_desc}"
                )
                if not can_resolve:
                    blocked = h.get("blocked_by", "")
                    needed = h.get("needed_external_data", [])
                    if blocked:
                        hyp_lines.append(f"    阻塞: {blocked}")
                    if needed:
                        hyp_lines.append(f"    需外部数据: {', '.join(needed)}")
            breakpoint_desc = "\n".join(hyp_lines)

        root_cause = case_root_cause.get(case_id, {})
        fix_suggestion = case_fix.get(case_id, "")

        # agent_type：收集所有涉及的 agent，逗号分隔（如 "turing,webvuln_verify"）
        agent_types = []
        for bp in bps:
            at = bp.get("agent_type", "")
            if at and at not in agent_types:
                agent_types.append(at)
        agent_type = ",".join(agent_types)

        # 责任方：优先从假设的 responsibility 推导（多值逗号分隔）
        # 一个 case 可能同时有 agent 责任（如 L8）和知识库责任（如 L4）
        # 无假设时回退到从断点 cause_code 推导
        if hypotheses:
            resp_set = {h.get("responsibility", "") for h in hypotheses if h.get("responsibility")}
            # 假设的 responsibility 可能是 agent/knowledge/external_data_source/eval_process
            # 归一化：external_data_source 和 eval_process 保留原值
            resp_set = {r for r in resp_set if r}
        else:
            all_cause_codes = {bp.get("cause_code", "") for bp in bps if bp.get("cause_code")}
            resp_set = {CAUSE_TO_RESPONSIBILITY.get(cc, "agent") for cc in all_cause_codes}
        # 排序保证 agent 在前（agent 是主要责任方）
        resp_order = {"agent": 0, "knowledge": 1, "external_data_source": 2, "eval_process": 3}
        responsibility = ",".join(sorted(resp_set, key=lambda r: resp_order.get(r, 99)))

        # DTS-{8位随机hex}，不可猜测、无规律
        dts_id = f"DTS-{uuid.uuid4().hex[:8].upper()}"

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
            "hypotheses": json.dumps(hypotheses, ensure_ascii=False) if hypotheses else None,
            "label_quality": json.dumps(label_quality, ensure_ascii=False) if label_quality else None,
            "analysis_data_path": analysis_data_path,
            "replay_eval_id": None,
            "replay_result": None,
            "status": "open",
            "responsibility": responsibility,
        })

    log("DTS", f"generated {len(issues)} DTS issues for eval={evaluation_id}")
    return issues
