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

from ..causal_chain.analyzer import _FN_SUB_TO_CAUSE
from ..core.causal_levels import (
    CAUSE_TO_LEVEL,
    CAUSE_DESCRIPTIONS,
    CAUSE_TO_RESPONSIBILITY,
    LEVEL_RANK as _LEVEL_RANK,
    prefer_grounded_cause,
)
from ..infra.log_util import log

# 成因码→描述、责任方映射统一从 core.causal_levels 导入（单一权威源）。

# ── fix_suggestion.target → 中文标签 ──

_TARGET_LABELS = {
    "agent_prompt": "Agent提示词",
    "agent_code": "Agent代码",
    "knowledge": "知识库",
    "memory": "记忆/Wiki",
    "external_data_source": "外部数据源",
    "eval_process": "评测流程",
}

# ── fix_suggestion.agent_type → 中文标签（集中配置见 v2/core/agents.py）──
from ..core.agents import AGENT_DISPLAY_NAMES as _AGENT_TYPE_LABELS

# ── fix_suggestion.knowledge_source → 中文标签 ──
_KNOWLEDGE_SOURCE_LABELS = {
    "knowledge_base": "知识库",
    "memory_wiki": "记忆/Wiki",
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


# _LEVEL_RANK 从 core.causal_levels 导入（单一权威源）。


def _pick_primary_hypothesis(hypotheses: list) -> dict | None:
    """跨链选主因：按最早断裂的 L 级别；confidence<0.7 不参与。

    不能按「挖掘链在前、验证链在后」的顺序取第一个，否则验证链的
    L2/A 会被挖掘链的 L7/G 覆盖，导致同一 case 两次跑出不同主因。
    """
    if not hypotheses:
        return None
    valid = [h for h in hypotheses if isinstance(h, dict)]
    if not valid:
        return None
    eligible = [h for h in valid
                if float(h.get("confidence", 0.7) or 0) >= 0.7]
    # 已证实的知识误导(G)优先于未发起的访问(A)，避免 L1 判定波动导致
    # 同一 case 在 A/L2 与 G/L7 之间翻转；FN 合成假设不参与该规则。
    pool = prefer_grounded_cause(eligible) if eligible else valid
    return sorted(
        pool,
        key=lambda h: (
            _LEVEL_RANK.get(
                CAUSE_TO_LEVEL.get(str(h.get("cause_code") or ""), ""), 99),
            -len(h.get("evidence_refs") or []),
            str(h.get("cause_code") or "Z"),
        ),
    )[0]


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
    insufficient_cases: set[str] = set()
    for case in root_cause_results:
        cid = case.get("case_id", "")
        if not cid:
            continue
        # 保存完整根因分析数据（供 DTS 详情页展示）
        case_full_data[cid] = case
        mining = case.get("mining", {}) or {}
        verify = case.get("verification", {}) or {}

        # 证据不足的 case 不生成问题单，只在报告里列出原因。
        # 两条链独立：只有「有 session 的链全部证据不足」才完全不生成单；
        # 一条链证据不足、另一条有结论时，仍按有结论的链生成。
        active_chains = [c for c in (mining, verify) if c.get("session_chain")]
        if active_chains and all(
                c.get("insufficient_evidence") for c in active_chains):
            insufficient_cases.add(cid)
            continue

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

        # ── FN 快捷路径合成假设 ──
        # sink_not_found / sink_found_no_report 由程序判定，不走 merge 阶段的
        # LLM 假设生成，导致 FN 问题单 hypotheses 为空。按「假设是问题载体」
        # 的原则，把 fn_miss 的漏报原因合成为一条假设供开发人员执行。
        if not all_hypotheses:
            fn = case.get("fn_miss") or {}
            if fn.get("miss_category"):
                sub = (fn.get("miss_detail") or {}).get("miss_sub_category", "")
                sub_label = (fn.get("miss_detail") or {}).get(
                    "miss_sub_category_label", "")
                cause = _FN_SUB_TO_CAUSE.get(sub, "H")
                reason = fn.get("miss_reason", "")
                _fn_agent = ""
                for _ct in ("mining", "verification"):
                    _at = (case.get(_ct) or {}).get("agent_type", "")
                    if _at:
                        _fn_agent = _at
                        break
                # MissDetailAnalyzer 的 evidence 字段引用 session 事件原文，
                # 作为合成假设的证据依据。confidence=0.5（次要结论）——
                # FN 合成假设不走 merge 阶段的证据卡校验体系，证据强度低于
                # FP 路径的 LLM 假设（confidence >= 0.7 才能做主因）。
                # 如果同一 case 同时有 FP 路径的 LLM 假设（confidence >= 0.7），
                # LLM 假设优先做主因；FN 合成假设只作次要结论展示。
                miss_evidence = (fn.get("miss_detail") or {}).get("evidence", "")
                all_hypotheses.append({
                    "hypothesis": reason or f"漏报：{fn.get('miss_category')}",
                    "probability": 0.9,
                    "responsibility": CAUSE_TO_RESPONSIBILITY.get(cause, "agent"),
                    "cause_code": cause,
                    "confidence": 0.5,
                    "evidence_refs": [],
                    "counter_evidence": "FN 合成假设：未走 merge 阶段证据卡校验",
                    "evidence": (
                        f"fn_miss 程序判定：miss_category={fn.get('miss_category')}"
                        + (f"，细分成因={sub_label}" if sub_label else "")
                        + (f"\nLLM 事实依据：{miss_evidence}" if miss_evidence else "")
                    ),
                    # FN 合成断点不是知识访问断点，不引用 L0-L7
                    "supporting_breakpoints": [],
                    "agent_can_resolve": True,
                    "blocked_by": "",
                    "needed_external_data": [],
                    "fix_suggestion": {
                        "target": "agent_code",
                        "agent_type": _fn_agent,
                        "knowledge_source": "",
                        "location": "挖掘范围/路径覆盖（sink 点未命中）",
                        "action": (
                            f"扩大挖掘覆盖：{reason}" if reason
                            else "扩大挖掘覆盖，确保 sink 点被读到"
                        ),
                        "expected_effect": "agent 能覆盖到该 sink 点，避免漏报",
                    },
                    "_synthesized_from_fn_miss": True,
                })

        case_hypotheses[cid] = all_hypotheses
        case_label_quality[cid] = label_quality
        # 兼容旧格式：如果没有假设但有 root_causes
        if all_hypotheses:
            # 主因按各链的 primary_cause 选取，不看 probability；
            # primary_cause 缺失时选证据最多者，并列按 cause_code 字母序。
            # 跨链主因：按最早断裂的 L 级别选，不能按链顺序取第一个。
            top = _pick_primary_hypothesis(all_hypotheses)
            if top:
                root_causes = {
                    "hypothesis": top.get("hypothesis", ""),
                    "probability": top.get("probability", 0),
                    "responsibility": top.get("responsibility", ""),
                    "evidence": top.get("evidence", ""),
                    "cause_code": top.get("cause_code", ""),
                }
        case_root_cause[cid] = root_causes
        case_fix[cid] = "\n".join(fix_parts) if fix_parts else ""

    # 按 case_id 分组，所有 agent 的断点合并到同一条单
    grouped: dict[str, list[dict]] = {}
    case_vuln_titles: dict[str, str] = {}
    case_outcomes: dict[str, str] = {}
    for case_entry in per_case_breakpoints:
        case_id = case_entry.get("case_id", "")
        vuln_title = case_entry.get("vuln_title", "")
        if not case_id:
            continue
        # 证据不足的 case 不生成问题单
        if case_id in insufficient_cases:
            continue
        if vuln_title and case_id not in case_vuln_titles:
            case_vuln_titles[case_id] = vuln_title
        # outcome 决定 case_type：FP=误报，FN=漏报
        outcome = case_entry.get("outcome", "")
        if outcome == "FN":
            case_outcomes[case_id] = "FN"
        elif case_id not in case_outcomes:
            case_outcomes[case_id] = "FP"
        breakpoints = case_entry.get("breakpoints", [])

        # 即使没有断点也要建 key——只有假设的 case 同样要生成问题单
        grouped.setdefault(case_id, [])
        for bp in breakpoints:
            cause_code = bp.get("cause_code", "")
            if not cause_code:
                continue
            grouped[case_id].append(bp)

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
        # 按最早断裂的 L 级别排序（升序），与主因选择规则一致。
        # 原来用 _CAUSE_SEVERITY（G 最高，reverse=True）会导致问题单顶部
        # cause_code=A（最早断裂）但正文断点第一条=G（最严重），自相矛盾。
        bps.sort(key=lambda b: (
            _LEVEL_RANK.get(b.get("break_level", ""), 99),
            -len(b.get("supports_hypotheses") or []),
            str(b.get("cause_code") or "Z"),
        ))
        # 可能没有任何断点（只有假设的 case）
        primary = bps[0] if bps else {}
        vuln_title = case_vuln_titles.get(case_id, "")
        primary_cause_code = primary.get("cause_code", "")
        primary_break_level = primary.get("break_level", "")

        # 顶层 cause_code 与 break_level 同源：都取主因假设。
        # 两者分开取（cause_code 用假设、break_level 用最严重断点）会导致
        # 问题单顶部与正文自相矛盾（如假设 C/L4 但断点 H/L8）。
        hypotheses = case_hypotheses.get(case_id, [])
        label_quality = case_label_quality.get(case_id, {})
        if hypotheses:
            # 跨链主因：同上，按最早断裂的 L 级别选。
            top_hyp = _pick_primary_hypothesis(hypotheses)
            cause_code = (top_hyp or {}).get("cause_code", "") or primary_cause_code
            break_level = CAUSE_TO_LEVEL.get(cause_code, "") or primary_break_level
        else:
            cause_code = primary_cause_code
            break_level = primary_break_level

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

        root_cause = case_root_cause.get(case_id, {})
        fix_suggestion = case_fix.get(case_id, "")

        # agent_type：收集所有涉及的 agent，逗号分隔（如 "turing,webvuln_verify"）
        agent_types = []
        for bp in bps:
            at = bp.get("agent_type", "")
            if at and at not in agent_types:
                agent_types.append(at)
        if not agent_types:
            # 无断点（只有假设）：从 case 原始数据的 mining/verification 取
            full = case_full_data.get(case_id) or {}
            for chain_type in ("mining", "verification"):
                at = (full.get(chain_type) or {}).get("agent_type", "")
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

        # {12位随机hex}，不可猜测、无规律（48 位随机，碰撞概率可忽略）
        dts_id = uuid.uuid4().hex[:12].upper()

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
                log("DTS", f"写入完整分析数据失败 case={case_id}: {e}")

        issues.append({
            "dts_id": dts_id,
            "evaluation_id": evaluation_id,
            "task_id": task_id,
            "case_id": case_id,
            "vuln_title": vuln_title,
            "agent_type": agent_type,
            "case_type": case_outcomes.get(case_id, "FP"),
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
