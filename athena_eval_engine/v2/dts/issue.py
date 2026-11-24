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
    """取置信度最高的一条假定线索，仅用于问题单顶层的展示摘要。

    线索不是结论：每个 case 可以有多条并存的假定线索，各自带置信度，
    详情页按置信度降序逐条展示。这里取第一条只是为了填充单值字段
    （cause_code / breakpoint_level），不代表其他线索被否定。
    """
    if not hypotheses:
        return None
    valid = [h for h in hypotheses if isinstance(h, dict)]
    if not valid:
        return None
    eligible = [h for h in valid
                if float(h.get("confidence", 0.7) or 0) >= 0.7]
    pool = eligible or valid
    # 排序：标注匹配度（annotation_fit）降序优先，缺省回退证据支撑度
    # （旧数据兼容）；同级按证据支撑度、最早断裂 L、证据数、cause_code
    # 做确定性 tie-break。展示/过滤门槛仍在证据支撑度（confidence）。
    def _fit(h):
        try:
            return float(h.get("annotation_fit",
                                h.get("confidence", 0.5)) or 0.5)
        except (TypeError, ValueError):
            return 0.5
    return sorted(
        pool,
        key=lambda h: (
            -_fit(h),
            -float(h.get("confidence", 0) or 0),
            _LEVEL_RANK.get(
                CAUSE_TO_LEVEL.get(str(h.get("cause_code") or ""), ""), 99),
            -len(h.get("evidence_refs") or []),
            str(h.get("cause_code") or "Z"),
        ),
    )[0]


# ── 人工标注分类（FP 误报原因下拉值，完整清单）──
# 问题单的作用是把修复路由到平台方可落地的修复点（agent prompt/code、
# 知识库、数据供给、评测流程）。责任不在平台侧的分类不生成问题单，
# 仍计入报告统计。

# 人工分类 → 是否无条件跳过问题单生成
# 模型幻觉：修复方是基础模型本身，平台无可落地修复点——不生成单
# （幻觉聚集时由看板统计趋势触发流程级改进，不是逐 case 单）；
# 但分类是现象级粗标签，分析发现可修根因（如缺知识导致的"编造"）时
# 照常生成，故不放这里、按分析结果条件跳过（见 _has_actionable_fix）。
_NON_ISSUE_CATEGORIES = {"其他非平台工具原因"}

# 平台可落地的修复通道（fix_suggestion.target 合法值）
_ACTIONABLE_FIX_TARGETS = {
    "agent_prompt", "agent_code", "knowledge", "memory",
    "external_data_source", "eval_process",
}

# 人工标注分类全量集合（解析校验用）
# 注意：「输入实际不可控或已过滤校验」与「输入实际可控或已过滤校验」是
# 平台下拉中同时存在的两个变体（存量数据中前者 175 条），均照常生成单。
_FP_CATEGORIES = {
    "模型幻觉", "重复上报", "判断错误", "测试/示例代码",
    "输入实际可控或已过滤校验", "输入实际不可控或已过滤校验",
    "上下文不足导致", "业务场景需要",
    "有框架防御但未提供", "其他误报原因", "其他非平台工具原因",
}


def is_label_confirm_knowledge_gap(case: dict) -> bool:
    """判定「标注前提待确认 + 顶层根因知识缺失」的应不建单 case。

    条件（两个都是，缺一不可）：
    - 有 session 的链**全部** needs_label_confirmation——分析自己声明
      「标注前提无法从 session 材料验证，需标注人先确认」；
    - 顶层根因是 C（查了没得）：修复方向是补充知识库，但**补什么知识
      取决于未确认的标注前提**（follow_up_questions 指向标注人）——
      先有鸡还是先有蛋，单不可落地，确认标注后再重新分析建单。

    与 generate_dts_issues 的跳过条件、报告 skipped 清单、
    /dts/regenerate 的定向清理共用本函数（单一权威源）。
    """
    mining = case.get("mining") or {}
    verify = case.get("verification") or {}
    active = [c for c in (mining, verify) if c.get("session_chain")]
    if not active:
        return False
    if not all((c.get("label_quality") or {}).get(
            "needs_label_confirmation") for c in active):
        return False
    # 顶层线索候选池与问题单生成同规则：FP 只取挖掘链（验证链回答
    # 「为什么没拦住」，不顶替 FP 根因）；FN 混池
    mining_hyps = mining.get("hypotheses") or []
    if (str(case.get("outcome") or "FP").upper() != "FN"
            and mining_hyps):
        pool = mining_hyps
    else:
        pool = mining_hyps + (verify.get("hypotheses") or [])
    if not pool:
        return False
    top = _pick_primary_hypothesis(pool)
    return bool(top and str(top.get("cause_code") or "") == "C")


def is_kb_annotation_conflict(case: dict) -> bool:
    """判定「知识库证据与人工标注矛盾」的应不建单 case（conflict 态）。

    L4 独立验证命中知识且方向为 conflict——知识内容直接反驳人工标注的
    误报前提（如标注称「商用版本已关闭这些入口」，知识给出「入口并非
    默认关闭」的事实）。若知识为真，该上报不构成误报；agent 查到该知识
    反而会坐实自己的上报结论——「该查没查」的修复对消除此误报无效。

    标注与知识库必有一错，**复核先于归因**：先由标注人对照知识库文章
    复核——标注错 → 上报不是误报（基线更正）；知识错 → 误导性知识
    （修正/下架，负向知识路径）。复核前不建单（仍计报告统计）。

    复核默认方向（用户定稿）：业务事实类的误报前提必须有知识库/业务
    说明支撑——**无支撑说明的默认不成立（漏洞成立）**，标注方需提供
    业务说明佐证，否则撤回误报标注。
    """
    for chain_type in ("mining", "verification"):
        l4 = (case.get(chain_type) or {}).get(
            "l4_independent_verification") or {}
        if (l4.get("l4_knowledge_exists") is True
                and str(l4.get("l4_knowledge_direction") or "")
                == "conflict"):
            return True
    return False


def cleanup_stale_dts_issues(
    evaluation_id: str,
    root_cause_results: list[dict],
    generated_case_ids: set[str],
    reports_dir: str,
) -> dict:
    """定向清理：按当前规则不再生成问题单的旧行（备份后删除）。

    重跑/re-generate 后，case 属于跳过分类而不再生成——旧行先备份到
    ``{eid}_dts_stale_backup_{ts}.json`` 再删除（连带回归记录）：
    - 人工分类「其他非平台工具原因」（责任在平台之外，无修复方）；
    - 人工分类「模型幻觉」且线索全部无平台可落地修复方；
    - 标注前提待确认且顶层根因知识缺失（is_label_confirm_knowledge_gap）；
    - 知识库证据与人工标注矛盾（is_kb_annotation_conflict，L4 conflict）。

    证据不足等其他「无单」原因的旧行**不删**（历史语义保留）。
    重跑评测与 /dts/regenerate 共用本函数——保证「重跑后按当前规则
    不应存在的单被删掉」，而不是只有 regenerate 才清理。

    Returns:
        {"deleted_issues", "deleted_regression_results", "dts_ids",
         "stale_case_ids", "backup_path"}；备份写失败时抛异常并中止删除。
    """
    from datetime import datetime as _dt

    from ..persistence.dts_repo import (
        delete_dts_issues_by_ids,
        get_dts_issue,
        list_dts_issues,
        list_regression_results,
    )

    result: dict = {"deleted_issues": 0, "deleted_regression_results": 0,
                    "dts_ids": [], "stale_case_ids": [], "backup_path": None}
    stale_case_ids: set[str] = set()
    for r in root_cause_results:
        cid = str(r.get("case_id") or "")
        if not cid or cid in generated_case_ids:
            continue
        category = _annotation_category(_case_annotation(r))
        if category in _NON_ISSUE_CATEGORIES:
            stale_case_ids.add(cid)
        elif category == "模型幻觉":
            hyps = ((r.get("mining") or {}).get("hypotheses") or []) + \
                ((r.get("verification") or {}).get("hypotheses") or [])
            if not _has_actionable_fix(hyps):
                stale_case_ids.add(cid)
        elif is_label_confirm_knowledge_gap(r):
            stale_case_ids.add(cid)
        elif is_kb_annotation_conflict(r):
            stale_case_ids.add(cid)
    result["stale_case_ids"] = sorted(stale_case_ids)
    if not stale_case_ids:
        return result

    # 全行查询（list 精简列定位 → get 取全行），备份后删除
    rows, _total = list_dts_issues(evaluation_id=evaluation_id, limit=100000)
    stale_rows = [i for i in rows
                  if str(i.get("case_id", "")) in stale_case_ids]
    if not stale_rows:
        return result
    backup = []
    for i in stale_rows:
        full = get_dts_issue(str(i.get("dts_id", ""))) or {}
        full["regression_history"] = list_regression_results(
            str(i.get("dts_id", "")))
        backup.append(full)
    ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(
        reports_dir, f"{evaluation_id}_dts_stale_backup_{ts}.json")
    with open(backup_path, "w", encoding="utf-8") as f:
        json.dump(backup, f, ensure_ascii=False, indent=2)
    deleted = delete_dts_issues_by_ids(
        [str(i.get("dts_id", "")) for i in stale_rows],
        evaluation_id=evaluation_id,
    )
    result.update(deleted)
    result["backup_path"] = backup_path
    return result


def _annotation_category(fp_reason: str) -> str:
    """从人工标注解析 FP 分类（下拉值）。

    标注格式「误报：<分类>：<说明>」（冒号可能半角/全角），
    返回分类名；无法识别（不在下拉清单内）返回空串。
    """
    text = str(fp_reason or "").strip()
    # 前缀「误报：/误报:」可能半角/全角
    for prefix in ("误报：", "误报:"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    # 分类在首个分隔符之前；无分隔符时整段即候选
    for sep in ("：", ":"):
        if sep in text:
            cat = text.split(sep, 1)[0].strip()
            return cat if cat in _FP_CATEGORIES else ""
    return text if text in _FP_CATEGORIES else ""


def _case_annotation(case: dict) -> str:
    """取 case 的人工标注原文（挖掘链优先，FP 才有）。"""
    for chain_key in ("mining", "verification"):
        rc = (case.get(chain_key) or {}).get("root_cause") or {}
        reason = rc.get("human_confirmation_reason") or ""
        if reason:
            return reason
    return ""


def _has_actionable_fix(hypotheses: list) -> bool:
    """线索中是否存在平台可落地的修复点。

    可落地 = agent 可解决（agent_can_resolve）、或需外部数据
    （needed_external_data）、或 fix_suggestion 指向平台修复通道。
    """
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        if h.get("agent_can_resolve") is True:
            return True
        if h.get("needed_external_data"):
            return True
        if str((h.get("fix_suggestion") or {}).get("target")
               or "") in _ACTIONABLE_FIX_TARGETS:
            return True
    return False


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

    跳过问题单生成的 case（仍计入报告统计，不落 dts_issue 表）：
    - 证据不足（有 session 的链全部 insufficient_evidence）；
    - 人工分类「其他非平台工具原因」（无条件：责任在平台之外，无修复方）；
    - 人工分类「模型幻觉」且线索全部无平台可落地修复方（条件：分类是
      现象级粗标签，分析发现可修根因时照常生成）；
    - 标注前提待确认且顶层根因知识缺失（全部链 needs_label_confirmation
      + 顶层 C：补什么知识取决于未确认的标注前提，单不可落地——
      见 is_label_confirm_knowledge_gap）；
    - 知识库证据与人工标注矛盾（L4 conflict：知识反驳标注前提，标注与
      知识库必有一错，先标注复核——见 is_kb_annotation_conflict）。
    """
    per_case_breakpoints = causal_chain_result.get("per_case_breakpoints", [])
    if not per_case_breakpoints:
        return []

    # 从 root_cause_results 构建 case_id → 完整根因分析数据 索引
    case_full_data: dict[str, dict] = {}
    case_root_cause: dict[str, dict] = {}
    case_fix: dict[str, str] = {}
    case_hypotheses: dict[str, list] = {}
    case_mining_hypotheses: dict[str, list] = {}
    case_label_quality: dict[str, dict] = {}
    insufficient_cases: set[str] = set()
    # 按人工分类跳过问题单生成的 case（无平台侧可落地修复方）
    skip_issue_cases: set[str] = set()
    for case in root_cause_results:
        cid = case.get("case_id", "")
        if not cid:
            continue
        # 保存完整根因分析数据（供 DTS 详情页展示）
        case_full_data[cid] = case
        mining = case.get("mining", {}) or {}
        verify = case.get("verification", {}) or {}

        # ── 按人工分类跳过（无条件类）──
        # 责任在平台工具之外（上游数据/外部系统）→ 平台无修复点，不开单。
        # 分类文案有变体风险（如「输入实际不可控」与「可控」并存时曾
        # 静默漏识别）：解析不到分类时打日志暴露，避免新文案悄无声息
        # 失效跳过规则。
        _annotation_raw = _case_annotation(case)
        annotation_category = _annotation_category(_annotation_raw)
        if _annotation_raw and not annotation_category:
            log("DTS", f"case {cid}: 人工标注分类未识别"
                      f"（跳过规则不适用，照常生成）。标注开头: "
                      f"{_annotation_raw[:40]}")
        if annotation_category in _NON_ISSUE_CATEGORIES:
            skip_issue_cases.add(cid)
            log("DTS", f"case {cid}: 人工分类「{annotation_category}」"
                      f"无平台侧修复方，跳过问题单生成")
            continue

        # 证据不足的 case 不生成问题单，只在报告里列出原因。
        # 两条链独立：只有「有 session 的链全部证据不足」才完全不生成单；
        # 一条链证据不足、另一条有结论时，仍按有结论的链生成。
        active_chains = [c for c in (mining, verify) if c.get("session_chain")]
        if active_chains and all(
                c.get("insufficient_evidence") for c in active_chains):
            insufficient_cases.add(cid)
            continue

        # ── 从多线索提取根因和修复建议 ──
        all_hypotheses = []
        mining_hypotheses = []
        root_causes = {}
        fix_parts = []
        label_quality = {"precision": "precise", "reason": "", "follow_up_questions": []}
        for chain_type, chain_data in (("挖掘", mining), ("验证", verify)):
            # 兼容旧格式：如果没有 hypotheses，从 root_cause 构建
            chain_hypotheses = chain_data.get("hypotheses") or []
            if chain_hypotheses:
                all_hypotheses.extend(chain_hypotheses)
                if chain_type == "挖掘":
                    mining_hypotheses.extend(chain_hypotheses)
                # 从线索提取 fix_suggestion
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
                        # 附加线索信息
                        hyp_desc = h.get("hypothesis", "")
                        prob = h.get("probability", 0)
                        resp = h.get("responsibility", "")
                        if hyp_desc:
                            parts.append(f"线索(P={prob}, {resp}): {hyp_desc}")
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

        # ── FN 快捷路径合成线索 ──
        # sink_not_found / sink_found_no_report 由程序判定，不走 merge 阶段的
        # LLM 线索生成，导致 FN 问题单 hypotheses 为空。按「线索是问题载体」
        # 的原则，把 fn_miss 的漏报原因合成为一条线索供开发人员执行。
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
                # 作为合成线索的证据依据。confidence=0.5（次要结论）——
                # FN 合成线索不走 merge 阶段的证据卡校验体系，证据强度低于
                # FP 路径的 LLM 线索（confidence >= 0.7 才进入顶层摘要）。
                # 如果同一 case 同时有 FP 路径的 LLM 线索（confidence >= 0.7），
                # LLM 线索优先进入顶层摘要；FN 合成线索只作次要线索展示。
                miss_evidence = (fn.get("miss_detail") or {}).get("evidence", "")
                # 两种漏报场景的修复方向不同：
                # - sink_not_found：sink 点没被读到 → 扩大挖掘覆盖
                # - sink_found_no_report：sink 已命中但未识别 → 修正判定/推理/验证
                if fn.get("miss_category") == "sink_not_found":
                    fix_location = "挖掘范围/路径覆盖（sink 点未命中）"
                    fix_action = (
                        f"扩大挖掘覆盖：{reason}" if reason
                        else "扩大挖掘覆盖，确保 sink 点被读到"
                    )
                    fix_effect = "agent 能覆盖到该 sink 点，避免漏报"
                else:
                    fix_location = "漏洞判定/推理/验证（sink 已命中但未识别）"
                    fix_action = (
                        f"修正判定逻辑：{sub_label or reason}"
                        if (sub_label or reason)
                        else "修正判定逻辑，避免已命中的 sink 被忽略"
                    )
                    fix_effect = "agent 能在已定位 sink 的基础上正确判定并上报漏洞"
                all_hypotheses.append({
                    "hypothesis": reason or f"漏报：{fn.get('miss_category')}",
                    "probability": 0.9,
                    "responsibility": CAUSE_TO_RESPONSIBILITY.get(cause, "agent"),
                    "cause_code": cause,
                    "confidence": 0.5,
                    "evidence_refs": [],
                    "counter_evidence": "FN 合成线索：未走 merge 阶段证据卡校验",
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
                        "location": fix_location,
                        "action": fix_action,
                        "expected_effect": fix_effect,
                    },
                    "_synthesized_from_fn_miss": True,
                })

        case_hypotheses[cid] = all_hypotheses
        case_mining_hypotheses[cid] = mining_hypotheses
        case_label_quality[cid] = label_quality

        # ── 按人工分类跳过（条件类）──
        # 模型幻觉：修复方是基础模型本身，平台无可落地修复点。分类是
        # 现象级粗标签——分析发现可修根因（如缺知识导致的"编造"）时
        # 照常生成，仅在线索全部无平台修复方时跳过。
        if (annotation_category == "模型幻觉"
                and not _has_actionable_fix(all_hypotheses)):
            skip_issue_cases.add(cid)
            log("DTS", f"case {cid}: 人工分类「模型幻觉」且无线索含平台"
                      f"可落地修复方，跳过问题单生成")
            continue
        # ── 标注前提待确认 + 顶层根因知识缺失 → 不建单 ──
        # 全部分析链声明「标注前提无法从 session 材料验证，需标注人先
        # 确认」，且顶层根因是 C（查了没得）：修复方向是补知识库，但补
        # 什么知识取决于未确认的标注前提（follow_up_questions 指向标注
        # 人）——单不可落地。先确认标注，再重新分析建单。
        if is_label_confirm_knowledge_gap(case):
            skip_issue_cases.add(cid)
            log("DTS", f"case {cid}: 标注前提待确认（全链 "
                      f"needs_label_confirmation）且顶层根因为 C（知识"
                      f"缺失），先确认标注再分析，跳过问题单生成")
            continue
        # ── 知识库证据与人工标注矛盾（L4 conflict）→ 不建单 ──
        # L4 查到的知识直接反驳标注的误报前提——agent 查到该知识反而
        # 坐实自己的上报结论，「该查没查」的修复无法消除此误报。
        # 标注与知识库必有一错：先标注复核（对照知识库文章），
        # 标注错 → 基线更正；知识错 → 修正/下架。复核前不建单。
        if is_kb_annotation_conflict(case):
            skip_issue_cases.add(cid)
            log("DTS", f"case {cid}: 知识库证据与人工标注矛盾"
                      f"（L4 conflict），先标注复核，跳过问题单生成")
            continue
        # 兼容旧格式：如果没有线索但有 root_causes
        if all_hypotheses:
            # 顶层摘要按置信度最高的一条线索选取，不看 probability；
            # primary_cause 缺失时选证据最多者，并列按 cause_code 字母序。
            # FP 单顶层要回答「误报为什么产生」——候选池只取挖掘链线索
            # （验证链线索回答「为什么没拦住」，属另一问题，不顶替 FP 根因）；
            # 挖掘链无线索时回退全池。FN 保持混池：挖掘（没找到）与
            # 验证（K 否定真漏洞）都解释漏报。
            top_pool = all_hypotheses
            if (str(case.get("outcome") or "FP").upper() != "FN"
                    and mining_hypotheses):
                top_pool = mining_hypotheses
            top = _pick_primary_hypothesis(top_pool)
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
        # 人工分类无平台侧修复方的 case 不生成问题单（仅计统计）
        if case_id in skip_issue_cases:
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

        # 即使没有断点也要建 key——只有线索的 case 同样要生成问题单
        grouped.setdefault(case_id, [])
        for bp in breakpoints:
            cause_code = bp.get("cause_code", "")
            if not cause_code:
                continue
            grouped[case_id].append(bp)

    # 跨 agent 去重：同一 case 内 cause_code + 级别 + session 完全相同的断点只保留一条
    # （mining 和 verification 可能各自产生相同的 L8 断点）。
    # 必须带 session_id——不同 session 是不同证据；按 evidence 文本去重会因
    # 模型措辞不同而时合时分，导致断点数在两次评测间漂移。
    for case_id, bps in grouped.items():
        seen = set()
        deduped = []
        for bp in bps:
            key = (bp.get("cause_code", ""), bp.get("break_level", ""),
                   bp.get("session_id", ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(bp)
        grouped[case_id] = deduped

    issues: list[dict] = []
    for case_id, bps in grouped.items():
        # 断点按最早断裂的 L 级别排序（升序）。
        # 原来用 _CAUSE_SEVERITY（G 最高，reverse=True）会导致问题单顶部
        # cause_code=A（最早断裂）但正文断点第一条=G（最严重），自相矛盾。
        bps.sort(key=lambda b: (
            _LEVEL_RANK.get(b.get("break_level", ""), 99),
            -len(b.get("supports_hypotheses") or []),
            str(b.get("cause_code") or "Z"),
        ))
        # 可能没有任何断点（只有线索的 case）
        primary = bps[0] if bps else {}
        vuln_title = case_vuln_titles.get(case_id, "")
        primary_cause_code = primary.get("cause_code", "")
        primary_break_level = primary.get("break_level", "")

        # 顶层 cause_code 与 break_level 同源：都取置信度最高的线索。
        # 两者分开取（cause_code 用线索、break_level 用最严重断点）会导致
        # 问题单顶部与正文自相矛盾（如线索 C/L4 但断点 H/L8）。
        hypotheses = case_hypotheses.get(case_id, [])
        label_quality = case_label_quality.get(case_id, {})
        if hypotheses:
            # 跨链摘要：同上，取置信度最高的线索；FP 单候选池只取挖掘链
            # （与上方 case_root_cause 的顶层选取同一规则，两处必须一致）。
            top_pool = hypotheses
            mining_hypotheses = case_mining_hypotheses.get(case_id) or []
            if (case_outcomes.get(case_id, "FP") != "FN"
                    and mining_hypotheses):
                top_pool = mining_hypotheses
            top_hyp = _pick_primary_hypothesis(top_pool)
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
            # 无断点（只有线索）：从 case 原始数据的 mining/verification 取
            full = case_full_data.get(case_id) or {}
            for chain_type in ("mining", "verification"):
                at = (full.get(chain_type) or {}).get("agent_type", "")
                if at and at not in agent_types:
                    agent_types.append(at)
        agent_type = ",".join(agent_types)

        # 责任方：优先从线索的 responsibility 推导（多值逗号分隔）
        # 一个 case 可能同时有 agent 责任（如 L8）和知识库责任（如 L4）
        # 无线索时回退到从断点 cause_code 推导
        if hypotheses:
            resp_set = {h.get("responsibility", "") for h in hypotheses if h.get("responsibility")}
            # 线索的 responsibility 可能是 agent/knowledge/external_data_source/eval_process
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
        session_chains_snapshot = None
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

        # session 调用链快照：生成时固化，页面不再依赖 session_graph 实时状态
        if full_data:
            try:
                from ..persistence.dts_repo import build_session_chains_snapshot
                session_chains_snapshot = build_session_chains_snapshot(
                    evaluation_id, full_data)
            except Exception as e:
                log("DTS", f"固化 session 链失败 case={case_id}: {e}")

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
            "session_chains": session_chains_snapshot,
            "replay_eval_id": None,
            "replay_result": None,
            "status": "open",
            "responsibility": responsibility,
        })

    log("DTS", f"generated {len(issues)} DTS issues for eval={evaluation_id}")
    return issues
