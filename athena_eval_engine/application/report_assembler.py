"""Report Assembler - 组装评测报告。

不重算 Metric(只消费 MetricResult/StatisticalResult/DiagnosticHit)。
AI 叙述性结论按 §6.4.2 契约产出 JSON(接 LLM glm-5.2)。
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log
from ..workers.parse_utils import _extract_json_objects_from_text
from ..workers.webvulnverify_trace_parser import WebVulnVerifyTraceParser as _WebVVParser
_extract_webvv_task_data = _WebVVParser._extract_webvv_task_data
_extract_webvv_title = _WebVVParser._extract_webvv_title


@dataclass
class ReportModel:
    evaluation_id: str
    p0: dict = field(default_factory=dict)
    p1: dict = field(default_factory=dict)
    p2: dict = field(default_factory=dict)
    raw_stats: dict = field(default_factory=dict)
    diagnostic_hits: list = field(default_factory=list)
    narrative: dict = field(default_factory=dict)
    kg_analysis: dict = field(default_factory=dict)
    vuln_analysis: dict = field(default_factory=dict)
    per_case_kg_analysis: list = field(default_factory=list)
    metric_groups: list = field(default_factory=list)
    summary: str = ""
    coverage: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    llm_token_usage: dict = field(default_factory=dict)


def assemble(evaluation_id: str, metrics: list, stats: list,
             diagnostic_hits: list, coverage: dict | None = None,
             pair_views: list | None = None) -> ReportModel:
    m_by = {m.metric_id: m for m in metrics}
    s_by = {s.metric_id: s for s in stats if s.metric_id}
    joint = [s for s in stats if s.scope_type == "JOINT"]

    def _entry(mid):
        m = m_by.get(mid)
        s = s_by.get(mid)
        if not m:
            return None
        return {
            "estimate": m.estimate, "unit": m.unit, "n": m.n,
            "calculation_status": m.calculation_status, "reason_code": m.reason_code,
            "ci_lower": s.ci_lower if s else None, "ci_upper": s.ci_upper if s else None,
            "p_value": s.p_value if s else None, "median": m.median, "iqr": m.iqr,
            "method": m.method or {},
        }

    p0 = {mid: _entry(mid) for mid in ("M1", "M4", "M13", "M14")}
    p1 = {mid: _entry(mid) for mid in ("M5", "M6", "M7", "M11", "M12")}
    p2 = {mid: _entry(mid) for mid in ("M8", "M9", "M10")}

    raw = {"delta_fpr": None, "delta_tool_calls": None, "kg_query_count": None}

    narrative = _build_narrative(metrics, stats, diagnostic_hits)

    return ReportModel(
        evaluation_id=evaluation_id, p0=p0, p1=p1, p2=p2,
        raw_stats=raw, diagnostic_hits=[
            {"rule_id": h.rule_id, "observed": h.observed,
             "interpretation": h.interpretation, "suggestion": h.suggestion}
            for h in diagnostic_hits
        ],
        narrative=narrative, coverage=coverage or {},
        notes=["Knowledge Utilization = Not Observable", "不输出总分", "Evidence Mode: SINGLE_PAIRED_RUN"],
    )


def _build_narrative(metrics, stats, hits) -> dict:
    m_by = {m.metric_id: m for m in metrics}
    s_by = {s.metric_id: s for s in stats if s.metric_id}

    def _ref(mid, field_name):
        m = m_by.get(mid); s = s_by.get(mid)
        src = "statistical_result" if field_name.startswith("ci") else "metric_result"
        val = getattr(s, field_name, None) if src == "statistical_result" else getattr(m, field_name, None)
        return {"source": src, "metric_id": mid, "field": field_name, "value": val} if val is not None else None

    refs = [r for r in [_ref("M1", "estimate"), _ref("M1", "ci_lower"),
                        _ref("M4", "estimate"), _ref("M13", "estimate"),
                        _ref("M14", "estimate")] if r]
    m1 = m_by.get("M1")
    summary = f"BA={m1.estimate:.3f}" if m1 and m1.estimate is not None else "BA=NA"
    return {
        "summary": summary + "(rule-based v1)",
        "outcome_interpretation": summary,
        "risk_interpretation": "; ".join(h.observed for h in hits) or "no significant regression risk",
        "mechanism_interpretation": "; ".join(h.observed for h in hits if "JSD" in h.observed) or "no significant behavior shift",
        "cost_interpretation": "; ".join(h.observed for h in hits if "Token" in h.observed) or "no significant cost change",
        "limitations": ["SINGLE_PAIRED_RUN", "v1 rule-based narrative"],
        "evidence_refs": refs,
    }


def render_json(model: ReportModel) -> str:
    return json.dumps(model.__dict__, default=lambda o: o.__dict__, ensure_ascii=False, indent=2)


def ai_narrative(metrics: list, stats: list, hits: list, metric_groups: list = None, tool_stats: list = None) -> dict:
    """Stage 3 AI narrative (LLM glm-5.2)."""
    m_by = {m.metric_id: m for m in metrics}
    s_by = {s.metric_id: s for s in stats if s.metric_id}
    joint = [s for s in stats if s.scope_type == "JOINT"]

    # 漏洞验证报告不包含成本效率(M8/M9/M10)和行为偏移(M7)
    all_verify = metric_groups and all(g.get("category") == "verify" for g in metric_groups)
    if all_verify:
        _metric_ids = ("M1", "M4", "M5", "M6", "M11", "M12", "M13", "M14")
    else:
        _metric_ids = ("M1", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "M11", "M12", "M13", "M14")

    metric_data = []
    for mid in _metric_ids:
        m = m_by.get(mid)
        s = s_by.get(mid)
        if m:
            metric_data.append({
                "metric_id": mid, "estimate": m.estimate, "unit": m.unit, "n": m.n,
                "calculation_status": m.calculation_status,
                "ci_lower": s.ci_lower if s else None, "ci_upper": s.ci_upper if s else None,
                "p_value": s.p_value if s else None,
            })
    mc_data = {}
    if joint:
        mc = joint[0]
        mc_data = {"statistic": mc.statistic, "p_value": mc.p_value, "status": mc.status}

    # 构建分组指标数据（成本类 M8/M9/M10 按分组引用，漏洞验证分组跳过）
    group_cost_data = []
    if metric_groups and not all_verify:
        for g in metric_groups:
            if g.get("category") == "verify":
                continue
            tid = g.get("task_id", "")
            label = g.get("label", "")
            p2 = g.get("p2", {})
            entry = {"task_id": tid, "label": label}
            for mid in ("M8", "M9", "M10"):
                m = p2.get(mid)
                if m:
                    entry[mid] = {"estimate": m.get("estimate"), "unit": m.get("unit"),
                                  "calculation_status": m.get("calculation_status")}
            group_cost_data.append(entry)

    # 构建 finding 流转数据（T001 提交 → T002 接收 → T002 验证）
    finding_flow_data = []
    if tool_stats:
        # 按 task_id 分组，每组内分 KG/NOGK
        _by_task: dict[str, dict] = {}
        for ts in tool_stats:
            tid = ts.get("task_id", "unknown")
            cond = "KG" if "NOGK" not in (ts.get("condition") or ts.get("task_run_id", "")) else "NOGK"
            if tid not in _by_task:
                _by_task[tid] = {}
            _by_task[tid][cond] = {
                "submitted": ts.get("analyze_received_count", 0),  # 入口：提交/接收的疑似漏洞数
                "confirmed": ts.get("finding_count", 0),           # 出口：确认为漏洞的数
                "false_positive": ts.get("false_positive_count", 0),
            }
        for tid in sorted(_by_task.keys()):
            finding_flow_data.append({"task_id": tid, **_by_task[tid]})

    # 根据报告类型构建 prompt
    if all_verify:
        _metric_def = (
            "# 指标定义\n"
            "| ID | 名称 | 含义 | 方向 | 单位 |\n"
            "|----|------|------|------|------|\n"
            "| M1 | ΔBA 准确率变化 | KG与No-KG平衡准确率差值 | 正=KG更准 | ratio |\n"
            "| M4 | ΔFNR 漏报率变化 | KG与No-KG漏报率差值 | 负=KG漏报更少 | ratio |\n"
            "| M13 | ΔFPR 误报率变化 | KG与No-KG误报率差值 | 负=KG误报更少 | ratio |\n"
            "| M14 | ΔPrecision 精确率变化 | KG与No-KG精确率差值 | 正=KG更准 | ratio |\n"
            "| M5 | KAR 知识访问率 | 知识查询占工具调用比例 | 衡量知识依赖 | ratio |\n"
            "| M6 | KDR 知识交付率 | 知识查询有效回复比例 | 衡量知识质量 | ratio |\n"
            "| M11 | MAR 记忆访问率 | 记忆读取占工具调用比例 | 衡量记忆依赖 | ratio |\n"
            "| M12 | MDR 记忆交付率 | 记忆读取成功返回比例 | 衡量记忆质量 | ratio |\n\n"
        )
        _conclusion_schema = (
            "# 输出 JSON Schema\n"
            "{\n"
            '  "summary": "总结论(≤300字)。回答：知识图谱与记忆是否有帮助？引用关键数值，用中文名称。",\n'
            '  "conclusion": "分析结论(300-500字)。分两段写：'
            "第一段【准确性】：基于准确率变化、漏报率变化、误报率变化、精确率变化，分析KG对漏洞判定准确性的净影响。指标不可计算时说明原因。"
            "第二段【行为与知识】：基于知识访问率、知识交付率、记忆访问率、记忆交付率，分析Agent行为模式变化与知识/记忆依赖。"
            '最后附统计显著性：基于McNemar检验p值判断差异是否显著(p<0.05为显著)。若输入有诊断规则命中，在此一并说明。'
            '若输入包含漏洞流转数据，在结论中引用：漏洞挖掘提交多少疑似漏洞、确认多少为漏洞；漏洞验证接收多少疑似漏洞、确认多少为漏洞。",\n'
            '  "limitations": ["局限性。如样本量不足、指标不可计算、单次评测无法统计显著等"],\n'
            '  "evidence_refs": [{"source":"metric_result","metric_id":"M1","field":"estimate","value":0.078}]\n'
            "}"
        )
        _cost_section = ""
    else:
        _metric_def = (
            "# 指标定义\n"
            "| ID | 名称 | 含义 | 方向 | 单位 |\n"
            "|----|------|------|------|------|\n"
            "| M1 | ΔBA 准确率变化 | KG与No-KG平衡准确率差值 | 正=KG更准 | ratio |\n"
            "| M4 | ΔFNR 漏报率变化 | KG与No-KG漏报率差值 | 负=KG漏报更少 | ratio |\n"
            "| M13 | ΔFPR 误报率变化 | KG与No-KG误报率差值 | 负=KG误报更少 | ratio |\n"
            "| M14 | ΔPrecision 精确率变化 | KG与No-KG精确率差值 | 正=KG更准 | ratio |\n"
            "| M5 | KAR 知识访问率 | 知识查询占工具调用比例 | 衡量知识依赖 | ratio |\n"
            "| M6 | KDR 知识交付率 | 知识查询有效回复比例 | 衡量知识质量 | ratio |\n"
            "| M7 | JSD 行为偏移 | KG与No-KG工具分布差异 | 0=相同 1=不同 | ratio |\n"
            "| M8 | ΔToken | KG-No-KG token消耗 | 负=KG更省 | tokens |\n"
            "| M9 | ΔSteps | KG-No-KG 推理步数 | 负=KG更少 | steps |\n"
            "| M10 | ΔTime | KG-No-KG 运行时长 | 负=KG更快 | ms |\n"
            "| M11 | MAR 记忆访问率 | 记忆读取占工具调用比例 | 衡量记忆依赖 | ratio |\n"
            "| M12 | MDR 记忆交付率 | 记忆读取成功返回比例 | 衡量记忆质量 | ratio |\n\n"
        )
        _conclusion_schema = (
            "# 输出 JSON Schema\n"
            "{\n"
            '  "summary": "总结论(≤300字)。回答：知识图谱与记忆是否有帮助？引用关键数值，用中文名称。",\n'
            '  "conclusion": "分析结论(400-600字)。分三段写：'
            "第一段【准确性】：基于准确率变化、漏报率变化、误报率变化、精确率变化，分析KG对漏洞判定准确性的净影响。指标不可计算时说明原因。"
            "第二段【行为与知识】：基于知识访问率、知识交付率、记忆访问率、记忆交付率、行为偏移，分析Agent行为模式变化与知识/记忆依赖。"
            "第三段【成本】：按分组分别引用token消耗、推理步数、运行时长的差值（如「漏洞挖掘：KG 多用 298M token；漏洞验证：KG 少用 4M token」），分析KG的资源代价。"
            '最后附统计显著性：基于McNemar检验p值判断差异是否显著(p<0.05为显著)。若输入有诊断规则命中，在此一并说明。'
            '若输入包含漏洞流转数据，在结论中引用：漏洞挖掘提交多少疑似漏洞、确认多少为漏洞；漏洞验证接收多少疑似漏洞、确认多少为漏洞。",\n'
            '  "limitations": ["局限性。如样本量不足、指标不可计算、单次评测无法统计显著等"],\n'
            '  "evidence_refs": [{"source":"metric_result","metric_id":"M1","field":"estimate","value":0.078}]\n'
            "}"
        )
        _cost_section = (
            "## 分组成本指标（M8/M9/M10 按分组拆分，引用成本数据时须按分组分别引用）\n"
            + json.dumps(group_cost_data, ensure_ascii=False, indent=2) + "\n\n"
        )

    prompt = [
        {"role": "system", "content": (
            "# 角色\n"
            "你是知识图谱与记忆安全评测的分析报告撰写员。\n\n"
            "# 背景\n"
            "评测方法：同一漏洞挖掘任务执行两次——实验组开启知识图谱与记忆(KG)、对照组不开启(No-KG)，"
            + (f"通过8项指标(M1-M6,M11,M12)量化知识图谱与记忆对 Agent 漏洞判定准确性和知识/记忆依赖的影响。\n\n"
               if all_verify else
               "通过12项指标(M1-M12)量化知识图谱与记忆对 Agent 漏洞判定准确性、行为模式、资源消耗三方面的影响。\n\n")
            +
            "# 知识图谱与记忆的使用方法\n"
            "知识图谱（KG）：Agent 通过代码知识查询工具查询知识图谱，获取项目代码结构、组件依赖、"
            "已知漏洞模式等知识，用于引导漏洞挖掘方向。\n"
            "记忆（Memory）：Agent 通过记忆引擎读取历史挖掘经验、写入新发现，"
            "用于跨会话积累和复用漏洞挖掘知识。\n"
            "在 KG 条件下，Agent 同时拥有知识图谱和记忆能力；在 No-KG 条件下，两者均不可用。\n"
            "知识图谱与记忆对漏洞挖掘的影响可分为：正向（帮助发现漏洞）、负向（误导方向）、中性（无显著影响）。\n\n"
            "# 任务\n"
            "基于输入的指标数据、McNemar 检验结果、诊断规则，生成结构化结论 JSON。\n\n"
            "# 约束\n"
            "1. 所有数值必须引自输入数据，严禁编造或推断\n"
            "2. conclusion 字段必填，不得留空。若某维度指标不可计算(calculation_status 非 CALCULATED)，须写明原因(如「准确率变化不可计算：基线全部为漏洞型，无对照样本」)\n"
            "3. 分析中须用指标的中文名称，不要用 M1、M4 等代号。如「准确率变化=7.8%，KG 更准」「知识访问率=0，Agent 未访问知识平台」\n"
            "4. 仅返回 JSON，无任何额外文字"
        )},
        {"role": "user", "content": (
            _metric_def
            + "# 输入数据\n"
            "## 全局指标结果（所有分组的汇总中位数）\n"
            + json.dumps(metric_data, ensure_ascii=False, indent=2) + "\n\n"
            + _cost_section
            + ("## 漏洞流转数据（入口=提交/接收的疑似漏洞数，出口=确认为漏洞的数）\n"
               + json.dumps(finding_flow_data, ensure_ascii=False, indent=2) + "\n\n"
               if finding_flow_data else "")
            + "## McNemar 联合检验（统计显著性）\n"
            + json.dumps(mc_data, ensure_ascii=False, indent=2) + "\n\n"
            "## 诊断命中规则（自动异常检测）\n"
            + json.dumps([{"rule_id": h.rule_id, "observed": h.observed, "interpretation": h.interpretation} for h in hits], ensure_ascii=False, indent=2) + "\n\n"
            + _conclusion_schema
        )},
    ]

    try:
        result = llm_mod.chat_json(prompt, temperature=0)
        if not result.get("evidence_refs"):
            refs = []
            for mid in ("M1", "M4", "M13", "M14"):
                m = m_by.get(mid)
                if m and m.estimate is not None:
                    refs.append({"source": "metric_result", "metric_id": mid, "field": "estimate", "value": m.estimate})
            result["evidence_refs"] = refs
        return result
    except Exception as e:
        import traceback as _tb
        log("REPORT", f"ai_narrative LLM 失败，降级规则生成: {e}")
        _tb.print_exc()
        m1 = m_by.get("M1")
        summary = f"BA={m1.estimate:.3f}" if m1 and m1.estimate is not None else "BA=NA"
        return {
            "summary": summary + "(LLM unavailable, rule-based)",
            "conclusion": f"LLM 不可用，无法生成分析结论。错误：{e}",
            "limitations": ["SINGLE_PAIRED_RUN", "LLM unavailable"],
            "evidence_refs": [{"source": "metric_result", "metric_id": "M1", "field": "estimate", "value": m1.estimate if m1 else None}],
        }


def ai_summary(eval_name, baseline_count, outcomes, metrics, tool_stats, kg_interactions_count):
    """AI generates evaluation summary from basic data."""
    kg_oc = next((o for o in outcomes if "KG" in o.get("task_run_id", "") and "NOGK" not in o.get("task_run_id", "")), {})
    nogk_oc = next((o for o in outcomes if "NOGK" in o.get("task_run_id", "")), {})
    kg_tool = next((t for t in tool_stats if "KG" in t.get("task_run_id", "") and "NOGK" not in t.get("task_run_id", "")), {})
    nogk_tool = next((t for t in tool_stats if "NOGK" in t.get("task_run_id", "")), {})
    p1 = metrics.get("p1", {})
    p2 = metrics.get("p2", {})
    m5 = p1.get("M5", {})
    m7 = p1.get("M7", {})
    m8 = p2.get("M8", {})
    m9 = p2.get("M9", {})
    m10 = p2.get("M10", {})

    data = {
        "eval_name": eval_name or "unnamed",
        "baseline_count": baseline_count,
        "kg": {"outcome": kg_oc.get("outcome"), "prediction": kg_oc.get("prediction"),
               "resolver_status": kg_oc.get("resolver_status"), "validation": kg_oc.get("validation"),
               "finding_count": kg_tool.get("finding_count", 0), "total_tools": kg_tool.get("total_tools", 0)},
        "nogk": {"outcome": nogk_oc.get("outcome"), "prediction": nogk_oc.get("prediction"),
                 "resolver_status": nogk_oc.get("resolver_status"), "validation": nogk_oc.get("validation"),
                 "finding_count": nogk_tool.get("finding_count", 0), "total_tools": nogk_tool.get("total_tools", 0)},
        "knowledge": {"interventions": kg_interactions_count,
                      "kar": m5.get("estimate"), "jsd": m7.get("estimate")},
        "cost": {"delta_token": m8.get("estimate"), "delta_steps": m9.get("estimate"), "delta_time_ms": m10.get("estimate")},
        "raw_stats": metrics.get("raw_stats", {}),
    }

    prompt = [
        {"role": "system", "content": (
            "# 角色\n"
            "你是知识图谱与记忆安全评测的摘要撰写员。\n\n"
            "# 背景\n"
            "评测方法：同一漏洞挖掘任务执行两次——实验组开启知识图谱与记忆(KG)、对照组不开启(No-KG)，对比差异。\n"
            "下方数据中 outcome=SUCCESS/FAIL 表示该组 Agent 是否成功找到漏洞，prediction=POSITIVE/NEGATIVE 表示 Agent 判定有无漏洞。\n\n"
            "# 任务\n"
            "基于输入数据，写一段 200-300 字的中文评测摘要。纯文本输出，不要 JSON。\n\n"
            "# 内容要求\n"
            "1. 评测范围：基线漏洞数、评测名称\n"
            "2. 漏洞发现：KG 与 No-KG 各提交多少 finding、outcome 是成功还是失败\n"
            "3. 知识图谱与记忆介入：介入次数(interventions)、知识访问率(kar)、行为偏移(jsd)\n"
            "4. 成本对比：token 差值(delta_token)、步数差值(delta_steps)、时长差值(delta_time_ms)，正值=KG 更耗\n"
            "5. 结论：知识图谱与记忆是否有帮助？"
        )},
        {"role": "user", "content": (
            "评测数据：\n" + json.dumps(data, ensure_ascii=False, indent=2)
        )},
    ]

    try:
        result = llm_mod.chat(prompt, temperature=0)
        return result.strip()
    except Exception as e:
        import traceback as _tb
        log("REPORT", f"ai_summary LLM 失败，降级规则生成: {e}")
        _tb.print_exc()
        parts = []
        parts.append("基准漏洞 " + str(baseline_count) + " 个")
        if kg_oc.get("outcome"):
            parts.append("KG 结果: " + kg_oc["outcome"])
        if nogk_oc.get("outcome"):
            parts.append("No-KG 结果: " + nogk_oc["outcome"])
        if kg_interactions_count:
            parts.append("知识图谱与记忆介入 " + str(kg_interactions_count) + " 次")
        if m8.get("estimate") is not None:
            parts.append("KG " + ("少用" if m8["estimate"] < 0 else "多用") + " " + str(abs(m8["estimate"])) + " token")
        if m7.get("estimate") is not None:
            parts.append("行为偏移 " + str(round(m7["estimate"]*100, 1)) + "%")
        return "; ".join(parts) + "(LLM 不可用，规则生成)"


def ai_vuln_analysis(facts: dict, bench_by_task: dict) -> dict:
    """统计 KG vs No-KG 的 TP/FP/FN/TN（纯代码统计，不调 LLM）。

    漏报原因分析由场景5（per_case_kg_analysis）在有知识交互数据时做，
    这里只统计混淆矩阵数字。

    数据隔离：按 task_id 分组统计，避免 T001（挖掘）和 T002（验证）的 case_results
    混在一起导致每个基线漏洞被计数两次。
    """
    # 按 task_id 分组，每组内再分 KG/NO-KG
    task_stats: dict[str, dict] = {}
    for tr_id, f in facts.items():
        cr = f.get("case_results", [])
        is_nogk = "NOGK" in tr_id
        tid = f.get("_task_id", "") or "unknown"
        if tid not in task_stats:
            task_stats[tid] = {"kg": [], "nogk": []}
        if is_nogk:
            task_stats[tid]["nogk"].extend(cr)
        else:
            task_stats[tid]["kg"].extend(cr)

    # 每个 task 独立统计
    per_task: dict[str, dict] = {}
    all_kg_tp = all_kg_fp = all_kg_fn = all_kg_tn = all_kg_na = 0
    all_nogk_tp = all_nogk_fp = all_nogk_fn = all_nogk_tn = all_nogk_na = 0
    for tid, stats in task_stats.items():
        kg_cases = stats["kg"]
        nogk_cases = stats["nogk"]
        kg_tp = sum(1 for c in kg_cases if c.get("confusion") == "TP")
        kg_fp = sum(1 for c in kg_cases if c.get("confusion") == "FP")
        kg_fn = sum(1 for c in kg_cases if c.get("confusion") == "FN")
        kg_tn = sum(1 for c in kg_cases if c.get("confusion") == "TN")
        kg_na = sum(1 for c in kg_cases if c.get("confusion") == "NA")
        nogk_tp = sum(1 for c in nogk_cases if c.get("confusion") == "TP")
        nogk_fp = sum(1 for c in nogk_cases if c.get("confusion") == "FP")
        nogk_fn = sum(1 for c in nogk_cases if c.get("confusion") == "FN")
        nogk_tn = sum(1 for c in nogk_cases if c.get("confusion") == "TN")
        nogk_na = sum(1 for c in nogk_cases if c.get("confusion") == "NA")
        per_task[tid] = {
            "kg_tp": kg_tp, "kg_fp": kg_fp, "kg_fn": kg_fn, "kg_tn": kg_tn, "kg_na": kg_na,
            "nogk_tp": nogk_tp, "nogk_fp": nogk_fp, "nogk_fn": nogk_fn, "nogk_tn": nogk_tn, "nogk_na": nogk_na,
        }
        all_kg_tp += kg_tp; all_kg_fp += kg_fp; all_kg_fn += kg_fn; all_kg_tn += kg_tn; all_kg_na += kg_na
        all_nogk_tp += nogk_tp; all_nogk_fp += nogk_fp; all_nogk_fn += nogk_fn; all_nogk_tn += nogk_tn; all_nogk_na += nogk_na

    return {
        "kg_tp": all_kg_tp, "kg_fp": all_kg_fp, "kg_fn": all_kg_fn, "kg_tn": all_kg_tn, "kg_na": all_kg_na,
        "nogk_tp": all_nogk_tp, "nogk_fp": all_nogk_fp, "nogk_fn": all_nogk_fn, "nogk_tn": all_nogk_tn, "nogk_na": all_nogk_na,
        "tp": all_kg_tp, "fp": all_kg_fp, "fn": all_kg_fn, "tn": all_kg_tn,  # 兼容旧前端
        "per_task": per_task,
    }


def rule_based_per_case_kg_analysis(case_results: list[dict], category: str = "",
                                    nogk_case_results: list[dict] | None = None) -> list[dict]:
    """LLM 未启用时生成逐 case 的确定性降级结论，不发起重试。"""
    result = []
    for case in case_results:
        case_id = case.get("case_id", "")
        confusion = case.get("confusion", "NA")

        # 提前计算 No-KG 的 confusion
        nogk_confusion = "NA"
        if nogk_case_results:
            for nc in nogk_case_results:
                if nc.get("case_id") == case_id:
                    nogk_confusion = nc.get("confusion", "NA")
                    break

        # NON-VULNERABLE 基线，KG 和 NO-KG 都判非漏洞（TN）→ 不列出，不处理
        if confusion == "TN" and nogk_confusion == "TN":
            continue

        # NA = agent 没找到漏洞（VULNERABLE 基线），列出但不做 AI 分析
        if confusion == "NA":
            result.append({
                "case_id": case_id,
                "kg_judgment": "NOT_FOUND",
                "query_summary": "无知识查询",
                "knowledge_summary": "",
                "impact": "NEUTRAL",
                "reason": "Agent 未找到此漏洞（NA），无 trace 数据，未进行 AI 分析。",
                "interactions": [],
                "memory_interactions": [],
            })
            continue

        # TP/FP = agent 确认为漏洞 → VULNERABILITY；FN/TN = agent 判定为非漏洞 → NON_VULNERABILITY
        judgment = "VULNERABILITY" if confusion in ("TP", "FP") else "NON_VULNERABILITY"
        impact = "POSITIVE" if confusion == "TP" else "NEGATIVE" if confusion == "FP" else "NEUTRAL"
        if confusion == "FN":
            reason = (f"Agent 找到此漏洞但判定为非漏洞（FN）。漏洞类型: {case.get('vulnerability_type', '未知')}，"
                      f"源文件: {case.get('source_file', '未知')}。LLM 未启用，无法深入分析原因。")
        elif confusion == "TN":
            reason = f"Agent 正确判定为非漏洞（TN）。LLM 未启用，未生成深入分析。"
        else:
            reason = f"KG 判定: {confusion}（规则降级，LLM 未启用）"
        result.append({
            "case_id": case_id,
            "kg_judgment": judgment,
            "query_summary": "LLM 未启用，未生成知识查询归因。",
            "knowledge_summary": "",
            "impact": impact,
            "reason": reason,
            "interactions": [],
            "memory_interactions": [],
        })
    return result


def ai_knowledge_analysis(interactions, outcome=None, baseline_count=0):
    """AI analyzes knowledge interventions' impact on vulnerability detection.

    分析知识图谱与记忆介入是否帮助 Agent 找到了正确的漏洞（TRUSTED）还是被忽略（IGNORED）。
    不依赖 follow_up 窗口，直接取所有 CALL 交互的完整 command+output 给 LLM 批量分析。
    """
    if not interactions:
        return {"analysis": "未检测到知识图谱与记忆介入行为。",
                "suggestion": "建议确认 KG 组运行记录是否开启了知识图谱与记忆配置。",
                "interactions_analysis": []}

    # 取所有 CALL 交互（知识查询），按 command 非空过滤
    call_interactions = [(i, iv) for i, iv in enumerate(interactions)
                         if iv.get("type") == "CALL" and (iv.get("command") or "").strip()]
    total_calls = len(call_interactions)

    # 取前 5 个 CALL 交互做详细分析（控制 prompt 大小）
    sampled = call_interactions

    # 构建每个交互的数据（command + 对应 RESULT output，截断控制大小）
    interactions_data = []
    for idx, iv in sampled:
        # 找对应的 RESULT（同 tool，紧随其后的 RESULT）
        result_output = ""
        for j in range(idx + 1, min(idx + 5, len(interactions))):
            r = interactions[j]
            if r.get("type") == "RESULT" and r.get("tool") == iv.get("tool"):
                result_output = r.get("output") or ""
                break
        interactions_data.append({
            "index": len(interactions_data),
            "tool": iv.get("tool", ""),
            "command": (iv.get("command") or ""),
            "output": result_output,
        })

    # 构建一次 LLM 调用，批量分析所有交互
    data = {
        "knowledge_interactions": [{"tool": iv.get("tool",""), "question": (iv.get("command") or ""), "answer": (iv.get("output") or "")} for _, iv in sampled],
        "outcome": outcome.get("outcome") if outcome else None,
        "prediction": outcome.get("prediction") if outcome else None,
        "baseline_count": baseline_count,
        "total_knowledge_queries": total_calls,
        "case_results": outcome.get("case_results", []) if outcome else [],
    }

    prompt = [
        {"role": "system", "content": "你是知识图谱与记忆介入效果分析员。分析 Agent 从知识图谱获取了什么知识，以及这些知识是否帮助发现了正确的漏洞。\n\n判断标准：\n- TRUSTED：Agent 信任并利用知识图谱的信息，直接帮助发现了漏洞\n- QUESTIONED：Agent 查询了知识但对结果有疑问，未直接利用\n- IGNORED：Agent 查询了知识但完全忽略了返回的内容\n\n只返回 JSON，不要任何额外文字。"},
        {"role": "user", "content": json.dumps(data, ensure_ascii=False, indent=2) + '\n\n对每个知识交互分析：\n1. Agent 请求了什么知识？（从 command 分析）\n2. 知识图谱返回了什么？（从 output 分析）\n3. 这次知识介入对漏洞发现的影响是什么？\n\n返回 JSON:\n{"interactions_analysis": [{"index": 0, "tool": "...", "command_summary": "<=50字中文", "output_summary": "<=50字中文", "impact": "TRUSTED|QUESTIONED|IGNORED", "reason": "<=100字中文"}], "overall_analysis": "<=200字中文总体分析", "suggestion": "<=100字中文建议"}'},
    ]

    try:
        result = llm_mod.chat_json(prompt, temperature=0)
        return {
            "analysis": result.get("overall_analysis", ""),
            "suggestion": result.get("suggestion", ""),
            "interactions_analysis": result.get("interactions_analysis", []),
        }
    except Exception as e:
        import traceback as _tb
        log("REPORT", f"ai_per_case_kg_analysis LLM 失败，降级规则生成: {e}")
        _tb.print_exc()
        oc = outcome.get("outcome") if outcome else "UNKNOWN"
        analysis = "知识查询 " + str(total_calls) + " 次，结果为 " + oc + "（LLM 不可用，规则生成）"
        return {"analysis": analysis, "suggestion": "检查知识内容是否与漏洞检测目标相关。",
                "interactions_analysis": []}


def ai_per_case_kg_analysis(case_results, interactions, bench_by_task=None, session_graph=None, nogk_case_results=None, events=None, memory_interactions=None, category="", parser=None):
    """AI 逐漏洞分析知识图谱与记忆介入效果。

    对每个基线漏洞，分析：
    1. KG 是否识别此漏洞（TP=漏洞, FP=非漏洞, FN=找到但判错, NA=未找到）
    2. Agent 向知识图谱与记忆问了什么
    3. 知识图谱与记忆返回了什么
    4. 对排查此漏洞是正向还是负向

    四种状态：
    - TP: agent确认漏洞，基线是漏洞（正确）
    - FP: agent确认漏洞，基线非漏洞（误报）
    - FN: agent判非漏洞，基线是漏洞（找到但判错）
    - NA: agent没找到，基线是漏洞（漏报）→ 跳过，无trace数据
    """
    import re

    if not case_results or (not interactions and not memory_interactions):
        return []

    # session 压缩缓存：同一 session 压缩一次，跨 case 复用
    _session_compress_cache: dict[str, dict] = {}

    # 有知识/记忆查询的 session_id 集合（用于判断 session 是否需要 LLM 压缩）
    _kg_session_ids = {iv.get("session_id", "") for iv in interactions if iv.get("type") == "CALL"}
    _mem_session_ids = {iv.get("session_id", "") for iv in memory_interactions if iv.get("type") == "CALL"} if memory_interactions else set()

    # 知识图谱交互：只有 athena CLI 命令才算（vuln_hunt_* 是内部黑板，不算知识图谱）
    # KnowledgeResolver 已经只捕获 athena 相关交互，这里不再按工具名过滤
    def _is_kg_interaction(iv):
        """判断是否为知识图谱交互：command 含 athena，或 tool 是 bash/skill 且 KnowledgeResolver 已标记。"""
        cmd = (iv.get("command") or "").lower()
        return "athena" in cmd or True  # KnowledgeResolver 已过滤，这里全部保留

    def _parse_kg_command(tool, cmd_str):
        """将 command 解析成可读的'问题'文本。支持 athena CLI 和 JSON 格式。"""
        cmd_str = cmd_str or ""
        # athena CLI: scripts/athena --project xxx ask "问题"
        if "athena" in cmd_str.lower() and "ask" in cmd_str.lower():
            import re as _re
            m = _re.search(r'ask\s+"([^"]*)"', cmd_str) or _re.search(r"ask\s+'([^']*)'", cmd_str)
            if m:
                return f"查询知识: {m.group(1)}"
            return f"查询知识: {cmd_str}"
        # JSON 格式
        try:
            d = json.loads(cmd_str) if isinstance(cmd_str, str) else cmd_str
            if not isinstance(d, dict):
                return str(d)
            return json.dumps(d, ensure_ascii=False)
        except Exception:
            return cmd_str
    def _parse_kg_output(out_str):
        """将 athena CLI 输出解析成可读的'回答'文本。"""
        out_str = out_str or ""
        return out_str
    # 提取知识图谱交互 CALL（KnowledgeResolver 已过滤，只含 athena 相关）
    kg_calls = [(i, iv) for i, iv in enumerate(interactions)
                if iv.get("type") == "CALL"
                and (iv.get("command") or "").strip()]

    # 按大小累计：每条限制 300 字（command+answer 各 150），累计到 6000 字，到达上限则停
    MAX_PROMPT_SIZE = 6000
    sampled_interactions = []
    total_size = 0

    if kg_calls:
        # 正常路径：成对的 CALL + 后续 RESULT
        for idx, _ in kg_calls:
            iv = interactions[idx]
            result_output = ""
            for j in range(idx + 1, min(idx + 5, len(interactions))):
                r = interactions[j]
                if r.get("type") == "RESULT" and r.get("tool") == iv.get("tool"):
                    result_output = r.get("output") or ""
                    break
            full_cmd = iv.get("command") or ""
            item = {
                "tool": iv.get("tool", ""),
                "command": full_cmd,
                "command_parsed": _parse_kg_command(iv.get("tool", ""), full_cmd),
                "answer": result_output,
                "output_parsed": _parse_kg_output(result_output),
                "session_id": iv.get("session_id", ""),
                "timestamp": iv.get("timestamp"),
            }
            item_size = len(item["tool"]) + len(item["command"]) + len(item["answer"])
            if total_size + item_size > MAX_PROMPT_SIZE:
                break
            sampled_interactions.append(item)
            total_size += item_size
    else:
        # Fallback：trace 只有 RESULT 没有 CALL，只捕获 athena 相关的 RESULT
        for iv in interactions:
            if iv.get("type") != "RESULT":
                continue
            tool = iv.get("tool", "")
            output = (iv.get("output") or "").strip()
            if not output:
                continue
            # 只认 athena 相关的 RESULT（athena CLI 输出或 athena 命令）
            is_kg = "athena" in (tool + " " + output).lower()
            if not is_kg:
                continue
            question = f"查询知识"
            answer = output
            item = {
                "tool": tool,
                "command": "",
                "command_parsed": question,
                "answer": answer,
                "output_parsed": _parse_kg_output(answer),
                "session_id": iv.get("session_id", ""),
                "timestamp": iv.get("timestamp"),
            }
            item_size = len(item["tool"]) + len(question) + len(answer)
            if total_size + item_size > MAX_PROMPT_SIZE:
                break
            sampled_interactions.append(item)
            total_size += item_size

    # 记忆交互采样
    sampled_mem_interactions = []
    if memory_interactions:
        mem_calls = [(i, iv) for i, iv in enumerate(memory_interactions)
                     if iv.get("type") == "CALL" and (iv.get("command") or "").strip()]
        mem_total_size = 0
        for idx, _ in mem_calls:
            iv = memory_interactions[idx]
            result_output = ""
            for j in range(idx + 1, min(idx + 5, len(memory_interactions))):
                r = memory_interactions[j]
                if r.get("type") == "RESULT" and r.get("tool") == iv.get("tool"):
                    result_output = r.get("output") or ""
                    break
            full_cmd = iv.get("command") or ""
            item = {
                "tool": iv.get("tool", ""),
                "command": full_cmd,
                "command_parsed": full_cmd,
                "answer": result_output,
                "output_parsed": result_output,
                "session_id": iv.get("session_id", ""),
                "timestamp": iv.get("timestamp"),
            }
            item_size = len(item["tool"]) + len(item["command"]) + len(item["answer"])
            if mem_total_size + item_size > MAX_PROMPT_SIZE:
                break
            sampled_mem_interactions.append(item)
            mem_total_size += item_size

    # ===== 从 JSONL trace 提取 finding 提交点（结论点），用于倒推挖掘链 =====
    # Turing: vuln_hunt_insert_finding (提交) → vuln_hunt_update_finding (AI判定 CONFIRMED/FALSE_POSITIVE)
    # Argo: ReportFindings (findings[].outcome: confirmed/no_change_needed)
    # SecMate: mcp__findings-store__store_finding
    finding_events = {}  # finding_id/display_id → info dict
    agent_findings_list = []  # Agent 提交的所有 finding 摘要（用于 FN 展示）
    _seen_fids = set()
    if events:
        # 预提取 WebVulnVerify 的 task_data（T001 上报的 source/sink 等信息）
        _webvv_task_data = _extract_webvv_task_data(events)
        for ev in events:
            if not hasattr(ev, "is_tool_call") or not ev.is_tool_call():
                continue
            tool = ev.tool_name or ""
            inp = ev.input_json or {}
            out_str = str(ev.output_json or "")
            # Turing: vuln_hunt_insert_finding
            if tool in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding"):
                m = re.search(r"id=([a-f0-9-]+)", out_str)
                fid = m.group(1) if m else str(inp.get("detection_id", "?"))
                display = re.search(r"Finding\s+(\S+)", out_str)
                display_id = display.group(1) if display else ""
                info = {
                    "finding_id": fid, "display_id": display_id,
                    "title": str(inp.get("title", "")),
                    "vuln_type": str(inp.get("vuln_type", "")),
                    "source": str(inp.get("source", "")),
                    "sink": str(inp.get("sink", "")),
                    "session_id": ev.session_id,
                    "timestamp": ev.timestamp_ms,
                    "validation_result": None,
                }
                finding_events[fid] = info
                if display_id:
                    finding_events[display_id] = info
                if fid not in _seen_fids:
                    _seen_fids.add(fid)
                    agent_findings_list.append(info)
            # Argo: ReportFindings
            elif tool in ("ReportFindings", "reportfindings"):
                for f in (inp.get("findings") or []):
                    fid = f.get("id", f.get("finding_id", "")) or f"{f.get('file','')}:{f.get('line','')}"
                    outcome = f.get("outcome", "")
                    vr = "CONFIRMED" if outcome in ("confirmed", "fixed", "needs_review") else ("FALSE_POSITIVE" if outcome == "no_change_needed" else None)
                    info = {
                        "finding_id": fid, "display_id": fid,
                        "title": str(f.get("short_summary", "")),
                        "vuln_type": str(f.get("category", "")),
                        "source": str(f.get("file", "")),
                        "sink": "", "session_id": ev.session_id,
                        "timestamp": ev.timestamp_ms,
                        "validation_result": vr,
                    }
                    finding_events[fid] = info
                    if fid not in _seen_fids:
                        _seen_fids.add(fid)
                        agent_findings_list.append(info)
            # SecMate: mcp__findings-store__store_finding（旧格式）
            elif tool == "mcp__findings-store__store_finding":
                finding_id = ""
                try:
                    result = json.loads(out_str)
                    nested = result.get("result", result) if isinstance(result, dict) else result
                    if isinstance(nested, str):
                        nested = json.loads(nested)
                    if isinstance(nested, dict):
                        finding_id = str(nested.get("finding_id", ""))
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
                finding_id = finding_id or str(inp.get("finding_id", "")) or f"secmate-{ev.event_id}"
                info = {
                    "finding_id": finding_id, "display_id": finding_id,
                    "title": str(inp.get("title", "") or inp.get("vuln_type", "")),
                    "vuln_type": str(inp.get("vuln_type", "") or inp.get("category", "")),
                    "source": str(inp.get("source", "") or inp.get("file_path", "")),
                    "sink": str(inp.get("sink", "") or inp.get("function_name", "")),
                    "session_id": ev.session_id,
                    "timestamp": ev.timestamp_ms,
                    "validation_result": None,
                }
                finding_events[finding_id] = info
                if finding_id not in _seen_fids:
                    _seen_fids.add(finding_id)
                    agent_findings_list.append(info)
            # SecMate 新格式: store_tiered_finding（中间 finding）
            elif tool.startswith("mcp__workflow-tools__store_tiered_fing"):
                finding_id = ""
                try:
                    result = json.loads(out_str)
                    nested = result.get("result", result) if isinstance(result, dict) else result
                    if isinstance(nested, str):
                        nested = json.loads(nested)
                    if isinstance(nested, dict):
                        finding_id = str(nested.get("finding_id", ""))
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
                finding_id = finding_id or f"secmate-{ev.event_id}"
                info = {
                    "finding_id": finding_id, "display_id": finding_id,
                    "title": str(inp.get("vuln_type", "")),
                    "vuln_type": str(inp.get("vuln_type", "")),
                    "source": str(inp.get("file_path", "")),
                    "sink": str(inp.get("function_name", "")),
                    "session_id": ev.session_id,
                    "timestamp": ev.timestamp_ms,
                    "validation_result": None,
                }
                finding_events[finding_id] = info
                if finding_id not in _seen_fids:
                    _seen_fids.add(finding_id)
                    agent_findings_list.append(info)
            # SecMate 新格式: store_tracer_verdict（最终判定 = 结论点）
            elif tool == "mcp__workflow-tools__store_tracer_verdict":
                outcome = str(inp.get("outcome", ""))
                vr = "CONFIRMED" if outcome in ("confirmed", "conditional") \
                    else ("FALSE_POSITIVE" if outcome == "refuted" else None)
                finding_id = ""
                try:
                    result = json.loads(out_str)
                    nested = result.get("result", result) if isinstance(result, dict) else result
                    if isinstance(nested, str):
                        nested = json.loads(nested)
                    if isinstance(nested, dict):
                        finding_id = str(nested.get("finding_id", ""))
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
                finding_id = finding_id or f"secmate-verdict-{ev.event_id}"
                info = {
                    "finding_id": finding_id, "display_id": finding_id,
                    "title": str(inp.get("title", "") or inp.get("vuln_type", "")),
                    "vuln_type": str(inp.get("vuln_type", "")),
                    "source": str(inp.get("file_path", "") or inp.get("primary_location", "")),
                    "sink": str(inp.get("function_name", "")),
                    "session_id": ev.session_id,
                    "timestamp": ev.timestamp_ms,
                    "validation_result": vr,
                }
                finding_events[finding_id] = info
                if finding_id not in _seen_fids:
                    _seen_fids.add(finding_id)
                    agent_findings_list.append(info)
            # WebVulnVerify: vulnerability_analyze / vulnerability_verify / vulnerability_cvss
            # 提交和判定在同一个 tool call，status 字段即 validation_result
            elif tool in ("vulnerability_analyze", "vulnerability_verify", "vulnerability_cvss"):
                status = str(inp.get("status", ""))
                vr = "CONFIRMED" if status in ("VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE", "UNIT_TEST_EXPLOITABLE") \
                    else ("FALSE_POSITIVE" if status in ("NOT_VULNERABLE", "NOT_EXPLOITABLE") else None)
                # vulnerability_id 由 WebVulnVerifyTraceParser 归一化（analyze 从 result 文本提取）
                vid = str(inp.get("vulnerability_id", ""))
                if not vid:
                    vid = f"wvv-{ev.event_id}"
                result_text = str(inp.get("result", ""))
                # 从 task_data 提取 source/sink（T001 上报的原始 finding 信息）
                td = _webvv_task_data.get(vid, {})
                # 从验证报告中提取具体标题（一句话结论），回退到 category
                title = _extract_webvv_title(result_text) or str(inp.get("category", ""))
                # vulnerability_cvss 无 status/result，不覆盖已有的 analyze/verify 结论
                if tool == "vulnerability_cvss" and vid in finding_events:
                    pass
                else:
                    info = {
                        "finding_id": vid, "display_id": vid,
                        "title": title,
                        "vuln_type": str(inp.get("category", "")),
                        "source": td.get("source", ""),
                        "sink": td.get("sink", ""),
                        "session_id": ev.session_id,
                        "timestamp": ev.timestamp_ms,
                        "validation_result": vr,
                    }
                    finding_events[vid] = info
                    if vid not in _seen_fids:
                        _seen_fids.add(vid)
                        agent_findings_list.append(info)
            # CVulnVerify: write 工具写 vuln_verify_final_verdict.json
            elif tool == "write":
                fp = str(inp.get("file_path") or inp.get("path") or "")
                if "vuln_verify_final_verdict" in fp:
                    content = inp.get("content", "")
                    if isinstance(content, str):
                        try:
                            vdata = json.loads(content)
                            case_id = str(vdata.get("case_id", "")) or f"cvv-{ev.event_id}"
                            verdict = vdata.get("verdict", "")
                            vr = "CONFIRMED" if verdict == "confirmed" \
                                else ("FALSE_POSITIVE" if verdict == "ruled_out" else None)
                            case_title = str(vdata.get("case_title", "") or vdata.get("title", "") or "")
                            info = {
                                "finding_id": case_id, "display_id": case_id,
                                "title": case_title if case_title else f"CVulnVerify {case_id}",
                                "vuln_type": str(vdata.get("vuln_type", "") or vdata.get("vulnerability_type", "") or ""),
                                "source": str(vdata.get("source_file", "") or vdata.get("source", "") or ""),
                                "sink": str(vdata.get("function_name", "") or vdata.get("sink", "") or ""),
                                "session_id": ev.session_id,
                                "timestamp": ev.timestamp_ms,
                                "validation_result": vr,
                            }
                            finding_events[case_id] = info
                            if case_id not in _seen_fids:
                                _seen_fids.add(case_id)
                                agent_findings_list.append(info)
                        except (json.JSONDecodeError, TypeError):
                            pass
        # DataflowVulnScan: assistant 文本中的 findings JSON（TEXT 事件，非 tool call）
        _dvs_ra_counter = 0
        _dvs_ra_fn_lines: set[str] = set()
        for ev in events:
            if not hasattr(ev, "event_type") or ev.event_type != "TEXT":
                continue
            if not ev.output_json:
                continue
            text = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
            if '"findings"' not in text:
                continue
            for data in _extract_json_objects_from_text(text):
                for f in (data.get("findings") or []):
                    _dvs_ra_counter += 1
                    sf = str(f.get("source_file", ""))
                    ln = str(f.get("line", ""))
                    fn = str(f.get("function_name", ""))
                    _dvs_ra_fn_lines.add(f"{fn}:{ln}")
                    fid = f"dvs-ra-{_dvs_ra_counter}"
                    if fid in _seen_fids:
                        continue
                    info = {
                        "finding_id": fid, "display_id": fid,
                        "title": str(f.get("title", "")),
                        "vuln_type": str(f.get("vuln_type", "")),
                        "source": sf,
                        "sink": fn,
                        "session_id": ev.session_id,
                        "timestamp": ev.timestamp_ms,
                        "validation_result": "CONFIRMED",
                    }
                    finding_events[fid] = info
                    _seen_fids.add(fid)
                    agent_findings_list.append(info)
        # 补充: vuln-judge 阶段 confirmed 候选（无对应 vuln-report finding 的 fn:line）
        for ev in events:
            if not hasattr(ev, "event_type") or ev.event_type != "TEXT":
                continue
            if not ev.output_json:
                continue
            text = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
            if '"candidates"' not in text:
                continue
            for data in _extract_json_objects_from_text(text):
                for c in (data.get("candidates") or []):
                    if c.get("judgment") != "confirmed":
                        continue
                    fn = str(c.get("function_name", ""))
                    ln = str(c.get("line", ""))
                    if f"{fn}:{ln}" in _dvs_ra_fn_lines:
                        continue
                    _dvs_ra_counter += 1
                    fid = f"dvs-ra-{_dvs_ra_counter}"
                    if fid in _seen_fids:
                        continue
                    info = {
                        "finding_id": fid, "display_id": fid,
                        "title": str(c.get("vuln_type", "")),
                        "vuln_type": str(c.get("vuln_type", "")),
                        "source": str(c.get("source_evidence", "")),
                        "sink": fn,
                        "session_id": ev.session_id,
                        "timestamp": ev.timestamp_ms,
                        "validation_result": "CONFIRMED",
                    }
                    finding_events[fid] = info
                    _seen_fids.add(fid)
                    agent_findings_list.append(info)
        # Argo: TOOL_RESULT 中含 findings JSON（findings.json 的 cat 结果）
        for ev in events:
            if not hasattr(ev, "event_type") or ev.event_type != "TOOL_RESULT":
                continue
            if not ev.output_json:
                continue
            out_str = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
            if '"verdict"' not in out_str or '"finding_id"' not in out_str:
                continue
            try:
                data = json.loads(out_str)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(data, list):
                continue
            for f in data:
                fid = str(f.get("id", "") or f.get("finding_id", ""))
                if not fid or fid in _seen_fids:
                    continue
                verdict = str(f.get("verdict", ""))
                vr = "CONFIRMED" if verdict == "CONFIRMED" \
                    else ("FALSE_POSITIVE" if verdict == "FALSE_POSITIVE" else None)
                info = {
                    "finding_id": fid, "display_id": fid,
                    "title": str(f.get("description", "")),
                    "vuln_type": str(f.get("cwe", "")),
                    "source": str(f.get("file", "")),
                    "sink": str(f.get("sink", "")),
                    "session_id": ev.session_id,
                    "timestamp": ev.timestamp_ms,
                    "validation_result": vr,
                }
                finding_events[fid] = info
                _seen_fids.add(fid)
                agent_findings_list.append(info)
        # 关联 Turing: vuln_hunt_update_finding 的 validation_result（AI 判定结论点）
        for ev in events:
            if not hasattr(ev, "is_tool_call") or not ev.is_tool_call():
                continue
            tool = ev.tool_name or ""
            if tool in ("vuln-hunt_update_finding", "vuln_hunt_update_finding"):
                inp = ev.input_json or {}
                fid = str(inp.get("finding_id", ""))
                vr = inp.get("validation_result", "")
                if fid in finding_events and vr in ("CONFIRMED", "FALSE_POSITIVE"):
                    finding_events[fid]["validation_result"] = vr
                    # 同步到 agent_findings_list
                    for af in agent_findings_list:
                        if af.get("finding_id") == fid:
                            af["validation_result"] = vr
                            break

    results = []
    for case in case_results:
        case_id = case.get("case_id", "")
        description = case.get("description", "")
        vuln_type = case.get("vulnerability_type", "")
        confusion = case.get("confusion", "NA")
        matched_fid = case.get("matched_finding_id", "")

        # 提前计算 No-KG 的 confusion
        nogk_confusion = "NA"
        if nogk_case_results:
            for nc in nogk_case_results:
                if nc.get("case_id") == case_id:
                    nogk_confusion = nc.get("confusion", "NA")
                    break

        # NON-VULNERABLE 基线，KG 和 NO-KG 都判非漏洞（TN）→ 不列出，不处理
        if confusion == "TN" and nogk_confusion == "TN":
            continue

        # NA = agent 没找到漏洞（VULNERABLE 基线），列出但不做 AI 分析
        if confusion == "NA":
            results.append({
                "case_id": case_id,
                "kg_judgment": "NOT_FOUND",
                "query_summary": "无知识查询",
                "knowledge_summary": "",
                "impact": "NEUTRAL",
                "reason": "Agent 未找到此漏洞（NA），无 trace 数据，未进行 AI 分析。",
                "interactions": [],
                "memory_interactions": [],
            })
            continue

        # 从 finding 提交点（结论点）倒推挖掘链
        finding_info = None
        if matched_fid:
            finding_info = finding_events.get(matched_fid)

        if finding_info or case.get("session_id"):
            # TP/FP: 从 finding 提交点倒推，挖掘链 = 关联 session 中提交之前的动作
            # 优先用 finding_events 的 session_id/timestamp；Dataflow ID 不匹配时回退到 case_results
            if finding_info:
                finding_session = finding_info["session_id"]
                finding_ts = finding_info["timestamp"]
            else:
                finding_session = case.get("session_id", "")
                finding_ts = case.get("finding_ts")
            # 反向追踪：通过 parser 的 session_graph BFS 获取跨 session 挖掘过程
            finding_dict = {"session_id": finding_session, "timestamp": finding_ts}
            if parser and events:
                mining_actions = parser.trace_finding_process(events, session_graph, finding_dict)
                related_sessions = parser._get_related_sessions(session_graph, finding_session)
            else:
                mining_actions = []
                related_sessions = {finding_session} if finding_session else set()
            # 知识/记忆交互也扩展到关联 session
            case_interactions = [iv for iv in sampled_interactions
                                 if iv.get("session_id") in related_sessions]
            case_mem_interactions = [iv for iv in sampled_mem_interactions
                                      if iv.get("session_id") in related_sessions]
        else:
            # 回退：无 finding 信息时不过滤
            mining_actions = []
            case_interactions = sampled_interactions if matched_fid else []
            case_mem_interactions = sampled_mem_interactions if matched_fid else []

        # 映射 confusion → kg_judgment
        # TP/FP = agent 确认为漏洞 → VULNERABILITY；FN/TN = agent 判定为非漏洞 → NON_VULNERABILITY
        kg_judgment = "VULNERABILITY" if confusion in ("TP", "FP") else "NON_VULNERABILITY"

        # KG 与 No-KG 都确认是漏洞（都 TP）→ 不需要 AI 介入分析
        if confusion == "TP" and nogk_confusion == "TP":
            results.append({
                "case_id": case_id,
                "kg_judgment": kg_judgment,
                "query_summary": "无知识查询" if not case_interactions else "有知识查询（双方均发现漏洞）",
                "knowledge_summary": "",
                "impact": "NEUTRAL",
                "reason": "KG 与 No-KG 均确认此漏洞，知识图谱与记忆未产生差异化影响",
                "interactions": case_interactions,
                "memory_interactions": case_mem_interactions,
            })
            continue

        # 无知识交互时的处理：直接判定，不调 LLM
        if not case_interactions:
            impact = "NEUTRAL"
            reason = "无知识图谱与记忆介入，无法评估知识对漏洞排查的影响"
            results.append({
                "case_id": case_id,
                "kg_judgment": kg_judgment,
                "query_summary": "无知识查询",
                "knowledge_summary": "无知识返回",
                "impact": impact,
                "reason": reason,
                "interactions": [],
                "memory_interactions": case_mem_interactions,
            })
            continue

        _agent_vr = case.get("agent_validation")
        data = {
            "baseline_vulnerability": {
                "case_id": case_id,
                "description": description,
                "vulnerability_type": vuln_type,
                "source_file": case.get("source_file", ""),
                "source_function": case.get("source_function", ""),
            },
            "kg_status": {
                "confusion": confusion,
                "kg_judgment": kg_judgment,
                "matched_finding_id": matched_fid or None,
                "agent_validation": _agent_vr,
            },
            "matched_finding": ({
                "title": finding_info["title"],
                "vuln_type": finding_info["vuln_type"],
                "source": finding_info["source"],
                "sink": finding_info["sink"],
                "validation_result": finding_info.get("validation_result"),
            } if finding_info else None),
            "agent_findings_list": [{"title": f["title"], "vuln_type": f["vuln_type"],
                                     "source": f["source"], "sink": f["sink"],
                                     "validation_result": f.get("validation_result")}
                                    for f in agent_findings_list],
            "knowledge_interactions": [{"tool": iv.get("tool",""),
                                        "question": iv.get("command_parsed") or iv.get("command",""),
                                        "answer": iv.get("output_parsed") or iv.get("answer","")} for iv in case_interactions],
            "mining_actions": mining_actions,
            "nogk_confusion": nogk_confusion,
        }

        # 根据 confusion + agent_validation 构建场景特定的问题
        if confusion == "TP":
            _case_q = (
                "## 场景：TP — Agent 找到并确认了漏洞\n"
                "1. 为什么能挖到这个漏洞？Agent 的挖掘链（mining_actions）如何接触到漏洞代码？\n"
                "2. 知识与记忆是正向/负向/中性？knowledge_interactions 是否引导 Agent 到漏洞所在区域？\n"
                "3. 与 No-KG（" + nogk_confusion + "）对比，知识是否产生了差异化影响？"
            )
        elif confusion == "FN":
            # FN: Agent 找到了漏洞但判定为非漏洞（FALSE_POSITIVE）
            _case_q = (
                "## 场景：FN — Agent 找到此漏洞但确认为非漏洞\n"
                "1. 为什么 Agent 将此漏洞确认为非漏洞（FALSE_POSITIVE）？判定依据是什么？\n"
                "2. 知识与记忆是正向/负向/中性？knowledge_interactions 是否影响了 Agent 的判定？\n"
                "3. 与 No-KG（" + nogk_confusion + "）对比，知识是否产生了差异化影响？"
            )
        elif confusion == "FP":
            _case_q = (
                "## 场景：FP — 基线非漏洞但 Agent 报告为漏洞\n"
                "1. 为什么误报？Agent 的挖掘链如何接触到这个非漏洞区域？\n"
                "2. 知识与记忆是正向/负向/中性？knowledge_interactions 是否误导了 Agent？\n"
                "3. 与 No-KG（" + nogk_confusion + "）对比，知识是否产生了差异化影响？"
            )
        else:  # TN
            _case_q = (
                "## 场景：TN — 基线非漏洞，Agent 正确排除或未报告\n"
                "1. 为什么正确排除（或未报告）？Agent 是否接触过此区域？\n"
                "2. 知识与记忆是正向/负向/中性？\n"
                "3. 与 No-KG（" + nogk_confusion + "）对比，知识是否产生了差异化影响？"
            )

        # token 估算 + 按 session 分组压缩：防止输入超限（不截断，用 LLM 逐 session 压缩）
        _data_str = json.dumps(data, ensure_ascii=False)
        if len(_data_str) > 840000:  # ~280k tokens，400k 上下文的 70%
            log("KG_ANALYSIS", f"prompt 数据过大 ({len(_data_str)} chars)，按 session 压缩 mining_actions...")
            # 1. mining_actions 按 session_id 分组，每组单独用 LLM 压缩成摘要（缓存复用）
            _actions = data.get("mining_actions", [])
            if _actions:
                _by_session: dict[str, list] = {}
                for a in _actions:
                    sid = a.get("session_id", "unknown")
                    _by_session.setdefault(sid, []).append(a)
                _compressed = []
                _cache_hits = 0
                for sid, acts in _by_session.items():
                    if sid in _session_compress_cache:
                        _compressed.append(_session_compress_cache[sid])
                        _cache_hits += 1
                        continue
                    _has_kg_mem = sid in _kg_session_ids or sid in _mem_session_ids
                    if _has_kg_mem:
                        _sys_content = (
                            "你是漏洞挖掘过程分析员。将一个 session 内的工具调用序列压缩成挖掘过程摘要。\n\n"
                            "# 压缩目标\n"
                            "分析知识与记忆的介入对漏洞挖掘产生了什么影响。以下内容必须保留：\n"
                            "1. 知识/记忆查询的完整问答：Agent 查询了什么、检索了什么、得到了什么回答\n"
                            "2. 知识/记忆回答对后续行为的影响：得到回答后 Agent 接下来做了什么（读了哪些新文件、搜索了什么新模式、提交了什么 finding）\n"
                            "3. 漏洞接触链：Agent 从哪个入口开始、读了哪些关键文件、如何一步步接触到漏洞代码\n"
                            "4. 判定决策点：Agent 提交 finding（确认漏洞）、排除漏洞、验证结果的依据\n\n"
                            "# 知识与记忆的识别规则\n"
                            "工具调用序列中，以下操作属于知识/记忆访问：\n"
                            "- 知识查询：命令中包含知识库检索工具调用（如 athena ask），用于查询项目代码结构、组件依赖、已知漏洞模式等\n"
                            "- 记忆读取：命令中包含记忆目录路径（如 memengine、/app/memory）的 read/grep/cat 操作，或记忆检索 CLI 命令（如 mem recall），用于读取历史挖掘经验\n"
                            "其他 read/grep/bash 为普通文件操作。\n\n"
                            '只返回 JSON：{"session_id": "' + sid + '", "mining_summary": "<=2000字中文，按时间线描述挖掘过程，重点标注知识/记忆查询的时机和后续行为变化", "knowledge_queries": [{"question": "查询内容", "answer": "回答要点", "follow_up": "得到回答后 Agent 做了什么"}], "key_actions": ["关键操作1", ...]}'
                        )
                    else:
                        _sys_content = (
                            "你是漏洞挖掘过程分析员。将一个 session 内的工具调用序列压缩成挖掘过程摘要。\n\n"
                            "# 压缩目标\n"
                            "此 session 无知识与记忆查询。以下内容必须保留：\n"
                            "1. 漏洞接触链：Agent 从哪个入口开始、读了哪些关键文件、如何一步步接触到漏洞代码\n"
                            "2. 判定决策点：Agent 提交 finding（确认漏洞）、排除漏洞、验证结果的依据\n"
                            "3. 与前后 session 的衔接：此 session 的操作结果如何导向下一步\n\n"
                            '只返回 JSON：{"session_id": "' + sid + '", "mining_summary": "<=2000字中文，按时间线描述挖掘过程", "key_actions": ["关键操作1", ...]}'
                        )
                    _comp_prompt = [
                        {"role": "system", "content": _sys_content},
                        {"role": "user", "content": json.dumps(acts, ensure_ascii=False)},
                    ]
                    try:
                        _r = llm_mod.chat_json(_comp_prompt, temperature=0, max_tokens=8000)
                        if isinstance(_r, dict):
                            _session_compress_cache[sid] = _r
                            _compressed.append(_r)
                        else:
                            _fallback = {"session_id": sid, "mining_summary": str(_r)[:500]}
                            _session_compress_cache[sid] = _fallback
                            _compressed.append(_fallback)
                    except Exception as _e:
                        log("KG_ANALYSIS", f"session {sid} LLM 压缩失败: {_e}")
                        _fallback = {"session_id": sid, "mining_summary": "压缩失败", "tool_count": len(acts)}
                        _session_compress_cache[sid] = _fallback
                        _compressed.append(_fallback)
                data["mining_actions"] = _compressed
                log("KG_ANALYSIS", f"mining_actions 按 session 压缩: {len(_by_session)} sessions ({_cache_hits} cache hits) → {len(_compressed)} 摘要")

            # 2. knowledge_interactions 保留 question（查询命令），不传 answer（完整输出）
            _kis = data.get("knowledge_interactions", [])
            if _kis:
                data["knowledge_interactions"] = [
                    {"tool": ki.get("tool", ""), "question": ki.get("question", "")}
                    for ki in _kis
                ]

            _data_str = json.dumps(data, ensure_ascii=False)
            log("KG_ANALYSIS", f"压缩后 {len(_data_str)} chars")

            # 压缩后仍超限 → 跳过 LLM，规则降级
            if len(_data_str) > 840000:
                log("KG_ANALYSIS", f"压缩后仍超限 ({len(_data_str)} chars)，跳过 LLM，规则降级")
                results.append({
                    "case_id": case_id,
                    "kg_judgment": kg_judgment,
                    "query_summary": "数据量过大，无法进行 AI 分析" if case_interactions else "无知识查询",
                    "knowledge_summary": "",
                    "impact": "NEUTRAL",
                    "reason": f"KG 判定: {confusion}（挖掘链数据过大，LLM 跳过，规则生成）",
                    "interactions": case_interactions,
                    "memory_interactions": case_mem_interactions,
                })
                continue

        prompt = [
            {"role": "system", "content": (
                "你是知识图谱与记忆介入效果分析员。结论先行，然后按场景分析。\n\n"
                "# 知识图谱与记忆的作用\n"
                "知识图谱（KG）：提供项目代码结构、组件依赖、已知漏洞模式等知识，用于引导漏洞挖掘方向。\n"
                "记忆（Memory）：存储历史挖掘经验，用于跨会话复用漏洞挖掘知识。\n"
                "在 KG 条件下，Agent 同时拥有知识图谱和记忆能力；在 No-KG 条件下，两者均不可用。\n\n"
                "# 数据说明\n"
                "- kg_status.confusion: TP/FN/FP/TN\n"
                "- kg_status.agent_validation: Agent 对此 finding 的判定（CONFIRMED=确认漏洞, FALSE_POSITIVE=判定非漏洞）\n"
                "- matched_finding: Agent 提交的与基线匹配的 finding（FN 无匹配时为 null）\n"
                "- mining_actions: 从 finding 提交点倒推的挖掘链。数据量大时已按工具类型聚合，每条含 actions 列表（去重后的完整操作）和 count（原始条数）\n"
                "- knowledge_interactions: Agent 与知识图谱/记忆的交互记录。数据量大时仅保留 question（查询命令），省略 answer（知识返回内容），此时应从 mining_actions 中推断知识的作用\n"
                "- nogk_confusion: No-KG 条件下的 confusion 结果\n\n"
                "# impact 判定规则\n"
                "- POSITIVE（正向）：知识引导 Agent 到正确区域，帮助发现/排除漏洞\n"
                "- NEGATIVE（负向）：知识误导 Agent，导致漏报/误报\n"
                "- NEUTRAL（中性）：知识未产生影响，或无知识交互\n\n"
                "# reason 写作要求（800字以内，结论先行）\n"
                "第一句给出结论：知识与记忆是正向/负向/中性帮助。\n"
                "然后按场景回答具体问题（见 user 消息）。\n"
                "必须引用 knowledge_interactions、mining_actions 中的具体内容作为证据，不要泛泛而谈。\n\n"
                "只返回 JSON。"
            )},
            {"role": "user", "content": json.dumps(data, ensure_ascii=False, indent=2) + (
                '\n\n' + _case_q +
                '\n\n返回 JSON: {"kg_judgment": "' + kg_judgment + '", '
                '"query_summary": "<=200字中文，概括Agent查询了什么", '
                '"knowledge_summary": "<=200字中文，概括知识返回了什么", '
                '"impact": "POSITIVE|NEGATIVE|NEUTRAL", '
                '"reason": "800字以内中文，结论先行"}'
            )},
        ]

        try:
            result = llm_mod.chat_json(prompt, temperature=0)
            result["case_id"] = case_id
            result["interactions"] = case_interactions
            result["memory_interactions"] = case_mem_interactions
            results.append(result)
        except Exception:
            results.append({
                "case_id": case_id,
                "kg_judgment": kg_judgment,
                "query_summary": "无相关知识查询" if not case_interactions else "LLM 分析失败",
                "knowledge_summary": "",
                "impact": "NEUTRAL",
                "reason": f"KG 判定: {confusion}（LLM 不可用，规则生成）",
                "interactions": case_interactions,
                "memory_interactions": case_mem_interactions,
            })

    return results
