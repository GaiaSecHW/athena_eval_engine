"""Report Assembler - 组装评测报告。

不重算 Metric(只消费 MetricResult/StatisticalResult/DiagnosticHit)。
AI 叙述性结论按 §6.4.2 契约产出 JSON(接 LLM glm-5.2)。
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from ..infrastructure import llm as llm_mod


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
        }

    p0 = {mid: _entry(mid) for mid in ("M1", "M2", "M3", "M4")}
    p0["m2_m3_mcnemar"] = {
        "joint_analysis_id": joint[0].joint_analysis_id if joint else None,
        "statistic": joint[0].statistic if joint else None,
        "p_value": joint[0].p_value if joint else None,
        "status": joint[0].status if joint else None,
    } if joint else None
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
                        _ref("M4", "estimate"), _ref("M2", "estimate"), _ref("M3", "estimate")] if r]
    m1 = m_by.get("M1")
    summary = f"BA={m1.estimate:.3f}" if m1 and m1.estimate is not None else "BA=NA"
    return {
        "summary": summary + "(rule-based v1)",
        "outcome_interpretation": summary,
        "risk_interpretation": "; ".join(h.observed for h in hits[:3]) or "no significant regression risk",
        "mechanism_interpretation": "; ".join(h.observed for h in hits if "JSD" in h.observed) or "no significant behavior shift",
        "cost_interpretation": "; ".join(h.observed for h in hits if "Token" in h.observed) or "no significant cost change",
        "limitations": ["SINGLE_PAIRED_RUN", "v1 rule-based narrative"],
        "evidence_refs": refs,
    }


def render_json(model: ReportModel) -> str:
    return json.dumps(model.__dict__, default=lambda o: o.__dict__, ensure_ascii=False, indent=2)


def ai_narrative(metrics: list, stats: list, hits: list, metric_groups: list = None) -> dict:
    """Stage 3 AI narrative (LLM glm-5.2)."""
    m_by = {m.metric_id: m for m in metrics}
    s_by = {s.metric_id: s for s in stats if s.metric_id}
    joint = [s for s in stats if s.scope_type == "JOINT"]

    metric_data = []
    for mid in ("M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "M11", "M12"):
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

    # 构建分组指标数据（成本类 M8/M9/M10 按分组引用）
    group_cost_data = []
    if metric_groups:
        for g in metric_groups:
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

    prompt = [
        {"role": "system", "content": (
            "# 角色\n"
            "你是知识图谱与记忆安全评测的分析报告撰写员。\n\n"
            "# 背景\n"
            "评测方法：同一漏洞挖掘任务执行两次——实验组开启知识图谱与记忆(KG)、对照组不开启(No-KG)，"
            "通过12项指标(M1-M12)量化知识图谱与记忆对 Agent 漏洞判定准确性、行为模式、资源消耗三方面的影响。\n\n"
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
            "3. 分析中须用指标的中文名称，不要用 M1、M2 等代号。如「准确率变化=7.8%，KG 更准」「知识访问率=0，Agent 未访问知识平台」\n"
            "4. 仅返回 JSON，无任何额外文字"
        )},
        {"role": "user", "content": (
            "# 指标定义\n"
            "| ID | 名称 | 含义 | 方向 | 单位 |\n"
            "|----|------|------|------|------|\n"
            "| M1 | ΔBA 准确率变化 | KG与No-KG平衡准确率差值 | 正=KG更准 | ratio |\n"
            "| M2 | IR 救回率 | No-KG失败任务中KG成功的比例 | 越高越好 | ratio |\n"
            "| M3 | RR 回归率 | No-KG成功任务中KG失败的比例 | 越低越好 | ratio |\n"
            "| M4 | ΔFNR 漏报率变化 | KG与No-KG漏报率差值 | 负=KG漏报更少 | ratio |\n"
            "| M5 | KAR 知识访问率 | 知识查询占工具调用比例 | 衡量知识依赖 | ratio |\n"
            "| M6 | KDR 知识交付率 | 知识查询有效回复比例 | 衡量知识质量 | ratio |\n"
            "| M7 | JSD 行为偏移 | KG与No-KG工具分布差异 | 0=相同 1=不同 | ratio |\n"
            "| M8 | ΔToken | KG-No-KG token消耗 | 负=KG更省 | tokens |\n"
            "| M9 | ΔSteps | KG-No-KG 推理步数 | 负=KG更少 | steps |\n"
            "| M10 | ΔTime | KG-No-KG 运行时长 | 负=KG更快 | ms |\n"
            "| M11 | MAR 记忆访问率 | 记忆读取占工具调用比例 | 衡量记忆依赖 | ratio |\n"
            "| M12 | MDR 记忆交付率 | 记忆读取成功返回比例 | 衡量记忆质量 | ratio |\n\n"
            "# 输入数据\n"
            "## 全局指标结果（所有分组的汇总中位数）\n"
            + json.dumps(metric_data, ensure_ascii=False, indent=2) + "\n\n"
            "## 分组成本指标（M8/M9/M10 按分组拆分，引用成本数据时须按分组分别引用）\n"
            + json.dumps(group_cost_data, ensure_ascii=False, indent=2) + "\n\n"
            "## McNemar 联合检验（统计显著性）\n"
            + json.dumps(mc_data, ensure_ascii=False, indent=2) + "\n\n"
            "## 诊断命中规则（自动异常检测）\n"
            + json.dumps([{"rule_id": h.rule_id, "observed": h.observed, "interpretation": h.interpretation} for h in hits], ensure_ascii=False, indent=2) + "\n\n"
            "# 输出 JSON Schema\n"
            "{\n"
            '  "summary": "总结论(≤300字)。回答：知识图谱与记忆是否有帮助？引用关键数值，用中文名称。",\n'
            '  "conclusion": "分析结论(400-600字)。分三段写：'
            "第一段【准确性】：基于准确率变化、救回率、回归率、漏报率变化，分析KG对漏洞判定准确性的净影响。指标不可计算时说明原因。"
            "第二段【行为与知识】：基于知识访问率、知识交付率、记忆访问率、记忆交付率、行为偏移，分析Agent行为模式变化与知识/记忆依赖。"
            "第三段【成本】：按分组分别引用token消耗、推理步数、运行时长的差值（如「漏洞挖掘：KG 多用 298M token；漏洞验证：KG 少用 4M token」），分析KG的资源代价。"
            '最后附统计显著性：基于McNemar检验p值判断差异是否显著(p<0.05为显著)。若输入有诊断规则命中，在此一并说明。",\n'
            '  "limitations": ["局限性。如样本量不足、指标不可计算、单次评测无法统计显著等"],\n'
            '  "evidence_refs": [{"source":"metric_result","metric_id":"M1","field":"estimate","value":0.078}]\n'
            "}"
        )},
    ]

    try:
        result = llm_mod.chat_json(prompt, temperature=0)
        if not result.get("evidence_refs"):
            refs = []
            for mid in ("M1", "M4", "M2", "M3"):
                m = m_by.get(mid)
                if m and m.estimate is not None:
                    refs.append({"source": "metric_result", "metric_id": mid, "field": "estimate", "value": m.estimate})
            result["evidence_refs"] = refs
        return result
    except Exception as e:
        import traceback as _tb
        print(f"[REPORT] ai_narrative LLM 失败，降级规则生成: {e}", flush=True)
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
        print(f"[REPORT] ai_summary LLM 失败，降级规则生成: {e}", flush=True)
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
    """
    kg_cases = []
    nogk_cases = []
    for tr_id, f in facts.items():
        cr = f.get("case_results", [])
        if "NOGK" in tr_id:
            nogk_cases.extend(cr)
        else:
            kg_cases.extend(cr)

    kg_tp = sum(1 for c in kg_cases if c.get("confusion") == "TP")
    kg_fp = sum(1 for c in kg_cases if c.get("confusion") == "FP")
    kg_fn = sum(1 for c in kg_cases if c.get("confusion") == "FN")
    kg_tn = sum(1 for c in kg_cases if c.get("confusion") == "TN")
    nogk_tp = sum(1 for c in nogk_cases if c.get("confusion") == "TP")
    nogk_fp = sum(1 for c in nogk_cases if c.get("confusion") == "FP")
    nogk_fn = sum(1 for c in nogk_cases if c.get("confusion") == "FN")
    nogk_tn = sum(1 for c in nogk_cases if c.get("confusion") == "TN")

    return {
        "kg_tp": kg_tp, "kg_fp": kg_fp, "kg_fn": kg_fn, "kg_tn": kg_tn,
        "nogk_tp": nogk_tp, "nogk_fp": nogk_fp, "nogk_fn": nogk_fn, "nogk_tn": nogk_tn,
        "tp": kg_tp, "fp": kg_fp, "fn": kg_fn, "tn": kg_tn,  # 兼容旧前端
    }


def rule_based_per_case_kg_analysis(case_results: list[dict]) -> list[dict]:
    """LLM 未启用时生成逐 case 的确定性降级结论，不发起重试。"""
    result = []
    for case in case_results:
        confusion = case.get("confusion", "NA")
        judgment = {"TP": "VULNERABILITY", "FP": "NON_VULNERABILITY"}.get(confusion, "NOT_FOUND")
        impact = "POSITIVE" if confusion == "TP" else "NEGATIVE" if confusion == "FP" else "NEUTRAL"
        if confusion == "FN":
            reason = (f"Agent 未发现此漏洞（FN）。漏洞类型: {case.get('vulnerability_type', '未知')}，"
                      f"源文件: {case.get('source_file', '未知')}。LLM 未启用，无法深入分析原因。")
        else:
            reason = f"KG 判定: {confusion}（规则降级，LLM 未启用）"
        result.append({
            "case_id": case.get("case_id", ""),
            "kg_judgment": judgment,
            "query_summary": "LLM 未启用，未生成知识查询归因。",
            "knowledge_summary": "",
            "impact": impact,
            "reason": reason,
            "interactions": [],
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
    sampled = call_interactions[:5]

    # 构建每个交互的数据（command + 对应 RESULT output，截断控制大小）
    interactions_data = []
    for idx, iv in sampled:
        # 找对应的 RESULT（同 tool，紧随其后的 RESULT）
        result_output = ""
        for j in range(idx + 1, min(idx + 5, len(interactions))):
            r = interactions[j]
            if r.get("type") == "RESULT" and r.get("tool") == iv.get("tool"):
                result_output = (r.get("output") or "")[:500]
                break
        interactions_data.append({
            "index": len(interactions_data),
            "tool": iv.get("tool", ""),
            "command": (iv.get("command") or "")[:300],
            "output": result_output,
        })

    # 构建一次 LLM 调用，批量分析所有交互
    data = {
        "knowledge_interactions": [{"tool": iv.get("tool",""), "question": (iv.get("command") or "")[:200], "answer": (iv.get("output") or "")[:200]} for _, iv in sampled],
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
        print(f"[REPORT] ai_per_case_kg_analysis LLM 失败，降级规则生成: {e}", flush=True)
        _tb.print_exc()
        oc = outcome.get("outcome") if outcome else "UNKNOWN"
        analysis = "知识查询 " + str(total_calls) + " 次，结果为 " + oc + "（LLM 不可用，规则生成）"
        return {"analysis": analysis, "suggestion": "检查知识内容是否与漏洞检测目标相关。",
                "interactions_analysis": []}


def ai_per_case_kg_analysis(case_results, interactions, bench_by_task=None, session_graph=None, nogk_case_results=None, events=None):
    """AI 逐漏洞分析知识图谱与记忆介入效果。

    对每个基线漏洞，分析：
    1. KG 是否识别此漏洞（TP=漏洞, FP=非漏洞, FN=未找到）
    2. Agent 向知识图谱与记忆问了什么
    3. 知识图谱与记忆返回了什么
    4. 对排查此漏洞是正向还是负向
    """
    import re

    if not case_results or not interactions:
        return []

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
                return f"查询知识: {m.group(1)[:150]}"
            return f"查询知识: {cmd_str[:150]}"
        # JSON 格式
        try:
            d = json.loads(cmd_str) if isinstance(cmd_str, str) else cmd_str
            if not isinstance(d, dict):
                return str(d)[:200]
            return json.dumps(d, ensure_ascii=False)[:200]
        except Exception:
            return cmd_str[:200]

    def _parse_kg_output(out_str):
        """将 athena CLI 输出解析成可读的'回答'文本。"""
        out_str = out_str or ""
        return out_str[:300]

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
                    result_output = (r.get("output") or "")[:500]
                    break
            full_cmd = iv.get("command") or ""
            item = {
                "tool": iv.get("tool", ""),
                "command": full_cmd[:300],
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
            answer = output[:200]
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

    results = []
    for case in case_results:
        case_id = case.get("case_id", "")
        description = case.get("description", "")
        vuln_type = case.get("vulnerability_type", "")
        confusion = case.get("confusion", "NA")
        matched_fid = case.get("matched_finding_id", "")
        case_session = case.get("session_id", "")

        # 用 session_graph 逆向遍历，找到该漏洞的完整调查链
        # 1. 从 case 的 session 出发 BFS
        related_sessions = set()
        if session_graph and case_session:
            related_sessions.add(case_session)
            queue = [case_session]
            visited = {case_session}
            while queue:
                cur = queue.pop(0)
                neighbors = session_graph.get('edges', {}).get(cur, set())
                for n in neighbors:
                    if n not in visited:
                        visited.add(n)
                        related_sessions.add(n)
                        queue.append(n)

        # 2. 通过基线漏洞的 source_file / source_function 找关联 session
        if session_graph:
            import re as _re2
            import os as _os
            file_names = set()
            # 优先从 case 的 source_file 提取 basename（evaluation_service 已从 metadata 填充）
            source_file = case.get("source_file", "")
            if source_file:
                file_names.add(_os.path.basename(source_file))
            # 从 description 提取文件名（扩展正则覆盖 .java/.go/.js/.ts/.py/.c/.h 等）
            file_names.update(_re2.findall(r'[\w\-]+\.\w{1,6}', description + " " + vuln_type))
            # 从 bench_by_task 的 metadata 提取 source_file（修复：metadata 非 metadata_json）
            if isinstance(bench_by_task, dict):
                for items in bench_by_task.values():
                    for ft in (items if isinstance(items, list) else [items]):
                        meta = getattr(ft, 'metadata', None)
                        if isinstance(meta, dict):
                            sf = meta.get("source_file", "")
                            if sf:
                                file_names.add(_os.path.basename(sf))
                        file_names.update(_re2.findall(r'[\w\-]+\.\w{1,6}', str(meta or '')))
            for fn in file_names:
                related_sessions.update(session_graph.get('file_to_sessions', {}).get(fn, set()))
            # 也通过 source_function 匹配：扫描 events 中提到该函数名的 session
            source_function = case.get("source_function", "")
            if source_function and events:
                for ev in events:
                    if not hasattr(ev, "is_tool_call") or not ev.is_tool_call():
                        continue
                    inp = ev.input_json or {}
                    ev_text = str(inp.get("command", "")) + str(inp.get("file_path", ""))
                    if source_function in ev_text:
                        related_sessions.add(ev.session_id)
            # 从文件/函数匹配到的 session 出发 BFS，扩展完整调查链
            if related_sessions and session_graph and session_graph.get('edges'):
                queue = list(related_sessions)
                visited = set(related_sessions)
                while queue:
                    cur = queue.pop(0)
                    neighbors = session_graph.get('edges', {}).get(cur, set())
                    for n in neighbors:
                        if n not in visited:
                            visited.add(n)
                            related_sessions.add(n)
                            queue.append(n)

        # 3. 过滤 sampled_interactions：只保留 session_id 在 related_sessions 里的
        if related_sessions and sampled_interactions:
            case_interactions = [iv for iv in sampled_interactions
                                 if iv.get("session_id", "") in related_sessions]
        elif not matched_fid:
            case_interactions = []
        else:
            case_interactions = sampled_interactions

        # 4. 从 events 提取挖掘过程摘要（按 related_sessions 过滤）
        mining_actions = []
        source_file_basename = ""
        if case.get("source_file"):
            import os as _os2
            source_file_basename = _os2.basename(case.get("source_file", ""))
        source_function = case.get("source_function", "")

        def _extract_action(ev):
            """从单个 event 提取挖掘行为摘要。"""
            inp = ev.input_json or {}
            tool = ev.tool_name or ""
            if tool == "bash":
                cmd = str(inp.get("command", ""))[:150]
                if cmd and not cmd.strip().startswith(("head", "cat ", "ls ", "grep ")):
                    return {"tool": "bash", "action": cmd, "session_id": ev.session_id}
            elif tool == "read":
                fp = str(inp.get("file_path", ""))[:150]
                if fp:
                    return {"tool": "read", "action": fp, "session_id": ev.session_id}
            elif tool in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding", "ReportFindings", "reportfindings"):
                title = str(inp.get("title", "") or inp.get("short_summary", ""))[:100]
                return {"tool": "finding", "action": title, "session_id": ev.session_id}
            elif tool == "write":
                fp = str(inp.get("file_path", ""))[:100]
                if fp:
                    return {"tool": "write", "action": fp, "session_id": ev.session_id}
            return None

        if events and related_sessions:
            for ev in events:
                if not hasattr(ev, "is_tool_call") or not ev.is_tool_call():
                    continue
                if ev.session_id not in related_sessions:
                    continue
                a = _extract_action(ev)
                if a:
                    mining_actions.append(a)
                if len(mining_actions) >= 30:
                    break

        # FN 案例且 mining_actions 为空：fallback 扫描全量 events
        # 优先提取与漏洞文件/函数相关的行为，再补充其他行为
        if not mining_actions and events and confusion == "FN":
            related_hits = []
            other_actions = []
            for ev in events:
                if not hasattr(ev, "is_tool_call") or not ev.is_tool_call():
                    continue
                a = _extract_action(ev)
                if not a:
                    continue
                action_text = (a.get("action", "") + " " + a.get("session_id", "")).lower()
                is_related = False
                if source_file_basename and source_file_basename.lower() in action_text:
                    is_related = True
                if source_function and source_function.lower() in action_text:
                    is_related = True
                if is_related:
                    related_hits.append(a)
                else:
                    other_actions.append(a)
            # 优先放相关行为，再补充其他行为（read 优先于 bash）
            mining_actions = related_hits[:20]
            other_sorted = sorted(other_actions, key=lambda x: (0 if x["tool"] == "read" else 1 if x["tool"] == "finding" else 2))
            mining_actions.extend(other_sorted[:30])
            if len(mining_actions) > 50:
                mining_actions = mining_actions[:50]

        # 映射 confusion → kg_judgment
        kg_judgment = "NOT_FOUND"
        if confusion == "TP":
            kg_judgment = "VULNERABILITY"
        elif confusion == "FP":
            kg_judgment = "NON_VULNERABILITY"

        # 找 No-KG 的 confusion（不再用于 impact，但保留用于对比记录）
        nogk_confusion = "NA"
        if nogk_case_results:
            for nc in nogk_case_results:
                if nc.get("case_id") == case_id:
                    nogk_confusion = nc.get("confusion", "NA")
                    break

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
            })
            continue

        # 无知识交互时的处理
        if not case_interactions:
            # FN 案例且无知识交互：调 LLM 分析为什么没有发现漏洞
            if kg_judgment == "NOT_FOUND":
                source_file = case.get("source_file", "")
                source_function = case.get("source_function", "")
                fn_data = {
                    "baseline_vulnerability": {
                        "case_id": case_id,
                        "description": description[:800],
                        "vulnerability_type": vuln_type,
                        "source_file": source_file,
                        "source_function": source_function,
                    },
                    "kg_status": {"confusion": confusion, "kg_judgment": kg_judgment},
                    "mining_actions": mining_actions,
                    "nogk_confusion": nogk_confusion,
                }
                fn_prompt = [
                    {"role": "system", "content": (
                        "你是漏洞挖掘失败分析员。Agent 未发现此基线漏洞（FN），请分析原因。\n\n"
                        "# 知识图谱与记忆的使用方法\n"
                        "知识图谱（KG）：Agent 通过代码知识查询工具查询知识图谱，获取项目代码结构、组件依赖、"
                        "已知漏洞模式等知识，用于引导漏洞挖掘方向。\n"
                        "记忆（Memory）：Agent 通过记忆引擎读取历史挖掘经验、写入新发现，"
                        "用于跨会话积累和复用漏洞挖掘知识。\n"
                        "在 KG 条件下，Agent 同时拥有知识图谱和记忆能力；在 No-KG 条件下，两者均不可用。\n\n"
                        "# 分析方法\n"
                        "将 baseline_vulnerability（基线漏洞详情）与 mining_actions（Agent 实际挖掘行为）逐项对比：\n"
                        "1. Agent 是否读取过 source_file？在 mining_actions 中搜索匹配的 read/bash 路径\n"
                        "2. Agent 是否分析了 source_function？在 mining_actions 中搜索函数名\n"
                        "3. Agent 提交的 finding 与 vulnerability_type 是否相关？\n"
                        "4. Agent 的挖掘范围覆盖了哪些文件/目录？是否偏离了漏洞所在区域？\n"
                        "5. Agent 是否查询了知识图谱与记忆？未查询是否是漏报原因之一？\n"
                        "6. No-KG 也漏报了吗（nogk_confusion）？双方都漏报说明漏洞本身难发现\n"
                        "7. 知识图谱与记忆对漏洞挖掘的影响：正向（引导到正确区域）、负向（误导方向）、中性（无影响）\n\n"
                        "只返回 JSON。"
                    )},
                    {"role": "user", "content": json.dumps(fn_data, ensure_ascii=False, indent=2) + (
                        '\n\n请对比基线漏洞信息与 Agent 挖掘过程，分析为什么 Agent 没有发现这个漏洞：\n'
                        '1. 基线漏洞在 ' + (source_file or '未知') + ' 的 ' + (source_function or '未知') + ' 中，'
                        '类型为 ' + (vuln_type or '未知') + '。Agent 在 mining_actions 中是否接触过这个文件/函数？\n'
                        '2. 如果 Agent 没接触过，Agent 主要在分析什么？（列出 mining_actions 中的主要文件/命令）\n'
                        '3. Agent 提交了哪些 finding？与基线漏洞类型是否相关？\n'
                        '4. No-KG 结果为 ' + nogk_confusion + '，说明什么？\n'
                        '5. 给出具体原因（如：未接触漏洞文件、挖掘方向偏离、漏洞类型不匹配、缺少知识引导等）\n\n'
                        '返回 JSON: {"kg_judgment": "NOT_FOUND", "query_summary": "无知识查询", "knowledge_summary": "无知识返回", "impact": "NEUTRAL", "reason": "<=150字中文，必须给出具体原因"}'
                    )},
                ]
                try:
                    result = llm_mod.chat_json(fn_prompt, temperature=0)
                    result["case_id"] = case_id
                    result["interactions"] = []
                    results.append(result)
                except Exception:
                    results.append({
                        "case_id": case_id,
                        "kg_judgment": kg_judgment,
                        "query_summary": "无知识查询",
                        "knowledge_summary": "无知识返回",
                        "impact": "NEUTRAL",
                        "reason": "Agent 未发现此漏洞，且无知识图谱与记忆介入。LLM 分析不可用。",
                        "interactions": [],
                    })
                continue
            # 非 FN 且无知识交互：直接判定，不调 LLM
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
            })
            continue

        data = {
            "baseline_vulnerability": {
                "case_id": case_id,
                "description": description[:800],
                "vulnerability_type": vuln_type,
                "source_file": case.get("source_file", ""),
                "source_function": case.get("source_function", ""),
            },
            "kg_status": {
                "confusion": confusion,
                "kg_judgment": kg_judgment,
                "matched_finding_id": matched_fid or None,
            },
            "knowledge_interactions": [{"tool": iv.get("tool",""),
                                        "question": iv.get("command_parsed") or iv.get("command",""),
                                        "answer": iv.get("output_parsed") or iv.get("answer","")} for iv in case_interactions],
            "mining_actions": mining_actions,
            "nogk_confusion": nogk_confusion,
        }

        # FN 案例追加"为什么没有发现"的分析指令
        fn_extra = ""
        if kg_judgment == "NOT_FOUND":
            fn_extra = (
                "\n5. 为什么 Agent 没有发现这个漏洞？在 mining_actions 中，Agent 是否读取过 source_file（"
                + (case.get("source_file", "") or "未知") + "）？Agent 主要在分析哪些文件？"
                "\n6. Agent 提交的 finding 与基线漏洞的 vulnerability_type 是否相关？"
                "\n7. 知识图谱与记忆是否包含此漏洞的相关信息？如果有，Agent 为什么没有利用？"
                "\n8. No-KG 也漏报了吗（nogk_confusion）？如果都漏报说明漏洞本身难发现。"
                "\n9. 必须给出具体原因（如：未接触漏洞文件/函数、挖掘方向偏离、漏洞类型不匹配等），不要泛泛而谈。"
            )
        prompt = [
            {"role": "system", "content": (
                "你是知识图谱与记忆介入效果分析员。针对每个基线漏洞，分析知识图谱与记忆的介入情况。\n\n"
                "# 知识图谱与记忆的使用方法\n"
                "知识图谱（KG）：Agent 通过代码知识查询工具查询知识图谱，获取项目代码结构、组件依赖、"
                "已知漏洞模式等知识，用于引导漏洞挖掘方向。\n"
                "记忆（Memory）：Agent 通过记忆引擎读取历史挖掘经验、写入新发现，"
                "用于跨会话积累和复用漏洞挖掘知识。\n"
                "在 KG 条件下，Agent 同时拥有知识图谱和记忆能力；在 No-KG 条件下，两者均不可用。\n\n"
                "# impact 判定规则（基于 KG 结果与基线的对比 + 知识交互内容）\n"
                "- POSITIVE（正向）：知识图谱与记忆提供的知识帮助 Agent 找到了与基线一致的漏洞，"
                "或引导 Agent 聚焦到正确的漏洞区域\n"
                "- NEGATIVE（负向）：知识图谱与记忆提供的信息误导了 Agent，导致与基线不符，"
                "或 Agent 过度依赖知识而忽略了实际代码中的漏洞\n"
                "- NEUTRAL（中性）：知识交互与漏洞排查无关，或知识未产生影响，"
                "Agent 的挖掘行为在有/无知识时无显著差异\n\n"
                "只返回 JSON。"
            )},
            {"role": "user", "content": json.dumps(data, ensure_ascii=False, indent=2) + (
                '\n\n分析：\n1. KG 是否识别此漏洞？\n2. Agent 向知识图谱与记忆问了什么？\n3. 知识图谱与记忆返回了什么？\n4. 知识对排查此漏洞是正向、负向还是中性？'
                + fn_extra +
                '\n\n返回 JSON: {"kg_judgment": "VULNERABILITY|NON_VULNERABILITY|NOT_FOUND", "query_summary": "<=50字中文", "knowledge_summary": "<=50字中文", "impact": "POSITIVE|NEGATIVE|NEUTRAL", "reason": "<=150字中文"}'
            )},
        ]

        try:
            result = llm_mod.chat_json(prompt, temperature=0)
            result["case_id"] = case_id
            result["interactions"] = case_interactions
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
            })

    return results
