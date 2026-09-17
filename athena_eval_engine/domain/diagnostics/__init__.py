"""Diagnostic Rule Engine（§9.19）— 薄层，只消费 MetricResult/StatisticalResult。

方向性符号定义见 §9.18。M7 用 shift_high/shift_low（neutral，不进 ↑/↓）。
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class DiagnosticHit:
    rule_id: str
    observed: str
    interpretation: str
    suggestion: str


def _dir(mr, sr, *, ref_threshold=None):
    """返回 ↑/↓/≈（Δ 型，CI 不跨 0 + 幅度阈值）。"""
    if mr is None or mr.estimate is None or sr is None:
        return "≈"
    lo, hi = sr.ci_lower, sr.ci_upper
    if lo is None or hi is None:
        return "≈"
    if lo <= 0 <= hi:
        return "≈"
    return "↑" if mr.estimate > 0 else "↓"


def diagnose(metrics: list, stats: list, *, kar_ref=0.8, kdr_ref=0.9,
             jsd_shift=0.10, directional_ratio=0.02) -> list[DiagnosticHit]:
    """metrics: [MetricResult]; stats: [StatisticalResult]。返回命中规则。"""
    m_by = {m.metric_id: m for m in metrics}
    s_by_metric = {s.metric_id: s for s in stats if s.metric_id in m_by}
    hits: list[DiagnosticHit] = []

    def get(mid):
        return m_by.get(mid), s_by_metric.get(mid)

    m5, s5 = get("M5"); m6, s6 = get("M6")
    m11, s11 = get("M11"); m12, s12 = get("M12")
    m7, s7 = get("M7"); m8, s8 = get("M8")

    # 知识访问率低
    if m5 and m5.estimate is not None and s5 and s5.ci_upper is not None:
        if s5.ci_upper < kar_ref:
            # 区分两种情况：完全未触达 vs 触达了但占比低
            if m5.n is not None and m5.n > 0 and m5.estimate > 0.001:
                # 有查询（绝对次数 > 0），只是占总工具调用比例低
                hits.append(DiagnosticHit("D1", f"知识访问率={m5.estimate:.1%}(低，{m5.n} 次工具调用中占比小)",
                                         "Agent 有知识查询行为，但知识使用占总工具调用比例低",
                                         "如需提高知识依赖度，检查任务设计与知识平台的关联度"))
            else:
                # 几乎无查询
                hits.append(DiagnosticHit("D1", f"知识访问率={m5.estimate:.1%}(极低)",
                                         "未观察到 Agent 对知识平台的充分触达",
                                         "检查 wiki mount 配置 / skill 调用链路"))
        if m5.estimate >= kar_ref and m6 and m6.estimate is not None and s6 and s6.ci_upper is not None and s6.ci_upper < kdr_ref:
            hits.append(DiagnosticHit("D2", f"知识访问率={m5.estimate:.1%}(高) 但 知识交付率={m6.estimate:.1%}(低)",
                                     "知识访问后的交付链路存在问题",
                                     "检查 wiki 内容路径 / reject_patterns 是否过严"))

    # ===== 记忆诊断（与知识诊断同结构：D8/D9）=====
    # D8: 记忆访问率低
    if m11 and m11.estimate is not None and s11 and s11.ci_upper is not None:
        if s11.ci_upper < kar_ref:
            if m11.n is not None and m11.n > 0 and m11.estimate > 0.001:
                hits.append(DiagnosticHit("D8", f"记忆访问率={m11.estimate:.1%}(低，{m11.n} 次工具调用中占比小)",
                                         "Agent 有记忆读取行为，但记忆使用占总工具调用比例低",
                                         "如需提高记忆依赖度，检查 memengine 集成与任务连贯性设计"))
            else:
                hits.append(DiagnosticHit("D8", f"记忆访问率={m11.estimate:.1%}(极低)",
                                         "未观察到 Agent 对记忆的充分使用",
                                         "检查 memengine 工具链路 / 子 agent 会话是否正常保存记忆"))
        if m11.estimate >= kar_ref and m12 and m12.estimate is not None and s12 and s12.ci_upper is not None and s12.ci_upper < kdr_ref:
            hits.append(DiagnosticHit("D9", f"记忆访问率={m11.estimate:.1%}(高) 但 记忆交付率={m12.estimate:.1%}(低)",
                                     "记忆读取后的内容获取存在问题",
                                     "检查记忆文件路径 / 记忆内容是否为空"))

    # 行为偏移大
    if m7 and m7.estimate is not None and m7.estimate >= jsd_shift:
        hits.append(DiagnosticHit("D4", f"行为偏移={m7.estimate:.2f}(大)",
                                 "工具行为变化显著",
                                 "可继续观察行为变化模式"))

    # token 增加
    if m8 and m8.estimate is not None and s8 and s8.ci_lower is not None and s8.ci_lower > 0:
        hits.append(DiagnosticHit("D6", f"token增加{m8.estimate:.0f}",
                                 "产生额外资源成本",
                                 "评估收益/成本比是否可接受"))

    return hits
