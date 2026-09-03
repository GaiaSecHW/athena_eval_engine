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
    m1, s1 = get("M1"); m7, s7 = get("M7"); m8, s8 = get("M8")

    # 知识访问率低
    if m5 and m5.estimate is not None and s5 and s5.ci_upper is not None:
        if s5.ci_upper < kar_ref:
            hits.append(DiagnosticHit("D1", f"知识访问率={m5.estimate:.2f}(低)",
                                     "未观察到 Agent 对知识平台的充分触达",
                                     "检查 wiki mount 配置 / skill 调用链路"))
        if m5.estimate >= kar_ref and m6 and m6.estimate is not None and s6 and s6.ci_upper is not None and s6.ci_upper < kdr_ref:
            hits.append(DiagnosticHit("D2", f"知识访问率={m5.estimate:.2f}(高) 但 知识交付率={m6.estimate:.2f}(低)",
                                     "知识访问后的交付链路存在问题",
                                     "检查 wiki 内容路径 / reject_patterns 是否过严"))

    # 知识交付率高 但 准确率无变化
    if m6 and m6.estimate is not None and s6 and s6.ci_lower is not None and s6.ci_lower > kdr_ref:
        if m1 and _dir(m1, s1) == "≈":
            hits.append(DiagnosticHit("D3", f"知识交付率={m6.estimate:.2f}(高) 但 准确率无变化",
                                     "知识已交付，但尚未观察到总体任务收益",
                                     "检查知识是否对齐目标 finding；考虑 benchmark 质量"))

    # 行为偏移大 + 准确率提升 / 回归率上升
    if m7 and m7.estimate is not None and m7.estimate >= jsd_shift:
        if m1 and _dir(m1, s1) == "↑":
            hits.append(DiagnosticHit("D4", f"行为偏移={m7.estimate:.2f}(大) + 准确率提升",
                                     "工具行为变化伴随总体效果提升",
                                     "可继续观察行为变化模式"))
        m3 = m_by.get("M3"); s3 = s_by_metric.get("M3")
        if m3 and _dir(m3, s3) == "↑":
            hits.append(DiagnosticHit("D5", f"行为偏移={m7.estimate:.2f}(大) + 回归率上升",
                                     "工具行为变化伴随回归风险上升",
                                     "检查是否引入新的误判路径"))

    # 准确率提升 但 token 大增
    if m1 and _dir(m1, s1) == "↑" and m8 and m8.estimate is not None and s8 and s8.ci_lower is not None and s8.ci_lower > 0:
        hits.append(DiagnosticHit("D6", f"准确率提升 + token增加{m8.estimate:.0f}",
                                 "效果提升但资源成本增加",
                                 "评估收益/成本比是否可接受"))

    # 准确率无变化 但 token 增加
    if m1 and _dir(m1, s1) == "≈" and m8 and m8.estimate is not None and s8 and s8.ci_lower is not None and s8.ci_lower > 0:
        hits.append(DiagnosticHit("D7", f"准确率无变化 + token增加{m8.estimate:.0f}",
                                 "未观察到明显收益，但产生额外成本",
                                 "检查 KG 是否真正被使用"))

    return hits
