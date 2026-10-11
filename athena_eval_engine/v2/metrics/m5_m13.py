"""Metric Engine — M5-M13。

方案不含 No-KG 对照组：
- M5/M6/M11/M12：从计数参数直接计算（Wilson CI）
- M7-M10（JSD/ΔToken/ΔSteps/ΔTime）：需要 KG vs No-KG 配对，返回 NA
- M13：误报率占位，实际值由 REPORTING 阶段填充
分母=0 → NA；UNDETERMINED 不计。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from .engine import wilson

CALCULATED = "CALCULATED"; NA = "NA"; BLOCKED = "BLOCKED"


@dataclass
class MetricResult:
    metric_id: str
    estimate: float | None
    unit: str
    n: int
    n_population: str
    median: float | None = None
    q1: float | None = None
    q3: float | None = None
    iqr: float | None = None
    calculation_status: str = CALCULATED
    reason_code: str | None = None
    method: dict = field(default_factory=dict)


@dataclass
class StatisticalResult:
    metric_id: str | None
    test_name: str
    statistic: float | None = None
    p_value: float | None = None
    ci_lower: float | None = None
    ci_upper: float | None = None
    testing_tier: str = "SECONDARY"
    scope_type: str = "METRIC"
    joint_analysis_id: str | None = None
    related_metric_ids: list | None = None
    status: str = CALCULATED
    reason_code: str | None = None
    details: dict = field(default_factory=dict)


# ===== M13 误报率（FPR） =====
def calc_m13() -> tuple[MetricResult, list[StatisticalResult]]:
    """M13 误报率占位：实际值由 REPORTING 阶段 _update_m13_fpr 用 LLM 基线匹配结果填充。"""
    return (MetricResult("M13", None, "ratio", 0, "primary_analysis",
                         calculation_status=NA, reason_code="PENDING_FPR_ANALYSIS",
                         method={}),
            [StatisticalResult("M13", "none",
                               testing_tier="PRIMARY", scope_type="METRIC",
                               status=NA, reason_code="PENDING_FPR_ANALYSIS")])


# ===== M5 KAR / M6 KDR =====
def calc_m5(kg_tool_calls: int, total_tool_calls: int, confidence=0.95) -> tuple[MetricResult, list[StatisticalResult]]:
    """M5 KAR 知识访问率 = 知识查询次数 / 总工具调用次数（交互级）。"""
    if total_tool_calls == 0:
        m = MetricResult("M5", None, "ratio", 0, "kg_enabled_valid", calculation_status=NA, reason_code="NO_TOOL_CALLS")
        return m, [StatisticalResult("M5", "wilson", testing_tier="SECONDARY", status=NA, reason_code="NO_TOOL_CALLS")]
    lo, hi, st, rc = wilson(kg_tool_calls, total_tool_calls, confidence)
    kar = kg_tool_calls / total_tool_calls
    return (MetricResult("M5", kar, "ratio", total_tool_calls, "kg_enabled_valid",
                         method={"uncertainty": "wilson",
                                 "kg_tool_calls": kg_tool_calls, "total_tool_calls": total_tool_calls}),
            [StatisticalResult("M5", "wilson", ci_lower=lo, ci_upper=hi,
                               testing_tier="SECONDARY", scope_type="METRIC", status=st, reason_code=rc)])


# ===== M11 记忆访问率 / M12 记忆交付率（与 M5/M6 同算法）=====
def calc_m11(mem_read_count: int, total_tool_calls: int, confidence=0.95) -> tuple[MetricResult, list[StatisticalResult]]:
    """M11 记忆访问率 = 记忆读取次数 / 总工具调用次数。同 M5 算法。"""
    if total_tool_calls == 0:
        m = MetricResult("M11", None, "ratio", 0, "kg_enabled_valid", calculation_status=NA, reason_code="NO_TOOL_CALLS")
        return m, [StatisticalResult("M11", "wilson", testing_tier="SECONDARY", status=NA, reason_code="NO_TOOL_CALLS")]
    lo, hi, st, rc = wilson(mem_read_count, total_tool_calls, confidence)
    mar = mem_read_count / total_tool_calls
    return (MetricResult("M11", mar, "ratio", total_tool_calls, "kg_enabled_valid",
                         method={"uncertainty": "wilson",
                                 "mem_read_count": mem_read_count, "total_tool_calls": total_tool_calls}),
            [StatisticalResult("M11", "wilson", ci_lower=lo, ci_upper=hi,
                               testing_tier="SECONDARY", scope_type="METRIC", status=st, reason_code=rc)])


def calc_m12(mem_successful_reads: int, mem_read_events: int, confidence=0.95) -> tuple[MetricResult, list[StatisticalResult]]:
    """M12 记忆交付率 = 成功记忆读取 / 记忆读取次数。同 M6 算法。"""
    if mem_read_events == 0:
        m = MetricResult("M12", None, "ratio", 0, "kg_access_valid", calculation_status=NA, reason_code="NO_MEMORY_ACCESS")
        return m, [StatisticalResult("M12", "wilson", testing_tier="SECONDARY", status=NA, reason_code="NO_MEMORY_ACCESS")]
    lo, hi, st, rc = wilson(mem_successful_reads, mem_read_events, confidence)
    mdr = mem_successful_reads / mem_read_events
    return (MetricResult("M12", mdr, "ratio", mem_read_events, "kg_access_valid",
                         method={"uncertainty": "wilson",
                                 "mem_successful_reads": mem_successful_reads, "mem_read_events": mem_read_events}),
            [StatisticalResult("M12", "wilson", ci_lower=lo, ci_upper=hi,
                               testing_tier="SECONDARY", scope_type="METRIC", status=st, reason_code=rc)])


def calc_m6(successful_read_count: int, access_event_count: int, confidence=0.95) -> tuple[MetricResult, list[StatisticalResult]]:
    """M6 KDR 知识交付率 = 有效回复次数 / 总查询次数（交互级，非任务级）。"""
    if access_event_count == 0:
        m = MetricResult("M6", None, "ratio", 0, "access_valid", calculation_status=NA, reason_code="NO_ACCESS_EVENT")
        return m, [StatisticalResult("M6", "wilson", testing_tier="SECONDARY", status=NA, reason_code="NO_ACCESS_EVENT")]
    capped_reads = min(successful_read_count, access_event_count)
    lo, hi, st, rc = wilson(capped_reads, access_event_count, confidence)
    kdr = capped_reads / access_event_count
    return (MetricResult("M6", kdr, "ratio", access_event_count, "access_valid",
                         method={"uncertainty": "wilson",
                                 "successful_read_count": capped_reads, "access_event_count": access_event_count}),
            [StatisticalResult("M6", "wilson", ci_lower=lo, ci_upper=hi,
                               testing_tier="SECONDARY", scope_type="METRIC", status=st, reason_code=rc)])


def run_all_metrics(*, kg_access_events=0, kg_successful_reads=0,
                     mem_read_count=0, mem_successful_reads=0,
                     kg_tool_calls=0, total_tool_calls=0, seed=42) -> dict:
    """跑全部指标 + 统计证据。返回 {metric_results, statistical_results}。

    方案不含 No-KG 对照组，M7-M10（JSD/ΔToken/ΔSteps/ΔTime）返回 NA。
    M5/M6/M11/M12 不依赖配对，直接从计数参数计算。
    """
    m5, s5 = calc_m5(kg_access_events, total_tool_calls)
    m6, s6 = calc_m6(kg_successful_reads, kg_access_events)
    m11, s11 = calc_m11(mem_read_count, total_tool_calls)
    m12, s12 = calc_m12(mem_successful_reads, mem_read_count)
    m13, s13 = calc_m13()
    # M7-M10 需要 KG vs No-KG 配对，方案无 No-KG，返回 NA
    m7 = MetricResult("M7", None, "ratio", 0, "jsd_valid",
                      calculation_status=NA, reason_code="NO_NOGK_CONTROL", method={})
    s7 = StatisticalResult("M7", "paired_bootstrap", testing_tier="SECONDARY",
                           status=NA, reason_code="NO_NOGK_CONTROL")
    m8 = MetricResult("M8", None, "tokens", 0, "delta_valid",
                      calculation_status=NA, reason_code="NO_NOGK_CONTROL", method={})
    s8 = StatisticalResult("M8", "wilcoxon_signed_rank", testing_tier="SECONDARY",
                           status=NA, reason_code="NO_NOGK_CONTROL")
    m9 = MetricResult("M9", None, "steps", 0, "delta_valid",
                      calculation_status=NA, reason_code="NO_NOGK_CONTROL", method={})
    s9 = StatisticalResult("M9", "wilcoxon_signed_rank", testing_tier="SECONDARY",
                           status=NA, reason_code="NO_NOGK_CONTROL")
    m10 = MetricResult("M10", None, "ms", 0, "delta_valid",
                       calculation_status=NA, reason_code="NO_NOGK_CONTROL", method={})
    s10 = StatisticalResult("M10", "wilcoxon_signed_rank", testing_tier="SECONDARY",
                            status=NA, reason_code="NO_NOGK_CONTROL")
    mrs = [m13, m5, m6, m7, m8, m9, m10, m11, m12]
    srs = s13 + s5 + s6 + s7 + s8 + s9 + s10 + s11 + s12
    return {"metric_results": mrs, "statistical_results": srs}
