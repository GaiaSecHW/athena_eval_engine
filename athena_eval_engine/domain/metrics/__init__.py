"""Metric Engine — M1-M10（§9.2 / §9.5-9.10）。

每个 Metric.calculate(context) → (MetricResult, [StatisticalResult])。
- M1/M4：dataset-level confusion + GT-stratified bootstrap CI
- M2/M3：IR=C/(C+D), RR=B/(A+B) + Paired Bootstrap CI + 联合 McNemar
- M5/M6：Wilson CI
- M7：JSD median + IQR + Paired Bootstrap
- M8-M10：ΔToken/Steps/Time median + IQR + Paired Bootstrap CI + Wilcoxon
分母=0 → NA + reason；UNDETERMINED 不计。
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import Callable
import numpy as np
from ..statistics.engine import (
    gt_stratified_paired_bootstrap, paired_bootstrap, wilson, mcnemar, wilcoxon,
    _UndefinedReplicate,
)

CALCULATED = "CALCULATED"; NA = "NA"; BLOCKED = "BLOCKED"


@dataclass
class PairView:
    """配对视图，供 estimator 用。gt=benchmark expected_label。"""
    kg_success: bool
    nogk_success: bool
    gt: str  # VULNERABLE / NON_VULNERABLE
    kg_outcome: str; nogk_outcome: str
    jsd: float | None
    delta_token: float | None
    delta_steps: float | None
    delta_time: float | None


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
    metric_id: str | None  # METRIC 行=M1-M10；JOINT 行=None
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


def _confusion(pairs: list[PairView]) -> dict:
    """dataset-level 2x2：A=Preserved,B=Regressed,C=Recovered,D=PersistedFailure。
    confusion: TP/FP/FN/TN per condition（dataset 聚合）。"""
    A = B = C = D = 0
    tp_kg = fp_kg = fn_kg = tn_kg = 0
    tp_n = fp_n = fn_n = tn_n = 0
    for p in pairs:
        ks, ns = p.kg_success, p.nogk_success
        if ns and ks: A += 1
        elif ns and not ks: B += 1
        elif (not ns) and ks: C += 1
        else: D += 1
        # KG confusion
        if p.kg_outcome == "SUCCESS":
            if p.gt == "VULNERABLE": tp_kg += 1
            else: fp_kg += 1
        else:
            if p.gt == "VULNERABLE": fn_kg += 1
            else: tn_kg += 1
        if p.nogk_outcome == "SUCCESS":
            if p.gt == "VULNERABLE": tp_n += 1
            else: fp_n += 1
        else:
            if p.gt == "VULNERABLE": fn_n += 1
            else: tn_n += 1
    return dict(A=A, B=B, C=C, D=D,
                tp_kg=tp_kg, fp_kg=fp_kg, fn_kg=fn_kg, tn_kg=tn_kg,
                tp_n=tp_n, fp_n=fp_n, fn_n=fn_n, tn_n=tn_n)


def _ba(cm, kg=True) -> float | None:
    """BA = (TPR+TNR)/2。TPR=TP/(TP+FN), TNR=TN/(TN+FP)。"""
    tp = cm["tp_kg"] if kg else cm["tp_n"]
    fn = cm["fn_kg"] if kg else cm["fn_n"]
    tn = cm["tn_kg"] if kg else cm["tn_n"]
    fp = cm["fp_kg"] if kg else cm["fp_n"]
    if (tp + fn) == 0 or (tn + fp) == 0:
        raise _UndefinedReplicate()
    return (tp / (tp + fn) + tn / (tn + fp)) / 2


def _fnr(cm, kg=True) -> float | None:
    fn = cm["fn_kg"] if kg else cm["fn_n"]
    tp = cm["tp_kg"] if kg else cm["tp_n"]
    if fn + tp == 0:
        raise _UndefinedReplicate()
    return fn / (fn + tp)


# ===== M1 ΔBA =====
def calc_m1(pairs: list[PairView], *, seed=42) -> tuple[MetricResult, list[StatisticalResult]]:
    cm = _confusion(pairs)
    try:
        est = _ba(cm, True) - _ba(cm, False)
    except _UndefinedReplicate:
        return (MetricResult("M1", None, "ratio", len(pairs), "primary_analysis",
                             calculation_status=NA, reason_code="NO_STRATUM",
                             method={"point_estimator": "dataset_confusion_matrix"}), [])
    br = gt_stratified_paired_bootstrap(pairs, lambda ps: _ba(_confusion(ps), True) - _ba(_confusion(ps), False),
                                        B=2000, seed=seed)
    status = CALCULATED if br.status == "CALCULATED" else NA
    # bootstrap 失败时，点估计不输出（NA 合约：NA 行不携带 estimate）
    m1_est = est if status == CALCULATED else None
    return (MetricResult("M1", m1_est, "ratio", len(pairs), "primary_analysis",
                         calculation_status=status,
                         reason_code=br.reason_code,
                         method={"uncertainty": "gt_stratified_paired_bootstrap",
                                 "bootstrap_valid_replicates": br.valid}),
            [StatisticalResult("M1", "gt_stratified_paired_bootstrap",
                               ci_lower=br.ci_lower, ci_upper=br.ci_upper,
                               testing_tier="PRIMARY", scope_type="METRIC",
                               status=status, reason_code=br.reason_code,
                               details={"bootstrap_B": br.requested, "valid": br.valid, "attempts": br.attempts})])


# ===== M2 IR + M3 RR + McNemar joint =====
def calc_m2_m3(pairs: list[PairView], *, seed=42) -> dict:
    cm = _confusion(pairs)
    A, B, C, D = cm["A"], cm["B"], cm["C"], cm["D"]
    # M2 IR = C/(C+D)
    if C + D == 0:
        m2 = MetricResult("M2", None, "ratio", C + D, "primary_analysis",
                          calculation_status=NA, reason_code="NO_VALID_DENOMINATOR", method={})
        m2s = [StatisticalResult("M2", "paired_bootstrap", testing_tier="PRIMARY",
                                 status=NA, reason_code="NO_VALID_DENOMINATOR")]
    else:
        ir = C / (C + D)
        br = paired_bootstrap(pairs, lambda ps: (lambda c: c["C"] / (c["C"] + c["D"]) if c["C"] + c["D"] else None)(_confusion(ps)) or 0,
                               B=2000, seed=seed)
        m2 = MetricResult("M2", ir, "ratio", C + D, "primary_analysis",
                          method={"point_estimator": "conditional_improvement_rate"})
        m2s = [StatisticalResult("M2", "paired_bootstrap", ci_lower=br.ci_lower, ci_upper=br.ci_upper,
                                 testing_tier="PRIMARY", scope_type="METRIC",
                                 status=CALCULATED if br.status == "CALCULATED" else NA,
                                 reason_code=br.reason_code, details={"valid": br.valid})]
    # M3 RR = B/(A+B)
    if A + B == 0:
        m3 = MetricResult("M3", None, "ratio", A + B, "primary_analysis",
                          calculation_status=NA, reason_code="NO_VALID_DENOMINATOR", method={})
        m3s = [StatisticalResult("M3", "paired_bootstrap", testing_tier="PRIMARY",
                                  status=NA, reason_code="NO_VALID_DENOMINATOR")]
    else:
        rr = B / (A + B)
        br = paired_bootstrap(pairs, lambda ps: (lambda c: c["B"] / (c["A"] + c["B"]) if c["A"] + c["B"] else None)(_confusion(ps)) or 0,
                               B=2000, seed=seed)
        m3 = MetricResult("M3", rr, "ratio", A + B, "primary_analysis",
                          method={"point_estimator": "conditional_regression_rate"})
        m3s = [StatisticalResult("M3", "paired_bootstrap", ci_lower=br.ci_lower, ci_upper=br.ci_upper,
                                 testing_tier="PRIMARY", scope_type="METRIC",
                                 status=CALCULATED if br.status == "CALCULATED" else NA,
                                 reason_code=br.reason_code, details={"valid": br.valid})]
    # McNemar joint（B vs C）
    mc = mcnemar(B, C)
    joint = StatisticalResult(None, "mcnemar_joint_m2_m3", statistic=mc["statistic"],
                              p_value=mc["p_value"], testing_tier="PRIMARY", scope_type="JOINT",
                              joint_analysis_id="J001", related_metric_ids=["M2", "M3"],
                              status=mc["status"], reason_code=mc.get("reason_code"),
                              details={"method": mc.get("method"), "b": B, "c": C})
    return {"m2": m2, "m3": m3, "statistical": m2s + m3s + [joint]}


# ===== M4 ΔFNR =====
def calc_m4(pairs: list[PairView], *, seed=42) -> tuple[MetricResult, list[StatisticalResult]]:
    cm = _confusion(pairs)
    try:
        est = _fnr(cm, True) - _fnr(cm, False)
    except _UndefinedReplicate:
        return (MetricResult("M4", None, "ratio", len(pairs), "primary_analysis",
                             calculation_status=NA, reason_code="NO_POSITIVE_GT", method={}), [])
    br = gt_stratified_paired_bootstrap(pairs, lambda ps: _fnr(_confusion(ps), True) - _fnr(_confusion(ps), False),
                                        B=2000, seed=seed)
    status = CALCULATED if br.status == "CALCULATED" else NA
    # bootstrap 失败时，点估计不输出（NA 合约：NA 行不携带 estimate）
    m4_est = est if status == CALCULATED else None
    return (MetricResult("M4", m4_est, "ratio", len(pairs), "primary_analysis",
                         calculation_status=status, reason_code=br.reason_code,
                         method={"uncertainty": "gt_stratified_paired_bootstrap", "valid": br.valid}),
            [StatisticalResult("M4", "gt_stratified_paired_bootstrap",
                               ci_lower=br.ci_lower, ci_upper=br.ci_upper,
                               testing_tier="PRIMARY", scope_type="METRIC",
                               status=status, reason_code=br.reason_code,
                               details={"valid": br.valid, "attempts": br.attempts})])


# ===== M5 KAR / M6 KDR =====
def calc_m5(kg_tool_calls: int, total_tool_calls: int, confidence=0.95) -> tuple[MetricResult, list[StatisticalResult]]:
    """M5 KAR 知识访问率 = 知识查询次数 / 总工具调用次数（交互级）。
    kg_tool_calls: 所有 KG 运行中分类为 KG 的工具调用数（Σ kg_count）
    total_tool_calls: 所有 KG 运行中总工具调用数（Σ total_tool_calls）"""
    if total_tool_calls == 0:
        m = MetricResult("M5", None, "ratio", 0, "kg_enabled_valid", calculation_status=NA, reason_code="NO_TOOL_CALLS")
        return m, [StatisticalResult("M5", "wilson", testing_tier="SECONDARY", status=NA, reason_code="NO_TOOL_CALLS")]
    lo, hi, st, rc = wilson(kg_tool_calls, total_tool_calls, confidence)
    kar = kg_tool_calls / total_tool_calls
    return (MetricResult("M5", kar, "ratio", total_tool_calls, "kg_enabled_valid",
                         method={"uncertainty": "wilson"}),
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
                         method={"uncertainty": "wilson"}),
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
                         method={"uncertainty": "wilson"}),
            [StatisticalResult("M12", "wilson", ci_lower=lo, ci_upper=hi,
                               testing_tier="SECONDARY", scope_type="METRIC", status=st, reason_code=rc)])


def calc_m6(successful_read_count: int, access_event_count: int, confidence=0.95) -> tuple[MetricResult, list[StatisticalResult]]:
    """M6 KDR 知识交付率 = 有效回复次数 / 总查询次数（交互级，非任务级）。
    successful_read_count: 所有 KG 运行中匹配到成功回复的事件数（Σ successful_read_count）
    access_event_count: 所有 KG 运行中知识访问事件数（Σ access_event_count）"""
    if access_event_count == 0:
        m = MetricResult("M6", None, "ratio", 0, "access_valid", calculation_status=NA, reason_code="NO_ACCESS_EVENT")
        return m, [StatisticalResult("M6", "wilson", testing_tier="SECONDARY", status=NA, reason_code="NO_ACCESS_EVENT")]
    # cap：successful_read_count 可能 > access_event_count（RESULT 匹配 success 但 CALL 未归类 access）
    capped_reads = min(successful_read_count, access_event_count)
    lo, hi, st, rc = wilson(capped_reads, access_event_count, confidence)
    kdr = capped_reads / access_event_count
    return (MetricResult("M6", kdr, "ratio", access_event_count, "access_valid",
                         method={"uncertainty": "wilson"}),
            [StatisticalResult("M6", "wilson", ci_lower=lo, ci_upper=hi,
                               testing_tier="SECONDARY", scope_type="METRIC", status=st, reason_code=rc)])


# ===== M7 JSD median + IQR + bootstrap =====
def _median_iqr(vals):
    arr = np.array([v for v in vals if v is not None])
    if len(arr) == 0:
        return None, None, None, None
    q1, med, q3 = np.percentile(arr, [25, 50, 75])
    return float(med), float(q1), float(q3), float(q3 - q1)


def calc_m7(pairs: list[PairView], *, seed=42) -> tuple[MetricResult, list[StatisticalResult]]:
    jsds = [p.jsd for p in pairs if p.jsd is not None]
    n = len(jsds)
    med, q1, q3, iqr = _median_iqr(jsds)
    if n == 0:
        return (MetricResult("M7", None, "ratio", 0, "jsd_valid", calculation_status=NA,
                             reason_code="TOOL_EVENT_MISSING", method={}),
                [StatisticalResult("M7", "paired_bootstrap", testing_tier="SECONDARY",
                                    status=NA, reason_code="TOOL_EVENT_MISSING")])
    br = paired_bootstrap(pairs, lambda ps: _median_iqr([p.jsd for p in ps if p.jsd is not None])[0],
                          B=2000, seed=seed)
    status = CALCULATED if br.status == "CALCULATED" else NA
    return (MetricResult("M7", med, "ratio", n, "jsd_valid", median=med, q1=q1, q3=q3, iqr=iqr,
                         calculation_status=status, reason_code=br.reason_code,
                         method={"aggregation": "median_iqr", "uncertainty": "paired_bootstrap", "valid": br.valid}),
            [StatisticalResult("M7", "paired_bootstrap", ci_lower=br.ci_lower, ci_upper=br.ci_upper,
                               testing_tier="SECONDARY", scope_type="METRIC", status=status,
                               reason_code=br.reason_code, details={"valid": br.valid})])


# ===== M8-M10 ΔToken/Steps/Time =====
def _calc_delta_metric(mid, field, pairs, *, seed=42, unit="tokens"):
    deltas = [getattr(p, field) for p in pairs if getattr(p, field) is not None]
    n = len(deltas)
    med, q1, q3, iqr = _median_iqr(deltas)
    if n == 0:
        # field="delta_token"/"delta_steps"/"delta_time" → TOKEN/STEP/TIME_INVALID
        _suffix = field.split('_')[1].upper().replace("STEPS", "STEP")
        return (MetricResult(mid, None, unit, 0, "delta_valid", calculation_status=NA,
                             reason_code=f"{_suffix}_INVALID", method={}),
                [StatisticalResult(mid, "wilcoxon_signed_rank", testing_tier="SECONDARY",
                                   status=NA, reason_code="INSUFFICIENT_PAIRS")])
    br = paired_bootstrap(pairs, lambda ps: _median_iqr([getattr(p, field) for p in ps if getattr(p, field) is not None])[0],
                          B=2000, seed=seed)
    wc = wilcoxon(deltas)
    bstatus = CALCULATED if br.status == "CALCULATED" else NA
    return (MetricResult(mid, med, unit, n, "delta_valid", median=med, q1=q1, q3=q3, iqr=iqr,
                         calculation_status=bstatus, reason_code=br.reason_code,
                         method={"aggregation": "median_iqr", "ci": "paired_bootstrap",
                                 "test": "wilcoxon", "valid": br.valid}),
            [StatisticalResult(mid, "wilcoxon_signed_rank", statistic=wc["statistic"], p_value=wc["p_value"],
                               ci_lower=br.ci_lower, ci_upper=br.ci_upper,
                               testing_tier="SECONDARY", scope_type="METRIC",
                               status=bstatus if wc["status"] == "CALCULATED" else NA,
                               reason_code=br.reason_code if br.status != "CALCULATED" else wc["reason_code"],
                               details={"ci_method": "paired_bootstrap", "test_method": "wilcoxon",
                                        "valid": br.valid})])


def calc_m8(pairs, *, seed=42): return _calc_delta_metric("M8", "delta_token", pairs, seed=seed, unit="tokens")
def calc_m9(pairs, *, seed=42): return _calc_delta_metric("M9", "delta_steps", pairs, seed=seed, unit="steps")
def calc_m10(pairs, *, seed=42): return _calc_delta_metric("M10", "delta_time", pairs, seed=seed, unit="ms")


def run_all_metrics(pairs: list[PairView], *, kg_access=0, kg_valid=0, kg_delivery=0, access=0,
                     kg_access_events=0, kg_successful_reads=0,
                     mem_read_count=0, mem_successful_reads=0,
                     kg_tool_calls=0, total_tool_calls=0, seed=42) -> dict:
    """跑全部 10 指标 + 统计证据。返回 {metric_results, statistical_results}。
    bootstrap 指标用线程池并行（numpy 释放 GIL）。"""
    from concurrent.futures import ThreadPoolExecutor
    mrs = []; srs = []
    # M5/M6 无 bootstrap，瞬时完成，直接算
    # M5 KAR 用 kg_access_events（实际知识查询次数）而非 kg_tool_calls（CanonicalAction 分类）
    m5, s5 = calc_m5(kg_access_events, total_tool_calls)
    m6, s6 = calc_m6(kg_successful_reads, kg_access_events)
    # M11/M12 记忆指标（同 M5/M6 算法）
    m11, s11 = calc_m11(mem_read_count, total_tool_calls)
    m12, s12 = calc_m12(mem_successful_reads, mem_read_count)
    # M1/M2M3/M4/M7/M8/M9/M10 有 bootstrap，并行
    with ThreadPoolExecutor(max_workers=4) as pool:
        fut_m1 = pool.submit(calc_m1, pairs, seed=seed)
        fut_m23 = pool.submit(calc_m2_m3, pairs, seed=seed)
        fut_m4 = pool.submit(calc_m4, pairs, seed=seed)
        fut_m7 = pool.submit(calc_m7, pairs, seed=seed)
        fut_m8 = pool.submit(calc_m8, pairs, seed=seed)
        fut_m9 = pool.submit(calc_m9, pairs, seed=seed)
        fut_m10 = pool.submit(calc_m10, pairs, seed=seed)
        m1, s1 = fut_m1.result()
        m23 = fut_m23.result()
        m4, s4 = fut_m4.result()
        m7, s7 = fut_m7.result()
        m8, s8 = fut_m8.result()
        m9, s9 = fut_m9.result()
        m10, s10 = fut_m10.result()
    # 按顺序排列
    mrs = [m1, m23["m2"], m23["m3"], m4, m5, m6, m7, m8, m9, m10, m11, m12]
    srs = s1 + m23["statistical"] + s4 + s5 + s6 + s7 + s8 + s9 + s10 + s11 + s12
    return {"metric_results": mrs, "statistical_results": srs}
