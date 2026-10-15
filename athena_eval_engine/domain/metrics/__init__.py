"""Metric / Statistical result data classes.

v2 pipeline 不使用 M1-M13 指标计算（已在 domain/metrics 中移除）。
保留 MetricResult / StatisticalResult 数据类供 fact_repo 类型引用。
"""
from __future__ import annotations
from dataclasses import dataclass, field

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
