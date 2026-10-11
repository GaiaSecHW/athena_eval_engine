"""TaskRun / BenchmarkItem 实体（§7.7 / §7.5）。"""
from __future__ import annotations
from dataclasses import dataclass, field
from .enums import Condition, ConditionSource, ExpectedLabel


@dataclass
class BenchmarkItem:
    benchmark_item_id: str
    benchmark_set_id: str
    task_id: str
    expected_label: ExpectedLabel | None  # None = 未标注 GT（无 benchmark 模式，M1-M4=NA）
    target_finding_id: str | None = None
    metadata: dict | None = None  # case 详情：description, vulnerability_type, failure_scenario


@dataclass
class TaskRun:
    task_run_id: str
    evaluation_id: str
    task_id: str
    trace_id: str
    condition: Condition
    condition_source: ConditionSource
    condition_conflict: bool = False
    benchmark_item_id: str | None = None
    turing_session_id: str | None = None
    experiment_fingerprint_hash: str | None = None
    trace_valid: bool = False
    runtime_valid: bool = False
    runtime_invalid_reason: str | None = None
    kg_runtime_state: str = "KG_UNKNOWN"
    started_at: int | None = None
    finished_at: int | None = None
    parser_version: str = "1.0"
