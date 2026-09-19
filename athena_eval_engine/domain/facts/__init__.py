"""Evaluation Facts（L2）— TaskRun Fact，§7.9-7.12。

Fact 永久归属 TaskRun，不依赖 Pair。Pairing 不回写 Fact。
"""
from __future__ import annotations
from pydantic import BaseModel, Field
from ..enums import (
    Condition, ConditionSource, Outcome, Prediction,
    ExpectedLabel, CalculationStatus,
)


class Evidence(BaseModel):
    """§5 Evidence 标准结构：{trace_id, session_id, message_id, part_id, tool_name, event_timestamp, field_path}"""
    trace_id: str
    session_id: str | None = None
    message_id: str | None = None
    part_id: str | None = None
    tool_name: str | None = None
    event_timestamp: int | None = None
    field_path: str | None = None


class OutcomeFact(BaseModel):
    """§7.9 — 一个 TaskRun 一条。"""
    outcome_fact_id: str
    task_run_id: str
    evaluation_id: str
    condition: Condition
    condition_source: ConditionSource
    condition_conflict: bool = False
    benchmark_item_id: str | None = None
    gt_label: ExpectedLabel | None = None
    prediction: Prediction | None = None
    outcome: Outcome
    target_finding_id: str | None = None
    validation_result: str | None = None  # CONFIRMED / FALSE_POSITIVE / NA
    resolver_status: str  # RESOLVED / NO_FINDING / NO_UPDATE / NO_GT / BENCHMARK_UNMATCHED / PARSE_ERROR / AI_MATCHED / AI_MATCH_ERROR / AI_AMBIGUOUS / AI_UNMATCHED / NO_VALIDATION
    resolver_version: str = "1.0"
    evidence: list[Evidence] = Field(default_factory=list)
    case_results: list = Field(default_factory=list)  # per-case TP/FP/FN/TN

    @staticmethod
    def undetermined(task_run_id: str, evaluation_id: str, condition: Condition,
                     condition_source: ConditionSource, reason: str,
                     benchmark_item_id: str | None = None) -> "OutcomeFact":
        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run_id}",
            task_run_id=task_run_id, evaluation_id=evaluation_id,
            condition=condition, condition_source=condition_source,
            benchmark_item_id=benchmark_item_id,
            outcome=Outcome.UNDETERMINED, prediction=Prediction.UNDETERMINED,
            resolver_status=reason, validation_result="NA",
        )


class KnowledgeInteractionFact(BaseModel):
    """§7.10 — Access / Delivery。"""
    knowledge_fact_id: str
    task_run_id: str
    evaluation_id: str
    access: bool = False
    delivery: bool = False
    mount_status: str = "UNKNOWN"  # SUCCESS / FAILED / UNKNOWN
    access_event_count: int = 0
    read_event_count: int = 0
    successful_read_count: int = 0
    interactions: list[dict] = Field(default_factory=list)  # 原始介入事件 [{tool, command, output_preview, timestamp}]
    resolver_version: str = "1.0"
    evidence: list[Evidence] = Field(default_factory=list)
    # 记忆交互（与知识同维度：只统计读取/检索，不统计写入）
    memory_access: bool = False
    memory_access_event_count: int = 0
    memory_successful_read_count: int = 0
    memory_interactions: list[dict] = Field(default_factory=list)


class ToolActionFact(BaseModel):
    """§7.11 — Canonical Action 频率分布。action_schema_version v1.0，5 业务 Action。"""
    tool_action_fact_id: str
    task_run_id: str
    evaluation_id: str
    action_schema_version: str = "1.0"
    kg_count: int = 0
    finding_count: int = 0
    code_count: int = 0
    shell_count: int = 0
    other_count: int = 0
    total_tool_calls: int = 0
    action_distribution: dict[str, int] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)


class ResourceFact(BaseModel):
    """§7.12 — Token / Steps / Duration。effective_tokens 经 G9 Gate 生成。"""
    resource_fact_id: str
    task_run_id: str
    evaluation_id: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    cache_read_tokens: int | None = None
    effective_tokens: int | None = None
    token_schema_valid: bool = False
    token_schema_version: str | None = None
    steps: int | None = None
    step_source: str = "step-start"
    step_integrity_warning: bool = False
    duration_ms: int | None = None
    time_valid: bool = False
    validity_status: str | None = None  # VALID / INVALID / PARTIAL
    evidence: list[Evidence] = Field(default_factory=list)


class PairDerivedFact(BaseModel):
    """§7.26 — L2 Pair Derived Fact（JSD_i / ΔToken_i / ΔSteps_i / ΔTime_i / PairTransition）。"""
    derived_fact_id: str
    evaluation_id: str
    task_pair_id: str
    derived_fact_type: str  # PAIR_TRANSITION / JSD / DELTA_TOKEN / DELTA_STEPS / DELTA_TIME
    value_numeric: float | None = None
    value_string: str | None = None
    status: str = "CALCULATED"  # CALCULATED / NA / BLOCKED
    reason_code: str | None = None
    resolver_version: str = "1.0"
    evidence: list[Evidence] = Field(default_factory=list)
    source_fact_refs: list[dict] = Field(default_factory=list)  # {fact_type, fact_id, condition}
