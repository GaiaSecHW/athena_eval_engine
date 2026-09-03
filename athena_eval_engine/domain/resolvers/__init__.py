"""Resolver / Parser 接口契约（§8.12 / §11.3）。

换 Agent 只换 TraceParser，后续 Resolver 全部复用。
所有 Resolver 决定"Trace 证明了什么"；Metric Engine 决定"事实如何算指标"。
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterator
from ..raw_event import RawEvent
from ..facts import OutcomeFact, KnowledgeInteractionFact, ToolActionFact, ResourceFact


class TraceParser(ABC):
    """SQLite → Canonical RawEvent（§8.1 L1）。"""

    @abstractmethod
    def parse(self, trace_source) -> Iterator[RawEvent]: ...


class TaskRunResolver(ABC):
    """从 Manifest + sidecar + trace metadata 解析 task_run（§8.4/§8.4a）。"""

    @abstractmethod
    def resolve(self, trace_source, manifest_entry: dict, events: list[RawEvent]) -> "TaskRun": ...


class TaskPairMatcher(ABC):
    """按 (evaluation_id, task_id) 分组配对（§8.5）。"""

    @abstractmethod
    def match(self, task_runs: list) -> list:  # list[TaskPair]
        ...


class OutcomeResolver(ABC):
    """Finding Candidate → BenchmarkMatch → validation_result → Outcome（§8.6）。
    Determinism：给定相同 Trace + Benchmark + 已持久化 FindingBenchmarkMatch + Config + Version → 相同 Fact。
    """

    @abstractmethod
    def resolve(self, task_run, benchmark, events: list[RawEvent]) -> OutcomeFact: ...


    # insert 无 update → UNDETERMINED（不默认 POSITIVE）；多 finding → 按 benchmark_item_id 对齐 target finding


class KnowledgeResolver(ABC):
    """Access / Delivery（§8.7/§8.8）。"""

    @abstractmethod
    def resolve(self, task_run, events: list[RawEvent]) -> KnowledgeInteractionFact: ...


class ToolActionResolver(ABC):
    """Canonical Action 频率分布（§8.9）。action_schema_version v1.0。"""

    @abstractmethod
    def resolve(self, task_run, events: list[RawEvent], schema) -> ToolActionFact: ...


class ResourceResolver(ABC):
    """Token / Steps / Duration（§8.10）。effective_tokens 经 G9 Gate。"""

    @abstractmethod
    def resolve(self, task_run, session) -> ResourceFact: ...
