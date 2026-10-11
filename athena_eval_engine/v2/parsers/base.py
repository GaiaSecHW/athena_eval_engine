"""BaseParser — 所有 parser 的抽象基类。

设计参考 docs/v2-architecture-design.md §4.1。

子类必须实现 5 个抽象方法（parse / extract_findings / build_session_graph /
load_session / label_session_phases），build_data_pack 是模板方法，子类不覆盖。
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..core.task_run import TaskRun

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """所有 parser 的抽象基类。"""

    @property
    @abstractmethod
    def agent_type(self) -> str:
        """返回 agent 类型标识（turing/argo/secmate/cvuln_verify/webvuln_verify/dataflow）。"""

    @abstractmethod
    def parse(self, trace_source: str) -> list[RawEvent]:
        """解析 trace，返回规范事件序列。"""

    @abstractmethod
    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """从事件中提取漏洞 finding。"""

    @abstractmethod
    def build_session_graph(self, events: list[RawEvent]) -> dict:
        """构建 session 关系图（parent_id 边）。"""

    @abstractmethod
    def load_session(self, trace_source: str) -> dict:
        """加载 session 元数据（token/step/time）。"""

    @abstractmethod
    def label_session_phases(
        self, events: list[RawEvent], session_meta: dict
    ) -> tuple[dict[str, str], dict[str, str]]:
        """标注 session 的业务阶段。

        返回 (session_phase_labels, session_phase_source)。
        - session_phase_labels: session_id -> 业务阶段名称（第一层+第二层程序标注）
        - session_phase_source: session_id -> 标注来源标识符

        各 parser 实现自己的标识符提取 + 规则映射，详见 docs/v2-architecture-design.md §4.3。
        """

    def build_data_pack(self, trace_source: str, task_run: TaskRun) -> DataPack:
        """完整解析，返回 DataPack。模板方法——子类不覆盖。

        按 docs/v2-architecture-design.md §4.1 实现：
        1. parse() -> events
        2. extract_findings(events) -> findings
        3. build_session_graph(events) -> session_graph
        4. load_session(trace_source) -> session_meta
        5. label_session_phases(events, session_meta) -> (phase_labels, phase_source)
        6. 4 个 resolver 从 events 提取 facts（延迟 import，resolver 在 #49 中实现）
        7. 组装 DataPack
        """
        # 1-5: parser 自身的抽象方法
        events = self.parse(trace_source)
        findings = self.extract_findings(events)
        session_graph = self.build_session_graph(events)
        session_meta = self.load_session(trace_source)
        phase_labels, phase_source = self.label_session_phases(events, session_meta)

        # 6: resolver 从 events 提取 facts
        # 延迟 import：resolver 尚未实现（#49），避免模块加载时 ImportError
        outcome = None
        knowledge = None
        tool_action = None
        resource = None
        try:
            from ..resolvers.outcome import OutcomeResolver
            from ..resolvers.knowledge import KnowledgeResolver
            from ..resolvers.tool_action import ToolActionResolver
            from ..resolvers.resource import ResourceResolver

            outcome = OutcomeResolver().resolve(task_run, events, findings)
            knowledge = KnowledgeResolver().resolve(task_run, events)
            tool_action = ToolActionResolver().resolve(task_run, events)
            resource = ResourceResolver().resolve(task_run, session_meta)
        except ImportError:
            logger.debug(
                "resolvers not yet implemented, DataPack will have None facts "
                "(task_run_id=%s)",
                task_run.task_run_id,
            )

        # 7: 组装 DataPack
        return DataPack(
            task_run_id=task_run.task_run_id,
            evaluation_id=task_run.evaluation_id,
            task_id=task_run.task_id,
            agent_type=self.agent_type,
            condition=task_run.condition.value if hasattr(task_run.condition, "value") else str(task_run.condition),
            events=events,
            findings=findings,
            session_graph=session_graph,
            session_meta=session_meta,
            session_phase_labels=phase_labels,
            session_phase_source=phase_source,
            outcome_fact=outcome,
            knowledge_fact=knowledge,
            tool_action_fact=tool_action,
            resource_fact=resource,
            benchmark_item=getattr(task_run, "benchmark_item", None),
        )
