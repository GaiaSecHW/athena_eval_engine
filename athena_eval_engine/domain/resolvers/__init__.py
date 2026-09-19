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

    @abstractmethod
    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """从事件中提取此 Agent 平台的 finding。

        各 parser 基于 Agent 源代码自身的 finding 处理逻辑实现此方法。
        返回 finding 字典列表，至少包含：
        - finding_id, display_id, title, description, vuln_type, severity
        - source, sink, validation_result, platform, session_id
        """
        ...

    def build_session_graph(self, events):
        """构建 session 关系图。各 agent parser 必须自己实现。

        session 关系必须精准——只有真实调用关系（parent_id、source_session_id 等）
        才能建边。共享文件/fact/ID 不是调用关系，不建边。
        """
        from collections import defaultdict
        return {
            'sessions': {}, 'file_to_sessions': defaultdict(set),
            'fact_to_sessions': defaultdict(set), 'edges': defaultdict(set),
            'parent_map': {},
        }

    def trace_finding_process(self, events: list[RawEvent], session_graph: dict,
                              finding: dict) -> list[dict]:
        """从指定 finding 出发，反向追踪跨 session 的挖掘分析过程（原则7）。

        利用 session_graph parent_map 向上追溯祖先链（最多 10 个 session），
        收集 finding 提交时间点之前的相关 session 事件，
        提取挖掘行为（文件读取、搜索、推理、工具调用）。

        Args:
            events: trace 的全部事件
            session_graph: build_session_graph() 返回的关系图
            finding: finding 字典，需含 session_id 和 _event_idx 或 timestamp

        Returns:
            按时间戳排序的挖掘行为列表 [{tool, action, session_id, ts}]
        """
        finding_session = finding.get("session_id", "")
        finding_ts = finding.get("timestamp") or finding.get("finding_ts")
        idx = finding.get("_event_idx")
        if idx is not None and idx < len(events) and not finding_ts:
            finding_ts = events[idx].timestamp_ms

        related_sessions = self._get_related_sessions(session_graph, finding_session)

        actions = []
        for ev in events:
            if not ev.is_tool_call():
                continue
            if ev.session_id not in related_sessions:
                continue
            if finding_ts and (ev.timestamp_ms or 0) > finding_ts:
                continue
            a = self._extract_action(ev)
            if a:
                actions.append(a)
        actions.sort(key=lambda a: a.get("ts", 0))
        return actions

    @staticmethod
    def _get_related_sessions(session_graph: dict, start_session: str) -> set:
        """从 start_session 沿 parent_map 向上追溯祖先链（含 start_session）。

        只走 parent_map（真实调用关系），不做 BFS 连通分量遍历。
        最多追溯 10 个 session。
        """
        if not start_session:
            return set()
        parent_map = session_graph.get('parent_map', {}) if session_graph else {}
        chain: list[str] = []
        visited: set[str] = set()
        sid = start_session
        while sid and sid not in visited and len(chain) < 10:
            chain.append(sid)
            visited.add(sid)
            sid = parent_map.get(sid)
        return set(chain)

    def _extract_action(self, ev: RawEvent) -> dict | None:
        """从单个 event 提取挖掘行为摘要。子类可覆盖实现平台特定逻辑。

        默认处理通用工具（bash/read/write），各 parser 在 override 中
        追加本平台的 finding 提交工具（如 vuln-hunt_insert_finding）。
        """
        inp = ev.input_json or {}
        tool = ev.tool_name or ""
        ts = ev.timestamp_ms or 0
        if tool == "bash":
            cmd = str(inp.get("command", ""))
            if cmd and not cmd.strip().startswith(("head", "cat ", "ls ", "grep ")):
                return {"tool": "bash", "action": cmd, "session_id": ev.session_id, "ts": ts}
        elif tool == "read":
            fp = str(inp.get("file_path", ""))
            if fp:
                return {"tool": "read", "action": fp, "session_id": ev.session_id, "ts": ts}
        elif tool == "write":
            fp = str(inp.get("file_path") or inp.get("path") or "")
            if fp:
                return {"tool": "write", "action": fp, "session_id": ev.session_id, "ts": ts}
        return None


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
