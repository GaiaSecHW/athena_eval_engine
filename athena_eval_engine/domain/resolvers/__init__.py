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

    def build_session_graph(self, events):
        """构建 session 关系图。子类可覆盖实现 agent 专有逻辑。

        默认实现：按共享文件名和 fact ID 关联 session。
        高频文件（如 package.json、README.md）被过多 session 共享时不建边，
        避免全连通图导致 BFS 返回所有 session。
        """
        import re
        import os
        from collections import defaultdict
        # 文件/fact 被 >此数量的 session 共享时不建边（防止常见文件产生噪声边）
        _MAX_SESSIONS_PER_LINK = 5
        graph = {
            'sessions': {}, 'file_to_sessions': defaultdict(set),
            'fact_to_sessions': defaultdict(set), 'edges': defaultdict(set),
        }
        for ev in events:
            sid = ev.session_id
            if not sid:
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {'files': set(), 'facts': set(), 'athena_qs': []}
            sg = graph['sessions'][sid]
            if not ev.is_tool_call():
                if ev.event_type == "SYSTEM_EVENT" and ev.output_json:
                    for fid in re.findall(r'(f\d{3,5})\s+(?:found|concluded|reported|discovered|noted|observed|identified)', str(ev.output_json)):
                        # f001 通常是系统初始化 fact（如 opencode session 初始化），
                        # 几乎所有 session 都引用，不作为关联依据。
                        # 下方频率过滤器也会自动过滤此类高频 fact。
                        if fid != 'f001':
                            sg['facts'].add(fid)
                            graph['fact_to_sessions'][fid].add(sid)
                continue
            tool = ev.tool_name or ""
            inp = ev.input_json or {}
            if tool == "bash":
                cmd = str(inp.get("command", ""))
                for fid in re.findall(r'f\d{3,5}', cmd):
                    if fid != 'f001':
                        sg['facts'].add(fid)
                        graph['fact_to_sessions'][fid].add(sid)
                if 'athena' in cmd.lower() and 'ask' in cmd:
                    m = re.search(r'ask\s+"([^"]{0,50})', cmd)
                    if m:
                        sg['athena_qs'].append(m.group(1))
                for fm in re.findall(r'[\w\-./]+\.[a-zA-Z]{1,6}', cmd):
                    basename = os.path.basename(fm)
                    if basename and len(basename) < 80 and not basename.startswith('.'):
                        sg['files'].add(basename)
                        graph['file_to_sessions'][basename].add(sid)
            elif tool == "read":
                fp = str(inp.get("file_path") or inp.get("filePath") or "")
                if fp:
                    basename = os.path.basename(fp)
                    if basename and len(basename) < 80:
                        sg['files'].add(basename)
                        graph['file_to_sessions'][basename].add(sid)
            elif tool in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding",
                          "vuln_hunt_query_detection", "vuln_hunt_update_detection_status",
                          "vulnerability_analyze", "vulnerability_verify",
                          "ReportFindings", "reportfindings"):
                # Turing: detection_id; WebVulnVerify: vulnerability_id; Argo: findings[].id
                fid = str(inp.get("detection_id") or inp.get("vulnerability_id") or "")
                if fid:
                    sg['facts'].add(fid)
                    graph['fact_to_sessions'][fid].add(sid)
                for f in (inp.get("findings") or []):
                    fid = f.get("id") or f.get("finding_id", "")
                    if fid:
                        sg['facts'].add(fid)
                        graph['fact_to_sessions'][fid].add(sid)
        # 构建边：共享 fact 或文件的 session 互相关联
        # 频率过滤：被 >_MAX_SESSIONS_PER_LINK 个 session 共享的项不建边（防止噪声）
        for fid, sids in graph['fact_to_sessions'].items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            graph['edges'][s1].add(s2)
        for fm, sids in graph['file_to_sessions'].items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            graph['edges'][s1].add(s2)
        return graph


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
