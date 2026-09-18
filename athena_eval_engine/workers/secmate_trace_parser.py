"""SecMate transcript JSONL -> Canonical RawEvent.

Trace 路径：/data/files/{project_id}/tasks/{task_id}/tools/secmate-*/run/.worker-config/projects/*/

SecMate uses the Claude SDK transcript envelope, but stores its actual agent
transcripts beneath ``run/.worker-config/projects`` instead of Argo's
``session/argo`` directory.  ``hook-watch/sessions`` is intentionally not
parsed: it records harness activity rather than the agent's execution trace.

findings.db（SQLite）位于 ``run/`` 目录下，extract_findings() 直接读取
findings.db 获取 final_verdict 级别的 finding，不从 JSONL event 流提取。
"""
from __future__ import annotations

import glob
import json
import os
import sqlite3
import time
from datetime import datetime
from typing import Iterator

from ..domain.raw_event import RawEvent
from ..domain.resolvers import TraceParser
from .parse_utils import attach_event_indices


_TOOL_MAP = {
    "Bash": "bash", "Read": "read", "Grep": "grep", "Glob": "glob",
    "Write": "write", "Edit": "edit", "Task": "task", "Skill": "skill",
    "TodoWrite": "todowrite",
}


def _find_jsonl_files(path: str) -> list[str]:
    """Find .jsonl files in a SecMate trace directory.

    SecMate stores agent transcripts in a subdirectory whose name is the
    normalized form of the parent run path (/ replaced by -), e.g.::

        .../run/.worker-config/projects/-data-files-...-run/*.jsonl

    Strategy: top-level → computed subdirectory → one-level subdirs fallback.
    """
    if not os.path.isdir(path):
        return [path]
    # 先读顶层 .jsonl（T002 等格式，文件直接在 projects/ 下）
    files = sorted(
        f for f in glob.glob(os.path.join(path, "*.jsonl"))
        if "hook-watch" not in f.replace("\\", "/")
    )
    if files:
        return files
    # 顶层为空，按 SecMate 目录规则计算子目录路径：
    # 子目录名 = URI 路径的规范化形式（/ 替换为 -）
    # 完整路径 = URI/.worker-config/projects/{子目录名}/
    normalized = path.replace("\\", "/").rstrip("/")
    suffix = "/.worker-config/projects"
    if normalized.endswith(suffix):
        # URI 已含 /.worker-config/projects，子目录名用去掉后缀的路径
        subdir_name = normalized[:-len(suffix)].replace("/", "-")
        subdir_path = os.path.join(path, subdir_name)
    else:
        # URI 不含 /.worker-config/projects，拼接指定目录
        subdir_name = normalized.replace("/", "-")
        subdir_path = os.path.join(path, ".worker-config", "projects", subdir_name)
    if os.path.isdir(subdir_path):
        return sorted(
            f for f in glob.glob(os.path.join(subdir_path, "*.jsonl"))
            if "hook-watch" not in f.replace("\\", "/")
        )
    # 兜底：搜索一级子目录
    for sub in os.listdir(path):
        sub_path = os.path.join(path, sub)
        if os.path.isdir(sub_path):
            files.extend(sorted(
                f for f in glob.glob(os.path.join(sub_path, "*.jsonl"))
                if "hook-watch" not in f.replace("\\", "/")
            ))
    return files


def is_secmate_trace(path: str) -> bool:
    """Identify a SecMate SDK transcript without relying solely on its path.

    SecMate traces use Claude SDK format with entrypoint="sdk-cli".
    Historical traces may be stored directly in session/ (not session/secmate/)
    with cwd="/app", so we only check entrypoint — Argo traces in session/argo/
    are already matched by the path-based dispatch in _get_parser().
    """
    paths = [path]
    if os.path.isdir(path):
        paths = _find_jsonl_files(path)
    for candidate in paths:
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f):
                    if line_no >= 20:
                        break
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("entrypoint") == "sdk-cli":
                        return True
        except OSError:
            continue
    return False


class SecMateTraceParser(TraceParser):
    """Parse SecMate Claude SDK transcripts, including nested subagents."""

    def __init__(self, parser_version: str = "secmate-1.0"):
        self.parser_version = parser_version
        self._source_uri: str | None = None

    @staticmethod
    def _files(uri: str) -> list[str]:
        return _find_jsonl_files(uri)

    @staticmethod
    def _is_kg_call(tool_name: str, tool_input: object) -> bool:
        """检测知识图谱交互。

        从源码与 trace 论证：
        1. scripts/athena / athena.py — KG 查询脚本（旧格式）
        2. scaffold run — KG 创建（trace 中 scaffold run --json 建立 seeddir 和 kg/）
        3. athena-skill — KG 查询 skill
        排除 head/cat/grep/ls 等只读查看命令（不算 KG 交互）
        """
        tool = _TOOL_MAP.get(tool_name, tool_name.lower())
        if tool == "bash" and isinstance(tool_input, dict):
            command = str(tool_input.get("command", "")).lower()
            if command.strip().startswith(("head", "cat ", "grep ", "ls ")):
                return False
            return ("scripts/athena" in command
                    or "athena.py" in command
                    or "scaffold run" in command)
        return tool == "skill" and isinstance(tool_input, dict) and str(
            tool_input.get("name", "")).lower() == "athena-skill"

    @staticmethod
    def _is_finding_tool(tool_name: str) -> bool:
        """SecMate 平台 finding 提交工具。

        从源码论证（findings_store/server.py + workflows/secmate-all-lite/tools_mcp.py）：
        - mcp__findings-store__store_finding — 核心 finding 存储
        - mcp__findings-store__store_finding_finalize_batch — 批量 finding 存储
        - mcp__workflow-tools__store_finding — workflow 别名
        - mcp__workflow-tools__store_tiered_finding[_ext] — 中间 finding
        - mcp__workflow-tools__store_final_verdict — 最终裁决（secmate-all-lite，当前工作流）
        - mcp__workflow-tools__store_tracer_verdict — 最终判定（secmate-flash，旧工作流兼容）
        """
        t = tool_name or ""
        return (t in ("mcp__findings-store__store_finding",
                      "mcp__findings-store__store_finding_finalize_batch",
                      "mcp__workflow-tools__store_finding",
                      "mcp__workflow-tools__store_tracer_verdict",
                      "mcp__workflow-tools__store_final_verdict")
                or t.startswith("mcp__workflow-tools__store_tiered_fing"))

    @staticmethod
    def _is_assistant_record(record: dict) -> bool:
        """判断是否为 assistant 记录（兼容两种格式）。

        格式1 (Claude API): record.type == "assistant"
        格式2 (SDK transcript): record.type == "message" and message.role == "assistant"
        """
        if record.get("type") == "assistant":
            return True
        if record.get("type") == "message":
            msg = record.get("message")
            return isinstance(msg, dict) and msg.get("role") == "assistant"
        return False

    @staticmethod
    def _is_user_record(record: dict) -> bool:
        """判断是否为 user 记录（兼容两种格式）。

        格式1: record.type == "user"
        格式2: record.type == "message" and message.role == "user"
        """
        if record.get("type") == "user":
            return True
        if record.get("type") == "message":
            msg = record.get("message")
            return isinstance(msg, dict) and msg.get("role") == "user"
        return False

    @staticmethod
    def _is_tool_result_record(record: dict) -> bool:
        """判断是否为 toolResult 记录（格式2 专用）。

        格式2: record.type == "message" and message.role == "toolResult"
        """
        if record.get("type") == "message":
            msg = record.get("message")
            return isinstance(msg, dict) and msg.get("role") == "toolResult"
        return False

    @staticmethod
    def _tool_call_parts(record: dict) -> list[dict]:
        """提取 record 中的 tool call parts（兼容两种格式）。

        格式1: content 中 type="tool_use", 字段 input
        格式2: content 中 type="toolCall", 字段 arguments
        统一输出: {id, name, input(统一), raw_type}
        """
        message = record.get("message")
        if not isinstance(message, dict):
            return []
        content = message.get("content", [])
        if not isinstance(content, list):
            return []
        parts = []
        for part in content:
            if not isinstance(part, dict):
                continue
            pt = part.get("type")
            if pt == "tool_use":
                parts.append({
                    "id": str(part.get("id", "")),
                    "name": part.get("name", ""),
                    "input": part.get("input") if isinstance(part.get("input"), dict) else None,
                    "raw_type": "tool_use",
                })
            elif pt == "toolCall":
                args = part.get("arguments")
                parts.append({
                    "id": str(part.get("id", "")),
                    "name": part.get("name", ""),
                    "input": args if isinstance(args, dict) else None,
                    "raw_type": "toolCall",
                })
        return parts

    @staticmethod
    def _tool_results(record: dict) -> list[tuple[str, str]]:
        """Return every (tool_use_id, result text) in a record.

        兼容三种格式：
        1. Claude API user record: content 中 type="tool_result"
        2. SDK transcript: type="message" role="toolResult"
        3. 旧格式: record.toolUseResult
        """
        message = record.get("message")
        # 格式2: role="toolResult" 的独立消息
        if isinstance(message, dict) and message.get("role") == "toolResult":
            call_id = str(message.get("toolCallId", ""))
            content = message.get("content", [])
            if isinstance(content, list):
                texts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts.append(part.get("text", ""))
                    elif isinstance(part, str):
                        texts.append(part)
                return [(call_id, "\n".join(texts))] if texts else []
            elif isinstance(content, str):
                return [(call_id, content)]
            return []
        # 格式1: user record 中 content 含 tool_result
        content = message.get("content", []) if isinstance(message, dict) else []
        results = []
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "tool_result":
                    value = part.get("content", "")
                    results.append((str(part.get("tool_use_id", "")),
                                    value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)))
        if results:
            return results
        # 格式3: 旧格式 fallback
        value = record.get("toolUseResult")
        if value is None:
            return []
        return [("", value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))]

    def parse(self, trace_source) -> Iterator[RawEvent]:
        uri = trace_source["source_uri"]
        self._source_uri = uri
        trace_id = trace_source.get("trace_id", uri)
        files = self._files(uri)
        calls: dict[str, dict] = {}
        results: dict[str, str] = {}

        # Associate results before emitting calls, so finding extractors can use
        # the store_finding response (which contains the generated finding_id).
        for path in files:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if self._is_assistant_record(record):
                        for part in self._tool_call_parts(record):
                            call_id = part["id"]
                            if call_id:
                                raw_name = part["name"]
                                calls[call_id] = {
                                    "tool_name": _TOOL_MAP.get(raw_name, str(raw_name).lower()),
                                    "is_kg": self._is_kg_call(str(raw_name), part["input"]),
                                }
                    elif self._is_tool_result_record(record):
                        for call_id, result in self._tool_results(record):
                            if call_id and result:
                                results[call_id] = result
                    elif self._is_user_record(record):
                        for call_id, result in self._tool_results(record):
                            if call_id and result:
                                results[call_id] = result

        totals = {"tokens_input": 0, "tokens_output": 0, "tokens_reasoning": 0, "cache_read_tokens": 0}
        step_count = 0
        min_ts = max_ts = None
        for path in files:
            session_id = os.path.splitext(os.path.basename(path))[0]
            with open(path, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    timestamp = self._parse_ts(record.get("timestamp", ""))
                    if timestamp is not None:
                        min_ts = timestamp if min_ts is None else min(min_ts, timestamp)
                        max_ts = timestamp if max_ts is None else max(max_ts, timestamp)
                    base_id = f"{session_id}-{line_no}"
                    message = record.get("message")
                    if self._is_assistant_record(record) and isinstance(message, dict):
                        content = message.get("content", [])
                        # 用 _tool_call_parts 统一提取 tool call（兼容 tool_use 和 toolCall）
                        tool_parts = {p["id"]: p for p in self._tool_call_parts(record)}
                        for index, part in enumerate(content if isinstance(content, list) else []):
                            if not isinstance(part, dict):
                                continue
                            part_type = part.get("type")
                            event_id = f"{base_id}-{index}"
                            if part_type in ("tool_use", "toolCall"):
                                call_id = str(part.get("id", ""))
                                info = calls.get(call_id, {})
                                # 统一取 input：tool_use → part.input, toolCall → part.arguments
                                inp = part.get("input")
                                if inp is None:
                                    inp = part.get("arguments")
                                    if not isinstance(inp, dict):
                                        inp = None
                                from ..domain.raw_event import detect_memory_flags
                                _is_mem, _is_mem_w = detect_memory_flags(info.get("tool_name") or "", inp)
                                _mapped = info.get("tool_name") or ""
                                yield RawEvent(event_id=event_id, trace_id=trace_id, session_id=session_id,
                                    event_type="TOOL_CALL", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                    part_id=event_id, step_no=None, tool_name=_mapped,
                                    input_json=inp,
                                    output_json=results.get(call_id), raw_type=part_type, source_table="jsonl",
                                    source_row_id=event_id, parser_version=self.parser_version,
                                    is_kg_interaction=info.get("is_kg", False),
                                    is_memory_interaction=_is_mem,
                                    is_memory_write=_is_mem_w,
                                    is_finding_submission=self._is_finding_tool(_mapped),
                                    call_id=call_id)
                            elif part_type == "text":
                                yield self._event(event_id, trace_id, session_id, "TEXT", timestamp, record, part.get("text"), "text")
                            elif part_type == "thinking":
                                yield self._event(event_id, trace_id, session_id, "REASONING", timestamp, record, part.get("thinking"), "thinking")
                        usage = message.get("usage")
                        if isinstance(usage, dict):
                            from ..domain.raw_event import usage_numbers
                            _ti, _to, _tr, _tcr = usage_numbers(usage)
                            totals["tokens_input"] += _ti
                            totals["tokens_output"] += _to
                            totals["tokens_reasoning"] += _tr
                            totals["cache_read_tokens"] += _tcr
                            step_count += 1
                            yield RawEvent(event_id=f"{base_id}-usage", trace_id=trace_id, session_id=session_id,
                                event_type="STEP_FINISH", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                part_id=f"{base_id}-usage", step_no=None, tool_name=None, input_json=usage,
                                output_json=None, raw_type="usage", source_table="jsonl",
                                source_row_id=f"{base_id}-usage", parser_version=self.parser_version)
                    elif self._is_tool_result_record(record):
                        for result_index, (call_id, result) in enumerate(self._tool_results(record)):
                            if not result:
                                continue
                            info = calls.get(call_id, {})
                            event_id = f"{base_id}-result{result_index}"
                            yield RawEvent(event_id=event_id, trace_id=trace_id, session_id=session_id,
                                event_type="TOOL_RESULT", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                part_id=event_id, step_no=None, tool_name=info.get("tool_name"),
                                input_json=None, output_json=result, raw_type="tool_result", source_table="jsonl",
                                source_row_id=event_id, parser_version=self.parser_version,
                                call_id=call_id)
                    elif self._is_user_record(record):
                        for result_index, (call_id, result) in enumerate(self._tool_results(record)):
                            if not result:
                                continue
                            info = calls.get(call_id, {})
                            event_id = f"{base_id}-result{result_index}"
                            yield RawEvent(event_id=event_id, trace_id=trace_id, session_id=session_id,
                                event_type="TOOL_RESULT", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                part_id=event_id, step_no=None, tool_name=info.get("tool_name"),
                                input_json=None, output_json=result, raw_type="tool_result", source_table="jsonl",
                                source_row_id=event_id, parser_version=self.parser_version,
                                call_id=call_id)
                    elif record.get("type") == "queue-operation" and record.get("operation") == "enqueue":
                        yield self._event(f"{base_id}-queue", trace_id, session_id, "SYSTEM_EVENT", timestamp,
                                          record, record.get("content"), "queue-enqueue")
        # SecMate has no separate step-start record: each assistant response
        # carrying usage is one model step.  Keep both counts on this same
        # contract so M9 is valid and does not emit a false integrity warning.
        self._session_cache = {"uri": uri, **totals, "time_created": min_ts, "time_updated": max_ts,
                               "_step_start_count": step_count, "_step_finish_count": step_count,
                               "model": "claude", "agent": "secmate"}

    def _event(self, event_id, trace_id, session_id, event_type, timestamp, record, output, raw_type):
        return RawEvent(event_id=event_id, trace_id=trace_id, session_id=session_id,
            event_type=event_type, timestamp_ms=timestamp, message_id=record.get("uuid"), part_id=event_id,
            step_no=None, tool_name=None, input_json=None, output_json=output, raw_type=raw_type,
            source_table="jsonl", source_row_id=event_id, parser_version=self.parser_version)

    @staticmethod
    def _parse_ts(value: str) -> int | None:
        try:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
        except (TypeError, ValueError):
            return None

    def load_session(self, trace_source) -> dict:
        cached = getattr(self, "_session_cache", None)
        if cached and cached["uri"] == trace_source["source_uri"]:
            return {key: value for key, value in cached.items() if key != "uri"}
        totals = {"tokens_input": 0, "tokens_output": 0, "tokens_reasoning": 0, "cache_read_tokens": 0}
        step_count = 0
        min_ts = max_ts = None
        for path in self._files(trace_source["source_uri"]):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    timestamp = self._parse_ts(record.get("timestamp", ""))
                    if timestamp is not None:
                        min_ts = timestamp if min_ts is None else min(min_ts, timestamp)
                        max_ts = timestamp if max_ts is None else max(max_ts, timestamp)
                    if not self._is_assistant_record(record):
                        continue
                    usage = record.get("message", {}).get("usage", {})
                    if not isinstance(usage, dict):
                        continue
                    from ..domain.raw_event import usage_numbers
                    _ti, _to, _tr, _tcr = usage_numbers(usage)
                    totals["tokens_input"] += _ti
                    totals["tokens_output"] += _to
                    totals["tokens_reasoning"] += _tr
                    totals["cache_read_tokens"] += _tcr
                    step_count += 1
        return {**totals, "time_created": min_ts, "time_updated": max_ts,
                "_step_start_count": step_count, "_step_finish_count": step_count,
                "model": "claude", "agent": "secmate"}

    def build_session_graph(self, events):
        """构建 session 关系图。

        SecMate session 关联机制（从源码与 trace 论证）：
        1. SEED_ID 共享：planner prompt 含 SEED_ID=xxx，sessions 共享同一 seed 关联
        2. finding_id 共享：store_finding/query_finding 工具调用中的 finding_id
        3. source_task_id/source_session_id：store_finding 的 input 含 source_task_id
           和 source_session_id，用于跨 session 关联（从 findings_db/server.py 论证）
        4. 共享文件（与基类默认实现相同）
        """
        import re
        import os
        from collections import defaultdict

        _MAX_SESSIONS_PER_LINK = 5
        _SEED_ID_RE = re.compile(r'SEED_ID=(\d+)')

        graph = {
            'sessions': {}, 'file_to_sessions': defaultdict(set),
            'seed_to_sessions': defaultdict(set),
            'finding_id_to_sessions': defaultdict(set),
            'source_task_to_sessions': defaultdict(set),
            'source_session_to_sessions': defaultdict(set),
            'edges': defaultdict(set),
            'parent_map': {},
        }
        _n = len(events)
        _start = time.time()
        from ..infrastructure.log_util import log as _log
        for idx, ev in enumerate(events):
            if _n > 10000 and idx > 0 and idx % 50000 == 0:
                _log("SINK_MATCH", f"SecMate build_session_graph {idx}/{_n} events "
                      f"elapsed={int(time.time()-_start)}s sessions={len(graph['sessions'])}")
            sid = ev.session_id
            if not sid:
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {'files': set(), 'seeds': set(), 'finding_ids': set(),
                                           'source_task_ids': set(), 'source_session_ids': set()}
            sg = graph['sessions'][sid]

            # TEXT 事件：提取 SEED_ID（来自 planner prompt）
            if ev.event_type == "TEXT" and ev.output_json:
                txt = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
                for m in _SEED_ID_RE.finditer(txt):
                    sg['seeds'].add(m.group(1))
                    graph['seed_to_sessions'][m.group(1)].add(sid)

            if not ev.is_tool_call():
                continue
            tool = ev.tool_name or ""
            inp = ev.input_json or {}

            # store_finding/query_finding：提取 finding_id + source_task_id + source_session_id
            # 从源码论证：findings_store 的 store_finding input 含 source_task_id 和 source_session_id
            if "store_finding" in tool or "query_finding" in tool or "store_tiered_finding" in tool \
                    or tool in ("mcp__findings-store__query", "mcp__findings-store__query_finding_overview"):
                fid = str(inp.get("finding_id") or inp.get("parent_id") or "")
                if fid:
                    sg['finding_ids'].add(fid)
                    graph['finding_id_to_sessions'][fid].add(sid)
                # 也从 output 提取 finding_id
                if ev.output_json:
                    out_str = ev.output_json if isinstance(ev.output_json, str) else json.dumps(ev.output_json, ensure_ascii=False)
                    for m in re.finditer(r'"finding_id"\s*:\s*"?(\d+)', out_str):
                        sg['finding_ids'].add(m.group(1))
                        graph['finding_id_to_sessions'][m.group(1)].add(sid)
                # source_task_id / source_session_id 关联
                stid = str(inp.get("source_task_id", "") or "")
                ssid = str(inp.get("source_session_id", "") or "")
                if stid:
                    sg['source_task_ids'].add(stid)
                    graph['source_task_to_sessions'][stid].add(sid)
                if ssid:
                    sg['source_session_ids'].add(ssid)
                    graph['source_session_to_sessions'][ssid].add(sid)
                    graph['parent_map'][sid] = ssid

            # 共享文件（与基类默认实现相同）
            if tool == "bash":
                cmd = str(inp.get("command", ""))
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

        # 构建边：共享 SEED_ID / finding_id / source_task_id / source_session_id 的 session 互相关联
        for seed, sids in graph['seed_to_sessions'].items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            graph['edges'][s1].add(s2)
        for fid, sids in graph['finding_id_to_sessions'].items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            graph['edges'][s1].add(s2)
        for stid, sids in graph['source_task_to_sessions'].items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            graph['edges'][s1].add(s2)
        for ssid, sids in graph['source_session_to_sessions'].items():
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

    @staticmethod
    def _secmate_tag_to_vr(tag: str) -> str | None:
        """Map SecMate review_verdict tag to validation_result.

        tag 值含义（从实际 trace 数据验证）：
        - review_positive[,confirmed[,challenge_required]] → CONFIRMED
        - review_negative[,reviewer_fp|conditional|hardening] → FALSE_POSITIVE
        - reviewer_fp → FALSE_POSITIVE
        - review_conditional / conditional / needs_review → None（不确定，不算确认）
        """
        if not tag:
            return None
        tag_l = tag.lower()
        if "review_positive" in tag_l:
            return "CONFIRMED"
        if "review_negative" in tag_l or "reviewer_fp" in tag_l:
            return "FALSE_POSITIVE"
        return None

    def _extract_action(self, ev):
        """SecMate 平台挖掘行为：追加 store_finding/store_final_verdict 为结论点。"""
        tool = ev.tool_name or ""
        ts = ev.timestamp_ms or 0
        if tool in ("mcp__findings-store__store_finding", "mcp__workflow-tools__store_finding"):
            inp = ev.input_json or {}
            title = str(inp.get("title", "") or inp.get("vuln_type", ""))
            return {"tool": "finding", "action": title, "session_id": ev.session_id, "ts": ts}
        if tool == "mcp__workflow-tools__store_final_verdict" or \
           tool == "mcp__workflow-tools__store_tracer_verdict" or \
           (tool and tool.startswith("mcp__workflow-tools__store_tiered_fing")):
            inp = ev.input_json or {}
            title = str(inp.get("title", "") or inp.get("vuln_type", ""))
            return {"tool": "finding", "action": title, "session_id": ev.session_id, "ts": ts}
        return super()._extract_action(ev)

    def _find_findings_db(self) -> str | None:
        """从 source_uri 定位 findings.db 路径。

        SecMate 的 findings.db 位于 trace 目录的上级：
        .../tasks/{task_id}/tools/secmate-*/run/findings.db
        而 source_uri 指向 .../run/.worker-config/projects
        """
        if not self._source_uri:
            return None
        uri = self._source_uri.replace("\\", "/")
        # 向上找到 run/ 目录
        if "/.worker-config/projects" in uri:
            run_dir = uri.split("/.worker-config/projects")[0]
        elif "/run/" in uri:
            run_dir = uri.split("/run/")[0] + "/run"
        else:
            # 尝试在 source_uri 同级或上级找
            run_dir = uri
        db_path = os.path.join(run_dir, "findings.db")
        if os.path.isfile(db_path):
            return db_path
        # 也在 tools/secmate-*/run/ 下找
        parent = os.path.dirname(run_dir)
        for candidate in glob.glob(os.path.join(parent, "*", "run", "findings.db")):
            if os.path.isfile(candidate):
                return candidate
        return None

    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """提取 SecMate 平台的 finding。

        直接读 findings.db（SQLite），与 SecMate 的 findings_sync.py 一致。
        findings.db 位于 .../run/findings.db，包含所有 finding 的最终状态。

        字段映射（findings.db → finding dict）：
        - id → finding_id
        - tag → 判断 CONFIRMED/FALSE_POSITIVE
        - level → level
        - vuln_type, file_path, line, function_name, description, score
        - payload (JSON) → title, severity, judgment, final_strength
        - source_session_id → session_id（关联原始 JSONL 文件）
        """
        db_path = self._find_findings_db()
        if not db_path:
            return []

        findings: list[dict] = []
        try:
            uri = f"file:{db_path}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=5) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, tag, level, level_num, file_path, line, function_name, "
                    "vuln_type, description, payload, evidence, status, score, "
                    "source_task_id, source_persona, source_session_id "
                    "FROM findings WHERE level = ? ORDER BY id ASC",
                    ("final_verdict",),
                ).fetchall()
        except (sqlite3.OperationalError, sqlite3.DatabaseError):
            return []

        for row in rows:
            row_dict = dict(row)
            tag = str(row_dict.get("tag") or "")
            tag_l = tag.lower()
            # tag 格式：final_positive,final_confirmed 或 final_negative,...
            if "final_positive" in tag_l:
                vr = "CONFIRMED"
            elif "final_negative" in tag_l:
                vr = "FALSE_POSITIVE"
            else:
                vr = None

            # payload 是 JSON 字符串，含 title/severity/judgment/final_strength 等
            payload = {}
            try:
                payload = json.loads(row_dict.get("payload") or "{}")
            except (json.JSONDecodeError, TypeError):
                pass

            finding_id = str(row_dict["id"])
            findings.append({
                "finding_id": finding_id,
                "display_id": finding_id,
                "title": str(payload.get("title") or row_dict.get("vuln_type") or ""),
                "description": str(row_dict.get("description") or ""),
                "vuln_type": str(row_dict.get("vuln_type") or ""),
                "severity": str(payload.get("severity") or ""),
                "source": str(row_dict.get("file_path") or payload.get("primary_location") or ""),
                "sink": str(row_dict.get("function_name") or ""),
                "validation_result": vr,
                "level": "final_verdict",
                "platform": "secmate",
                "session_id": str(row_dict.get("source_session_id") or ""),
            })

        return findings

