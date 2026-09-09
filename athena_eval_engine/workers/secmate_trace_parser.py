"""SecMate transcript JSONL -> Canonical RawEvent.

SecMate uses the Claude SDK transcript envelope, but stores its actual agent
transcripts beneath ``run/.worker-config/projects`` instead of Argo's
``session/argo`` directory.  ``hook-watch/sessions`` is intentionally not
parsed: it records harness activity rather than the agent's execution trace.
"""
from __future__ import annotations

import glob
import json
import os
from datetime import datetime
from typing import Iterator

from ..domain.raw_event import RawEvent
from ..domain.resolvers import TraceParser


_TOOL_MAP = {
    "Bash": "bash", "Read": "read", "Grep": "grep", "Glob": "glob",
    "Write": "write", "Edit": "edit", "Task": "task", "Skill": "skill",
    "TodoWrite": "todowrite",
}


def is_secmate_trace(path: str) -> bool:
    """Identify a SecMate SDK transcript without relying solely on its path."""
    paths = [path]
    if os.path.isdir(path):
        paths = sorted(glob.glob(os.path.join(path, "**", "*.jsonl"), recursive=True))
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
                    if (record.get("entrypoint") == "sdk-cli"
                            and "/tools/secmate-" in str(record.get("cwd", ""))):
                        return True
        except OSError:
            continue
    return False


class SecMateTraceParser(TraceParser):
    """Parse SecMate Claude SDK transcripts, including nested subagents."""

    def __init__(self, parser_version: str = "secmate-1.0"):
        self.parser_version = parser_version

    @staticmethod
    def _files(uri: str) -> list[str]:
        if not os.path.isdir(uri):
            return [uri]
        return sorted(glob.glob(os.path.join(uri, "**", "*.jsonl"), recursive=True))

    @staticmethod
    def _is_kg_call(tool_name: str, tool_input: object) -> bool:
        tool = _TOOL_MAP.get(tool_name, tool_name.lower())
        if tool == "bash" and isinstance(tool_input, dict):
            command = str(tool_input.get("command", "")).lower()
            return (("scripts/athena" in command or "athena.py" in command)
                    and not command.strip().startswith(("head", "cat ", "grep ", "ls ")))
        return tool == "skill" and isinstance(tool_input, dict) and str(
            tool_input.get("name", "")).lower() == "athena-skill"

    @staticmethod
    def _tool_results(record: dict) -> list[tuple[str, str]]:
        """Return every (tool_use_id, result text) in a Claude SDK user record."""
        message = record.get("message")
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
        value = record.get("toolUseResult")
        if value is None:
            return []
        return [("", value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))]

    def parse(self, trace_source) -> Iterator[RawEvent]:
        uri = trace_source["source_uri"]
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
                    if record.get("type") == "assistant":
                        message = record.get("message")
                        for part in message.get("content", []) if isinstance(message, dict) else []:
                            if isinstance(part, dict) and part.get("type") == "tool_use":
                                call_id = str(part.get("id", ""))
                                if call_id:
                                    calls[call_id] = {
                                        "tool_name": _TOOL_MAP.get(part.get("name", ""), str(part.get("name", "")).lower()),
                                        "is_kg": self._is_kg_call(str(part.get("name", "")), part.get("input")),
                                    }
                    elif record.get("type") == "user":
                        for call_id, result in self._tool_results(record):
                            if call_id and result:
                                results[call_id] = result

        totals = {"input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0, "cache_read_tokens": 0}
        step_count = 0
        min_ts = max_ts = None
        for path in files:
            session_id = os.path.splitext(os.path.relpath(path, uri) if os.path.isdir(uri) else os.path.basename(path))[0]
            session_id = session_id.replace("\\", "/")
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
                    if record.get("type") == "assistant" and isinstance(message, dict):
                        content = message.get("content", [])
                        for index, part in enumerate(content if isinstance(content, list) else []):
                            if not isinstance(part, dict):
                                continue
                            part_type = part.get("type")
                            event_id = f"{base_id}-{index}"
                            if part_type == "tool_use":
                                call_id = str(part.get("id", ""))
                                info = calls.get(call_id, {})
                                from ..domain.raw_event import detect_memory_flags
                                _is_mem, _is_mem_w = detect_memory_flags(info.get("tool_name") or "", part.get("input"))
                                yield RawEvent(event_id=event_id, trace_id=trace_id, session_id=session_id,
                                    event_type="TOOL_CALL", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                    part_id=event_id, step_no=None, tool_name=info.get("tool_name"),
                                    input_json=part.get("input") if isinstance(part.get("input"), dict) else None,
                                    output_json=results.get(call_id), raw_type="tool_use", source_table="jsonl",
                                    source_row_id=event_id, parser_version=self.parser_version,
                                    is_kg_interaction=info.get("is_kg", False),
                                    is_memory_interaction=_is_mem,
                                    is_memory_write=_is_mem_w)
                            elif part_type == "text":
                                yield self._event(event_id, trace_id, session_id, "TEXT", timestamp, record, part.get("text"), "text")
                            elif part_type == "thinking":
                                yield self._event(event_id, trace_id, session_id, "REASONING", timestamp, record, part.get("thinking"), "thinking")
                        usage = message.get("usage")
                        if isinstance(usage, dict):
                            totals["input_tokens"] += usage.get("input_tokens", 0) or 0
                            totals["output_tokens"] += usage.get("output_tokens", 0) or 0
                            totals["reasoning_tokens"] += usage.get("reasoning_tokens", 0) or 0
                            totals["cache_read_tokens"] += usage.get("cache_read_tokens", 0) or 0
                            step_count += 1
                            yield RawEvent(event_id=f"{base_id}-usage", trace_id=trace_id, session_id=session_id,
                                event_type="STEP_FINISH", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                part_id=f"{base_id}-usage", step_no=None, tool_name=None, input_json=usage,
                                output_json=None, raw_type="usage", source_table="jsonl",
                                source_row_id=f"{base_id}-usage", parser_version=self.parser_version)
                    elif record.get("type") == "user":
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
                                is_kg_interaction=info.get("is_kg", False))
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
        totals = {"input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0, "cache_read_tokens": 0}
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
                    if record.get("type") != "assistant":
                        continue
                    usage = record.get("message", {}).get("usage", {})
                    if not isinstance(usage, dict):
                        continue
                    totals["input_tokens"] += usage.get("input_tokens", 0) or 0
                    totals["output_tokens"] += usage.get("output_tokens", 0) or 0
                    totals["reasoning_tokens"] += usage.get("reasoning_tokens", 0) or 0
                    totals["cache_read_tokens"] += usage.get("cache_read_tokens", 0) or 0
                    step_count += 1
        return {**totals, "time_created": min_ts, "time_updated": max_ts,
                "_step_start_count": step_count, "_step_finish_count": step_count,
                "model": "claude", "agent": "secmate"}
