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

        从源码论证（findings_store/server.py + workflows/secmate-flash/tools_mcp.py）：
        - mcp__findings-store__store_finding — 核心 finding 存储
        - mcp__findings-store__store_finding_finalize_batch — 批量 finding 存储
        - mcp__workflow-tools__store_finding — workflow 别名
        - mcp__workflow-tools__store_tiered_finding[_ext] — 中间 finding
        - mcp__workflow-tools__store_tracer_verdict — 最终判定
        - mcp__workflow-tools__store_final_verdict — 旧格式 fallback
        """
        t = tool_name or ""
        return (t in ("mcp__findings-store__store_finding",
                      "mcp__findings-store__store_finding_finalize_batch",
                      "mcp__workflow-tools__store_finding",
                      "mcp__workflow-tools__store_tracer_verdict",
                      "mcp__workflow-tools__store_final_verdict")
                or t.startswith("mcp__workflow-tools__store_tiered_fing"))

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
                                _mapped = info.get("tool_name") or ""
                                yield RawEvent(event_id=event_id, trace_id=trace_id, session_id=session_id,
                                    event_type="TOOL_CALL", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                    part_id=event_id, step_no=None, tool_name=_mapped,
                                    input_json=part.get("input") if isinstance(part.get("input"), dict) else None,
                                    output_json=results.get(call_id), raw_type="tool_use", source_table="jsonl",
                                    source_row_id=event_id, parser_version=self.parser_version,
                                    is_kg_interaction=info.get("is_kg", False),
                                    is_memory_interaction=_is_mem,
                                    is_memory_write=_is_mem_w,
                                    is_finding_submission=self._is_finding_tool(_mapped))
                            elif part_type == "text":
                                yield self._event(event_id, trace_id, session_id, "TEXT", timestamp, record, part.get("text"), "text")
                            elif part_type == "thinking":
                                yield self._event(event_id, trace_id, session_id, "REASONING", timestamp, record, part.get("thinking"), "thinking")
                        usage = message.get("usage")
                        if isinstance(usage, dict):
                            from ..domain.raw_event import usage_numbers
                            _ti, _to, _tr, _tcr = usage_numbers(usage)
                            totals["input_tokens"] += _ti
                            totals["output_tokens"] += _to
                            totals["reasoning_tokens"] += _tr
                            totals["cache_read_tokens"] += _tcr
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
                    from ..domain.raw_event import usage_numbers
                    _ti, _to, _tr, _tcr = usage_numbers(usage)
                    totals["input_tokens"] += _ti
                    totals["output_tokens"] += _to
                    totals["reasoning_tokens"] += _tr
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
        3. 共享文件（与基类默认实现相同）
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
            'edges': defaultdict(set),
        }
        for ev in events:
            sid = ev.session_id
            if not sid:
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {'files': set(), 'seeds': set(), 'finding_ids': set()}
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

            # store_finding/query_finding：提取 finding_id
            # 从源码论证：findings_store 注册了 query 和 query_finding_overview，
            # workflow_tools 注册了 query_finding，均含 finding_id 参数
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

        # 构建边：共享 SEED_ID 或 finding_id 的 session 互相关联
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
        - review_positive / confirm_positive → CONFIRMED
        - review_negative / reviewer_fp → FALSE_POSITIVE
        - conditional / needs_review → None（不确定，不算确认）
        """
        if not tag:
            return None
        tag_l = tag.lower()
        if "review_positive" in tag_l or "confirm_positive" in tag_l:
            return "CONFIRMED"
        if "review_negative" in tag_l or "reviewer_fp" in tag_l:
            return "FALSE_POSITIVE"
        return None

    def _extract_action(self, ev):
        """SecMate 平台挖掘行为：追加 store_finding/store_tracer_verdict 为结论点。"""
        tool = ev.tool_name or ""
        ts = ev.timestamp_ms or 0
        if tool in ("mcp__findings-store__store_finding", "mcp__workflow-tools__store_finding"):
            inp = ev.input_json or {}
            title = str(inp.get("title", "") or inp.get("vuln_type", ""))
            return {"tool": "finding", "action": title, "session_id": ev.session_id, "ts": ts}
        if tool == "mcp__workflow-tools__store_tracer_verdict" or \
           (tool and tool.startswith("mcp__workflow-tools__store_tiered_fing")):
            inp = ev.input_json or {}
            title = str(inp.get("title", "") or inp.get("vuln_type", ""))
            return {"tool": "finding", "action": title, "session_id": ev.session_id, "ts": ts}
        return super()._extract_action(ev)

    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """提取 SecMate 平台的 finding。

        从源码论证（findings_db/server.py + workflows/secmate-flash/tools_mcp.py）：
        1. store_finding（findings-store MCP 或 workflow-tools alias）— 核心 finding 存储
        2. store_finding_finalize_batch — 批量 finding 存储（findings 列表）
        3. store_tiered_finding[_ext]（中间 finding，新格式）
        4. store_tracer_verdict（最终判定，outcome=confirmed/conditional/refuted）
        5. store_final_verdict（旧格式 fallback）
        """
        findings: dict[str, dict] = {}

        for _ei, e in enumerate(events):
            if not e.is_tool_call():
                continue
            tool = e.tool_name or ""
            inp = e.input_json or {}
            out_str = ""
            if e.output_json is not None:
                out_str = e.output_json if isinstance(e.output_json, str) else json.dumps(e.output_json, ensure_ascii=False)

            # store_finding
            if tool in ("mcp__findings-store__store_finding", "mcp__workflow-tools__store_finding"):
                level = str(inp.get("level", ""))
                tag = str(inp.get("tag", ""))
                if level == "review_verdict":
                    vr = self._secmate_tag_to_vr(tag)
                    parent_id = str(inp.get("parent_id", ""))
                    if parent_id and parent_id in findings:
                        findings[parent_id]["validation_result"] = vr
                    else:
                        fid = parent_id or f"secmate-verdict-{e.event_id}"
                        findings[fid] = {
                            "finding_id": fid,
                            "display_id": fid,
                            "title": str(inp.get("vuln_type", "")) or str(inp.get("description", "")),
                            "description": str(inp.get("description", "")),
                            "vuln_type": str(inp.get("vuln_type", "")),
                            "severity": str(inp.get("score", "")),
                            "source": str(inp.get("file_path", "")),
                            "sink": str(inp.get("function_name", "")),
                            "validation_result": vr,
                            "platform": "secmate",
                            "session_id": e.session_id,
                        }
                else:
                    finding_id = ""
                    try:
                        result = json.loads(out_str)
                        nested = result.get("result", result) if isinstance(result, dict) else result
                        if isinstance(nested, str):
                            nested = json.loads(nested)
                        if isinstance(nested, dict):
                            finding_id = str(nested.get("finding_id", ""))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass
                    finding_id = finding_id or str(inp.get("finding_id", "")) or f"secmate-{e.event_id}"
                    findings[finding_id] = {
                        "finding_id": finding_id,
                        "display_id": finding_id,
                        "title": str(inp.get("title", "")) or str(inp.get("vuln_type", "")),
                        "description": str(inp.get("description", "")),
                        "vuln_type": str(inp.get("vuln_type", "")) or str(inp.get("category", "")),
                        "severity": str(inp.get("severity", "")) or str(inp.get("score", "")),
                        "source": str(inp.get("source", "") or inp.get("source_refs", "") or inp.get("file_path", "")),
                        "sink": str(inp.get("sink", "") or inp.get("function_name", "")),
                        "validation_result": None,
                        "platform": "secmate",
                        "session_id": e.session_id,
                    }

            # store_finding_finalize_batch — 批量 finding 存储
            # 从源码论证：findings_store 注册了 store_finding_finalize_batch，
            # input 含 findings 列表，每项与 store_finding 字段相同
            elif tool == "mcp__findings-store__store_finding_finalize_batch":
                batch = inp.get("findings", [])
                if not isinstance(batch, list):
                    batch = []
                for bi, bf in enumerate(batch):
                    if not isinstance(bf, dict):
                        continue
                    b_level = str(bf.get("level", ""))
                    b_tag = str(bf.get("tag", ""))
                    b_fid = ""
                    try:
                        result = json.loads(out_str)
                        nested = result.get("result", result) if isinstance(result, dict) else result
                        if isinstance(nested, str):
                            nested = json.loads(nested)
                        if isinstance(nested, dict):
                            items = nested.get("findings", nested.get("results", []))
                            if isinstance(items, list) and bi < len(items) and isinstance(items[bi], dict):
                                b_fid = str(items[bi].get("finding_id", ""))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass
                    b_fid = b_fid or str(bf.get("finding_id", "")) or f"secmate-batch-{e.event_id}-{bi}"
                    findings[b_fid] = {
                        "finding_id": b_fid,
                        "display_id": b_fid,
                        "title": str(bf.get("title", "")) or str(bf.get("vuln_type", "")),
                        "description": str(bf.get("description", "")),
                        "vuln_type": str(bf.get("vuln_type", "")) or str(bf.get("category", "")),
                        "severity": str(bf.get("severity", "")) or str(bf.get("score", "")),
                        "source": str(bf.get("source", "") or bf.get("source_refs", "") or bf.get("file_path", "")),
                        "sink": str(bf.get("sink", "") or bf.get("function_name", "")),
                        "validation_result": self._secmate_tag_to_vr(b_tag) if b_level == "review_verdict" else None,
                        "platform": "secmate",
                        "session_id": e.session_id,
                    }

            # store_tiered_finding（新格式中间 finding）
            elif tool.startswith("mcp__workflow-tools__store_tiered_fing"):
                finding_id = ""
                try:
                    result = json.loads(out_str)
                    nested = result.get("result", result) if isinstance(result, dict) else result
                    if isinstance(nested, str):
                        nested = json.loads(nested)
                    if isinstance(nested, dict):
                        finding_id = str(nested.get("finding_id", ""))
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
                finding_id = finding_id or f"secmate-{e.event_id}"
                findings[finding_id] = {
                    "finding_id": finding_id,
                    "display_id": finding_id,
                    "title": str(inp.get("vuln_type", "")),
                    "description": inp.get("description", ""),
                    "vuln_type": inp.get("vuln_type", ""),
                    "severity": inp.get("severity", "") or str(inp.get("score", "")),
                    "source": str(inp.get("file_path", "")),
                    "sink": str(inp.get("function_name", "")),
                    "validation_result": None,
                    "platform": "secmate",
                    "session_id": e.session_id,
                }

            # store_tracer_verdict / store_final_verdict
            # 从源码论证：store_tracer_verdict 的 input 含 outcome（confirmed/conditional/refuted），
            # 不含 tag（tag 由工具内部设置）。直接用 outcome 映射 validation_result。
            # store_final_verdict 为旧格式 fallback，保留兼容。
            elif tool in ("mcp__workflow-tools__store_tracer_verdict",
                           "mcp__workflow-tools__store_final_verdict"):
                outcome = str(inp.get("outcome", ""))
                if outcome in ("confirmed", "conditional"):
                    vr = "CONFIRMED"
                elif outcome == "refuted":
                    vr = "FALSE_POSITIVE"
                else:
                    vr = None
                finding_id = ""
                try:
                    result = json.loads(out_str)
                    nested = result.get("result", result) if isinstance(result, dict) else result
                    if isinstance(nested, str):
                        nested = json.loads(nested)
                    if isinstance(nested, dict):
                        finding_id = str(nested.get("finding_id", ""))
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
                finding_id = finding_id or f"secmate-verdict-{e.event_id}"
                findings[finding_id] = {
                    "finding_id": finding_id,
                    "display_id": finding_id,
                    "title": str(inp.get("title", "")) or str(inp.get("vuln_type", "")),
                    "description": inp.get("description", ""),
                    "vuln_type": inp.get("vuln_type", ""),
                    "severity": inp.get("severity", ""),
                    "source": str(inp.get("file_path", "") or inp.get("primary_location", "")),
                    "sink": str(inp.get("function_name", "")),
                    "validation_result": vr,
                    "platform": "secmate",
                    "session_id": e.session_id,
                }

        attach_event_indices(findings, events)
        return list(findings.values())

