"""SecMate transcript JSONL -> Canonical RawEvent (v2).

从老代码 workers/secmate_trace_parser.py 拷贝核心逻辑，适配 v2 BaseParser 接口。

Trace 路径：/data/files/{project_id}/tasks/{task_id}/tools/secmate-*/run/.worker-config/projects/*/

SecMate uses the Claude SDK transcript envelope, but stores its actual agent
transcripts beneath ``run/.worker-config/projects`` instead of Argo's
``session/argo`` directory.  ``hook-watch/sessions`` is intentionally not
parsed: it records harness activity rather than the agent's execution trace.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
import time
from datetime import datetime
from typing import Iterator

from ..base import BaseParser
from ...core.raw_event import RawEvent, detect_memory_flags, usage_numbers


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

    Strategy: top-level -> computed subdirectory -> one-level subdirs fallback.
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
    with cwd="/app", so we only check entrypoint -- Argo traces in session/argo/
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


class SecMateParser(BaseParser):
    """Parse SecMate Claude SDK transcripts, including nested subagents.

    从老代码 workers/secmate_trace_parser.py 拷贝核心逻辑，适配 v2 BaseParser 接口。
    """

    def __init__(self, parser_version: str = "secmate-2.0"):
        self.parser_version = parser_version
        self._source_uri: str | None = None
        self._original_uri: str | None = None
        self._session_cache: dict | None = None

    @property
    def agent_type(self) -> str:
        return "secmate"

    def _extract_tool_task_id(self) -> str | None:
        """从 source_uri 提取 secmate tool_task_id。

        source_uri 形如 .../tasks/{task_id}/tools/secmate-XXX-{ts}/run/.worker-config/projects/...
        tool_task_id = "secmate-XXX-{ts}"（目录名，对应 MySQL finding.tool_task_id）。

        k8s 模式下 trace 被拷贝到 /tmp/eval_traces/，目录结构压扁成连字符路径：
          .../df59d212_-data-files-{project}-tasks-{task}-tools-secmate-XXX-{ts}-run
        （无 /tools/ 和 /run 分隔符），需从连字符段中提取 secmate-XXX-{ts}。
        """
        uri = (self._source_uri or "").replace("\\", "/")
        # 匹配 tools/secmate-XXX-{ts}/ 段（原始目录结构）
        m = re.search(r"/tools/(secmate-[^/]+?)/run(?:/|$)", uri)
        if m:
            return m.group(1)
        # k8s /tmp 压扁路径：-tools-secmate-XXX-{ts}-run
        m2 = re.search(r"-tools-(secmate-[^/]+?)-run(?:/|$)", uri)
        if m2:
            return m2.group(1)
        return None

    @staticmethod
    def _files(uri: str) -> list[str]:
        return _find_jsonl_files(uri)

    @staticmethod
    def _is_kg_call(tool_name: str, tool_input: object) -> bool:
        """检测知识图谱交互。

        从源码与 trace 论证：
        1. scripts/athena / athena.py -- KG 查询脚本（旧格式）
        2. scaffold run -- KG 创建（trace 中 scaffold run --json 建立 seeddir 和 kg/）
        3. athena-skill -- KG 查询 skill
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

    def parse(self, trace_source) -> list[RawEvent]:
        """解析 SecMate JSONL trace，返回规范事件序列。

        从老代码 secmate_trace_parser.py 的 parse() 方法拷贝。
        老代码返回 Iterator[RawEvent]，v2 返回 list[RawEvent]。
        """
        uri = trace_source["source_uri"]
        self._source_uri = uri
        self._original_uri = trace_source.get("original_source_uri")
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

        events: list[RawEvent] = []
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
                                # 统一取 input：tool_use -> part.input, toolCall -> part.arguments
                                inp = part.get("input")
                                if inp is None:
                                    inp = part.get("arguments")
                                    if not isinstance(inp, dict):
                                        inp = None
                                _is_mem, _is_mem_w = detect_memory_flags(info.get("tool_name") or "", inp)
                                _mapped = info.get("tool_name") or ""
                                events.append(RawEvent(
                                    event_id=event_id, trace_id=trace_id, session_id=session_id,
                                    event_type="TOOL_CALL", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                    part_id=event_id, step_no=None, tool_name=_mapped,
                                    input_json=inp,
                                    output_json=results.get(call_id), raw_type=part_type, source_table="jsonl",
                                    source_row_id=event_id, parser_version=self.parser_version,
                                    is_kg_interaction=info.get("is_kg", False),
                                    is_memory_interaction=_is_mem,
                                    is_memory_write=_is_mem_w,
                                    call_id=call_id))
                            elif part_type == "text":
                                events.append(self._event(event_id, trace_id, session_id, "TEXT", timestamp, record, part.get("text"), "text"))
                            elif part_type == "thinking":
                                events.append(self._event(event_id, trace_id, session_id, "REASONING", timestamp, record, part.get("thinking"), "thinking"))
                        usage = message.get("usage")
                        if isinstance(usage, dict):
                            _ti, _to, _tr, _tcr = usage_numbers(usage)
                            totals["tokens_input"] += _ti
                            totals["tokens_output"] += _to
                            totals["tokens_reasoning"] += _tr
                            totals["cache_read_tokens"] += _tcr
                            step_count += 1
                            events.append(RawEvent(
                                event_id=f"{base_id}-usage", trace_id=trace_id, session_id=session_id,
                                event_type="STEP_FINISH", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                part_id=f"{base_id}-usage", step_no=None, tool_name=None, input_json=usage,
                                output_json=None, raw_type="usage", source_table="jsonl",
                                source_row_id=f"{base_id}-usage", parser_version=self.parser_version))
                    elif self._is_tool_result_record(record):
                        for result_index, (call_id, result) in enumerate(self._tool_results(record)):
                            if not result:
                                continue
                            info = calls.get(call_id, {})
                            event_id = f"{base_id}-result{result_index}"
                            events.append(RawEvent(
                                event_id=event_id, trace_id=trace_id, session_id=session_id,
                                event_type="TOOL_RESULT", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                part_id=event_id, step_no=None, tool_name=info.get("tool_name"),
                                input_json=None, output_json=result, raw_type="tool_result", source_table="jsonl",
                                source_row_id=event_id, parser_version=self.parser_version,
                                call_id=call_id,
                                is_kg_interaction=info.get("is_kg", False)))
                    elif self._is_user_record(record):
                        for result_index, (call_id, result) in enumerate(self._tool_results(record)):
                            if not result:
                                continue
                            info = calls.get(call_id, {})
                            event_id = f"{base_id}-result{result_index}"
                            events.append(RawEvent(
                                event_id=event_id, trace_id=trace_id, session_id=session_id,
                                event_type="TOOL_RESULT", timestamp_ms=timestamp, message_id=record.get("uuid"),
                                part_id=event_id, step_no=None, tool_name=info.get("tool_name"),
                                input_json=None, output_json=result, raw_type="tool_result", source_table="jsonl",
                                source_row_id=event_id, parser_version=self.parser_version,
                                call_id=call_id,
                                is_kg_interaction=info.get("is_kg", False)))
                    elif record.get("type") == "queue-operation" and record.get("operation") == "enqueue":
                        events.append(self._event(f"{base_id}-queue", trace_id, session_id, "SYSTEM_EVENT", timestamp,
                                                  record, record.get("content"), "queue-enqueue"))
        # SecMate has no separate step-start record: each assistant response
        # carrying usage is one model step.  Keep both counts on this same
        # contract so M9 is valid and does not emit a false integrity warning.
        self._session_cache = {"uri": uri, **totals, "time_created": min_ts, "time_updated": max_ts,
                               "_step_start_count": step_count, "_step_finish_count": step_count,
                               "model": "claude", "agent": "secmate"}

        return events

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
        """加载 session 元数据（token/step/time）。

        从老代码 secmate_trace_parser.py 的 load_session() 方法拷贝。
        """
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
                    _ti, _to, _tr, _tcr = usage_numbers(usage)
                    totals["tokens_input"] += _ti
                    totals["tokens_output"] += _to
                    totals["tokens_reasoning"] += _tr
                    totals["cache_read_tokens"] += _tcr
                    step_count += 1
        return {**totals, "time_created": min_ts, "time_updated": max_ts,
                "_step_start_count": step_count, "_step_finish_count": step_count,
                "model": "claude", "agent": "secmate"}

    def build_session_graph(self, events) -> dict:
        """构建 session 关系图。

        SecMate session 关联机制（从源码与 trace 数据验证）：

        parent_map/edges 的唯一来源是 **findings.db 的 finding_edges**：
        finding 级别的 parent/derived_from 派生关系，通过 findings.source_session_id
        映射到 session 级别边。语义是"产生相关漏洞发现的 session 之间的关系"
        （挖掘逻辑链），不是"session A 调用了 session B"的严格调用关系。
        SecMate 的 session（agent CLI 进程一次运行，UUID 文件）彼此独立运行，
        不存在嵌套调用——这是与 argo/turing 的本质区别。

        已排查并排除的来源：
        - **trace parentUuid**：每个 session 文件都有 parentUuid，但父 UUID
          全部不在本 run 的 session 集合内（指向 agent_spawner CLI 父进程的
          全局 session），不可用于构建 case 内调用链。
        - **events.jsonl spawn**：任务级派生（persona 调度单元），非 session 级。
        - **MySQL task.parent_task_id**：任务级父子，无 session 级。
        - **共享文件**：仅收集不建边——共享不是调用关系，会导致 BFS 误连。

        辅助关联（不进 parent_map，仅供查询）：
        1. SEED_ID 共享：planner prompt 含 SEED_ID=xxx，sessions 共享同一 seed
        2. finding_id 共享：store_finding/query_finding 工具调用中的 finding_id

        注意：source_session_id 是 agent_spawner 从 AGENTFL_SESSION_ID 环境变量注入的
        （agent_spawner/server.py line 986），不在 store_finding 的 input 参数中
        （findings_db/server.py store_finding 函数签名无此参数）。
        因此不能从 tool call input 中提取，必须从 findings.db 读取。
        """
        from collections import defaultdict
        import logging
        _log = logging.getLogger(__name__)

        _SEED_ID_RE = re.compile(r'SEED_ID=(\d+)')

        graph = {
            'sessions': {}, 'file_to_sessions': defaultdict(set),
            'seed_to_sessions': defaultdict(set),
            'finding_id_to_sessions': defaultdict(set),
            'edges': defaultdict(set),
            'parent_map': {},
        }
        _n = len(events)
        _start = time.time()
        for idx, ev in enumerate(events):
            if _n > 10000 and idx > 0 and idx % 50000 == 0:
                _log.debug("SecMate build_session_graph %d/%d events elapsed=%ds sessions=%d",
                           idx, _n, int(time.time() - _start), len(graph['sessions']))
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

            # store_finding/query_finding：提取 finding_id（用于 finding_id_to_sessions）
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

            # 共享文件（仅收集不建边——共享不是调用关系）
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

        # 构建边：从 findings.db 的 finding_edges 表读取 finding 级别关系，
        # 通过 findings.source_session_id 映射到 session 级别边。
        # source_session_id 是 agent_spawner 从 AGENTFL_SESSION_ID 环境变量注入的
        # （agent_spawner/server.py line 986），不在 store_finding 的 input 参数中。
        db_path = self._find_findings_db()
        if db_path and os.path.isfile(db_path):
            try:
                conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
                # finding_id -> source_session_id 映射
                # （findings.db 是运行产物，含 session 级关联 source_session_id；
                #   MySQL finding 表无 source_session_id，通过 source_finding_id 桥接）
                finding_to_session: dict[str, str] = {}
                finding_session_set: dict[str, str] = {}
                for r in conn.execute(
                    "SELECT id, source_session_id "
                    "FROM findings "
                    "WHERE source_session_id IS NOT NULL "
                    "  AND source_session_id != ''"
                ).fetchall():
                    fid = str(r[0])
                    finding_to_session[fid] = r[1]
                    finding_session_set[fid] = r[1]
                # finding_edges -> session 级别边
                # source_id 是 parent finding（先创建），target_id 是 child finding（derived）
                for r in conn.execute(
                    "SELECT source_id, target_id FROM finding_edges"
                ).fetchall():
                    src_sid = finding_to_session.get(str(r[0]))
                    tgt_sid = finding_to_session.get(str(r[1]))
                    if src_sid and tgt_sid and src_sid != tgt_sid:
                        graph['parent_map'][tgt_sid] = src_sid
                        graph['edges'][tgt_sid].add(src_sid)
                        graph['edges'][src_sid].add(tgt_sid)
                conn.close()

                # ── 从 secmate MySQL 提取 finding title（权威源），桥接 session ──
                # MySQL finding 表：title（精确标题）+ source_finding_id + tool_task_id。
                # source_finding_id = findings.db 的 findings.id → 关联 source_session_id。
                # 只有 report_state='reported' 的才是实际上报的 finding（参与匹配）。
                # 匹配键用 title（与 turing 的 title 索引一致），而非 description。
                try:
                    from ...infra.agent_db import AgentDBManager
                    mgr = AgentDBManager()
                    mysql_conn = mgr.get_connection("secmate")
                    if mysql_conn is not None:
                        try:
                            cur = mysql_conn.cursor()
                            # tool_task_id = source_uri 中 tools/secmate-XXX/ 的目录名
                            tool_task_id = self._extract_tool_task_id()
                            if tool_task_id:
                                cur.execute(
                                    "SELECT title, source_finding_id FROM finding "
                                    "WHERE tool_task_id = %s AND report_state = %s "
                                    "AND title IS NOT NULL AND title != ''",
                                    (tool_task_id, "reported"),
                                )
                                rows = cur.fetchall()
                                cur.close()
                                # source_finding_id → session 的 finding_descs
                                # （title 作索引键；桥接不到 session 的 finding 跳过——
                                #  匹配仍可命中 title，但 session 为空）
                                for f_title, source_fid in rows:
                                    f_title = str(f_title or "").strip()
                                    if not f_title:
                                        continue
                                    src_sid = finding_session_set.get(str(source_fid), "")
                                    if src_sid:
                                        sdata = graph['sessions'].get(src_sid)
                                        if sdata is not None:
                                            sdata.setdefault('finding_descs', {})
                                            sdata['finding_descs'][f_title] = f_title
                            _log.debug(
                                "SecMate MySQL finding 提取: tool_task_id=%s, "
                                "reported=%d",
                                tool_task_id or "?",
                                len(rows) if tool_task_id else 0,
                            )
                        finally:
                            mysql_conn.close()
                except Exception as e:
                    _log.debug("SecMate MySQL finding 提取失败: %s", e)
                _log.debug("SecMate build_session_graph: finding_edges -> %d session edges, %d total edges",
                           len(graph['parent_map']),
                           sum(len(v) for v in graph['edges'].values()) // 2)
            except Exception as e:
                _log.debug("SecMate build_session_graph: findings.db read failed: %s", e)

        return graph

    def _find_findings_db(self) -> str | None:
        """从 source_uri 定位 findings.db 路径。

        SecMate 的 findings.db 位于 trace 目录的上级：
        .../tasks/{task_id}/tools/secmate-*/run/findings.db
        而 source_uri 指向 .../run/.worker-config/projects

        k8s 模式下 trace 目录被拷贝到 /tmp/eval_traces/，
        findings.db 额外拷贝为同级 *_findings.db 文件。
        拷贝路径找不到时，回退到原始 /data/... 路径直接读 NFS 兜底。
        """
        if not self._source_uri:
            return None
        uri = self._source_uri.replace("\\", "/")
        # 向上找到 run/ 目录
        if "/.worker-config/projects" in uri:
            run_dir = uri.split("/.worker-config/projects")[0]
        elif "/.worker-config/project" in uri:
            run_dir = uri.split("/.worker-config/project")[0]
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
        # k8s 拷贝路径：在同级目录找 *_findings.db
        if "/tmp/" in uri:
            sibling_dir = os.path.dirname(uri)
            for candidate in glob.glob(os.path.join(sibling_dir, "*_findings.db")):
                if os.path.isfile(candidate):
                    return candidate
        # 兜底：回退到原始 /data/... 路径直接读 NFS 上的 findings.db
        if self._original_uri:
            orig = self._original_uri.replace("\\", "/")
            if "/.worker-config/projects" in orig:
                orig_run_dir = orig.split("/.worker-config/projects")[0]
            elif "/.worker-config/project" in orig:
                orig_run_dir = orig.split("/.worker-config/project")[0]
            elif "/run/" in orig:
                orig_run_dir = orig.split("/run/")[0] + "/run"
            else:
                orig_run_dir = orig
            orig_db = os.path.join(orig_run_dir, "findings.db")
            if os.path.isfile(orig_db):
                return orig_db
            # 原始路径的 tools/secmate-*/run/ 下找
            orig_parent = os.path.dirname(orig_run_dir)
            for candidate in glob.glob(os.path.join(orig_parent, "*", "run", "findings.db")):
                if os.path.isfile(candidate):
                    return candidate
        return None

    def label_session_phases(
        self, events: list[RawEvent], session_meta: dict
    ) -> tuple[dict[str, str], dict[str, str]]:
        """标注 session 的业务阶段（finding 逻辑已移除）。

        返回 (session_phase_labels, session_phase_source)。
        所有 session 标注为 "未知"，后续由 LLM 细分模块处理。
        """
        session_phase_labels: dict[str, str] = {}
        session_phase_source: dict[str, str] = {}
        for ev in events:
            sid = ev.session_id
            if sid and sid not in session_phase_labels:
                session_phase_labels[sid] = "未知"
                session_phase_source[sid] = "no_persona_found"
        return session_phase_labels, session_phase_source
