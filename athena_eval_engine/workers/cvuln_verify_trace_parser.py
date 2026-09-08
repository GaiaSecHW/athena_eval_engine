"""CVulnVerifyTraceParser — CVulnVerify JSONL session → Canonical RawEvent。

与 Argo（Claude Code JSONL）格式不同：
  - type: session / model_change / thinking_level_change / message
  - message.role: user / assistant / toolResult
  - toolCall: {type, id, name, arguments:{path,command}}
  - RESULT: message role=toolResult, content[].text
  - tool names: read / bash / write（全小写）

解析目录时可按 source_task_id 过滤 .jsonl 文件（一个漏洞一个 jsonl）。
"""
from __future__ import annotations
import json
import os
import re
import glob
from typing import Iterator
from datetime import datetime
from ..domain.raw_event import RawEvent


class CVulnVerifyTraceParser:
    """解析 CVulnVerify JSONL session 日志。"""

    def __init__(self, parser_version: str = "cvuln-verify-1.0"):
        self.parser_version = parser_version
        self._last_tool_id = None
        self._last_tool_name = None
        self._tool_kg = {}

    _TASK_PATH_RE = re.compile(r"/tasks/([0-9a-f]{24})(?:/|$)")

    def _files(self, trace_source) -> list[str]:
        """取得本次评测应读取的 case 文件。

        c_vuln_verify 目录由多个原始平台任务共享。发现阶段以 case API 做正式
        归属，解析阶段用 trace 内的任务上下文将已下载目录收窄到同一任务。
        """
        uri = trace_source["source_uri"]
        files = sorted(glob.glob(os.path.join(uri, "*.jsonl"))) if os.path.isdir(uri) else [uri]
        source_task_id = trace_source.get("source_task_id")
        if not source_task_id:
            return files
        return [path for path in files if self._source_task_id(path) == source_task_id]

    def _source_task_id(self, path: str) -> str | None:
        """从首条用户任务上下文中的历史记忆路径提取原始平台任务 ID。"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    message = event.get("message") or {}
                    if event.get("type") != "message" or message.get("role") != "user":
                        continue
                    text = "\n".join(str(c.get("text", "")) for c in (message.get("content") or [])
                                     if isinstance(c, dict))
                    task_ids = self._TASK_PATH_RE.findall(text)
                    return task_ids[-1] if task_ids else None
        except (OSError, UnicodeDecodeError):
            return None
        return None

    def parse(self, trace_source) -> Iterator[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)
        session_id = trace_source.get("turing_session_id", "")

        files = self._files(trace_source)

        # 预收集所有 toolCall 的 is_kg 标记（按 id）
        self._tool_kg = {}
        for fpath in files:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if d.get("type") == "message":
                        msg = d.get("message", {})
                        if not isinstance(msg, dict):
                            continue
                        for c in (msg.get("content", []) if isinstance(msg.get("content"), list) else []):
                            if isinstance(c, dict) and c.get("type") == "toolCall":
                                tid = c.get("id", "")
                                is_kg = self._is_kg_call(c.get("name", ""), c.get("arguments", {}))
                                if tid:
                                    self._tool_kg[tid] = is_kg

        for fpath in files:
            sid = os.path.splitext(os.path.basename(fpath))[0]
            with open(fpath, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    for ev in self._obj_to_events(d, trace_id, sid, line_no):
                        yield ev

    def _is_kg_call(self, tool_name: str, args) -> bool:
        """判断是否为知识图谱调用：bash command 含 athena CLI 脚本路径。"""
        if not isinstance(args, dict):
            return False
        cmd = str(args.get("command", "")).lower()
        has_script = "scripts/athena" in cmd or "athena.py" in cmd
        is_view = cmd.strip().startswith(("head", "cat ", "grep ", "ls "))
        return has_script and not is_view

    def _obj_to_events(self, d: dict, trace_id: str, session_id: str, line_no: int) -> list[RawEvent]:
        t = d.get("type", "")
        ts = self._parse_ts(d.get("timestamp", ""))
        eid = f"{session_id}-{line_no}"
        evs = []

        if t == "message":
            msg = d.get("message", {})
            if not isinstance(msg, dict):
                return []
            role = msg.get("role", "")
            content = msg.get("content", [])
            if not isinstance(content, list):
                return []

            for ci, c in enumerate(content):
                if not isinstance(c, dict):
                    continue
                ct = c.get("type", "")
                if ct == "toolCall":
                    tool_name = c.get("name", "")
                    args = c.get("arguments", {})
                    tid = c.get("id", "")
                    self._last_tool_id = tid
                    self._last_tool_name = tool_name
                    is_kg = self._tool_kg.get(tid, False) if tid else self._is_kg_call(tool_name, args)
                    evs.append(RawEvent(
                        event_id=f"{eid}-t{ci}", trace_id=trace_id, session_id=session_id,
                        event_type="TOOL_CALL", timestamp_ms=ts,
                        message_id=None, part_id=f"{eid}-t{ci}",
                        step_no=None, tool_name=tool_name,
                        input_json=args if isinstance(args, dict) else None, output_json=None,
                        raw_type="toolCall", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-{ci}",
                        parser_version=self.parser_version,
                        is_kg_interaction=is_kg,
                    ))
                elif ct == "text":
                    evs.append(RawEvent(
                        event_id=f"{eid}-x{ci}", trace_id=trace_id, session_id=session_id,
                        event_type="TEXT", timestamp_ms=ts,
                        message_id=None, part_id=f"{eid}-x{ci}",
                        step_no=None, tool_name=None, input_json=None, output_json=c.get("text"),
                        raw_type="text", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-{ci}",
                        parser_version=self.parser_version,
                    ))
                elif ct == "thinking":
                    evs.append(RawEvent(
                        event_id=f"{eid}-r{ci}", trace_id=trace_id, session_id=session_id,
                        event_type="REASONING", timestamp_ms=ts,
                        message_id=None, part_id=f"{eid}-r{ci}",
                        step_no=None, tool_name=None, input_json=None, output_json=c.get("thinking"),
                        raw_type="thinking", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-{ci}",
                        parser_version=self.parser_version,
                    ))
            usage = msg.get("usage", {})
            if isinstance(usage, dict):
                evs.append(RawEvent(
                    event_id=f"{eid}-u", trace_id=trace_id, session_id=session_id,
                    event_type="STEP_FINISH", timestamp_ms=ts,
                    message_id=None, part_id=f"{eid}-u",
                    step_no=None, tool_name=None,
                    input_json=usage, output_json=None,
                    raw_type="usage", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-u",
                    parser_version=self.parser_version,
                ))

        return evs

    def _parse_ts(self, ts_str: str) -> int | None:
        if not ts_str:
            return None
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return None

    def load_session(self, trace_source) -> dict:
        """从 JSONL 累计 token + step 数。"""
        files = self._files(trace_source)

        ti = to = tr = tcr = 0
        n_step_start = n_step_finish = 0
        ts_min = ts_max = None

        for fpath in files:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts = self._parse_ts(d.get("timestamp", ""))
                    if ts:
                        ts_min = ts if ts_min is None else min(ts_min, ts)
                        ts_max = ts if ts_max is None else max(ts_max, ts)
                    t = d.get("type", "")
                    if t == "message":
                        msg = d.get("message", {})
                        if isinstance(msg, dict):
                            usage = msg.get("usage", {})
                            if isinstance(usage, dict):
                                ti += usage.get("input_tokens", 0) or 0
                                to += usage.get("output_tokens", 0) or 0
                                tr += usage.get("reasoning_tokens", 0) or 0
                                cache = usage.get("cache_read_tokens", 0) or 0
                                tcr += cache if isinstance(cache, (int, float)) else 0
                            if msg.get("role") == "assistant":
                                n_step_finish += 1

        sess = {
            "tokens_input": ti, "tokens_output": to,
            "tokens_reasoning": tr, "cache_read_tokens": tcr,
            "time_created": ts_min, "time_updated": ts_max,
            "_step_start_count": n_step_start,
            "_step_finish_count": n_step_finish,
            "model": "auto", "agent": "cvuln-verify",
        }
        return sess
