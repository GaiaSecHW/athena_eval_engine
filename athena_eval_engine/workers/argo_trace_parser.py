"""ArgoTraceParser — Claude Code JSONL session 日志 → Canonical RawEvent。

与 TuringTraceParser（opencode.db SQLite）不同，Argo 用 Claude Code CLI 原生 JSONL 格式。
每个 session 目录含多个 .jsonl 文件（每轮一个），每行一个 JSON 对象。

type 映射：
  assistant + content[tool_use]  → TOOL_CALL（tool name 大写：Bash/Read/Grep/Glob）
  user + toolUseResult          → TOOL_RESULT
  assistant + content[thinking] → REASONING
  assistant + content[text]     → TEXT
  queue-operation + enqueue     → SYSTEM_EVENT（任务 prompt）

finding 结构差异：
  Argo: toolUseResult 含 {finding_id, verdict: "CONFIRMED"/"FALSE_POSITIVE", description}
  （opencode.db: input.validation_result）
"""
from __future__ import annotations
import json
import os
import re
import glob
from typing import Iterator
from ..domain.raw_event import RawEvent


# Claude Code 工具名 → 小写
_TOOL_MAP = {
    "Bash": "bash", "Read": "read", "Grep": "grep", "Glob": "glob",
    "Write": "write", "Edit": "edit", "Task": "task", "Skill": "skill",
}


class ArgoTraceParser:
    """解析 Argo（Claude Code CLI）JSONL session 日志。"""

    def __init__(self, parser_version: str = "argo-1.0"):
        self.parser_version = parser_version
        self._last_tool_name = None

    def parse(self, trace_source) -> Iterator[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)
        session_id = trace_source.get("turing_session_id", "")

        # 如果是目录，读所有 .jsonl；如果是单文件，读它
        if os.path.isdir(uri):
            files = sorted(glob.glob(os.path.join(uri, "*.jsonl")))
        else:
            files = [uri]

        # 先收集所有 tool_use 的 is_kg 标记（按 tool_use_id），用于 RESULT 继承
        tool_use_kg = {}  # tool_use_id -> is_kg
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
                    if d.get("type") == "assistant":
                        for c in (d.get("message", {}).get("content", []) if isinstance(d.get("message"), dict) else []):
                            if isinstance(c, dict) and c.get("type") == "tool_use":
                                tid = c.get("id", "")
                                tool = c.get("name", "")
                                tool_lower = _TOOL_MAP.get(tool, tool.lower())
                                is_kg = False
                                if tool_lower == "bash" and isinstance(c.get("input"), dict):
                                    cmd = str(c.get("input", {}).get("command", ""))
                                    cmd_l = cmd.lower()
                                    has_script = "scripts/athena" in cmd_l or "athena.py" in cmd_l
                                    is_view = cmd_l.strip().startswith(("head", "cat ", "grep ", "ls "))
                                    if has_script and not is_view:
                                        is_kg = True
                                elif tool_lower == "skill" and isinstance(c.get("input"), dict):
                                    if str(c.get("input", {}).get("name", "")).lower() == "athena-skill":
                                        is_kg = True
                                if tid:
                                    tool_use_kg[tid] = is_kg

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
                    for ev in self._obj_to_events(d, trace_id, sid, line_no, tool_use_kg):
                        yield ev

    def _obj_to_events(self, d: dict, trace_id: str, session_id: str, line_no: int, tool_use_kg: dict = None) -> list[RawEvent]:
        """把一个 JSONL 行转成 RawEvent（可能多个）。"""
        t = d.get("type", "")
        ts = self._parse_ts(d.get("timestamp", ""))
        eid = f"{session_id}-{line_no}"
        evs = []

        if t == "assistant":
            msg = d.get("message", {})
            if not isinstance(msg, dict):
                return []
            content = msg.get("content", [])
            if not isinstance(content, list):
                return []
            for ci, c in enumerate(content):
                if not isinstance(c, dict):
                    continue
                ct = c.get("type", "")
                if ct == "tool_use":
                    tool = c.get("name", "")
                    inp = c.get("input", {})
                    tool_lower = _TOOL_MAP.get(tool, tool.lower())
                    tid = c.get("id", "")
                    # 从预收集的 tool_use_kg 取 is_kg 标记
                    is_kg = tool_use_kg.get(tid, False) if tool_use_kg else False
                    evs.append(RawEvent(
                        event_id=f"{eid}-t{ci}", trace_id=trace_id, session_id=session_id,
                        event_type="TOOL_CALL", timestamp_ms=ts,
                        message_id=d.get("uuid"), part_id=f"{eid}-t{ci}",
                        step_no=None, tool_name=tool_lower,
                        input_json=inp if isinstance(inp, dict) else None, output_json=None,
                        raw_type="tool_use", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-{ci}",
                        parser_version=self.parser_version,
                        is_kg_interaction=is_kg,
                    ))
                elif ct == "text":
                    evs.append(RawEvent(
                        event_id=f"{eid}-x{ci}", trace_id=trace_id, session_id=session_id,
                        event_type="TEXT", timestamp_ms=ts,
                        message_id=d.get("uuid"), part_id=f"{eid}-x{ci}",
                        step_no=None, tool_name=None, input_json=None, output_json=c.get("text"),
                        raw_type="text", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-{ci}",
                        parser_version=self.parser_version,
                    ))
                elif ct == "thinking":
                    evs.append(RawEvent(
                        event_id=f"{eid}-r{ci}", trace_id=trace_id, session_id=session_id,
                        event_type="REASONING", timestamp_ms=ts,
                        message_id=d.get("uuid"), part_id=f"{eid}-r{ci}",
                        step_no=None, tool_name=None, input_json=None, output_json=c.get("thinking"),
                        raw_type="thinking", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-{ci}",
                        parser_version=self.parser_version,
                    ))
            # 从 message.usage 提取 token
            usage = msg.get("usage", {})
            if isinstance(usage, dict):
                evs.append(RawEvent(
                    event_id=f"{eid}-u", trace_id=trace_id, session_id=session_id,
                    event_type="STEP_FINISH", timestamp_ms=ts,
                    message_id=d.get("uuid"), part_id=f"{eid}-u",
                    step_no=None, tool_name=None,
                    input_json=usage, output_json=None,
                    raw_type="usage", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-u",
                    parser_version=self.parser_version,
                ))

        elif t == "user":
            tur = d.get("toolUseResult")
            if tur is not None:
                out_str = ""
                if isinstance(tur, str):
                    out_str = tur
                elif isinstance(tur, dict):
                    out_str = tur.get("stdout", "") or json.dumps(tur, ensure_ascii=False)
                # 用 tool_use_id 从预收集的标记取 is_kg
                tid = ""
                content_list = d.get("message", {}).get("content", []) if isinstance(d.get("message"), dict) else []
                if isinstance(content_list, list):
                    for c in content_list:
                        if isinstance(c, dict) and c.get("type") == "tool_result":
                            tid = c.get("tool_use_id", "")
                            break
                is_kg = tool_use_kg.get(tid, False) if (tool_use_kg and tid) else False
                # tool_name 也从 tool_use_kg 取（如果有），否则用 _last_tool_name 兜底
                tn = self._last_tool_name or ""
                evs.append(RawEvent(
                    event_id=f"{eid}-res", trace_id=trace_id, session_id=session_id,
                    event_type="TOOL_RESULT", timestamp_ms=ts,
                    message_id=d.get("uuid"), part_id=f"{eid}-res",
                    step_no=None, tool_name=tn, input_json=None, output_json=out_str,
                    raw_type="toolUseResult", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-res",
                    parser_version=self.parser_version,
                    is_kg_interaction=is_kg,
                ))

        elif t == "queue-operation" and d.get("operation") == "enqueue":
            evs.append(RawEvent(
                event_id=f"{eid}-q", trace_id=trace_id, session_id=session_id,
                event_type="SYSTEM_EVENT", timestamp_ms=ts,
                message_id=None, part_id=f"{eid}-q",
                step_no=None, tool_name=None,
                input_json=None, output_json=d.get("content"),
                raw_type="queue-enqueue", parse_status="OK",
                source_table="jsonl", source_row_id=f"{eid}-q",
                parser_version=self.parser_version,
            ))

        return evs

    def _parse_ts(self, ts_str: str) -> int | None:
        """ISO 8601 → ms epoch。"""
        if not ts_str:
            return None
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return None

    def load_session(self, trace_source) -> dict:
        """从 JSONL 累计 token + step 数（替代 SQLite session 表）。"""
        uri = trace_source["source_uri"]
        if os.path.isdir(uri):
            files = sorted(glob.glob(os.path.join(uri, "*.jsonl")))
        else:
            files = [uri]

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
                    if t == "assistant":
                        msg = d.get("message", {})
                        if isinstance(msg, dict):
                            usage = msg.get("usage", {})
                            if isinstance(usage, dict):
                                ti += usage.get("input_tokens", 0) or 0
                                to += usage.get("output_tokens", 0) or 0
                                tr += usage.get("reasoning_tokens", 0) or 0  # may not exist
                                cache = usage.get("cache_read_tokens", 0) or 0
                                tcr += cache if isinstance(cache, (int, float)) else 0
                        n_step_finish += 1  # each assistant msg = one step
                    elif t == "queue-operation":
                        n_step_start += 1

        sess = {
            "tokens_input": ti, "tokens_output": to,
            "tokens_reasoning": tr, "cache_read_tokens": tcr,
            "time_created": ts_min, "time_updated": ts_max,
            "_step_start_count": n_step_start,
            "_step_finish_count": n_step_finish,
            "model": "claude", "agent": "argo",
        }
        return sess
