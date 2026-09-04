"""DataflowVulnScanTraceParser — dataflow_vuln_scan pi-agent JSONL session → Canonical RawEvent。

目录结构（新工具）：
  .../session/dataflow_vuln_scan/<dvs_run_id>/*.jsonl
  每个 jsonl 是一轮单函数分析（taint / vuln-judge / vuln-report），另有
  *.system-prompt.json / *.md 旁路文件（解析时跳过）。

与 CVulnVerify（同 pi-agent 信封）格式异同：
  相同：
    - type: session / model_change / thinking_level_change / message
    - message.role: user / assistant / toolResult
    - content: toolCall {id, name, arguments} / text / thinking
  不同：
    - toolResult：toolCallId / toolName 在 message 层（CVulnVerify 在 content 层按 type 区分）
    - usage 键名：input / output / reasoning / cacheRead（CVulnVerify/Argo 用 input_tokens 等）
    - 文件按 dvs_run_id 子目录组织，需递归读取

source_uri 可指向 dataflow_vuln_scan 目录、某个 dvs_* 子目录或单个 .jsonl。
"""
from __future__ import annotations
import json
import os
import glob
from typing import Iterator
from datetime import datetime
from ..domain.raw_event import RawEvent


class DataflowVulnScanTraceParser:
    """解析 dataflow_vuln_scan JSONL session 日志。"""

    def __init__(self, parser_version: str = "dataflow-1.0"):
        self.parser_version = parser_version
        self._tool_kg = {}
        self._seen_msg_ids: set[str] = set()

    def _list_files(self, uri: str) -> list[str]:
        if os.path.isdir(uri):
            files = sorted(glob.glob(os.path.join(uri, "**", "*.jsonl"), recursive=True))
            # 跳过 system-prompt 旁路文件（以 .jsonl.system-prompt.json 结尾，不会命中 *.jsonl；
            # 此处防御性过滤文件名含 system-prompt 的条目）
            return [f for f in files if "system-prompt" not in os.path.basename(f)]
        return [uri]

    def _session_id(self, base: str, fpath: str) -> str:
        """用相对路径（子目录/文件名）区分各轮分析，避免不同 dvs_run 同名文件冲突。"""
        if os.path.isdir(base):
            rel = os.path.relpath(fpath, base).replace("\\", "/")
            if rel.lower().endswith(".jsonl"):
                rel = rel[: -len(".jsonl")]
            return rel
        return os.path.splitext(os.path.basename(fpath))[0]

    def parse(self, trace_source) -> Iterator[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)

        files = self._list_files(uri)

        # 预收集所有 toolCall 的 is_kg 标记（按 id，供 toolResult 继承）
        self._tool_kg = {}
        self._seen_msg_ids = set()
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
                                if tid:
                                    self._tool_kg[tid] = self._is_kg_call(
                                        c.get("name", ""), c.get("arguments", {}))

        for fpath in files:
            sid = self._session_id(uri, fpath)
            with open(fpath, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # 子 session 会完整继承父 session 历史（同 message id replay）；
                    # 同一 trace 内去重，保证每个事件只计一次
                    mid = d.get("id", "") if isinstance(d, dict) else ""
                    if d.get("type") == "message" and mid:
                        if mid in self._seen_msg_ids:
                            continue
                        self._seen_msg_ids.add(mid)
                    for ev in self._obj_to_events(d, trace_id, sid, line_no):
                        yield ev

    def _is_kg_call(self, tool_name: str, args) -> bool:
        """判断是否为知识图谱调用：bash command 含 athena CLI 脚本路径（与 CVulnVerify/Argo 一致）。"""
        if not isinstance(args, dict):
            return False
        cmd = str(args.get("command", "")).lower()
        has_script = "scripts/athena" in cmd or "athena.py" in cmd
        is_view = cmd.strip().startswith(("head", "cat ", "grep ", "ls "))
        return has_script and not is_view

    def _obj_to_events(self, d: dict, trace_id: str, session_id: str, line_no: int) -> list[RawEvent]:
        t = d.get("type", "")
        ts = self._parse_ts(d.get("timestamp", ""))
        # usage 可能只有毫秒时间戳（response 内 timestamp 为 epoch ms 数字）
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

            # toolResult：toolCallId/toolName 在 message 层，content 为 text 片段
            if role == "toolResult":
                tid = msg.get("toolCallId", "")
                tool_name = msg.get("toolName", "")
                is_kg = self._tool_kg.get(tid, False) if tid else False
                texts = [c.get("text", "") for c in content
                         if isinstance(c, dict) and isinstance(c.get("text"), str)]
                evs.append(RawEvent(
                    event_id=f"{eid}-res", trace_id=trace_id, session_id=session_id,
                    event_type="TOOL_RESULT", timestamp_ms=ts,
                    message_id=d.get("id"), part_id=f"{eid}-res",
                    step_no=None, tool_name=tool_name or None,
                    input_json=None, output_json="\n".join(texts) if texts else None,
                    raw_type="toolResult", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-res",
                    parser_version=self.parser_version,
                    is_kg_interaction=is_kg,
                ))
            else:
                for ci, c in enumerate(content):
                    if not isinstance(c, dict):
                        continue
                    ct = c.get("type", "")
                    if ct == "toolCall":
                        tool_name = c.get("name", "")
                        args = c.get("arguments", {})
                        tid = c.get("id", "")
                        is_kg = self._tool_kg.get(tid, False) if tid else self._is_kg_call(tool_name, args)
                        evs.append(RawEvent(
                            event_id=f"{eid}-t{ci}", trace_id=trace_id, session_id=session_id,
                            event_type="TOOL_CALL", timestamp_ms=ts,
                            message_id=d.get("id"), part_id=f"{eid}-t{ci}",
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
                            message_id=d.get("id"), part_id=f"{eid}-x{ci}",
                            step_no=None, tool_name=None, input_json=None, output_json=c.get("text"),
                            raw_type="text", parse_status="OK",
                            source_table="jsonl", source_row_id=f"{eid}-{ci}",
                            parser_version=self.parser_version,
                        ))
                    elif ct == "thinking":
                        evs.append(RawEvent(
                            event_id=f"{eid}-r{ci}", trace_id=trace_id, session_id=session_id,
                            event_type="REASONING", timestamp_ms=ts,
                            message_id=d.get("id"), part_id=f"{eid}-r{ci}",
                            step_no=None, tool_name=None, input_json=None, output_json=c.get("thinking"),
                            raw_type="thinking", parse_status="OK",
                            source_table="jsonl", source_row_id=f"{eid}-{ci}",
                            parser_version=self.parser_version,
                        ))
            usage = msg.get("usage", {})
            if isinstance(usage, dict) and usage:
                evs.append(RawEvent(
                    event_id=f"{eid}-u", trace_id=trace_id, session_id=session_id,
                    event_type="STEP_FINISH", timestamp_ms=ts,
                    message_id=d.get("id"), part_id=f"{eid}-u",
                    step_no=None, tool_name=None,
                    input_json=usage, output_json=None,
                    raw_type="usage", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-u",
                    parser_version=self.parser_version,
                ))

        return evs

    def _parse_ts(self, ts_str) -> int | None:
        # 时间戳可能是 ISO 字符串，也可能是 epoch ms 数字（assistant usage 行）
        if ts_str is None or ts_str == "":
            return None
        if isinstance(ts_str, (int, float)):
            return int(ts_str)
        try:
            dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return None

    @staticmethod
    def _usage_numbers(usage: dict) -> tuple[int, int, int, int]:
        """兼容 input/output/reasoning/cacheRead（本格式）与 input_tokens 等（其他格式）。"""
        def num(*keys) -> int:
            for k in keys:
                v = usage.get(k)
                if isinstance(v, (int, float)):
                    return int(v)
            return 0
        ti = num("input_tokens", "input")
        to = num("output_tokens", "output")
        tr = num("reasoning_tokens", "reasoning")
        tcr = num("cache_read_tokens", "cacheRead", "cache_read")
        return ti, to, tr, tcr

    def load_session(self, trace_source) -> dict:
        """从 JSONL 累计 token + step 数。"""
        uri = trace_source["source_uri"]
        files = self._list_files(uri)

        ti = to = tr = tcr = 0
        n_step_start = n_step_finish = 0
        ts_min = ts_max = None
        seen: set[str] = set()

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
                    # 与 parse() 同样的继承 replay 去重，避免 token 重复累计
                    mid = d.get("id", "") if isinstance(d, dict) else ""
                    if d.get("type") == "message" and mid:
                        if mid in seen:
                            continue
                        seen.add(mid)
                    ts = self._parse_ts(d.get("timestamp", ""))
                    if ts:
                        ts_min = ts if ts_min is None else min(ts_min, ts)
                        ts_max = ts if ts_max is None else max(ts_max, ts)
                    if d.get("type") == "message":
                        msg = d.get("message", {})
                        if isinstance(msg, dict):
                            usage = msg.get("usage", {})
                            if isinstance(usage, dict):
                                ai, ao, ar, ac = self._usage_numbers(usage)
                                ti += ai
                                to += ao
                                tr += ar
                                tcr += ac
                            if msg.get("role") == "assistant":
                                n_step_finish += 1

        sess = {
            "tokens_input": ti, "tokens_output": to,
            "tokens_reasoning": tr, "cache_read_tokens": tcr,
            "time_created": ts_min, "time_updated": ts_max,
            "_step_start_count": n_step_start,
            "_step_finish_count": n_step_finish,
            "model": "auto", "agent": "dataflow-vuln-scan",
        }
        return sess
