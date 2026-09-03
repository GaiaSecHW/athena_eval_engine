"""TuringTraceParser — Turing SQLite → Canonical RawEvent（§8.1 L1 / §8.2 / §8.3）。

读 session 表 + part 表（data JSON）。不解析业务语义（那是 Resolver 的职责）。
Schema Gate：required=[session, message, part], optional=[event]。part 表缺失 → BLOCK。
单条 part.data 损坏 → 该 Event INVALID + Parser Error，继续解析其他。
"""
from __future__ import annotations
import json
import re
import sqlite3
from typing import Iterator
from ..domain.raw_event import RawEvent, EVENT_TYPES
from ..domain.resolvers import TraceParser


# part.type → event_type 映射（§1 R1）
TYPE_MAP = {
    "tool": None,  # 需看 input/output 判 TOOL_CALL / TOOL_RESULT，由 _classify_tool 决定
    "step-start": "STEP_START",
    "step-finish": "STEP_FINISH",
    "text": "TEXT",
    "reasoning": "REASONING",
}


class TuringTraceParser(TraceParser):
    def __init__(self, parser_version: str = "1.0"):
        self.parser_version = parser_version

    def parse(self, trace_source) -> Iterator[RawEvent]:
        """trace_source: dict {trace_id, source_uri(.db path), session_id?}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source["trace_id"]
        session_id = trace_source.get("turing_session_id") or trace_source.get("session_id") or ""

        conn = sqlite3.connect(uri)
        conn.row_factory = sqlite3.Row
        try:
            # Schema Gate
            self._check_schema(conn)
            # Session row（用于 ResourceResolver，此处仅取 session_id）
            # Part rows
            for row in conn.execute("SELECT * FROM part ORDER BY id"):
                yield self._part_to_event(row, trace_id, session_id)
        finally:
            conn.close()

    def _check_schema(self, conn):
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r["name"] for r in cur.fetchall()}
        if "part" not in tables or "session" not in tables:
            raise RuntimeError(f"Schema Gate BLOCK: required tables [session, part] missing, got {tables}")

    def load_session(self, trace_source) -> dict:
        """读 session 表（tokens / model / agent / time_created / time_updated）+ 计 step-start 数（§1 R1）。"""
        uri = trace_source["source_uri"]
        conn = sqlite3.connect(uri); conn.row_factory = sqlite3.Row
        try:
            self._check_schema(conn)
            row = conn.execute("SELECT * FROM session LIMIT 1").fetchone()
            sess = dict(row) if row else {}
            # 统一 Python 遍历 part 计 step-start/step-finish + 累计 tokens（兼容 type 列 / data.type 两种 schema）
            n_start = n_finish = 0
            ti = to = tr = tcr = 0
            for r in conn.execute("SELECT * FROM part"):
                cols = r.keys() if hasattr(r, "keys") else []
                t = str(r["type"]) if "type" in cols else ""
                d = None
                try: d = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
                except: d = None
                if not t and isinstance(d, dict): t = str(d.get("type") or "")
                if t == "step-start": n_start += 1
                elif t == "step-finish":
                    n_finish += 1
                    if isinstance(d, dict):
                        tk = d.get("tokens", {})
                        ti += tk.get("input", 0) or 0
                        to += tk.get("output", 0) or 0
                        tr += tk.get("reasoning", 0) or 0
                        tcr += (tk.get("cache", {}).get("read", 0) if isinstance(tk.get("cache"), dict) else 0) or 0
            sess["_step_start_count"] = n_start
            sess["_step_finish_count"] = n_finish
            # opencode session 行 tokens 常为 0；从 step-finish 累计
            if (not sess.get("tokens_input") and not sess.get("tokens_output")) and (ti or to):
                sess["tokens_input"] = ti; sess["tokens_output"] = to
                sess["tokens_reasoning"] = tr; sess["cache_read_tokens"] = tcr
            return sess
        finally:
            conn.close()

    def _part_to_event(self, row, trace_id, session_id) -> RawEvent:
        # 兼容两种 schema：合成 fixture（part 有 type 列）vs 真实 opencode.db（type 在 data JSON 内）
        cols = row.keys() if hasattr(row, "keys") else []
        raw_type = str(row["type"] or "") if "type" in cols else ""
        part_id = str(row["id"])
        data = {}
        parse_status = "OK"; parse_error = None
        raw_data = row["data"]
        if isinstance(raw_data, str):
            try: data = json.loads(raw_data)
            except json.JSONDecodeError as e: parse_status = "INVALID"; parse_error = f"json_decode: {e}"
        elif isinstance(raw_data, (bytes, bytearray)):
            try: data = json.loads(raw_data.decode("utf-8"))
            except Exception as e: parse_status = "INVALID"; parse_error = f"json_decode_bytes: {e}"
        elif raw_data is not None and isinstance(raw_data, dict):
            data = raw_data

        # 若 part 表无 type 列，type 从 data JSON 取（opencode 格式）
        if not raw_type and isinstance(data, dict):
            raw_type = str(data.get("type") or "")

        event_type = self._classify(raw_type, data)
        # timestamp：opencode reasoning.time.start / part.time_created / data.timestamp_ms
        ts = None
        if isinstance(data, dict):
            t = data.get("time")
            if isinstance(t, dict): ts = t.get("start")
            if ts is None: ts = data.get("timestamp_ms")
        if ts is None and "time_created" in cols: ts = row["time_created"]
        msg_id = str(row["message_id"]) if "message_id" in cols and row["message_id"] else (data.get("message_id") if isinstance(data, dict) else None)
        step_no = data.get("step_no") if isinstance(data, dict) else None
        # tool：opencode 格式 tool 名在 data.tool，input/output 在 data.state.input/output
        tool_name = None; inp = None; outp = None
        if isinstance(data, dict):
            tool_name = data.get("tool") or data.get("tool_name")
            state = data.get("state") if isinstance(data.get("state"), dict) else {}
            inp = state.get("input") if state else data.get("input")
            outp = state.get("output") if state else data.get("output")

        # 知识图谱交互标记：Turing 通过 athena CLI (bash) 调用知识图谱
        # 精确匹配：command 含 athena CLI 脚本路径，且不是查看命令(head/cat/grep/ls)
        is_kg = False
        if tool_name == "bash" and isinstance(inp, dict):
            cmd = str(inp.get("command", ""))
            cmd_l = cmd.lower()
            has_script = "scripts/athena" in cmd_l or "athena.py" in cmd_l
            is_view = cmd_l.strip().startswith(("head", "cat ", "grep ", "ls "))
            if has_script and not is_view:
                is_kg = True
        # Athena RESULT：只有 bash 工具的 output 含"知识库"才算（skill 加载的 skill_content 不算）
        if not is_kg and tool_name == "bash" and outp and isinstance(outp, str) and "知识库" in outp:
            is_kg = True

        return RawEvent(
            event_id=f"evt-{trace_id}-{part_id}",
            trace_id=trace_id, session_id=session_id, event_type=event_type,
            timestamp_ms=int(ts) if ts is not None else None,
            message_id=str(msg_id) if msg_id else None, part_id=part_id,
            step_no=int(step_no) if step_no is not None else None,
            tool_name=tool_name, input_json=inp, output_json=outp,
            raw_type=raw_type, parse_status=parse_status, parse_error=parse_error,
            source_table="part", source_row_id=part_id, parser_version=self.parser_version,
            is_kg_interaction=is_kg,
        )

    def _classify(self, raw_type: str, data: dict) -> str:
        """part.type → event_type。opencode tool part（含 state）= 单个 TOOL_CALL 事件（call+result 合一）。"""
        if raw_type == "tool":
            # opencode：一个 tool part 含 state{input,output}（call+result 合一）→ TOOL_CALL
            # 合成 fixture：有 input 无 output → TOOL_CALL；有 output 无 input → TOOL_RESULT
            if isinstance(data, dict) and isinstance(data.get("state"), dict):
                return "TOOL_CALL"
            if isinstance(data, dict) and data.get("output") is not None and data.get("input") is None:
                return "TOOL_RESULT"
            return "TOOL_CALL"
        m = {"step-start": "STEP_START", "step-finish": "STEP_FINISH",
             "text": "TEXT", "reasoning": "REASONING"}
        if raw_type in m: return m[raw_type]
        if raw_type == "session-start": return "SESSION_START"
        if raw_type == "session-end": return "SESSION_END"
        return "UNKNOWN"
