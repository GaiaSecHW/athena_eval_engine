"""Canonical Raw Event（§8.2）— Parser 输出，Resolver 输入。

Metric Engine 永不直接读 SQLite。TuringTraceParser 把 SQLite part 行解析为 RawEvent。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

# §8.2 event_type 枚举
EVENT_TYPES = {
    "SESSION_START", "SESSION_END", "MESSAGE", "TEXT", "REASONING",
    "TOOL_CALL", "TOOL_RESULT", "STEP_START", "STEP_FINISH",
    "SYSTEM_EVENT", "UNKNOWN",
}


@dataclass
class RawEvent:
    event_id: str
    trace_id: str
    session_id: str
    event_type: str            # EVENT_TYPES 之一；未识别 → UNKNOWN
    timestamp_ms: int | None
    message_id: str | None
    part_id: str | None
    step_no: int | None
    tool_name: str | None
    input_json: dict | None
    output_json: dict | None
    raw_type: str              # 原始 part.type（如 'tool' / 'step-start' / 'text'）
    parse_status: str = "OK"  # OK / PARTIAL / INVALID
    parse_error: str | None = None
    source_table: str = "part"  # 'part' / 'session' / 'event'
    source_row_id: str = ""
    parser_version: str = "1.0"
    is_kg_interaction: bool = False  # parser 标记：是否为知识图谱交互（Athena 检索/知识查询）

    def is_tool_call(self) -> bool:
        return self.event_type == "TOOL_CALL"

    def is_tool_result(self) -> bool:
        return self.event_type == "TOOL_RESULT"
