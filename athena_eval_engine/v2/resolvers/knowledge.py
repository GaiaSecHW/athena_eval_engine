"""KnowledgeResolver — 从 events 提取知识交互与记忆交互（§8.7/§8.8）。

平台无关：只依赖 RawEvent 的 is_kg_interaction / is_memory_interaction flag，
不检查平台特定工具名。config 驱动 access_rules / delivery_rules（机械规则配置化）。

从老代码拷贝，去掉对 parse_utils 的依赖，自带需要的工具函数。
"""
from __future__ import annotations

import json
import re

from ..core.raw_event import RawEvent
from ..core.task_run import TaskRun
from ..core.facts import KnowledgeInteractionFact, Evidence
from ..core.enums import Condition


def _ev(e: RawEvent, field_path: str | None = None) -> Evidence:
    """从 RawEvent 构建 Evidence。"""
    return Evidence(
        trace_id=e.trace_id, session_id=e.session_id, message_id=e.message_id,
        part_id=e.part_id, tool_name=e.tool_name, event_timestamp=e.timestamp_ms,
        field_path=field_path,
    )


def _path_of(e: RawEvent) -> str:
    """从 input_json 提取路径（read/bash 的 file_path / command）。"""
    d = e.input_json or {}
    return str(d.get("file_path") or d.get("path") or d.get("command") or "")


class KnowledgeResolver:
    """从 events 提取知识交互与记忆交互。

    知识图谱交互由 parser 标记（is_kg_interaction），resolver 不硬编码工具名。
    记忆交互由 parser 标记（is_memory_interaction / is_memory_write）。

    config 结构（可选，向后兼容）：
        access_rules:
            kg_tools: list[str]      # 知识图谱工具名（向后兼容）
            skill_names: list[str]   # skill 工具名
            text_patterns: list[str] # prompt 注入文本模式
            path_patterns: list[str] # 路径模式
            command_patterns: list[str]  # 命令正则
        delivery_rules:
            reject_patterns: list[str]   # 不算成功交付的输出模式
            kg_success_patterns: list[str]  # 成功标记
    """

    def __init__(self, config: dict | None = None):
        config = config or {}
        self.access_rules = config.get("access_rules", {})
        self.delivery_rules = config.get("delivery_rules", {})
        self._reject_re = [re.compile(p) for p in self.delivery_rules.get("reject_patterns", [])]
        self._kg_success = self.delivery_rules.get(
            "kg_success_patterns", ["knowledge persisted", "Success:", '"result"']
        )
        self._kg_tools = set(self.access_rules.get("kg_tools", []))
        self._text_patterns = self.access_rules.get("text_patterns", [])

    def resolve(self, task_run: TaskRun, events: list[RawEvent]) -> KnowledgeInteractionFact:
        access_evs: list[Evidence] = []
        read_evs: list[Evidence] = []
        delivery_ok = False
        mount_status = "UNKNOWN"
        text_access = False
        interactions: list[dict] = []       # 原始介入事件
        memory_interactions: list[dict] = []  # 记忆交互事件（只读）
        mem_call_ids: set[str] = set()      # 记忆 CALL 的 call_id（用于 RESULT 精确配对）
        mem_success_count = 0

        for idx, e in enumerate(events):
            # text part 含 Reference/Athena 指引 = prompt 注入了知识库
            if e.event_type == "TEXT" and self._text_patterns:
                raw = ""
                if isinstance(e.input_json, str):
                    raw = e.input_json
                elif e.output_json is not None:
                    raw = str(e.output_json)
                if any(p in raw for p in self._text_patterns):
                    text_access = True
                    access_evs.append(_ev(e, "$.text"))
                continue

            if not (e.is_tool_call() or e.is_tool_result()):
                continue

            path = _path_of(e)
            tool = e.tool_name or ""

            # 知识图谱交互由 parser 标记（is_kg_interaction），resolver 不硬编码工具名
            is_kg = e.is_kg_interaction

            # 记忆交互由 parser 标记（is_memory_interaction=读取/检索，is_memory_write=写入）
            is_mem = e.is_memory_interaction

            if is_mem and e.is_tool_call():
                cmd = path if path else (
                    e.input_json if isinstance(e.input_json, str)
                    else json.dumps(e.input_json, ensure_ascii=False) if e.input_json
                    else ""
                )
                memory_interactions.append({
                    "tool": e.tool_name or "", "type": "CALL",
                    "command": cmd, "output": "",
                    "timestamp": e.timestamp_ms, "session_id": e.session_id,
                })
                if e.call_id:
                    mem_call_ids.add(e.call_id)

            # 记忆 RESULT：与 CALL 精确配对（通过 call_id）
            # TOOL_RESULT 不继承 is_memory_interaction 标记（避免重复统计），
            # 通过 call_id 在 mem_call_ids 中匹配识别记忆 RESULT。
            # Turing trace 的 TOOL_CALL 含 output（call+result 合一），也要检查。
            is_mem_result = (
                (e.is_tool_result() and e.call_id and e.call_id in mem_call_ids) or
                (is_mem and e.is_tool_call() and e.output_json is not None)
            )
            if is_mem_result:
                out = e.output_json
                out_str = out if isinstance(out, str) else (
                    json.dumps(out, ensure_ascii=False) if out is not None else ""
                )
                memory_interactions.append({
                    "tool": e.tool_name or "", "type": "RESULT",
                    "command": "", "output": out_str or "",
                    "timestamp": e.timestamp_ms, "session_id": e.session_id,
                })
                # 有非空输出 = 成功读取
                if out_str and out_str.strip() not in ("", "[]", "{}", "null"):
                    mem_success_count += 1

            if is_kg and e.is_tool_call():
                access_evs.append(_ev(e, "$.tool_name|path"))
                # 捕获知识介入原始事件（TOOL_CALL — 命令/输入 + 后续行为窗口）
                cmd = path if path else (
                    e.input_json if isinstance(e.input_json, str)
                    else json.dumps(e.input_json, ensure_ascii=False) if e.input_json
                    else ""
                )
                follow_up = self._follow_up_summary(events, idx)
                interactions.append({
                    "tool": tool, "type": "CALL",
                    "command": cmd, "output": "",
                    "timestamp": e.timestamp_ms,
                    "follow_up": follow_up, "session_id": e.session_id,
                })

            # Delivery：有 output 的事件都检查（TOOL_RESULT 或 TOOL_CALL 带 output）
            if e.is_tool_result() or (e.is_tool_call() and e.output_json is not None):
                out = e.output_json
                out_str = out if isinstance(out, str) else (
                    json.dumps(out, ensure_ascii=False) if out is not None else ""
                )
                has_success = any(s in out_str for s in self._kg_success) if out_str else False
                if "NFS symlink set" in out_str:
                    mount_status = "SUCCESS"
                elif "No wiki mount" in out_str:
                    mount_status = "FAILED"
                # 只对知识图谱交互计 delivery，reject 匹配到的不算成功交付
                if is_kg and out_str and not any(r.search(out_str.strip()) for r in self._reject_re):
                    _err_like = out_str.strip().lower().startswith((
                        "error", "execution error", "failed", "exception",
                    ))
                    if has_success or (
                        out_str.strip() not in ("", "[]", "{}") and not _err_like
                    ):
                        read_evs.append(_ev(e, "$.output"))
                        delivery_ok = True
                # 捕获知识图谱 RESULT
                if is_kg:
                    if "submit_knowledge" in tool:
                        continue
                    interactions.append({
                        "tool": tool, "type": "RESULT",
                        "command": "", "output": out_str or "",
                        "timestamp": e.timestamp_ms, "session_id": e.session_id,
                    })

        # prompt 注入也算 access
        has_access = bool(access_evs) or text_access
        mem_call_count = len([m for m in memory_interactions if m.get("type") == "CALL"])

        return KnowledgeInteractionFact(
            knowledge_fact_id=f"kif-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            access=bool(access_evs), delivery=delivery_ok, mount_status=mount_status,
            access_event_count=len(access_evs), read_event_count=len(read_evs),
            successful_read_count=len(read_evs) if delivery_ok else 0,
            interactions=interactions,
            evidence=access_evs + read_evs,
            memory_access=mem_call_count > 0,
            memory_access_event_count=mem_call_count,
            memory_successful_read_count=mem_success_count,
            memory_interactions=memory_interactions,
        )

    def _follow_up_summary(self, events: list[RawEvent], start: int, n: int = 3) -> list[dict]:
        """取后续 N 个事件的摘要（tool_name + command/output）。n=3 控制体积。"""
        out = []
        for j in range(start + 1, min(start + 1 + n, len(events))):
            e = events[j]
            if not (e.is_tool_call() or e.is_tool_result()):
                continue
            path = _path_of(e)
            tool = e.tool_name or ""
            cmd = path or ""
            out_str = ""
            if e.output_json is not None:
                out_str = (
                    e.output_json if isinstance(e.output_json, str)
                    else json.dumps(e.output_json, ensure_ascii=False)
                )
            out.append({
                "tool": tool,
                "type": "CALL" if e.is_tool_call() else "RESULT",
                "command": cmd, "output": out_str,
            })
        return out
