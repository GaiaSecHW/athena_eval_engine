"""ArgoParser — Claude Code JSONL session 日志 → Canonical RawEvent。

从老代码 ``workers/argo_trace_parser.py`` 拷贝核心逻辑，适配 v2 架构：
- 继承 ``v2.parsers.base.BaseParser``（而非老代码的 ``TraceParser``）
- import v2 内部模块（``core.raw_event``、``infra.agent_db``）
- 工具函数从本目录 ``.utils`` 导入
- 新增 ``label_session_phases()`` 方法实现 session 业务阶段标注

Trace 路径：/data/files/{project_id}/tasks/{task_id}/session/argo/

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

from ..base import BaseParser
from ...core.raw_event import RawEvent, detect_memory_flags, usage_numbers
from ...infra.agent_db import AgentDBManager
from ...infra import llm as _llm_mod
from .utils import (
    attach_event_indices,
    _extract_json_objects_from_text,
    parse_json_lenient,
    extract_json_payloads,
)

import logging
_log = logging.getLogger(__name__)


# Claude Code 工具名 → 小写
_TOOL_MAP = {
    "Bash": "bash", "Read": "read", "Grep": "grep", "Glob": "glob",
    "Write": "write", "Edit": "edit", "Task": "task", "Skill": "skill",
}


class ArgoParser(BaseParser):
    """解析 Argo（Claude Code CLI）JSONL session 日志。"""

    def __init__(self, parser_version: str = "argo-1.0", llm_module=None):
        self.parser_version = parser_version
        self._llm = llm_module  # 可选的自定义 LLM 模块；默认用 v2 infra.llm 模块函数
        self._session_parents: dict[str, str] = {}  # child_sid -> parent_sid（从 JSONL sessionId 字段提取）

    # ------------------------------------------------------------------
    # BaseParser 抽象属性
    # ------------------------------------------------------------------

    @property
    def agent_type(self) -> str:
        return "argo"

    # ------------------------------------------------------------------
    # JSONL 文件解析
    # ------------------------------------------------------------------

    @staticmethod
    def _is_finding_tool(tool_name: str) -> bool:
        """Argo 平台 finding 提交工具。"""
        return tool_name in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding")

    @staticmethod
    def _resolve_jsonl_files(uri: str) -> list[str]:
        """解析 .jsonl 文件列表。

        source_uri 可能指向 session/ 目录（标准布局，jsonl 在 argo/ 子目录下），
        也可能直接指向 session/argo/ 目录（jsonl 直接在此目录下）。
        k8s 拷贝后 source_uri 指向拷贝目录，jsonl 直接在顶层。
        """
        if not os.path.isdir(uri):
            return [uri]
        # 优先在 uri/argo/ 下找（标准布局：uri=session/）
        argo_dir = os.path.join(uri, "argo")
        if os.path.isdir(argo_dir):
            return sorted(glob.glob(os.path.join(argo_dir, "**", "*.jsonl"), recursive=True))
        # uri 本身就是 argo/ 目录或拷贝目录，jsonl 直接在顶层
        files = sorted(glob.glob(os.path.join(uri, "**", "*.jsonl"), recursive=True))
        return files

    # ------------------------------------------------------------------
    # parse()
    # ------------------------------------------------------------------

    def parse(self, trace_source) -> list[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)
        session_id = trace_source.get("turing_session_id", "")

        # 如果是目录，读所有 .jsonl（含 argo/ 子目录）；如果是单文件，读它
        files = self._resolve_jsonl_files(uri)

        # 先收集所有 tool_use 的 is_kg/is_mem/tool_name 标记（按 tool_use_id），用于 RESULT 继承
        tool_use_kg = {}  # tool_use_id -> is_kg
        tool_use_mem = {}  # tool_use_id -> (is_mem, is_mem_w)
        tool_use_names = {}  # tool_use_id -> tool_name
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
                                is_mem, is_mem_w = detect_memory_flags(tool_lower, c.get("input"))
                                if tid:
                                    tool_use_kg[tid] = is_kg
                                    tool_use_mem[tid] = (is_mem, is_mem_w)
                                    tool_use_names[tid] = tool_lower

        events: list[RawEvent] = []
        for fpath in files:
            sid = os.path.splitext(os.path.basename(fpath))[0]
            _parent_sid = None
            with open(fpath, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # 从 JSONL 元数据推断 session 父子关系
                    # 子 session 的 sessionId 字段 = 父 session ID（与文件名 sid 不同）
                    # 根 session 的 sessionId = 自己的 ID（与文件名相同）
                    if _parent_sid is None:
                        _jsonl_sid = d.get("sessionId", "")
                        if _jsonl_sid and _jsonl_sid != sid:
                            _parent_sid = _jsonl_sid
                    for ev in self._obj_to_events(d, trace_id, sid, line_no, tool_use_kg, tool_use_mem, tool_use_names):
                        events.append(ev)
            if _parent_sid:
                self._session_parents[sid] = _parent_sid

        return events

    def _obj_to_events(self, d: dict, trace_id: str, session_id: str, line_no: int, tool_use_kg: dict = None, tool_use_mem: dict = None, tool_use_names: dict = None) -> list[RawEvent]:
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
                    # 记忆交互标记
                    is_mem, is_mem_w = detect_memory_flags(tool_lower, inp)
                    is_finding = self._is_finding_tool(tool_lower)
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
                        is_finding_submission=is_finding,
                        is_memory_interaction=is_mem,
                        is_memory_write=is_mem_w,
                        call_id=tid,
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
                tn = tool_use_names.get(tid, "") if (tool_use_names and tid) else ""
                # 从预收集标记继承 is_kg / is_mem（RESULT 事件需要这些标记才能被 resolver 计为 delivery）
                is_kg = tool_use_kg.get(tid, False) if (tool_use_kg and tid) else False
                mem_flags = tool_use_mem.get(tid, (False, False)) if (tool_use_mem and tid) else (False, False)
                evs.append(RawEvent(
                    event_id=f"{eid}-res", trace_id=trace_id, session_id=session_id,
                    event_type="TOOL_RESULT", timestamp_ms=ts,
                    message_id=d.get("uuid"), part_id=f"{eid}-res",
                    step_no=None, tool_name=tn, input_json=None, output_json=out_str,
                    raw_type="toolUseResult", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-res",
                    parser_version=self.parser_version,
                    call_id=tid,
                    is_kg_interaction=is_kg,
                    is_memory_interaction=mem_flags[0],
                    is_memory_write=mem_flags[1],
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

    # ------------------------------------------------------------------
    # load_session()
    # ------------------------------------------------------------------

    def load_session(self, trace_source) -> dict:
        """从 JSONL 累计 token + step 数（替代 SQLite session 表）。"""
        uri = trace_source["source_uri"]
        files = self._resolve_jsonl_files(uri)

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
                                ai, ao, ar, ac = usage_numbers(usage)
                                ti += ai; to += ao; tr += ar; tcr += ac
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

    # ------------------------------------------------------------------
    # build_session_graph()
    # ------------------------------------------------------------------

    def build_session_graph(self, events: list[RawEvent]) -> dict:
        """构建 session 关系图（Argo 特有逻辑）。

        Argo (Claude Code) 的 session 结构——分段挖掘：
        - 根 session：漏洞挖掘主 session，spawn 多个子 agent session 按模块/功能分段
        - 子 agent session：在 subagents/ 子目录下，JSONL 的 sessionId 字段 = 父 session ID
        - 根 session 的 sessionId = 自己的 ID（与文件名相同）

        Session 父子关系来源（优先级从高到低）：
        1. JSONL 的 sessionId 字段：子 session 的 sessionId != 文件名 → sessionId 是父
        2. Fact 引用链：session B 引用 fact f → B 依赖创建 f 的 session A → A 是 B 的父
           - verified_finding → verify session：通过 original_finding_id 链可靠匹配
           - finding → investigate session：通过 description 中的 fact 引用 + 时间排序间接推断
           - module → 无创建 session（root）
        """
        from collections import defaultdict as _dd
        import time as _time
        graph = {
            'sessions': {},
            'file_to_sessions': _dd(set),
            'fact_to_sessions': _dd(set),
            'fact_details': {},  # fact_id -> {type, description, original_finding_id}
            'edges': _dd(set),
            'parent_map': {},
        }

        _n = len(events)
        _start = _time.time()
        for idx, ev in enumerate(events):
            if _n > 10000 and idx > 0 and idx % 50000 == 0:
                _log.debug("Argo build_session_graph %d/%d events elapsed=%ds sessions=%d",
                           idx, _n, int(_time.time() - _start), len(graph['sessions']))
            sid = ev.session_id
            if not sid:
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {
                    'files': set(), 'facts': set(), 'athena_qs': [],
                    'session_type': None,  # 'investigate' / 'verify'
                    'task_type': None,     # 'investigate' / 'verify' / 'reason'
                    'finding_keys': set(),
                    'time_created': None,
                    'time_updated': None,
                }
            sg = graph['sessions'][sid]
            # 追踪 session 时间范围（用于 fact→creator 时间排序）
            if ev.timestamp_ms:
                ts = ev.timestamp_ms
                if sg['time_created'] is None or ts < sg['time_created']:
                    sg['time_created'] = ts
                if sg['time_updated'] is None or ts > sg['time_updated']:
                    sg['time_updated'] = ts

            # SYSTEM_EVENT: queue-operation prompt，含任务类型和 fact 引用
            if ev.event_type == "SYSTEM_EVENT" and ev.output_json:
                content = str(ev.output_json)
                # 提取任务类型
                if sg['task_type'] is None:
                    if content.startswith("# Investigate") or "# Investigate" in content[:50]:
                        sg['task_type'] = 'investigate'
                    elif content.startswith("# Verify") or "# Verify" in content[:50]:
                        sg['task_type'] = 'verify'
                    elif content.startswith("# Reason") or "# Reason" in content[:50]:
                        sg['task_type'] = 'reason'
                # verify session 标记
                if "## Finding to Verify" in content or "# Verify:" in content:
                    sg['session_type'] = 'verify'
                # fact 引用（prompt 文本中引用的 fact ID）
                # 用 negative lookbehind 避免 hex 字符串（如项目 ID 中的 f58851）误匹配
                for fid in re.findall(r'(?<![\da-zA-Z])(f\d{3,5})(?!\d)', content):
                    if fid != 'f001':
                        sg['facts'].add(fid)
                        graph['fact_to_sessions'][fid].add(sid)
                continue

            # TEXT 事件: investigate finding 提交 + verify verdict 提交
            if ev.event_type == "TEXT" and ev.output_json:
                txt = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
                if '"accepted"' in txt:
                    for payload in self._extract_accepted_payloads(txt, use_llm=False):
                        data = payload.get("data", payload)
                        if not isinstance(data, dict):
                            continue
                        if "findings" in data:
                            sg['session_type'] = 'investigate'
                            if sg['task_type'] is None:
                                sg['task_type'] = 'investigate'
                            for f in data.get("findings", []):
                                if not isinstance(f, dict):
                                    continue
                                key = self._finding_key(f)
                                if key and key != "(,,)":
                                    sg['finding_keys'].add(key)
                        # verify verdict: 存 verdict description 用于后续匹配 verified_finding
                        if "verdict" in data:
                            sg['session_type'] = 'verify'
                            verdict_desc = data.get("description", "")
                            if verdict_desc:
                                sg['verdict_desc'] = verdict_desc

            if not ev.is_tool_call():
                # TOOL_RESULT: 解析 argo.memory get 结果
                if ev.event_type == "TOOL_RESULT" and ev.output_json:
                    result = str(ev.output_json)
                    if 'id: f' in result or '- id: f' in result:
                        parsed = self._parse_memory_get_result(result)
                        for fid, details in parsed.items():
                            if fid not in graph['fact_details']:
                                graph['fact_details'][fid] = details
                continue

            tool = ev.tool_name or ""
            inp = ev.input_json or {}

            if tool == "bash":
                cmd = str(inp.get("command", ""))
                # argo.memory get fXXX → fact 关联
                if "argo.memory" in cmd and " get" in cmd:
                    fact_ids = re.findall(r'(?<![\da-zA-Z])(f\d{3,5})(?!\d)', cmd)
                    fact_ids = [f for f in fact_ids if f != 'f001']
                    for fid in fact_ids:
                        sg['facts'].add(fid)
                        graph['fact_to_sessions'][fid].add(sid)
                # athena 查询
                if 'athena' in cmd.lower() and 'ask' in cmd:
                    m = re.search(r'ask\s+"([^"]{0,50})', cmd)
                    if m:
                        sg['athena_qs'].append(m.group(1))
                # 文件引用（匹配任意扩展名）
                for fm in re.findall(r'[\w\-./]+\.[a-zA-Z]{1,6}', cmd):
                    basename = os.path.basename(fm)
                    if basename and len(basename) < 80 and not basename.startswith('.'):
                        sg['files'].add(basename)
                        graph['file_to_sessions'][basename].add(sid)

            elif tool == "read":
                fp = str(inp.get("file_path", ""))
                if fp:
                    basename = os.path.basename(fp)
                    if basename and len(basename) < 80:
                        sg['files'].add(basename)
                        graph['file_to_sessions'][basename].add(sid)

        # 构建 fact_to_creator 映射
        fact_to_creator = self._build_fact_to_creator(graph)

        # 构建边：从 JSONL session 数据推断真实调用关系
        # 来源 1: sessionId 字段（子 agent → 父 session）
        for child_sid, parent_sid in self._session_parents.items():
            if child_sid not in graph['parent_map']:
                graph['parent_map'][child_sid] = parent_sid
            graph['edges'][child_sid].add(parent_sid)
            graph['edges'][parent_sid].add(child_sid)

        # 来源 2: Fact 引用链（session B 引用 fact f → B 依赖创建 f 的 session A）
        # 时间约束：creator 必须在 child 之前完成，避免循环依赖
        for sid, sg_data in graph['sessions'].items():
            if not sg_data.get('facts'):
                continue
            child_start = sg_data.get('time_created') or 0
            best_parent = None
            best_parent_time = 0
            for fid in sg_data['facts']:
                creator = fact_to_creator.get(fid)
                if not creator or creator == sid:
                    continue
                creator_sg = graph['sessions'].get(creator)
                if not creator_sg:
                    continue
                # creator 必须在 child 开始前完成（避免循环依赖）
                creator_end = creator_sg.get('time_updated') or 0
                if creator_end == 0 or creator_end >= child_start:
                    continue
                # 选完成时间最接近 child 开始的 creator（最直接的依赖）
                if creator_end > best_parent_time:
                    best_parent = creator
                    best_parent_time = creator_end
            if best_parent and sid not in graph['parent_map']:
                graph['parent_map'][sid] = best_parent
                graph['edges'][sid].add(best_parent)
                graph['edges'][best_parent].add(sid)

        return graph

    # ------------------------------------------------------------------
    # session graph 内部工具方法
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_memory_get_result(result: str) -> dict:
        """解析 argo.memory get 的 TOOL_RESULT（YAML 格式）。

        格式：
          facts:
          - id: f004
            type: module
            description: 'Module ...'
            metadata:
              path: services/...
            created_at: '2026-09-12T11:25:34Z'
          - id: f031
            type: verified_finding
            description: 已确认：...
            metadata:
              verdict: CONFIRMED
              original_finding_id: f011

        或 results: 前缀（search 命令）。

        返回 {fact_id: {type, description, original_finding_id}}。
        """
        parsed = {}
        # 分割 fact block：每个 block 以 "- id: fXXX" 开头
        blocks = re.split(r'\n- id: ', result)
        for block in blocks[1:]:  # 跳过前导文本
            fid_m = re.match(r'(f\d+)', block)
            if not fid_m:
                continue
            fid = fid_m.group(1)
            ftype_m = re.search(r'type:\s*(\w+)', block)
            ftype = ftype_m.group(1) if ftype_m else 'unknown'
            # description: 取到下一个 2-space 缩进 key 为止
            desc_m = re.search(
                r'description:\s*(.+?)(?=\n  \w+:|\n- id:|\nmetadata:|\ncreated_at:|\nsuggestions:|\ntotal:|\nshown:|\ntruncated:|\Z)',
                block, re.DOTALL,
            )
            desc = desc_m.group(1).strip() if desc_m else ''
            # 去除 YAML 引号
            if desc.startswith("'") and desc.endswith("'"):
                desc = desc[1:-1].replace("''", "'")
            elif desc.startswith('"') and desc.endswith('"'):
                desc = desc[1:-1]
            # 折叠多行 description 为单行
            desc = re.sub(r'\s+', ' ', desc).strip()
            # original_finding_id（verified_finding 专有）
            orig_m = re.search(r'original_finding_id:\s*(f\d+)', block)
            orig_fid = orig_m.group(1) if orig_m else None
            parsed[fid] = {
                'type': ftype,
                'description': desc,
                'original_finding_id': orig_fid,
            }
        return parsed

    def _build_fact_to_creator(self, graph: dict) -> dict:
        """构建 fact_id → creating_session_id 映射。

        策略：
        A. verified_finding → verify session（可靠）
           通过 original_finding_id 找到原始 finding，查 fact_to_sessions 找 verify session。
        B. finding → investigate session（间接推断）
           从 description 中提取 fact ID 引用，查 fact_to_sessions 找 investigate session。
        C. module → 无创建 session（dispatcher 创建，不是 session 输出）
        E. verified_finding → verify session（语义匹配）
           当策略 A 失败时，用 verified_finding description 与 verify session 的 verdict_desc 前缀匹配。
        """
        fact_to_creator: dict[str, str] = {}
        fact_details = graph.get('fact_details', {})
        fact_to_sessions = graph.get('fact_to_sessions', {})
        sessions = graph.get('sessions', {})

        for fid, details in fact_details.items():
            ftype = details.get('type', '')
            if ftype == 'module':
                continue  # module fact 由 dispatcher 创建，不是 session 输出

            if ftype == 'verified_finding':
                # 策略 A: 通过 original_finding_id 找创建该 verified_finding 的 verify session
                orig_fid = details.get('original_finding_id')
                if not orig_fid:
                    # original_finding_id 不在 trace YAML 中（DB-only metadata）
                    # Argo 复用原始 finding ID 作为 verified_finding ID，用 fact 自身 ID 查找
                    orig_fid = fid
                # 查引用原始 finding 的 session，筛选 verify 类型
                ref_sessions = fact_to_sessions.get(orig_fid, set())
                for ref_sid in ref_sessions:
                    sg = sessions.get(ref_sid, {})
                    if sg.get('task_type') == 'verify' or sg.get('session_type') == 'verify':
                        fact_to_creator[fid] = ref_sid
                        break
                # 策略 E: 通过 verdict_desc 匹配 verified_finding description
                # verify session 的 verdict 输出包含 description，与 verified_finding 的 description 一致
                if fid not in fact_to_creator:
                    vf_desc = details.get('description', '')[:100]
                    if vf_desc:
                        for sid_key, sg_data in sessions.items():
                            if sg_data.get('task_type') != 'verify' and sg_data.get('session_type') != 'verify':
                                continue
                            vd = sg_data.get('verdict_desc', '')[:100]
                            if vd and vf_desc == vd:
                                fact_to_creator[fid] = sid_key
                                break

            elif ftype == 'finding':
                # 策略 B: 从 description 中提取 fact ID 引用，找 investigate session
                desc = details.get('description', '')
                # 提取 description 中的 fact ID（如 "per prior finding f095"）
                ref_fids = re.findall(r'(?<![\da-zA-Z])(f\d{3,5})(?!\d)', desc)
                ref_fids = [f for f in ref_fids if f != 'f001' and f != fid]
                if ref_fids:
                    # 找引用了这些 fact 的 investigate session
                    candidates: set[str] = set()
                    for ref_fid in ref_fids:
                        for ref_sid in fact_to_sessions.get(ref_fid, set()):
                            sg = sessions.get(ref_sid, {})
                            if sg.get('task_type') == 'investigate' or sg.get('session_type') == 'investigate':
                                candidates.add(ref_sid)
                    # 取时间最早的 investigate session（最可能是创建者）
                    if candidates:
                        best = min(
                            candidates,
                            key=lambda s: sessions[s].get('time_updated') or 0,
                        )
                        fact_to_creator[fid] = best

            elif ftype == 'fact':
                # 普通观察 fact：同样从 description 中提取引用
                desc = details.get('description', '')
                ref_fids = re.findall(r'(?<![\da-zA-Z])(f\d{3,5})(?!\d)', desc)
                ref_fids = [f for f in ref_fids if f != 'f001' and f != fid]
                if ref_fids:
                    candidates: set[str] = set()
                    for ref_fid in ref_fids:
                        for ref_sid in fact_to_sessions.get(ref_fid, set()):
                            candidates.add(ref_sid)
                    if candidates:
                        best = min(
                            candidates,
                            key=lambda s: sessions[s].get('time_updated') or 0,
                        )
                        fact_to_creator[fid] = best

        return fact_to_creator

    # ------------------------------------------------------------------
    # extract_findings()
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_key(f: dict) -> str:
        """从 (cwe, file, line_range) 生成唯一 key，用于分组同一 finding 的多次验证。

        line_range 归一化：如果是嵌套列表 [[a,b],[c,d]]，取第一个子范围。
        """
        cwe = str(f.get("cwe", ""))
        file_val = str(f.get("file", ""))
        lr = f.get("line_range", "")
        if isinstance(lr, list):
            if lr and isinstance(lr[0], list):
                # 嵌套列表 [[a,b],[c,d]] → 取第一个子范围
                lr = f"{lr[0][0]}-{lr[0][-1]}" if lr[0] else ""
            elif lr:
                lr = f"{lr[0]}-{lr[-1]}"
            else:
                lr = ""
        else:
            lr = str(lr)
        return f"({cwe},{file_val},{lr})"

    @staticmethod
    def _extract_file(value) -> str:
        """从 source/sink 值提取文件路径（可能是 dict 或 str）。"""
        if isinstance(value, dict):
            return str(value.get("file", ""))
        return str(value) if value else ""

    @staticmethod
    def _normalize_line_range(lr) -> tuple[int, int]:
        """将 line_range 归一化为 (start, end) 元组。

        接受: "351-431", [351, 431], [[351, 431]], None → (0, 0)
        """
        if not lr:
            return (0, 0)
        if isinstance(lr, str):
            parts = lr.replace(" ", "").split("-")
            try:
                return (int(parts[0]), int(parts[-1]))
            except (ValueError, IndexError):
                return (0, 0)
        if isinstance(lr, list):
            if lr and isinstance(lr[0], list):
                flat = [x for sub in lr for x in (sub if isinstance(sub, list) else [sub])]
            else:
                flat = lr
            try:
                return (int(flat[0]), int(flat[-1]))
            except (ValueError, IndexError):
                return (0, 0)
        return (0, 0)

    @staticmethod
    def _lr_distance(a: tuple[int, int], b: tuple[int, int]) -> int:
        """两个 line_range 的距离：重叠则为 0，否则为间距。"""
        if a == (0, 0) or b == (0, 0):
            return 0  # 缺失 line_range 时不做距离惩罚
        if a[1] < b[0]:
            return b[0] - a[1]
        if b[1] < a[0]:
            return a[0] - b[1]
        return 0  # 重叠

    def _extract_accepted_payloads(self, text: str, *, use_llm: bool = True) -> list[dict]:
        """从文本中提取 JSON payload。

        nazhua 平台的 validate_verify_payload 不要求 accepted: true，
        没有 accepted 字段时直接用 payload 本身作为 data。
        因此本方法只过滤 accepted:false，其余全部保留（含裸 payload）。

        三种策略：
        1. ```json 代码块中的 JSON 对象（raw_decode + 容错补全）
        2. 文本中直接出现的 JSON 对象（花括号匹配 + 容错补全），
           搜索关键词：accepted, verdict, findings
        3. LLM 兜底：前两种策略都无法解析时，用 LLM 从文本中提取 JSON
           （use_llm=False 时跳过，用于 build_session_graph 等纯 CPU 场景）
        """
        results: list[dict] = []
        seen: set[str] = set()

        def _add(obj: dict) -> None:
            if obj.get("accepted") is False:
                return
            sig = json.dumps(obj, sort_keys=True, ensure_ascii=False)
            if sig not in seen:
                seen.add(sig)
                results.append(obj)

        # 策略 1: ```json 代码块
        for obj in _extract_json_objects_from_text(text):
            _add(obj)
        # 策略 1 补充: raw_decode 失败时，手动提取 ```json 块并容错解析
        marker = '```json'
        search_start = 0
        while True:
            idx = text.find(marker, search_start)
            if idx == -1:
                break
            brace_idx = text.find('{', idx + len(marker))
            if brace_idx == -1:
                search_start = idx + len(marker)
                continue
            close_idx = text.find('```', brace_idx)
            if close_idx < 0:
                close_idx = len(text)
            json_str = text[brace_idx:close_idx]
            obj = parse_json_lenient(json_str)
            if obj:
                _add(obj)
            search_start = close_idx + 3
        if results:
            return results

        # 策略 2: 关键词+花括号匹配（用共享函数）
        for obj in extract_json_payloads(text, keywords=['"verdict"', '"findings"']):
            _add(obj)

        # 策略 3: LLM 兜底 — 前两种策略都无法解析时，用 LLM 从文本中提取 JSON
        # 文本中无 { 则不可能包含 JSON，跳过 LLM 调用
        # use_llm=False 时跳过（build_session_graph 等纯 CPU 场景）
        llm_enabled = _llm_mod.is_enabled() if self._llm is None else (
            hasattr(self._llm, "is_enabled") and self._llm.is_enabled()
        )
        if use_llm and not results and '{' in text and llm_enabled:
            try:
                prompt = (
                    "以下文本是安全分析 agent 的回复，其中包含一个 JSON payload"
                    "（格式如 {\"accepted\": true, \"data\": {\"findings\": [...], \"facts\": [...]}}）。"
                    "请从中提取完整的 JSON 对象。只返回 JSON，不要任何额外文字。"
                    "如果文本中没有 JSON 对象，返回 {}。"
                )
                if self._llm is not None:
                    payload = self._llm.chat_json(
                        [{"role": "user", "content": prompt + "\n\n" + text}],
                        temperature=0,
                        reasoning_effort="none",
                    )
                else:
                    payload = _llm_mod.chat_json(
                        [{"role": "user", "content": prompt + "\n\n" + text}],
                        temperature=0,
                        reasoning_effort="none",
                    )
                if isinstance(payload, dict):
                    _add(payload)
            except Exception as e:
                _log.debug("_extract_accepted_payloads LLM fallback failed: %s", str(e)[:200])

        return results

    @staticmethod
    def _extract_finding_meta_from_sysprompt(content: str) -> dict | None:
        """从 verify session 的 system prompt 中提取 finding metadata。

        system prompt 格式：
        # Verify: Finding Confirmation
        ...
        **Metadata:**
        ```json
        { "cwe": "...", "file": "...", "line_range": [...], ... }
        ```
        """
        meta_idx = content.find("**Metadata:**")
        if meta_idx < 0:
            meta_idx = content.find("## Finding to Verify")
        if meta_idx < 0:
            return None
        sub = content[meta_idx:]
        for obj in _extract_json_objects_from_text(sub):
            if "cwe" in obj or "file" in obj:
                return obj
        return None

    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """提取 Argo 平台的 finding。

        数据源：
        1. investigate session TEXT 事件 {"accepted": true, "data": {"findings": [...]}}
           → finding 的诞生 session，包含完整漏洞信息（cwe, file, source, sink, severity, ...）
        2. verify session SYSTEM_EVENT system prompt 包含 finding metadata（cwe, file, line_range）
        3. verify session TEXT 事件 {"accepted": true, "data": {"verdict": "..."}}
           → 验证结论

        关联方式：
        - finding 从 investigate session 提取，session_id = investigate session
        - verify session 的 system prompt 包含 finding metadata (cwe, file, line_range)
        - Pass 1: 精确匹配 (cwe, file, line_range)
        - Pass 2: 精确匹配失败时，回退到 (cwe, file) 模糊匹配（line_range 最近），
          因为 nazhua 用 original_finding_id 关联，不依赖 line_range，
          verify session 的 line_range 可能与 investigate session 不同
        - 同一 finding 被多次验证时，取最后一个 verdict（last-wins）

        过滤规则：
        - 只保留 verdict ∈ {CONFIRMED, MANUAL_REVIEW, FALSE_POSITIVE} 的 finding
        - DUPLICATE、NEEDS_REVIEW、未验证的 finding 不提取
        """
        # key -> finding dict
        findings: dict[str, dict] = {}
        # session_id -> [(verdict, event_idx)]
        session_verdicts: dict[str, list[tuple[str, int]]] = {}
        # session_id -> finding key（从 verify system prompt 提取）
        session_finding_key: dict[str, str] = {}
        # session_id -> (cwe, file, line_range_tuple) from verify system prompt
        session_meta: dict[str, tuple[str, str, tuple[int, int]]] = {}

        for i, e in enumerate(events):
            if len(events) > 10000 and i > 0 and i % 50000 == 0:
                _log.debug("Argo extract_findings %d/%d events findings=%d",
                           i, len(events), len(findings))
            # SYSTEM_EVENT: verify session system prompt，含 finding metadata
            if e.event_type == "SYSTEM_EVENT" and e.output_json:
                content = str(e.output_json)
                if "## Finding to Verify" in content or "# Verify:" in content:
                    meta = self._extract_finding_meta_from_sysprompt(content)
                    if meta:
                        key = self._finding_key(meta)
                        if key and key != "(,,)":
                            session_finding_key[e.session_id] = key
                        session_meta[e.session_id] = (
                            str(meta.get("cwe", "")),
                            str(meta.get("file", "")),
                            self._normalize_line_range(meta.get("line_range")),
                        )

            # TEXT 事件: investigate findings 和 verify verdicts
            if e.event_type == "TEXT" and e.output_json:
                txt = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
                for payload in self._extract_accepted_payloads(txt, use_llm=False):
                    data = payload.get("data", payload)
                    if not isinstance(data, dict):
                        continue
                    # investigate session: data.findings[]
                    if "findings" in data:
                        for f in data.get("findings", []):
                            if not isinstance(f, dict):
                                continue
                            key = self._finding_key(f)
                            if not key or key == "(,,)":
                                continue
                            findings[key] = {
                                "finding_id": key,
                                "display_id": key,
                                "title": str(f.get("description", ""))[:200],
                                "description": str(f.get("description", "")),
                                "vuln_type": str(f.get("cwe", "")),
                                "file": str(f.get("file", "")),
                                "severity": str(f.get("severity", "")),
                                "source": self._extract_file(f.get("source")),
                                "sink": self._extract_file(f.get("sink")),
                                "validation_result": None,
                                "platform": "argo",
                                "session_id": e.session_id,
                                "_event_idx": i,
                                "_line_range": self._normalize_line_range(f.get("line_range")),
                            }
                    # verify session: data.verdict
                    if "verdict" in data:
                        verdict = str(data.get("verdict", "")).upper()
                        session_verdicts.setdefault(e.session_id, []).append((verdict, i))

        # Phase 2: 关联 verdict 到 finding（跨 session 全局 last-wins）
        # Pass 1: 精确匹配 (cwe, file, line_range)
        verdicts_by_key: dict[str, list[tuple[str, int, str]]] = {}  # key -> [(verdict, event_idx, session_id)]
        unmatched: list[tuple[str, int, str]] = []  # (verdict, event_idx, session_id)
        for sid, vlist in session_verdicts.items():
            key = session_finding_key.get(sid)
            if key and key in findings:
                verdicts_by_key.setdefault(key, []).extend([(v, i, sid) for v, i in vlist])
            else:
                for v, i in vlist:
                    unmatched.append((v, i, sid))

        # Pass 2: 模糊匹配 (cwe, file) — verify session 的 line_range 可能与 investigate 不同
        # nazhua 用 original_finding_id 关联，不依赖 line_range
        # 同一 (cwe, file) 可能对应多个 finding，将 verdict 关联到所有候选，
        # 由 last-wins（按 event_idx 排序取最后一个）决定最终 verdict
        cwe_file_index: dict[str, list[str]] = {}
        for fkey, f in findings.items():
            cf = f"({f['vuln_type']},{f['file']})"
            cwe_file_index.setdefault(cf, []).append(fkey)

        for verdict, event_idx, sid in unmatched:
            meta = session_meta.get(sid)
            if not meta:
                continue
            cwe, file_val, lr = meta
            cf_key = f"({cwe},{file_val})"
            candidates = cwe_file_index.get(cf_key, [])
            if not candidates:
                continue
            if len(candidates) == 1:
                matched_key = candidates[0]
                verdicts_by_key.setdefault(matched_key, []).append((verdict, event_idx, sid))
            else:
                # 多个候选：关联到所有候选，由 last-wins 决定
                for matched_key in candidates:
                    verdicts_by_key.setdefault(matched_key, []).append((verdict, event_idx, sid))

        for key, vlist in verdicts_by_key.items():
            vlist.sort(key=lambda v: v[1])  # 全局按 event_idx 排序
            last_verdict, last_idx, last_sid = vlist[-1]
            if key in findings:
                findings[key]["validation_result"] = last_verdict
                findings[key]["_verify_session_id"] = last_sid

        # Phase 3: 过滤 — 只保留 CONFIRMED / MANUAL_REVIEW / FALSE_POSITIVE
        result = [f for f in findings.values()
                  if f.get("validation_result") in ("CONFIRMED", "MANUAL_REVIEW", "FALSE_POSITIVE")]

        attach_event_indices({f["finding_id"]: f for f in result}, events)
        return result

    # ------------------------------------------------------------------
    # label_session_phases() — 新实现
    # ------------------------------------------------------------------

    # task_type → 业务阶段映射（来自 docs/knowledge-effect-eval-requirements.md §4.1）
    _TASK_TYPE_PHASE_MAP: dict[str, str] = {
        "bootstrap": "入口识别+数据流追踪",
        "investigate": "漏洞模式识别/Sink点定位/漏洞判定与上报",
        "verify": "漏洞判定与上报",
        # reason → 不属于 5 阶段（跳过 L0–L7）
    }

    # prompt 标题前缀 → task_type
    _PROMPT_TITLE_MAP: dict[str, str] = {
        "# bootstrap": "bootstrap",
        "# investigate": "investigate",
        "# verify": "verify",
        "# reason": "reason",
    }

    def _extract_task_type_from_prompt(self, content: str) -> str | None:
        """从 JSONL 第一行 prompt 标题提取 task_type。

        prompt 标题格式（来自 docs/agent-session-phase-classification.md §3.1）：
        - `# Bootstrap: Codebase Reconnaissance`
        - `# Investigate: Source Code Review`
        - `# Verify: Finding Confirmation`
        - `# Reason: Blackboard Review and Dispatch`
        """
        if not content:
            return None
        # 取前 100 字符匹配（prompt 标题在开头）
        prefix = content[:100].lower()
        for title_prefix, task_type in self._PROMPT_TITLE_MAP.items():
            if prefix.startswith(title_prefix):
                return task_type
        return None

    def _query_task_type_from_db(self, session_ids: list[str]) -> dict[str, str]:
        """从 Argo MySQL `intents` 表查询 session_id → task_type。

        SQL（来自 docs/agent-db-queries.md §2）：
            SELECT session_id, task_type FROM intents WHERE session_id IN (:session_ids)

        连接失败时返回空 dict（不抛异常——DB 查询是交叉验证，非唯一来源）。
        """
        if not session_ids:
            return {}
        try:
            mgr = AgentDBManager()
            conn = mgr.get_connection("argo")
            if conn is None:
                return {}
            try:
                cur = conn.cursor()
                placeholders = ", ".join(["%s"] * len(session_ids))
                sql = f"SELECT session_id, task_type FROM intents WHERE session_id IN ({placeholders})"
                cur.execute(sql, session_ids)
                rows = cur.fetchall()
                result: dict[str, str] = {}
                for row in rows:
                    sid = row[0]
                    tt = row[1]
                    if sid and tt:
                        result[sid] = str(tt).lower()
                cur.close()
                return result
            finally:
                conn.close()
        except Exception as e:
            _log.debug("Argo _query_task_type_from_db failed: %s", str(e)[:200])
            return {}

    def label_session_phases(
        self, events: list[RawEvent], session_meta: dict
    ) -> tuple[dict[str, str], dict[str, str]]:
        """标注 session 的业务阶段。

        实现三层标注架构的第一层+第二层（程序确定性部分）。
        第三层 LLM 细分由 lifecycle 分析模块在 build_data_pack() 之后统一执行。

        流程：
        1. 从 JSONL 第一行 prompt 标题提取 task_type（bootstrap/investigate/verify/reason）
        2. 或用 AgentDBManager 查询 Argo MySQL `intents` 表获取 task_type
        3. 按 docs/agent-session-phase-classification.md §3.1 的映射表将 task_type → 业务阶段
        4. 返回 (session_phase_labels, session_phase_source)

        返回:
            session_phase_labels: session_id -> 业务阶段名称
            session_phase_source: session_id -> 标注来源标识符（task_type 值）
        """
        session_phase_labels: dict[str, str] = {}
        session_phase_source: dict[str, str] = {}

        # Step 1: 从 SYSTEM_EVENT（queue-operation prompt）提取每个 session 的 task_type
        # 每个 session 的第一个 SYSTEM_EVENT 就是 prompt
        session_task_types: dict[str, str] = {}
        for ev in events:
            if ev.event_type != "SYSTEM_EVENT" or not ev.output_json:
                continue
            sid = ev.session_id
            if not sid or sid in session_task_types:
                continue
            content = str(ev.output_json)
            task_type = self._extract_task_type_from_prompt(content)
            if task_type:
                session_task_types[sid] = task_type

        # Step 2: 对未从 prompt 提取到 task_type 的 session，查 Argo MySQL intents 表
        missing_sids = [
            sid for sid in {ev.session_id for ev in events if ev.session_id}
            if sid not in session_task_types
        ]
        if missing_sids:
            db_task_types = self._query_task_type_from_db(missing_sids)
            for sid, tt in db_task_types.items():
                session_task_types[sid] = tt

        # Step 3: 按 task_type → 业务阶段映射
        for sid, task_type in session_task_types.items():
            phase = self._TASK_TYPE_PHASE_MAP.get(task_type)
            if phase:
                session_phase_labels[sid] = phase
                session_phase_source[sid] = task_type
            else:
                # reason 或未知 task_type：不标注阶段（L0–L7 跳过）
                session_phase_source[sid] = task_type

        return session_phase_labels, session_phase_source
