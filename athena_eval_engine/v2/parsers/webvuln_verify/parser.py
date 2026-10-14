"""WebVulnVerifyParser — WebVulnVerify JSONL session 日志 → Canonical RawEvent。

从老代码 ``workers/webvulnverify_trace_parser.py`` 拷贝核心逻辑，适配 v2 架构：
- 继承 ``v2.parsers.base.BaseParser``（而非老代码的 ``TraceParser``）
- import v2 内部模块（``core.raw_event``）
- 工具函数从本目录 ``.utils`` 导入
- 新增 ``label_session_phases()`` 方法实现 session 业务阶段标注

Trace 路径：/data/files/{project_id}/tasks/{task_id}/session/WebVerify/*.jsonl

WebVulnVerify 是 ai-analyzer Agent 的漏洞分析工具，trace 格式为 JSONL，每行一个 JSON 对象。
与 Turing（SQLite）和 Argo（Claude Code JSONL）不同，WebVulnVerify 使用自定义 JSONL 格式。

JSONL 行类型：
  session_meta        → SESSION_START（会话元数据：id/project_id/title/time/metadata）
  tool_schema         → SYSTEM_EVENT（工具定义声明，跳过或标记）
  message_completed   → 按 message.role + part_type 分发：
    role=System   + text             → TEXT（系统 prompt / agent_policy）
    role=User     + text             → TEXT（任务 prompt / task_data）
    role=Assistant + text            → TEXT
    role=Assistant + thinking        → REASONING
    role=Assistant + tool_call       → TOOL_CALL（name: bash/read/grep/vulnerability_analyze 等）
    role=Tool     + tool_result      → TOOL_RESULT（content + tool_call_id 关联）

finding 结构：
  vulnerability_verify 是唯一识别入口（对应 Turing 的 update_finding）：
    input 含 {vulnerability_id, status, result, confidence, category}
    status: EXTERNAL_REQUEST_EXPLOITABLE/INTERNAL_REQUEST_EXPLOITABLE/UNIT_TEST_EXPLOITABLE/NOT_EXPLOITABLE
  vulnerability_analyze 提供补充详情（title/category，ID 嵌在 result 文本中）
  vulnerability_cvss 提供补充 CVSS 评分（vulnerability_id + cvss 对象）

token 信息：message.usage 含 input_tokens/output_tokens/reasoning_tokens/cache_read_tokens

timestamp：
  part.created_at（ISO 8601）或 session.time.created（epoch ms）

WebVulnVerify 无独立数据库，session 关系和阶段标识符都从 trace JSONL 提取。
"""
from __future__ import annotations
import json
import os
import re
import glob
import time
from typing import Iterator
from datetime import datetime

from ..base import BaseParser
from ...core.raw_event import RawEvent, detect_memory_flags, usage_numbers
from .utils import attach_event_indices

import logging
_log = logging.getLogger(__name__)


# WebVulnVerify 工具名 → 小写（保持与 Turing/Argo 一致）
_TOOL_MAP = {
    "bash": "bash",
    "read": "read",
    "grep": "grep",
    "glob": "glob",
    "write": "write",
    "edit": "edit",
    "task": "task",
    "skill": "skill",
    "vulnerability_analyze": "vulnerability_analyze",
    "vulnerability_cvss": "vulnerability_cvss",
    "vulnerability_verify": "vulnerability_verify",
    "vulneribility_verify": "vulnerability_verify",  # 拼写错误归一化
    "todowrite": "todowrite",
    "athena_ask": "athena_ask",
}


def is_webvulnverify_trace(path: str) -> bool:
    """检测 JSONL 是否为 WebVulnVerify 格式（含 session_meta 行类型）。

    供 parser 注册选择逻辑调用，避免格式检测逻辑嵌在 run() 内部。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                return d.get("type") == "session_meta"
    except Exception:
        pass
    return False


class WebVulnVerifyParser(BaseParser):
    """解析 WebVulnVerify（ai-analyzer）JSONL session 日志。"""

    def __init__(self, parser_version: str = "webvulnverify-1.0"):
        self.parser_version = parser_version

    # ------------------------------------------------------------------
    # BaseParser 抽象属性
    # ------------------------------------------------------------------

    @property
    def agent_type(self) -> str:
        return "webvuln_verify"

    # ------------------------------------------------------------------
    # parse()
    # ------------------------------------------------------------------

    def parse(self, trace_source) -> list[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件, trace_id?, session_id?}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)
        session_id = trace_source.get("turing_session_id") or trace_source.get("session_id") or ""

        # 如果是目录，读所有 .jsonl；如果是单文件，读它
        if os.path.isdir(uri):
            files = sorted(glob.glob(os.path.join(uri, "*.jsonl")))
            if not files:
                # poc-gen-verify 目录结构：workspaces/{ws}/.pi/sessions/*.jsonl
                files = sorted(glob.glob(os.path.join(uri, "*", ".pi", "sessions", "*.jsonl")))
        else:
            files = [uri]

        # 第一遍：收集 tool_call 的 id → {tool_name, is_kg} 映射，用于 TOOL_RESULT 继承
        tool_call_info: dict[str, dict] = {}  # call_id → {tool_name, is_kg}
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
                    if d.get("type") != "message_completed":
                        continue
                    msg = d.get("message", {})
                    if not isinstance(msg, dict):
                        continue
                    if msg.get("role") != "Assistant":
                        continue
                    for p in msg.get("parts", []):
                        pt = p.get("part_type", {})
                        if not isinstance(pt, dict) or pt.get("type") != "tool_call":
                            continue
                        call_id = pt.get("id", "")
                        tool_name = _TOOL_MAP.get(pt.get("name", ""), pt.get("name", "").lower())
                        is_kg = self._is_kg_interaction(tool_name, pt.get("input"))
                        is_mem, is_mem_w = detect_memory_flags(tool_name, pt.get("input"))
                        if call_id:
                            tool_call_info[call_id] = {"tool_name": tool_name, "is_kg": is_kg,
                                                        "is_mem": is_mem, "is_mem_w": is_mem_w}

        # 第二遍：逐行解析为 RawEvent
        events: list[RawEvent] = []
        for fpath in files:
            # 优先从 session_meta 行提取真实 session ID
            # 回退到外部传入的 session_id 或文件名
            sid = session_id
            if not sid:
                # 第一遍扫描：找 session_meta.session.id
                with open(fpath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            d = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if d.get("type") == "session_meta":
                            sess = d.get("session", {})
                            if isinstance(sess, dict) and sess.get("id"):
                                sid = sess["id"]
                                break
                if not sid:
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
                    for ev in self._obj_to_events(d, trace_id, sid, line_no, tool_call_info):
                        events.append(ev)

        return events

    def _obj_to_events(self, d: dict, trace_id: str, session_id: str,
                       line_no: int, tool_call_info: dict = None) -> list[RawEvent]:
        """把一个 JSONL 行转成 RawEvent（可能多个）。"""
        t = d.get("type", "")
        ts = self._parse_ts(d)
        eid_prefix = f"{session_id}-{line_no}"
        evs = []

        if t == "session_meta":
            sess = d.get("session", {})
            evs.append(RawEvent(
                event_id=f"{eid_prefix}-meta", trace_id=trace_id, session_id=session_id,
                event_type="SESSION_START", timestamp_ms=ts,
                message_id=None, part_id=f"{eid_prefix}-meta",
                step_no=None, tool_name=None,
                input_json=sess, output_json=None,
                raw_type="session_meta", parse_status="OK",
                source_table="jsonl", source_row_id=f"{eid_prefix}-meta",
                parser_version=self.parser_version,
            ))

        elif t == "tool_schema":
            evs.append(RawEvent(
                event_id=f"{eid_prefix}-schema", trace_id=trace_id, session_id=session_id,
                event_type="SYSTEM_EVENT", timestamp_ms=ts,
                message_id=None, part_id=f"{eid_prefix}-schema",
                step_no=None, tool_name=None,
                input_json=d.get("tools"), output_json=None,
                raw_type="tool_schema", parse_status="OK",
                source_table="jsonl", source_row_id=f"{eid_prefix}-schema",
                parser_version=self.parser_version,
            ))

        elif t == "message_completed":
            msg = d.get("message", {})
            if not isinstance(msg, dict):
                return evs
            role = msg.get("role", "")
            msg_id = msg.get("id")
            parts = msg.get("parts", [])
            step_no = None  # WebVulnVerify 无显式 step 编号，用 Assistant message 序号

            for j, p in enumerate(parts):
                pt = p.get("part_type", {})
                if not isinstance(pt, dict):
                    continue
                ptype = pt.get("type", "")
                part_id = p.get("id", f"{eid_prefix}-{j}")

                if ptype == "text" and role in ("System", "User", "Assistant"):
                    evs.append(RawEvent(
                        event_id=f"{eid_prefix}-{j}", trace_id=trace_id, session_id=session_id,
                        event_type="TEXT", timestamp_ms=ts,
                        message_id=msg_id, part_id=part_id,
                        step_no=step_no, tool_name=None,
                        input_json=None, output_json=pt.get("text"),
                        raw_type="text", parse_status="OK",
                        source_table="jsonl", source_row_id=part_id,
                        parser_version=self.parser_version,
                    ))

                elif ptype == "thinking" and role == "Assistant":
                    evs.append(RawEvent(
                        event_id=f"{eid_prefix}-{j}", trace_id=trace_id, session_id=session_id,
                        event_type="REASONING", timestamp_ms=ts,
                        message_id=msg_id, part_id=part_id,
                        step_no=step_no, tool_name=None,
                        input_json=None, output_json=pt.get("thinking"),
                        raw_type="thinking", parse_status="OK",
                        source_table="jsonl", source_row_id=part_id,
                        parser_version=self.parser_version,
                    ))

                elif ptype == "tool_call" and role == "Assistant":
                    tool_name = _TOOL_MAP.get(pt.get("name", ""), pt.get("name", "").lower())
                    call_id = pt.get("id", "")
                    inp = pt.get("input")
                    # WebVulnVerify 特有归一化：vulnerability_analyze 的 vulnerability_id
                    # 嵌在 result 文本里（如 "**漏洞 ID**: 50346" / "| 漏洞 ID | 50327 |" /
                    # "Vulnerability ID: 50293" / "vulnerability ID 50223" /
                    # "漽洞 ID | 50327"（乱码/变体）），
                    # 提取后写入 input_json，使下游公共方法只需 inp.get("vulnerability_id")
                    if tool_name in ("vulnerability_analyze", "vulnerability_verify") and isinstance(inp, dict) and not inp.get("vulnerability_id"):
                        result_text = str(inp.get("result", ""))
                        if result_text:
                            m = re.search(r'(?:[\u4e00-\u9fff]洞|[Vv]ulnerability)\s*ID[^\d]*(\d+)', result_text)
                            if m:
                                inp = {**inp, "vulnerability_id": m.group(1)}
                    is_kg = self._is_kg_interaction(tool_name, inp)
                    is_mem, is_mem_w = detect_memory_flags(tool_name, inp)
                    is_finding = self._is_finding_tool(tool_name)
                    if tool_call_info and call_id:
                        tool_call_info[call_id] = {"tool_name": tool_name, "is_kg": is_kg, "is_mem": is_mem, "is_mem_w": is_mem_w}
                    evs.append(RawEvent(
                        event_id=f"{eid_prefix}-{j}", trace_id=trace_id, session_id=session_id,
                        event_type="TOOL_CALL", timestamp_ms=ts,
                        message_id=msg_id, part_id=part_id,
                        step_no=step_no, tool_name=tool_name,
                        input_json=inp, output_json=None,
                        raw_type="tool_call", parse_status="OK",
                        source_table="jsonl", source_row_id=part_id,
                        parser_version=self.parser_version,
                        is_kg_interaction=is_kg,
                        is_memory_interaction=is_mem,
                        is_memory_write=is_mem_w,
                        is_finding_submission=is_finding,
                        call_id=call_id,
                    ))

                elif ptype == "tool_result" and role == "Tool":
                    call_id = pt.get("tool_call_id", "")
                    info = (tool_call_info or {}).get(call_id, {})
                    tool_name = info.get("tool_name", "")
                    content = pt.get("content")
                    is_error = pt.get("is_error", False)
                    evs.append(RawEvent(
                        event_id=f"{eid_prefix}-{j}", trace_id=trace_id, session_id=session_id,
                        event_type="TOOL_RESULT", timestamp_ms=ts,
                        message_id=msg_id, part_id=part_id,
                        step_no=step_no, tool_name=tool_name,
                        input_json=None, output_json=content,
                        raw_type="tool_result", parse_status="OK",
                        source_table="jsonl", source_row_id=part_id,
                        parser_version=self.parser_version,
                        call_id=call_id,
                        is_kg_interaction=info.get("is_kg", False),
                    ))

        return evs

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _is_kg_interaction(self, tool_name: str, input_json) -> bool:
        """判断是否为知识图谱交互。

        WebVulnVerify 的 KG 交互模式：
        - bash 工具执行 athena CLI 脚本（scripts/athena / athena.py）
        - skill 工具加载 athena-skill
        - athena_ask 工具直接查询 Athena 安全知识库（知识图谱）
        """
        if tool_name == "athena_ask":
            return True
        if tool_name == "bash" and isinstance(input_json, dict):
            cmd = str(input_json.get("command", ""))
            cmd_l = cmd.lower()
            has_script = "scripts/athena" in cmd_l or "athena.py" in cmd_l
            is_view = cmd_l.strip().startswith(("head", "cat ", "grep ", "ls "))
            if has_script and not is_view:
                return True
        elif tool_name == "skill" and isinstance(input_json, dict):
            if str(input_json.get("name", "")).lower() == "athena-skill":
                return True
        return False

    @staticmethod
    def _is_finding_tool(tool_name: str) -> bool:
        """WebVulnVerify 平台 finding 提交工具——仅 vulnerability_verify 是结论写入工具。"""
        return tool_name == "vulnerability_verify"

    def _parse_ts(self, d: dict) -> int | None:
        """从 JSONL 行提取 timestamp（ms epoch）。

        优先级：part.created_at (ISO) > session.time.created (epoch ms) > message.created_at (ISO)
        """
        # session_meta: session.time.created (epoch ms)
        sess = d.get("session", {})
        if isinstance(sess, dict):
            t = sess.get("time", {})
            if isinstance(t, dict) and t.get("created"):
                return int(t["created"])

        # message_completed: message.created_at (ISO 8601) 或 parts[0].created_at
        msg = d.get("message", {})
        if isinstance(msg, dict):
            ts_str = msg.get("created_at", "")
            if ts_str:
                return self._iso_to_ms(ts_str)
            parts = msg.get("parts", [])
            if parts and isinstance(parts[0], dict):
                ts_str = parts[0].get("created_at", "")
                if ts_str:
                    return self._iso_to_ms(ts_str)

        return None

    @staticmethod
    def _iso_to_ms(ts) -> int | None:
        """ISO 8601 或 epoch ms 整数 -> ms epoch。"""
        if not ts:
            return None
        # 纯数字：已经是 epoch ms
        if isinstance(ts, (int, float)):
            return int(ts)
        ts_str = str(ts)
        if ts_str.isdigit():
            return int(ts_str)
        # ISO 8601 字符串
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # load_session()
    # ------------------------------------------------------------------

    def load_session(self, trace_source) -> dict:
        """从 JSONL 累计 token + step 数（替代 SQLite session 表）。

        返回格式与 Turing/Argo parser 的 load_session 对齐，供 ResourceResolver 使用。
        """
        uri = trace_source["source_uri"]
        if os.path.isdir(uri):
            files = sorted(glob.glob(os.path.join(uri, "*.jsonl")))
        else:
            files = [uri]

        ti = to = tr = tcr = 0
        n_step_start = n_step_finish = 0
        ts_min = ts_max = None
        session_id = ""
        model = "unknown"
        agent = "webvulnverify"

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

                    ts = self._parse_ts(d)
                    if ts:
                        ts_min = ts if ts_min is None else min(ts_min, ts)
                        ts_max = ts if ts_max is None else max(ts_max, ts)

                    t = d.get("type", "")

                    if t == "session_meta":
                        sess = d.get("session", {})
                        session_id = sess.get("id", "")
                        n_step_start += 1  # session 开始 = 一次 step-start
                        # metadata 中的 agent_id / mount_source
                        meta = sess.get("metadata", {})
                        if isinstance(meta, dict):
                            if meta.get("agent_id"):
                                agent = meta.get("agent_id")

                    elif t == "message_completed":
                        msg = d.get("message", {})
                        if not isinstance(msg, dict):
                            continue
                        role = msg.get("role", "")
                        if role == "Assistant":
                            n_step_finish += 1
                            usage = msg.get("usage", {})
                            if isinstance(usage, dict):
                                ai, ao, ar, ac = usage_numbers(usage)
                                ti += ai; to += ao; tr += ar; tcr += ac
                            # model 信息
                            m = msg.get("metadata", {})
                            if isinstance(m, dict) and m.get("model_id"):
                                model = m["model_id"]

        sess = {
            "tokens_input": ti, "tokens_output": to,
            "tokens_reasoning": tr, "cache_read_tokens": tcr,
            "time_created": ts_min, "time_updated": ts_max,
            "_step_start_count": n_step_start,
            "_step_finish_count": n_step_finish,
            "model": model, "agent": agent,
            "session_id": session_id,
        }
        return sess

    # ------------------------------------------------------------------
    # build_session_graph()
    # ------------------------------------------------------------------

    def build_session_graph(self, events: list[RawEvent]) -> dict:
        """构建 session 关系图。

        WebVulnVerify 是验证 agent，一个 task 验证多个漏洞，每个漏洞有独立的
        analyze → verify → cvss 流程。session 关系按 vulnerability_id 分组：
        - 同一个 vid 的 session 按时间顺序串联（analyze → verify → cvss）
        - 不同 vid 之间没有调用关系
        - parent_id 不作为调用链边——它只是 session 创建时的父 session，
          所有子 session 都指向同一个 agent 主 session，不是验证流程关系
        """
        graph = {
            'sessions': {}, 'file_to_sessions': {},
            'vuln_id_to_sessions': {},
            'edges': {},
            'parent_map': {},
        }
        from collections import defaultdict as _dd
        graph['file_to_sessions'] = _dd(set)
        graph['vuln_id_to_sessions'] = _dd(set)
        graph['edges'] = _dd(set)
        _n = len(events)
        _start = time.time()

        # vid -> list of (timestamp_ms, session_id) — 用于按时间排序建链
        vid_session_ts: dict[str, list[tuple[int, str]]] = _dd(list)

        for idx, ev in enumerate(events):
            if _n > 10000 and idx > 0 and idx % 50000 == 0:
                _log.debug("WebVulnVerify build_session_graph %d/%d events "
                           "elapsed=%ds sessions=%d",
                           idx, _n, int(time.time() - _start), len(graph['sessions']))
            sid = ev.session_id
            if not sid:
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {'files': set(), 'vuln_ids': set()}
            sg = graph['sessions'][sid]

            # SESSION_START (session_meta): 提取 metadata.vulnerability_id
            if ev.event_type == "SESSION_START" and isinstance(ev.input_json, dict):
                sess = ev.input_json
                meta = sess.get("metadata", {})
                if isinstance(meta, dict):
                    vid = str(meta.get("vulnerability_id", ""))
                    if vid:
                        sg['vuln_ids'].add(vid)
                        graph['vuln_id_to_sessions'][vid].add(sid)
                        vid_session_ts[vid].append((ev.timestamp_ms or 0, sid))

            if not ev.is_tool_call():
                continue
            tool = ev.tool_name or ""
            inp = ev.input_json or {}

            # vulnerability_analyze/verify/cvss：提取 vulnerability_id
            if tool in ("vulnerability_analyze", "vulnerability_verify", "vulnerability_cvss"):
                vid = str(inp.get("vulnerability_id", ""))
                if vid:
                    sg['vuln_ids'].add(vid)
                    graph['vuln_id_to_sessions'][vid].add(sid)
                    # 记录时间戳用于排序（只在第一次出现时记录）
                    if not any(s == sid for _, s in vid_session_ts[vid]):
                        vid_session_ts[vid].append((ev.timestamp_ms or 0, sid))

            # 共享文件（保留用于文件关联分析，但不用于建边）
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

        # 按 vulnerability_id 分组建边：同一 vid 的 session 按时间顺序串联
        # analyze (最早) → verify → cvss (最晚)，形成线性链
        for vid, ts_sid_list in vid_session_ts.items():
            if len(ts_sid_list) <= 1:
                continue
            # 按时间戳排序
            ts_sid_list.sort(key=lambda x: x[0])
            # 串联相邻 session
            for i in range(len(ts_sid_list) - 1):
                child_sid = ts_sid_list[i][1]
                parent_sid = ts_sid_list[i + 1][1]
                # analyze 是父，verify 是子（analyze 先执行，verify 后执行）
                graph['edges'][parent_sid].add(child_sid)
                graph['edges'][child_sid].add(parent_sid)
                graph['parent_map'][parent_sid] = child_sid

        return graph

    # ------------------------------------------------------------------
    # extract_findings()
    # ------------------------------------------------------------------

    # vulnerability_verify status → validation_result 映射
    # 源代码论证（tool_schema + SKILL.md step 10）：
    #   vulnerability_verify 是验证结论的唯一写入工具，status enum 4 个值
    #   EXTERNAL_REQUEST_EXPLOITABLE / INTERNAL_REQUEST_EXPLOITABLE / UNIT_TEST_EXPLOITABLE
    #   → 漏洞确认（CONFIRMED）
    #   NOT_EXPLOITABLE → 非漏洞（FALSE_POSITIVE）
    _VV_STATUS_MAP = {
        "EXTERNAL_REQUEST_EXPLOITABLE": "CONFIRMED",
        "INTERNAL_REQUEST_EXPLOITABLE": "CONFIRMED",
        "UNIT_TEST_EXPLOITABLE": "CONFIRMED",
        "NOT_EXPLOITABLE": "FALSE_POSITIVE",
    }

    @staticmethod
    def _extract_webvv_task_data(events: list) -> dict[str, dict]:
        """从 WebVulnVerify trace 的 User message (task_data) 中提取 source/sink 等信息。

        T002 的 User message 包含 T001 上报的 finding 数据，格式为：
        <task_data>
        VULNERABILITY INFORMATION:
        - Vulnerability ID: 50318
        - File URI: DPOrderFulfillmentService/.../FileBucketService.java
        - URL: /rest/dp/order/fulfillment/v1/order/supplement
        - Source: supplement() 方法接收...
        - Sink: FileBucketService.getInputStream()...
        </task_data>

        返回 {vulnerability_id: {source, sink, file_uri, url}} 映射。
        """
        result_map: dict[str, dict] = {}
        for e in events:
            text = ""
            if isinstance(e.input_json, str):
                text = e.input_json
            elif isinstance(e.output_json, str):
                text = e.output_json
            elif e.output_json is not None:
                text = str(e.output_json)
            elif e.input_json is not None:
                text = str(e.input_json)

            if not text or "task_data" not in text:
                continue

            vid_m = re.search(r'[Vv]ulnerability[_ ]?[Ii][Dd][:：]\s*(\S+)', text)
            if not vid_m:
                continue
            vid = vid_m.group(1).strip()

            def _extract_field(label: str) -> str:
                m = re.search(rf'-\s*{label}[:：]\s*(.+?)(?=\n\s*-|\Z)', text, re.DOTALL)
                return m.group(1).strip() if m else ""

            result_map[vid] = {
                "source": _extract_field("Source"),
                "sink": _extract_field("Sink"),
                "file_uri": _extract_field("File URI"),
                "url": _extract_field("URL"),
            }

        return result_map

    @staticmethod
    def _extract_webvv_title(result_text: str) -> str:
        """从 WebVulnVerify 的验证报告 (result 字段) 中提取具体标题。

        优先提取"一句话结论"，其次提取元数据表中的"漏洞类型"。
        如果都提取不到，返回空字符串（调用方回退到 category）。
        """
        if not result_text:
            return ""

        # 1. "一句话结论：xxx" → 取结论文本
        m = re.search(r'一句话结论[：:]\s*(.+?)(?=\n\n|\n#|\n-|\Z)', result_text, re.DOTALL)
        if m:
            return m.group(1).strip()

        # 2. 元数据表 "| 漏洞类型 | xxx |" → 取值
        m = re.search(r'漏洞类型\s*\|\s*(.+?)\s*\|', result_text)
        if m:
            return m.group(1).strip()

        return ""

    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """提取 WebVulnVerify 平台的 finding。

        vulnerability_verify 是唯一识别入口（对应 Turing 的 update_finding）：
        - status EXTERNAL_REQUEST_EXPLOITABLE/INTERNAL_REQUEST_EXPLOITABLE/UNIT_TEST_EXPLOITABLE → CONFIRMED
        - status NOT_EXPLOITABLE → FALSE_POSITIVE

        vulnerability_analyze 提供补充详情（标题/类型），vulnerability_cvss 提供 CVSS 评分。
        vulnerability_id 从 input 字段或 result 文本中提取（_obj_to_events 已归一化）。

        Trace 数据论证（82 sessions, 4897 tool_calls）：
        - vulnerability_analyze 和 vulnerability_verify **100% 在不同 session**
          （每个 session 有独立 metadata.vulnerability_id，analyze session ≠ verify session）
        - session_id = analyze session（类似 Argo 的 investigate session）
        - _verify_session_id = verify session（vulnerability_verify 所在 session）
        - 无 analyze session 时回退：session_id = verify session
        """
        # Phase 1: 收集补充数据
        analyze_details: dict[str, dict] = {}  # vid → {title, vuln_type, session_id}
        cvss_data: dict[str, dict] = {}       # vid → cvss
        task_data = self._extract_webvv_task_data(events)

        for e in events:
            if not e.is_tool_call():
                continue
            tool = e.tool_name or ""
            inp = e.input_json or {}

            if tool == "vulnerability_analyze":
                vid = str(inp.get("vulnerability_id", ""))
                if not vid:
                    continue
                result_text = str(inp.get("result", ""))
                analyze_details[vid] = {
                    "title": self._extract_webvv_title(result_text),
                    "vuln_type": inp.get("category", ""),
                    "session_id": e.session_id,
                }

            elif tool == "vulnerability_cvss":
                vid = str(inp.get("vulnerability_id", ""))
                if not vid:
                    continue
                cvss_data[vid] = inp.get("cvss", {})

        # Phase 2: vulnerability_verify → 创建 finding 条目（唯一识别入口）
        findings: dict[str, dict] = {}

        for _ei, e in enumerate(events):
            if not e.is_tool_call():
                continue
            if (e.tool_name or "") != "vulnerability_verify":
                continue
            inp = e.input_json or {}
            vid = str(inp.get("vulnerability_id", ""))
            if not vid:
                continue
            status = str(inp.get("status", "")).upper()
            vr = self._VV_STATUS_MAP.get(status)
            if vr is None:
                continue
            result_text = str(inp.get("result", ""))
            td = task_data.get(vid, {})
            ad = analyze_details.get(vid, {})
            title = self._extract_webvv_title(result_text) or ad.get("title", "") or inp.get("category", "")
            # analyze session 作为 session_id（类似 Argo investigate session），
            # verify session 作为 _verify_session_id（与 fact_repo 对齐）
            analyze_sid = ad.get("session_id", "")
            verify_sid = e.session_id
            findings[vid] = {
                "finding_id": vid,
                "display_id": vid,
                "title": title,
                "description": result_text,
                "vuln_type": inp.get("category", "") or ad.get("vuln_type", ""),
                "severity": "",
                "source": td.get("source", ""),
                "sink": td.get("sink", ""),
                "validation_result": vr,
                "platform": "webvulnverify",
                "confidence": inp.get("confidence"),
                "cvss": cvss_data.get(vid),
                "session_id": analyze_sid or verify_sid,
                "_verify_session_id": verify_sid,
            }

        attach_event_indices(findings, events)
        return list(findings.values())

    # ------------------------------------------------------------------
    # label_session_phases() — 新实现
    # ------------------------------------------------------------------

    # 工具名 → 业务阶段映射（来自 docs/agent-session-phase-classification.md §3.6）
    # vulnerability_analyze 涵盖"漏洞理解 + 代码定位"两个阶段，需第三层 LLM 细分
    _TOOL_PHASE_MAP: dict[str, str] = {
        "vulnerability_analyze": "漏洞理解+代码定位",
        "vulnerability_verify": "判定上报",
        "vulnerability_cvss": "判定上报",
        "read": "验证执行",
        "bash": "验证执行",
        "grep": "验证执行",
    }

    def label_session_phases(
        self, events: list[RawEvent], session_meta: dict
    ) -> tuple[dict[str, str], dict[str, str]]:
        """标注 session 的业务阶段。

        实现三层标注架构的第一层+第二层（程序确定性部分）。
        第三层 LLM 细分由 lifecycle 分析模块在 build_data_pack() 之后统一执行。

        流程：
        1. 从 JSONL trace 提取每个 session 的 tool_call.name 序列
        2. 按工具名映射到业务阶段（docs/agent-session-phase-classification.md §3.6）
        3. 返回 (session_phase_labels, session_phase_source)

        返回:
            session_phase_labels: session_id -> 业务阶段名称
            session_phase_source: session_id -> 标注来源标识符（工具名集合）

        工具名 → 业务阶段映射：
            vulnerability_analyze → 漏洞理解+代码定位（需 LLM 细分）
            vulnerability_verify/cvss → 判定上报
            read/bash/grep → 验证执行

        WebVulnVerify 无独立数据库，session 关系和阶段标识符都从 trace JSONL 提取。
        """
        session_phase_labels: dict[str, str] = {}
        session_phase_source: dict[str, str] = {}

        # Step 1: 从 events 提取每个 session 的工具调用序列
        # session_id -> set of tool_name
        session_tool_sets: dict[str, set[str]] = {}
        for ev in events:
            if not ev.is_tool_call():
                continue
            sid = ev.session_id
            if not sid:
                continue
            tool = ev.tool_name or ""
            if not tool:
                continue
            session_tool_sets.setdefault(sid, set()).add(tool)

        # Step 2: 按工具名 → 业务阶段映射
        # 优先级：vulnerability_verify/cvss（判定上报）> vulnerability_analyze（漏洞理解+代码定位）> read/bash/grep（验证执行）
        # 如果一个 session 同时有多个阶段工具，取优先级最高的
        _PHASE_PRIORITY = {
            "判定上报": 3,
            "漏洞理解+代码定位": 2,
            "验证执行": 1,
        }

        for sid, tool_set in session_tool_sets.items():
            phases: set[str] = set()
            for tool in tool_set:
                phase = self._TOOL_PHASE_MAP.get(tool)
                if phase:
                    phases.add(phase)

            if not phases:
                # 无可映射工具的 session，不标注阶段
                session_phase_source[sid] = ",".join(sorted(tool_set))
                continue

            # 取优先级最高的阶段
            best_phase = max(phases, key=lambda p: _PHASE_PRIORITY.get(p, 0))
            session_phase_labels[sid] = best_phase
            # 标注来源：工具名集合（按字母排序）
            session_phase_source[sid] = ",".join(sorted(tool_set))

        return session_phase_labels, session_phase_source
