"""CVulnVerifyParser — CVulnVerify JSONL session → Canonical RawEvent。

从老代码 ``workers/cvuln_verify_trace_parser.py`` 拷贝核心逻辑，适配 v2 架构：
- 继承 ``v2.parsers.base.BaseParser``（而非老代码的 ``TraceParser``）
- import v2 内部模块（``core.raw_event``、``infra.agent_db``）
- 工具函数从本目录 ``.utils`` 导入
- 新增 ``label_session_phases()`` 方法实现 session 业务阶段标注

Trace 路径：/data/files/{project_id}/tasks/c_vuln_verify/*.jsonl

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
from datetime import datetime
from typing import Iterator

from ..base import BaseParser
from ...core.raw_event import RawEvent, detect_memory_flags, usage_numbers
from ...infra.agent_db import AgentDBManager
from .utils import parse_json_lenient

import logging
_log = logging.getLogger(__name__)


class CVulnVerifyParser(BaseParser):
    """解析 CVulnVerify JSONL session 日志。"""

    def __init__(self, parser_version: str = "cvuln-verify-1.0"):
        self.parser_version = parser_version
        self._last_tool_id = None
        self._last_tool_name = None
        self._tool_kg = {}
        self._tool_mem = {}
        self._trace_metadata_cache: dict[str, tuple[str | None, str | None]] = {}

    _TASK_PATH_RE = re.compile(r"/tasks/([0-9a-f]{24})(?:/|$)")
    _CASE_ID_RE = re.compile(r"漏洞\s*ID\s*[:：]\s*([^\s]+)")

    # ------------------------------------------------------------------
    # BaseParser 抽象属性
    # ------------------------------------------------------------------

    @property
    def agent_type(self) -> str:
        return "cvuln_verify"

    # ------------------------------------------------------------------
    # JSONL 文件解析
    # ------------------------------------------------------------------

    def _files(self, trace_source) -> list[str]:
        """取得本次评测应读取的 case 文件。

        c_vuln_verify 目录由多个原始平台任务共享。发现阶段以 case API 做正式
        归属，解析阶段用 trace 内的任务上下文将已下载目录收窄到同一任务。

        支持两种目录结构：
        - 旧：tasks/c_vuln_verify/*.jsonl（文件直接在目录下）
        - 新：app/secflow-app-vuln-verify-v2/{task_id}/run/*.jsonl（文件在子目录）
        """
        uri = trace_source["source_uri"]
        if os.path.isdir(uri):
            files = sorted(glob.glob(os.path.join(uri, "*.jsonl")))
            if not files:
                # 新目录结构：{task_id}/run/*.jsonl
                files = sorted(glob.glob(os.path.join(uri, "*", "run", "*.jsonl")))
        else:
            files = [uri]
        source_task_id = trace_source.get("source_task_id")
        if not source_task_id:
            return files
        task_files: list[tuple[str, str | None]] = []
        for path in files:
            task_id, case_id = self._trace_metadata(path)
            if task_id == source_task_id:
                task_files.append((path, case_id))

        source_case_ids = {str(case_id) for case_id in trace_source.get("source_case_ids", [])
                           if case_id}
        if not source_case_ids:
            return [path for path, _ in task_files]

        filtered = [path for path, case_id in task_files if case_id in source_case_ids]
        if filtered:
            _log.debug("CVulnVerify benchmark case 过滤: task=%s files=%d -> %d",
                       source_task_id, len(task_files), len(filtered))
            return filtered

        # 不同 benchmark 来源的 case ID 可能不在同一命名空间。完全不命中时
        # 保留任务级过滤，避免把有效 trace 错误地解析为空。
        _log.debug("CVulnVerify benchmark case 未命中 trace，回退任务级过滤: "
                   "task=%s benchmark_cases=%d task_files=%d",
                   source_task_id, len(source_case_ids), len(task_files))
        return [path for path, _ in task_files]

    def _trace_metadata(self, path: str) -> tuple[str | None, str | None]:
        """从首条用户消息提取平台任务和漏洞 case ID。"""
        cached = self._trace_metadata_cache.get(path)
        if cached is not None:
            return cached
        result: tuple[str | None, str | None] = (None, None)
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
                    case_match = self._CASE_ID_RE.search(text)
                    result = (task_ids[-1] if task_ids else None,
                              case_match.group(1) if case_match else None)
                    break
        except (OSError, UnicodeDecodeError):
            pass
        self._trace_metadata_cache[path] = result
        return result

    # ------------------------------------------------------------------
    # parse()
    # ------------------------------------------------------------------

    def parse(self, trace_source) -> list[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)
        session_id = trace_source.get("turing_session_id", "")

        files = self._files(trace_source)

        # 预收集所有 toolCall 的 is_kg 和 memory 标记（按 id）
        self._tool_kg = {}
        self._tool_mem = {}
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
                                tool_name = c.get("name", "")
                                args = c.get("arguments", {})
                                is_kg = self._is_kg_call(tool_name, args)
                                is_mem, is_mem_w = detect_memory_flags(tool_name, args)
                                if tid:
                                    self._tool_kg[tid] = is_kg
                                    self._tool_mem[tid] = (is_mem, is_mem_w)

        events: list[RawEvent] = []
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
                        events.append(ev)

        return events

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

        if t == "session":
            # session 行可能含 parent_id（类似 WebVulnVerify 的 session_meta）
            sess = d.get("session", d)
            if isinstance(sess, dict):
                pid = str(sess.get("parent_id") or sess.get("parentId") or "")
                if pid:
                    evs.append(RawEvent(
                        event_type="SESSION_START", session_id=session_id,
                        trace_id=trace_id, event_id=eid, timestamp_ms=ts,
                        tool_name="", input_json={"parent_id": pid},
                        output_json=None, raw_type="session",
                    ))
            return evs

        if t == "message":
            msg = d.get("message", {})
            if not isinstance(msg, dict):
                return []
            role = msg.get("role", "")
            content = msg.get("content", [])
            if not isinstance(content, list):
                return []

            # toolResult 消息：创建 TOOL_RESULT 事件
            if role == "toolResult":
                tool_name = msg.get("toolName", "")
                _tid = getattr(self, "_last_tool_id", "")
                # 合并所有 text content 作为输出
                result_text = ""
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        result_text += c.get("text", "")
                evs.append(RawEvent(
                    event_id=f"{eid}-tr", trace_id=trace_id, session_id=session_id,
                    event_type="TOOL_RESULT", timestamp_ms=ts,
                    message_id=None, part_id=f"{eid}-tr",
                    step_no=None, tool_name=tool_name,
                    input_json=None, output_json=result_text or None,
                    raw_type="toolResult", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-tr",
                    parser_version=self.parser_version,
                    call_id=_tid,
                    is_kg_interaction=self._tool_kg.get(_tid, False) if _tid else False,
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

            # 非 toolResult：处理 toolCall / text / thinking
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
                    is_mem, is_mem_w = detect_memory_flags(tool_name, args)
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
                        is_memory_interaction=is_mem,
                        is_memory_write=is_mem_w,
                        call_id=tid,
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

    # ------------------------------------------------------------------
    # load_session()
    # ------------------------------------------------------------------

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
                                ai, ao, ar, ac = usage_numbers(usage)
                                ti += ai; to += ao; tr += ar; tcr += ac
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

    # ------------------------------------------------------------------
    # build_session_graph()
    # ------------------------------------------------------------------

    def _fetch_predecessor_map(self) -> dict[str, str]:
        """从 CVulnVerify PostgreSQL 查询 predecessor_attempt_id 映射。

        CVulnVerify 的 session 父子关系（重试链）存储在 vuln_verify_attempt 表的
        predecessor_attempt_id 列中，不在 JSONL trace 文件里。
        JSONL 文件名 = attempt_id（UUID），与 DB id 列直接对应。

        连接失败时返回空 dict（graceful degradation）。
        """
        try:
            mgr = AgentDBManager()
            conn = mgr.get_connection("cvuln_verify")
            if conn is None:
                return {}
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, predecessor_attempt_id FROM vuln_verify_attempt "
                    "WHERE predecessor_attempt_id IS NOT NULL"
                )
                mapping = {str(r[0]): str(r[1]) for r in cur.fetchall()}
                cur.close()
                return mapping
            finally:
                conn.close()
        except Exception as e:
            _log.debug("CVulnVerify _fetch_predecessor_map failed: %s", str(e)[:200])
            return {}

    def build_session_graph(self, events: list[RawEvent]) -> dict:
        """构建 CVulnVerify session 关系图。

        Session 父子关系（重试链）来源：
        1. CVulnVerify PostgreSQL vuln_verify_attempt.predecessor_attempt_id（主要）
           — JSONL 文件名 = attempt_id，与 DB id 直接对应
        2. JSONL session 行 parent_id（备选，当前 CVulnVerify 不写此字段）

        不建共享文件/fact 边——共享不是调用关系，会导致 BFS 误连。
        """
        from collections import defaultdict

        graph = {
            'sessions': {}, 'file_to_sessions': defaultdict(set),
            'fact_to_sessions': defaultdict(set), 'edges': defaultdict(set),
            'parent_map': {},
        }

        finding_to_session = {}
        for ev in events:
            sid = ev.session_id
            if not sid:
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {'files': set(), 'facts': set(), 'athena_qs': [],
                                          'session_type': 'verify', 'memory_reads': [], 'case_id': ''}
            sg = graph['sessions'][sid]

            # SESSION_START: 提取 parent_id → parent_map（备选机制）
            if ev.event_type == "SESSION_START" and isinstance(ev.input_json, dict):
                pid = str(ev.input_json.get("parent_id") or "")
                if pid:
                    graph['parent_map'][sid] = pid
                    graph['edges'][sid].add(pid)
                    graph['edges'][pid].add(sid)

            if not ev.is_tool_call():
                continue
            tool = ev.tool_name or ""
            inp = ev.input_json or {}

            # verdict 提交：提取 case_id
            if tool == "write":
                fp = str(inp.get("file_path") or inp.get("path") or "")
                if "vuln_verify_final_verdict" in fp:
                    content = inp.get("content", "")
                    if isinstance(content, str):
                        try:
                            vdata = json.loads(content)
                            case_id = str(vdata.get("case_id", ""))
                            if case_id:
                                sg['case_id'] = case_id
                                finding_to_session[case_id] = sid
                        except (json.JSONDecodeError, TypeError):
                            pass
            elif tool in ("bash", "bash_tool", "shell"):
                cmd = str(inp.get("command", ""))
                if "vuln_verify_final_verdict" in cmd:
                    vdata = self._extract_verdict_from_bash_cmd(cmd)
                    if vdata:
                        case_id = str(vdata.get("case_id", ""))
                        if case_id:
                            sg['case_id'] = case_id
                            finding_to_session[case_id] = sid

            # 记忆读取路径
            if ev.is_memory_interaction and tool in ("bash", "bash_tool", "shell"):
                cmd = str(inp.get("command", ""))
                for m in re.finditer(r'(?:cat|head|tail|grep)\s+(\S*memengine\S+|/\S*app/memory\S*)', cmd):
                    sg['memory_reads'].append(m.group(1))

        # 从 CVulnVerify DB 查询 predecessor 链（主要机制）
        # session_id = attempt_id = JSONL 文件名，与 DB id 直接对应
        if not graph['parent_map']:
            predecessor_map = self._fetch_predecessor_map()
            if predecessor_map:
                session_ids = set(graph['sessions'].keys())
                _matched = 0
                for sid, pid in predecessor_map.items():
                    if sid in session_ids and pid in session_ids:
                        graph['parent_map'][sid] = pid
                        graph['edges'][sid].add(pid)
                        graph['edges'][pid].add(sid)
                        _matched += 1
                _log.debug("CVulnVerify build_session_graph: predecessor_attempt_id → "
                           "%d session edges (DB has %d, sessions=%d)",
                           _matched, len(predecessor_map), len(session_ids))

        graph['finding_to_session'] = finding_to_session
        return graph

    @staticmethod
    def _extract_verdict_from_bash_cmd(cmd: str) -> dict | None:
        """从 bash cat > heredoc 命令中提取 verdict JSON。

        命令格式：
            cat > /tmp/.../vuln_verify_final_verdict.json << 'JSONEOF'
            { "case_id": "...", "verdict": "confirmed", ... }
            JSONEOF
        """
        brace_idx = cmd.find("{")
        if brace_idx == -1:
            return None
        # 复用 _parse_verdict_json 的三级回退逻辑
        return CVulnVerifyParser._parse_verdict_json(cmd[brace_idx:])

    @staticmethod
    def _parse_verdict_json(content: str) -> dict | None:
        """解析 verdict JSON，两级回退：parse_json_lenient → regex。"""
        # 1. parse_json_lenient（json.loads → raw_decode → 花括号补全）
        v = parse_json_lenient(content)
        if v and v.get("case_id"):
            return v
        # 2. regex 回退：提取 case_id + verdict（最小必要字段）
        cid_m = re.search(r'"case_id"\s*:\s*"([^"]+)"', content)
        v_m = re.search(r'"verdict"\s*:\s*"([^"]+)"', content)
        if cid_m:
            vdata = {"case_id": cid_m.group(1)}
            if v_m:
                vdata["verdict"] = v_m.group(1)
            # 尝试提取其他字段
            for field, pattern in [
                ("case_title", r'"case_title"\s*:\s*"([^"]*)"'),
                ("title", r'"title"\s*:\s*"([^"]*)"'),
                ("vuln_type", r'"vuln_type"\s*:\s*"([^"]*)"'),
                ("vulnerability_type", r'"vulnerability_type"\s*:\s*"([^"]*)"'),
                ("source_file", r'"source_file"\s*:\s*"([^"]*)"'),
                ("source", r'"source"\s*:\s*"([^"]*)"'),
                ("function_name", r'"function_name"\s*:\s*"([^"]*)"'),
                ("sink", r'"sink"\s*:\s*"([^"]*)"'),
                ("severity", r'"severity"\s*:\s*"([^"]*)"'),
                ("summary", r'"summary"\s*:\s*"([^"]*)"'),
                ("description", r'"description"\s*:\s*"([^"]*)"'),
                ("ruled_out_by", r'"ruled_out_by"\s*:\s*"([^"]*)"'),
            ]:
                m = re.search(pattern, content)
                if m:
                    vdata[field] = m.group(1)
            # evidence[].location 提取（regex 回退路径）
            locs = re.findall(r'"location"\s*:\s*"([^"]+)"', content)
            if locs:
                vdata["evidence_locations"] = locs
            return vdata
        return None

    # ------------------------------------------------------------------
    # label_session_phases()
    # ------------------------------------------------------------------

    # worker_type → 业务阶段映射（来自 docs/agent-session-phase-classification.md §3.5）
    _WORKER_TYPE_PHASE_MAP: dict[str, str] = {
        "source-verifier": "漏洞理解+代码定位+验证执行",
        "c-formal-verifier": "验证执行",
        "binary-instrumentation-poc": "验证执行",
    }

    def label_session_phases(
        self, events: list[RawEvent], session_meta: dict
    ) -> tuple[dict[str, str], dict[str, str]]:
        """标注 session 的业务阶段。

        实现三层标注架构的第一层+第二层（程序确定性部分）。
        第三层 LLM 细分由 lifecycle 分析模块在 build_data_pack() 之后统一执行。

        流程：
        1. 从 events 提取所有 session_id（JSONL 文件名 = attempt_id）
        2. 用 AgentDBManager 查询 PostgreSQL vuln_verify_attempt 表获取 worker_type
        3. 按 docs/agent-session-phase-classification.md §3.5 的映射表将 worker_type → 业务阶段
        4. 返回 (session_phase_labels, session_phase_source)

        返回:
            session_phase_labels: session_id -> 业务阶段名称
            session_phase_source: session_id -> 标注来源标识符（worker_type 值）
        """
        session_phase_labels: dict[str, str] = {}
        session_phase_source: dict[str, str] = {}

        # Step 1: 从 events 提取所有 session_id
        session_ids = sorted({ev.session_id for ev in events if ev.session_id})
        if not session_ids:
            return session_phase_labels, session_phase_source

        # Step 2: 用 AgentDBManager 查询 PostgreSQL vuln_verify_attempt 表获取 worker_type
        worker_types = self._query_worker_type_from_db(session_ids)

        # Step 3: 按 worker_type → 业务阶段映射
        for sid, worker_type in worker_types.items():
            phase = self._WORKER_TYPE_PHASE_MAP.get(worker_type)
            if phase:
                session_phase_labels[sid] = phase
                session_phase_source[sid] = worker_type
            else:
                # 未知或空 worker_type：不标注阶段（L0–L7 跳过）
                session_phase_source[sid] = worker_type

        return session_phase_labels, session_phase_source

    def _query_worker_type_from_db(self, session_ids: list[str]) -> dict[str, str]:
        """从 CVulnVerify PostgreSQL ``vuln_verify_attempt`` 表查询 attempt_id → worker_type。

        SQL（来自 docs/agent-db-queries.md §5）::

            SELECT id, worker_type FROM vuln_verify_attempt WHERE id = ANY($1::uuid[])

        JSONL 文件名 = attempt_id（UUID），与 DB ``vuln_verify_attempt.id`` 直接对应。

        连接失败时返回空 dict（不抛异常——DB 查询是标注来源，非唯一数据源；
        连接失败的 session 将不被标注阶段，L0–L7 跳过）。
        """
        if not session_ids:
            return {}
        try:
            mgr = AgentDBManager()
            conn = mgr.get_connection("cvuln_verify")
            if conn is None:
                return {}
            try:
                cur = conn.cursor()
                # PostgreSQL 批量查询：id = ANY(%s::uuid[])
                # psycopg2 支持 list 参数直接传给 ANY(%s)
                cur.execute(
                    "SELECT id, worker_type FROM vuln_verify_attempt "
                    "WHERE id = ANY(%s::uuid[])",
                    (session_ids,),
                )
                rows = cur.fetchall()
                result: dict[str, str] = {}
                for row in rows:
                    attempt_id = str(row[0]) if row[0] else ""
                    worker_type = str(row[1]) if row[1] else ""
                    if attempt_id and worker_type:
                        result[attempt_id] = worker_type
                cur.close()
                return result
            finally:
                conn.close()
        except Exception as e:
            _log.debug("CVulnVerify _query_worker_type_from_db failed: %s", str(e)[:200])
            return {}
