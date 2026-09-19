"""CVulnVerifyTraceParser — CVulnVerify JSONL session → Canonical RawEvent。

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
from typing import Iterator
from datetime import datetime
from ..domain.raw_event import RawEvent
from ..domain.resolvers import TraceParser
from ..infrastructure.log_util import log
from .parse_utils import parse_json_lenient


class CVulnVerifyTraceParser(TraceParser):
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
            log("CVULN", f"benchmark case 过滤: task={source_task_id} "
                  f"files={len(task_files)} -> {len(filtered)}")
            return filtered

        # 不同 benchmark 来源的 case ID 可能不在同一命名空间。完全不命中时
        # 保留任务级过滤，避免把有效 trace 错误地解析为空。
        log("CVULN", f"benchmark case 未命中 trace，回退任务级过滤: "
              f"task={source_task_id} benchmark_cases={len(source_case_ids)} "
              f"task_files={len(task_files)}")
        return [path for path, _ in task_files]

    def _source_task_id(self, path: str) -> str | None:
        """从首条用户任务上下文中的历史记忆路径提取原始平台任务 ID。"""
        return self._trace_metadata(path)[0]

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

    def parse(self, trace_source) -> Iterator[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)
        session_id = trace_source.get("turing_session_id", "")

        files = self._files(trace_source)

        # 预收集所有 toolCall 的 is_kg 和 memory 标记（按 id）
        self._tool_kg = {}
        self._tool_mem = {}
        from ..domain.raw_event import detect_memory_flags
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

    @staticmethod
    def _is_finding_tool(tool_name: str, args) -> bool:
        """CVulnVerify 平台 finding 提交：write/bash 写 vuln_verify_final_verdict。"""
        t = tool_name or ""
        if t == "write" and isinstance(args, dict):
            fp = str(args.get("file_path") or args.get("path") or "")
            return "vuln_verify_final_verdict" in fp
        if t in ("bash", "bash_tool", "shell") and isinstance(args, dict):
            cmd = str(args.get("command", ""))
            return "vuln_verify_final_verdict" in cmd
        return False

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
                    call_id=getattr(self, "_last_tool_id", ""),
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
                    from ..domain.raw_event import detect_memory_flags
                    is_mem, is_mem_w = detect_memory_flags(tool_name, args)
                    is_finding = self._is_finding_tool(tool_name, args)
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
                        is_finding_submission=is_finding,
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
                                from ..domain.raw_event import usage_numbers
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

    def build_session_graph(self, events):
        """构建 CVulnVerify session 关系图。

        只建 SESSION_START parent_id 父子边（真实调用关系）。
        不建共享文件/fact 边——共享不是调用关系，会导致 BFS 误连。
        """
        import re
        import json
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

            # SESSION_START: 提取 parent_id → parent_map
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
        return CVulnVerifyTraceParser._parse_verdict_json(cmd[brace_idx:])

    def _extract_action(self, ev):
        """CVulnVerify 平台挖掘行为：write vuln_verify_final_verdict 为结论点。"""
        tool = ev.tool_name or ""
        ts = ev.timestamp_ms or 0
        if tool == "write":
            inp = ev.input_json or {}
            fp = str(inp.get("file_path") or inp.get("path") or "")
            if "vuln_verify_final_verdict" in fp:
                return {"tool": "finding", "action": fp, "session_id": ev.session_id, "ts": ts}
        return super()._extract_action(ev)

    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """提取 CVulnVerify 平台的 finding（verdict）。

        两种提交方式：
        1. write 工具写 vuln_verify_final_verdict.json
        2. bash cat > heredoc 写 vuln_verify_final_verdict.json

        agent 写的 verdict JSON 可能有语法错误（未终止字符串、缺少分隔符等），
        json.loads 失败时依次回退 raw_decode → regex 提取 case_id/verdict。
        """
        from .parse_utils import attach_event_indices
        findings: dict[str, dict] = {}

        for _ei, e in enumerate(events):
            if not e.is_tool_call():
                continue
            tool = e.tool_name or ""
            inp = e.input_json or {}

            # write 工具写 verdict JSON
            if tool == "write":
                fp = str(inp.get("file_path") or inp.get("path") or "")
                if "vuln_verify_final_verdict" in fp:
                    content = inp.get("content", "")
                    if isinstance(content, str):
                        vdata = self._parse_verdict_json(content)
                        if vdata:
                            f = self._build_finding(vdata, e)
                            if f:
                                findings[f["finding_id"]] = f

            # bash cat > heredoc 写 verdict JSON
            elif tool in ("bash", "bash_tool", "shell"):
                cmd = str(inp.get("command", ""))
                if "vuln_verify_final_verdict" in cmd:
                    vdata = self._extract_verdict_from_bash_cmd(cmd)
                    if vdata:
                        f = self._build_finding(vdata, e)
                        if f:
                            findings[f["finding_id"]] = f

        attach_event_indices(findings, events)
        return list(findings.values())

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
            return vdata
        return None

    @staticmethod
    def _build_finding(vdata: dict, e) -> dict | None:
        """从解析后的 verdict dict 构建 finding dict。"""
        case_id = str(vdata.get("case_id", "")) or f"cvv-{e.event_id}"
        verdict = vdata.get("verdict", "")
        vr = "CONFIRMED" if verdict == "confirmed" else ("FALSE_POSITIVE" if verdict == "ruled_out" else "UNCERTAIN")
        case_title = str(vdata.get("case_title", "") or vdata.get("title", "") or "")
        vt = str(vdata.get("vuln_type", "") or vdata.get("vulnerability_type", "") or "")
        src = str(vdata.get("source_file", "") or vdata.get("source", "") or "")
        fn = str(vdata.get("function_name", "") or vdata.get("sink", "") or "")
        desc = str(vdata.get("summary", "") or vdata.get("description", "") or "")
        if not desc:
            desc = str(vdata.get("ruled_out_by", ""))
        return {
            "finding_id": case_id,
            "display_id": case_id,
            "title": case_title if case_title else f"CVulnVerify {case_id}",
            "description": desc,
            "vuln_type": vt,
            "severity": str(vdata.get("severity", "")),
            "source": src,
            "sink": fn,
            "validation_result": vr,
            "platform": "cvuln-verify",
            "session_id": e.session_id,
        }
