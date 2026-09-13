"""DataflowVulnScanTraceParser — dataflow_vuln_scan pi-agent JSONL session → Canonical RawEvent。

Trace 路径：/data/files/{project_id}/tasks/{task_id}/session/dataflow_vuln_scan/

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
from ..domain.resolvers import TraceParser
from .parse_utils import _extract_json_objects_from_text, attach_event_indices


class DataflowVulnScanTraceParser(TraceParser):
    """解析 dataflow_vuln_scan JSONL session 日志。"""

    def __init__(self, parser_version: str = "dataflow-1.0"):
        self.parser_version = parser_version
        self._tool_kg = {}
        self._tool_mem = {}
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

    def _find_dvs_app_dir(self, uri: str) -> str | None:
        """从 trace 目录路径推导 DVS app 目录路径。

        trace: /data/files/{project_id}/tasks/{task_id}/session/dataflow_vuln_scan
        app:   /data/files/{project_id}/app/secflow-app-dataflow-vuln-scan
        """
        parts = uri.replace("\\", "/").rstrip("/").split("/")
        if "files" not in parts:
            return None
        idx = parts.index("files")
        if idx + 1 >= len(parts):
            return None
        project_id = parts[idx + 1]
        dvs_app = f"/data/files/{project_id}/app/secflow-app-dataflow-vuln-scan"
        return dvs_app if os.path.isdir(dvs_app) else None

    def _parse_intake_events(self, uri: str, trace_id: str) -> list[RawEvent]:
        """从 DVS app 目录的 events.jsonl 提取 vuln_intake_result 事件。

        每个 status=reported 的 vuln_intake_result 对应一个漏洞中心 case。
        session 文件可能被清理（4/33 个 DVS run），events.jsonl 是完整记录。
        """
        dvs_app = self._find_dvs_app_dir(uri)
        if not dvs_app:
            return []

        events_files = sorted(glob.glob(
            os.path.join(dvs_app, "dvs_*", "output", "events.jsonl")
        ))
        results: list[RawEvent] = []
        for fpath in events_files:
            dvs_name = os.path.basename(os.path.dirname(os.path.dirname(fpath)))
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if d.get("event_type") != "vuln_intake_result":
                        continue
                    # 不按 parent_task_id 过滤：同一 project 下多个 T001 任务
                    # 各自触发 DVS 扫描并上报漏洞，T002 收到的是全部，parser 也应取全部。
                    payload = d.get("payload", {})
                    if payload.get("status") != "reported":
                        continue
                    fid = str(payload.get("finding_id", ""))
                    case_id = str(payload.get("case_id", ""))
                    fn = str(payload.get("function", ""))
                    ln = str(payload.get("line", ""))
                    title = str(payload.get("title", ""))
                    vt = str(payload.get("vuln_type", ""))
                    severity = str(payload.get("severity", ""))
                    source_file = str(payload.get("source_file", ""))
                    summary = str(payload.get("summary", ""))
                    findings_json = json.dumps({
                        "findings": [{
                            "finding_id": fid,
                            "case_id": case_id,
                            "function_name": fn,
                            "line": ln,
                            "title": title,
                            "vuln_type": vt,
                            "severity": severity,
                            "source_file": source_file,
                            "summary": summary,
                        }]
                    }, ensure_ascii=False)
                    ts = self._parse_ts(d.get("created_at", ""))
                    eid = f"intake-{dvs_name}-{line_no}"
                    results.append(RawEvent(
                        event_id=eid, trace_id=trace_id,
                        session_id="dvs-intake-result",
                        event_type="TEXT", timestamp_ms=ts,
                        message_id=d.get("id", ""), part_id=f"{eid}-x0",
                        step_no=None, tool_name=None,
                        input_json=None, output_json=findings_json,
                        raw_type="text", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-x0",
                        parser_version=self.parser_version,
                    ))
        return results

    def parse(self, trace_source) -> Iterator[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        trace_id = trace_source.get("trace_id", uri)

        files = self._list_files(uri)

        # 预收集所有 toolCall 的 is_kg 和 memory 标记（按 id，供 toolResult 继承）
        self._tool_kg = {}
        self._tool_mem = {}
        self._seen_msg_ids = set()
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
                                if tid:
                                    tool_name = c.get("name", "")
                                    args = c.get("arguments", {})
                                    self._tool_kg[tid] = self._is_kg_call(tool_name, args)
                                    is_mem, is_mem_w = detect_memory_flags(tool_name, args)
                                    self._tool_mem[tid] = (is_mem, is_mem_w)

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

        # 从 DVS app 目录的 events.jsonl 提取上报记录（vuln_intake_result）
        # session 文件可能被清理，events.jsonl 是完整上报记录
        for ev in self._parse_intake_events(uri, trace_id):
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
                tool_name = msg.get("toolName", "")
                tid = msg.get("toolCallId", "")
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
                    call_id=tid,
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
                        from ..domain.raw_event import detect_memory_flags
                        is_mem, is_mem_w = detect_memory_flags(tool_name, args)
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
                            is_memory_interaction=is_mem,
                            is_memory_write=is_mem_w,
                            call_id=tid,
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
        from ..domain.raw_event import usage_numbers
        return usage_numbers(usage)

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

    def build_session_graph(self, events):
        """构建 DVS session 关系图。

        在基类（共享文件/fact/athena 查询）基础上增加：
        - session_type = 'scan'
        - finding_to_session 映射（case_id → dvs-intake-result）
        - dvs_run_id 标注（从 session_id 路径提取）
        - intake session → 同 dvs_run_id 的分析 session 边
        - 记忆读取路径
        """
        import re
        graph = super().build_session_graph(events)
        finding_to_session = {}

        # 第一遍：标注 session_type、dvs_run_id，提取 intake case_id
        for ev in events:
            sid = ev.session_id
            if not sid or sid not in graph.get('sessions', {}):
                continue
            sg = graph['sessions'][sid]
            if 'session_type' not in sg:
                sg['session_type'] = 'scan'
            if 'memory_reads' not in sg:
                sg['memory_reads'] = []

            # 从 session_id 路径提取 dvs_run_id（如 dvs_xxx/d00-func-judge-00）
            if 'dvs_run_id' not in sg:
                parts = sid.split('/')
                if parts and parts[0].startswith('dvs_'):
                    sg['dvs_run_id'] = parts[0]
                elif sid == 'dvs-intake-result':
                    sg['dvs_run_id'] = ''

            # intake events: 提取 case_id
            if sid == 'dvs-intake-result' and ev.event_type == "TEXT" and ev.output_json:
                text = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
                if '"case_id"' in text:
                    for data in _extract_json_objects_from_text(text):
                        for f in (data.get("findings") or []):
                            case_id = str(f.get("case_id", ""))
                            if case_id:
                                finding_to_session[case_id] = sid

            # 记忆读取路径
            if ev.is_tool_call() and ev.is_memory_interaction:
                tool = ev.tool_name or ""
                inp = ev.input_json or {}
                if tool in ("bash", "bash_tool", "shell"):
                    cmd = str(inp.get("command", ""))
                    for m in re.finditer(r'(?:cat|head|tail|grep)\s+(\S*memengine\S+|/\S*app/memory\S*)', cmd):
                        sg['memory_reads'].append(m.group(1))

        # 第二遍：为 intake session 建边到同 dvs_run_id 的分析 session
        intake_session = graph['sessions'].get('dvs-intake-result')
        if intake_session:
            # 收集所有有 case_id 的 dvs_run_id
            intake_dvs_runs: set[str] = set()
            for ev in events:
                if ev.session_id == 'dvs-intake-result' and ev.event_id:
                    # event_id 格式: intake-{dvs_name}-{line_no}
                    parts = ev.event_id.split('-', 2)
                    if len(parts) >= 2:
                        intake_dvs_runs.add(parts[1])

            # 为每个有 finding 的 dvs_run_id 创建边
            for sid, sg in graph['sessions'].items():
                dvs_run = sg.get('dvs_run_id', '')
                if dvs_run and dvs_run in intake_dvs_runs:
                    graph['edges']['dvs-intake-result'].add(sid)
                    graph['edges'][sid].add('dvs-intake-result')

        graph['finding_to_session'] = finding_to_session
        return graph

    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """提取 DataflowVulnScan 平台的 finding。

        两个数据源：
        1. intake events（dvs-intake-result session）— 服务端自动提交到漏洞中心的记录
        2. candidates JSON（vuln-judge 阶段）— 仅在无 intake events 时补充
        """
        findings: dict[str, dict] = {}
        _dvs_counter = 0
        _dvs_fn_lines_with_findings: set[str] = set()
        _has_intake_events = any(
            e.event_type == "TEXT" and e.session_id == "dvs-intake-result"
            for e in events
        )

        for e in events:
            if e.event_type != "TEXT" or not e.output_json:
                continue
            if _has_intake_events and e.session_id != "dvs-intake-result":
                continue
            text = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
            if '"findings"' not in text:
                continue
            for data in _extract_json_objects_from_text(text):
                for f in (data.get("findings") or []):
                    _dvs_counter += 1
                    title = str(f.get("title", ""))
                    fn = str(f.get("function_name", ""))
                    ln = str(f.get("line", ""))
                    vt = str(f.get("vuln_type", ""))
                    _dvs_fn_lines_with_findings.add(f"{fn}:{ln}")
                    case_id = str(f.get("case_id", ""))
                    fid = case_id if case_id else f"dvs-{_dvs_counter}"
                    findings[fid] = {
                        "finding_id": str(f.get("finding_id", fid)),
                        "display_id": fid,
                        "title": title,
                        "description": str(f.get("summary", "")),
                        "vuln_type": vt,
                        "severity": str(f.get("severity", "")),
                        "source": str(f.get("source_file", "")),
                        "sink": fn,
                        "validation_result": "CONFIRMED",
                        "platform": "dataflow-vuln-scan",
                        "session_id": e.session_id,
                    }

        # 补充: 从 vuln-judge 阶段的 candidates JSON 提取 confirmed 候选
        if not _has_intake_events:
            for e in events:
                if e.event_type != "TEXT" or not e.output_json:
                    continue
                text = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
                if '"candidates"' not in text:
                    continue
                for data in _extract_json_objects_from_text(text):
                    for f in (data.get("candidates") or []):
                        if f.get("judgment") != "confirmed":
                            continue
                        fn = str(f.get("function_name", ""))
                        ln = str(f.get("line", ""))
                        if f"{fn}:{ln}" in _dvs_fn_lines_with_findings:
                            continue
                        _dvs_counter += 1
                        vt = str(f.get("vuln_type", ""))
                        fid = f"dvs-{_dvs_counter}"
                        findings[fid] = {
                            "finding_id": fid,
                            "display_id": fid,
                            "title": vt,
                            "description": str(f.get("reason", "")),
                            "vuln_type": vt,
                            "severity": str(f.get("severity", "")),
                            "source": str(f.get("source_evidence", "")),
                            "sink": fn,
                            "validation_result": "CONFIRMED",
                            "platform": "dataflow-vuln-scan",
                            "session_id": e.session_id,
                        }

        attach_event_indices(findings, events)
        return list(findings.values())

