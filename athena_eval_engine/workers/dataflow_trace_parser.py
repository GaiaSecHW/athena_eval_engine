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
from .parse_utils import _extract_json_objects_from_text, attach_event_indices, extract_json_payloads


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

        每个 dvs_run_id 是一组独立的函数分析运行（按调用链深度 d00→d01→d02
        关联）。不同 dvs_run_id 之间无调用链关系，不应建边。

        基类按共享文件/fact 建边，但不同 dvs_run 可能分析同一源文件
        （如 hks_core.c），产生跨 dvs_run 的传递性边，导致 BFS 全连通。
        因此在基类建边后，按 dvs_run_id 过滤：只保留同 dvs_run 内的边。

        dvs-intake-result 是虚拟 session（汇总 events.jsonl 提交记录），
        不属于任何分析链，不参与建边。
        """
        import re
        from collections import defaultdict
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
                    for data in extract_json_payloads(text, keywords=['"case_id"', '"findings"']):
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

        # 第二遍：按 dvs_run_id 过滤边，只保留同 dvs_run 内的连接
        # 基类可能因跨 dvs_run 共享文件产生噪声边，这里重建
        _MAX_SESSIONS_PER_LINK = 5
        filtered_edges = defaultdict(set)

        for fid, sids in graph.get('fact_to_sessions', {}).items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            r1 = graph['sessions'].get(s1, {}).get('dvs_run_id', '')
                            r2 = graph['sessions'].get(s2, {}).get('dvs_run_id', '')
                            if r1 and r2 and r1 == r2:
                                filtered_edges[s1].add(s2)

        for fm, sids in graph.get('file_to_sessions', {}).items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            r1 = graph['sessions'].get(s1, {}).get('dvs_run_id', '')
                            r2 = graph['sessions'].get(s2, {}).get('dvs_run_id', '')
                            if r1 and r2 and r1 == r2:
                                filtered_edges[s1].add(s2)

        graph['edges'] = filtered_edges

        # ---- Build parent_map from session_id naming rules ----
        # Format: dvs_xxx/d{depth}-{func}-{analysisType}-{param}-{index}[-TaintFunctionGuess][-error{N}]
        #
        # Analysis types (in flow order):
        #   taint/track (initial, parallel) → vuln-judge → vuln-pattern-enhancement
        #   → vuln-false-positive-judge → vuln-report
        #
        # Four dimensions of parent-child:
        # 1. Cross-depth: d00→d01→d02 (function call chain)
        # 2. Same-depth analysis flow: taint/track → vuln-judge → ...
        # 3. Error retry: -errorN → original (non-error)
        # 4. TaintFunctionGuess: sub-analysis of taint (same depth/func/param)
        #
        # Error patterns differ by type:
        # - taint: error in param position: taint-error{N}-{index}
        # - track/vuln-*: error at end: ...-error{N}$
        # - TaintFunctionGuess: error at end: ...-TaintFunctionGuess-error{N}
        if 'parent_map' not in graph:
            graph['parent_map'] = {}
        _ANALYSIS_FLOW = ['taint', 'track', 'vuln-judge',
                          'vuln-pattern-enhancement', 'vuln-false-positive-judge', 'vuln-report']
        _INITIAL_TYPES = {'taint', 'track'}

        _session_meta: dict[str, dict] = {}
        _depth_groups: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))

        for sid in graph['sessions']:
            if sid == 'dvs-intake-result':
                continue
            parts = sid.split('/')
            if len(parts) < 2 or not parts[0].startswith('dvs_'):
                continue
            dvs_run = parts[0]
            rest = parts[1]

            m_depth = re.match(r'd(\d+)-(.+)', rest)
            if not m_depth:
                continue
            depth = int(m_depth.group(1))
            rest2 = m_depth.group(2)

            # 1. Strip TaintFunctionGuess suffix (with optional error)
            is_tfg = False
            error_num = 0
            tfg_m = re.search(r'-TaintFunctionGuess(-error(\d+))?$', rest2)
            if tfg_m:
                is_tfg = True
                if tfg_m.group(2):
                    error_num = int(tfg_m.group(2))
                rest2 = rest2[:tfg_m.start()]

            # 2. Strip error suffix at end (for track, vuln-*, non-TFG taint)
            if error_num == 0:
                err_m = re.search(r'-error(\d+)$', rest2)
                if err_m:
                    error_num = int(err_m.group(1))
                    rest2 = rest2[:err_m.start()]

            # 3. Identify analysis type (search longest first to avoid partial matches)
            analysis_type = ''
            for at in sorted(_ANALYSIS_FLOW, key=len, reverse=True):
                marker = f'-{at}-'
                if marker in rest2:
                    analysis_type = at
                    break
            if not analysis_type:
                for at in sorted(_ANALYSIS_FLOW, key=len, reverse=True):
                    if rest2.endswith(f'-{at}'):
                        analysis_type = at
                        break

            # 4. Split function name and param signature
            func = rest2
            param_sig = ''
            if analysis_type:
                marker = f'-{analysis_type}-'
                idx = rest2.find(marker)
                if idx > 0:
                    func = rest2[:idx]
                    param_sig = rest2[idx + len(marker):]
                else:
                    idx = rest2.rfind(f'-{analysis_type}')
                    if idx > 0:
                        func = rest2[:idx]

            # 5. Handle taint error in param position: taint-error{N}-{index}
            #    (taint retries have error{N} where param should be, not at end)
            if analysis_type == 'taint' and not is_tfg and param_sig:
                err_param_m = re.match(r'error(\d+)(?:-(.+))?$', param_sig)
                if err_param_m:
                    error_num = int(err_param_m.group(1))
                    param_sig = err_param_m.group(2) or ''

            _session_meta[sid] = {
                'dvs_run': dvs_run, 'depth': depth, 'func': func,
                'analysis_type': analysis_type, 'error_num': error_num,
                'is_tfg': is_tfg, 'param_sig': param_sig,
            }
            _depth_groups[dvs_run][depth].append(sid)

        for sid, info in _session_meta.items():
            dvs_run = info['dvs_run']
            depth = info['depth']

            # 1. Error retry → parent is non-error original
            if info['error_num'] > 0:
                for other_sid, other_info in _session_meta.items():
                    if (other_info['dvs_run'] == dvs_run and
                        other_info['depth'] == depth and
                        other_info['func'] == info['func'] and
                        other_info['analysis_type'] == info['analysis_type'] and
                        other_info['error_num'] == 0 and
                        other_info['is_tfg'] == info['is_tfg']):
                        # For TFG errors, also match param_sig
                        if info['is_tfg'] and other_info['param_sig'] != info['param_sig']:
                            continue
                        graph['parent_map'][sid] = other_sid
                        break
                continue

            # 2. TaintFunctionGuess → parent is corresponding taint session
            if info['is_tfg']:
                for other_sid, other_info in _session_meta.items():
                    if (other_info['dvs_run'] == dvs_run and
                        other_info['depth'] == depth and
                        other_info['func'] == info['func'] and
                        other_info['analysis_type'] == 'taint' and
                        not other_info['is_tfg'] and
                        other_info['error_num'] == 0 and
                        other_info['param_sig'] == info['param_sig']):
                        graph['parent_map'][sid] = other_sid
                        break
                continue

            # 3. Same-depth analysis flow → parent is previous analysis type
            if info['analysis_type'] and info['analysis_type'] not in _INITIAL_TYPES:
                at_idx = _ANALYSIS_FLOW.index(info['analysis_type'])
                for prev_idx in range(at_idx - 1, -1, -1):
                    prev_at = _ANALYSIS_FLOW[prev_idx]
                    for other_sid, other_info in _session_meta.items():
                        if (other_info['dvs_run'] == dvs_run and
                            other_info['depth'] == depth and
                            other_info['func'] == info['func'] and
                            other_info['analysis_type'] == prev_at and
                            other_info['error_num'] == 0 and
                            not other_info['is_tfg']):
                            graph['parent_map'][sid] = other_sid
                            break
                    if sid in graph['parent_map']:
                        break
                if sid in graph['parent_map']:
                    continue

            # 4. Cross-depth → parent is at depth N-1
            if depth > 0:
                prev_sids = _depth_groups[dvs_run].get(depth - 1, [])
                if len(prev_sids) == 1:
                    graph['parent_map'][sid] = prev_sids[0]
                elif len(prev_sids) > 1:
                    # Use shared files to find closest parent
                    best_parent = None
                    best_count = -1
                    for p_sid in prev_sids:
                        shared = 0
                        for _fid, f_sids in graph.get('file_to_sessions', {}).items():
                            if sid in f_sids and p_sid in f_sids:
                                shared += 1
                        if shared > best_count:
                            best_count = shared
                            best_parent = p_sid
                    if best_parent and best_count > 0:
                        graph['parent_map'][sid] = best_parent

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
            for data in extract_json_payloads(text, keywords=['"findings"']):
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
                for data in extract_json_payloads(text, keywords=['"candidates"']):
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

