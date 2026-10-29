"""DataflowVulnScanParser — dataflow_vuln_scan pi-agent JSONL session → Canonical RawEvent。

从老代码 ``workers/dataflow_trace_parser.py`` 拷贝核心逻辑，适配 v2 架构：
- 继承 ``v2.parsers.base.BaseParser``（而非老代码的 ``TraceParser``）
- import v2 内部模块（``core.raw_event``、``infra.agent_db``）
- 工具函数从本目录 ``.utils`` 导入
- 新增 ``label_session_phases()`` 方法实现 session 业务阶段标注

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
import re
import glob
import logging
from collections import defaultdict
from datetime import datetime

from ..base import BaseParser
from ...core.raw_event import RawEvent, detect_memory_flags, usage_numbers
from ...infra.agent_db import AgentDBManager
from .utils import (
    extract_json_payloads,
)

_log = logging.getLogger(__name__)


class DataflowVulnScanParser(BaseParser):
    """解析 dataflow_vuln_scan JSONL session 日志。"""

    def __init__(self, parser_version: str = "dataflow-1.0"):
        self.parser_version = parser_version
        self._tool_kg = {}
        self._tool_mem = {}
        self._seen_msg_ids: set[str] = set()
        self._original_uri: str | None = None

    # ------------------------------------------------------------------
    # BaseParser 抽象属性
    # ------------------------------------------------------------------

    @property
    def agent_type(self) -> str:
        return "dataflow"

    # ------------------------------------------------------------------
    # JSONL 文件解析
    # ------------------------------------------------------------------

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

        k8s 拷贝后 uri 为 /tmp/... 路径，不含 /data/files/，
        用 original_source_uri 兜底推导原始路径。
        """
        for candidate_uri in (uri, self._original_uri):
            if not candidate_uri:
                continue
            parts = candidate_uri.replace("\\", "/").rstrip("/").split("/")
            if "files" not in parts:
                continue
            idx = parts.index("files")
            if idx + 1 >= len(parts):
                continue
            project_id = parts[idx + 1]
            dvs_app = f"/data/files/{project_id}/app/secflow-app-dataflow-vuln-scan"
            if os.path.isdir(dvs_app):
                return dvs_app
        return None

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
                        # session_id 用 dvs_name 作 run_id（dvs_name 已含 dvs_ 前缀，
                        # 如 dvs_e211133b344c4c1e），与真实 scan session
                        # （dvs_{run_id}/d00-...）同前缀，供 findings extractor 的
                        # _map_to_real_session 把上报 finding 关联到真实挖掘 session。
                        # 不能再加 dvs_ 前缀（旧代码拼成 dvs_dvs_{run_id} 双前缀，
                        # 与 scan run_id 不匹配，映射失败导致占位 intake 被当真实 session）。
                        session_id=f"{dvs_name}/intake-result",
                        event_type="TEXT", timestamp_ms=ts,
                        message_id=d.get("id", ""), part_id=f"{eid}-x0",
                        step_no=None, tool_name=None,
                        input_json=None, output_json=findings_json,
                        raw_type="text", parse_status="OK",
                        source_table="jsonl", source_row_id=f"{eid}-x0",
                        parser_version=self.parser_version,
                    ))
        return results

    # ------------------------------------------------------------------
    # parse()
    # ------------------------------------------------------------------

    def parse(self, trace_source) -> list[RawEvent]:
        """trace_source: {source_uri: 目录路径或单 .jsonl 文件}"""
        uri = trace_source["source_uri"]
        self._original_uri = trace_source.get("original_source_uri")
        trace_id = trace_source.get("trace_id", uri)

        files = self._list_files(uri)

        # 预收集所有 toolCall 的 is_kg 和 memory 标记（按 id，供 toolResult 继承）
        self._tool_kg = {}
        self._tool_mem = {}
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
                                    tool_name = c.get("name", "")
                                    args = c.get("arguments", {})
                                    self._tool_kg[tid] = self._is_kg_call(tool_name, args)
                                    is_mem, is_mem_w = detect_memory_flags(tool_name, args)
                                    self._tool_mem[tid] = (is_mem, is_mem_w)

        events: list[RawEvent] = []
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
                        events.append(ev)

        # 从 DVS app 目录的 events.jsonl 提取上报记录（vuln_intake_result）
        # session 文件可能被清理，events.jsonl 是完整上报记录
        for ev in self._parse_intake_events(uri, trace_id):
            events.append(ev)

        return events

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
                    is_kg_interaction=self._tool_kg.get(tid, False) if tid else False,
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
        return usage_numbers(usage)

    # ------------------------------------------------------------------
    # load_session()
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # build_session_graph()
    # ------------------------------------------------------------------

    def build_session_graph(self, events: list[RawEvent]) -> dict:
        """构建 DVS session 关系图。

        只建 session_id 命名规则推导的 parent_map 父子边（真实调用关系）。
        不建共享文件/fact 边——共享不是调用关系，会导致 BFS 误连。
        """
        graph = {
            'sessions': {}, 'file_to_sessions': defaultdict(set),
            'fact_to_sessions': defaultdict(set), 'edges': defaultdict(set),
            'parent_map': {},
        }
        finding_to_session = {}

        # 第一遍：收集 session 元数据
        for ev in events:
            sid = ev.session_id
            if not sid:
                continue
            # intake 合成占位 session（dvs_{run}/intake-result）不是 trace 落地的
            # session 文件，不写入 session_graph——避免 debug/DTS 显示幽灵节点。
            # 其 case_id 提取仍保留（供 finding_to_session），但 sid 不进 sessions。
            if sid.endswith('/intake-result'):
                if ev.event_type == "TEXT" and ev.output_json:
                    text = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
                    if '"case_id"' in text:
                        for data in extract_json_payloads(text, keywords=['"case_id"', '"findings"']):
                            for f in (data.get("findings") or []):
                                case_id = str(f.get("case_id", ""))
                                if case_id:
                                    finding_to_session[case_id] = sid
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {'files': set(), 'facts': set(), 'athena_qs': [],
                                          'session_type': 'scan', 'memory_reads': []}
            sg = graph['sessions'][sid]

            # 从 session_id 路径提取 dvs_run_id（如 dvs_xxx/d00-func-judge-00）
            if 'dvs_run_id' not in sg:
                parts = sid.split('/')
                if parts and parts[0].startswith('dvs_'):
                    sg['dvs_run_id'] = parts[0]

            # 收集文件（仅用于多候选父消歧，不建边）
            if ev.is_tool_call():
                tool = ev.tool_name or ""
                inp = ev.input_json or {}
                if tool in ("bash", "bash_tool", "shell"):
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

                # 记忆读取路径
                if ev.is_memory_interaction:
                    cmd = str(inp.get("command", ""))
                    for m in re.finditer(r'(?:cat|head|tail|grep)\s+(\S*memengine\S+|/\S*app/memory\S*)', cmd):
                        sg['memory_reads'].append(m.group(1))

        # ---- Build parent_map from session_id naming rules ----
        # Format: dvs_xxx/d{depth}-{func}-{analysisType}-{param}-{index}[-TaintFunctionGuess][-error{N}]
        #
        # Analysis types (in flow order):
        #   taint/track/fptrack (initial, parallel) → vuln-judge → vuln-pattern-enhancement
        #   → vuln-false-positive-judge → vuln-report
        #
        # Five dimensions of parent-child:
        # 1. Cross-depth: d00→d01→d02 (function call chain)
        # 2. Same-depth analysis flow: taint/track/fptrack → vuln-judge → ...
        # 3. Error retry: -errorN → original (non-error)
        # 4. TaintFunctionGuess: sub-analysis of taint (same depth/func/param)
        # 5. Initial fork: track/fptrack fork from taint at same depth
        #
        # Error patterns differ by type:
        # - taint: error in param position: taint-error{N}-{index}
        # - track/fptrack/vuln-*: error at end: ...-error{N}$
        # - TaintFunctionGuess: error at end: ...-TaintFunctionGuess-error{N}
        if 'parent_map' not in graph:
            graph['parent_map'] = {}
        _ANALYSIS_FLOW = ['taint', 'track', 'fptrack', 'vuln-judge',
                          'vuln-pattern-enhancement', 'vuln-false-positive-judge', 'vuln-report']
        _INITIAL_TYPES = {'taint', 'track', 'fptrack'}

        _session_meta: dict[str, dict] = {}
        _depth_groups: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))

        for sid in graph['sessions']:
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
            #    vuln-report forks from same parent as vuln-false-positive-judge
            #    (report_parent_session), not from vuln-false-positive-judge itself
            if info['analysis_type'] and info['analysis_type'] not in _INITIAL_TYPES:
                at_idx = _ANALYSIS_FLOW.index(info['analysis_type'])
                _skip_types = set()
                if info['analysis_type'] == 'vuln-report':
                    _skip_types.add('vuln-false-positive-judge')
                for prev_idx in range(at_idx - 1, -1, -1):
                    prev_at = _ANALYSIS_FLOW[prev_idx]
                    if prev_at in _skip_types:
                        continue
                    # Two passes: prefer non-error, fall back to error
                    for _accept_error in (False, True):
                        for other_sid, other_info in _session_meta.items():
                            if (other_info['dvs_run'] == dvs_run and
                                other_info['depth'] == depth and
                                other_info['func'] == info['func'] and
                                other_info['analysis_type'] == prev_at and
                                not other_info['is_tfg'] and
                                bool(other_info['error_num']) == _accept_error):
                                graph['parent_map'][sid] = other_sid
                                break
                        if sid in graph['parent_map']:
                            break
                    if sid in graph['parent_map']:
                        break
                if sid in graph['parent_map']:
                    continue

            # 3b. Initial fork: track/fptrack → taint session at same depth
            if info['analysis_type'] in _INITIAL_TYPES and info['analysis_type'] != 'taint':
                best_parent = None
                best_count = -1
                for other_sid, other_info in _session_meta.items():
                    if (other_info['dvs_run'] == dvs_run and
                        other_info['depth'] == depth and
                        other_info['func'] == info['func'] and
                        other_info['analysis_type'] == 'taint' and
                        not other_info['is_tfg']):
                        shared = 0
                        for _fid, f_sids in graph.get('file_to_sessions', {}).items():
                            if sid in f_sids and other_sid in f_sids:
                                shared += 1
                        if shared > best_count:
                            best_count = shared
                            best_parent = other_sid
                if best_parent is not None:
                    graph['parent_map'][sid] = best_parent
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

        # 从 parent_map 构建 edges
        for sid, pid in graph['parent_map'].items():
            graph['edges'][sid].add(pid)
            graph['edges'][pid].add(sid)

        graph['finding_to_session'] = finding_to_session
        return graph

    # ------------------------------------------------------------------
    # label_session_phases() — 新实现
    # ------------------------------------------------------------------

    # analysisType → 业务阶段映射（来自 docs/agent-session-phase-classification.md §3.4
    #   和 docs/knowledge-effect-eval-requirements.md §4.1）
    _ANALYSIS_TYPE_PHASE_MAP: dict[str, str] = {
        "taint": "数据流追踪",
        "track": "数据流追踪",
        "fptrack": "数据流追踪",
        "vuln-judge": "漏洞判定与上报",
        "vuln-pattern-enhancement": "漏洞模式识别",
        "vuln-false-positive-judge": "漏洞判定与上报",
        "vuln-report": "漏洞判定与上报",
    }

    # analysisType 枚举（按 flow 顺序，用于文件名解析时最长匹配优先）
    _ANALYSIS_FLOW = [
        'taint', 'track', 'fptrack', 'vuln-judge',
        'vuln-pattern-enhancement', 'vuln-false-positive-judge', 'vuln-report',
    ]

    @classmethod
    def _extract_analysis_type_from_session_id(cls, session_id: str) -> str | None:
        """从 session_id（JSONL 文件名去掉扩展名后的相对路径）解析 analysisType。

        文件名格式（来自 docs/agent-session-phase-classification.md §3.4）：
          dvs_xxx/d{depth:02d}-{func}-{analysisType}-{taint}-{NN}

        示例：dvs_abc/d00-main_handler-taint-taint_param-01
              dvs_abc/d01-helper-vuln-judge-some_param-02

        解析规则：
          1. 取 '/' 后的文件名部分
          2. 去掉 d{depth}- 前缀
          3. 去掉 TaintFunctionGuess 后缀（含可选 error）
          4. 去掉 error 后缀
          5. 在剩余部分中匹配 analysisType（最长优先，用 -{type}- 或 -{type} 结尾）

        返回 analysisType 字符串，无法提取时返回 None。
        """
        if not session_id:
            return None

        parts = session_id.split('/')
        if len(parts) < 2 or not parts[0].startswith('dvs_'):
            return None
        rest = parts[1]

        # 去掉 d{depth}- 前缀
        m_depth = re.match(r'd(\d+)-(.+)', rest)
        if not m_depth:
            return None
        rest2 = m_depth.group(2)

        # 去掉 TaintFunctionGuess 后缀（含可选 error）
        tfg_m = re.search(r'-TaintFunctionGuess(-error(\d+))?$', rest2)
        if tfg_m:
            rest2 = rest2[:tfg_m.start()]

        # 去掉 error 后缀
        err_m = re.search(r'-error(\d+)$', rest2)
        if err_m:
            rest2 = rest2[:err_m.start()]

        # 匹配 analysisType（最长优先，避免 'vuln-judge' 被 'taint' 部分匹配）
        for at in sorted(cls._ANALYSIS_FLOW, key=len, reverse=True):
            marker = f'-{at}-'
            if marker in rest2:
                return at
        for at in sorted(cls._ANALYSIS_FLOW, key=len, reverse=True):
            if rest2.endswith(f'-{at}'):
                return at

        return None

    def _query_session_kind_from_db(
        self, session_ids: list[str], project_id: str | None
    ) -> dict[str, str]:
        """从 DVS MySQL ``dvs_task_graph_sessions`` 表查询 session_kind（即 analysisType）。

        SQL（来自 docs/agent-db-queries.md §4）：
            SELECT session_relpath, session_kind
            FROM dvs_task_graph_sessions
            WHERE session_kind IS NOT NULL

        注意（来自 docs/data-verification.md）：
        - session_kind 就是 analysisType，5 个值完全一致
        - 7 个旧库查询 dvs_task_graph_sessions 会遇"表不存在"错误，需降级到 orchestration 表
        - orchestration 表无 session_kind 字段，无法提取 analysisType（从文件名提取即可）

        连接失败或表不存在时返回空 dict（不抛异常——DB 查询是交叉验证，文件名提取是主要来源）。
        """
        if not session_ids:
            return {}
        try:
            mgr = AgentDBManager()
            conn = mgr.get_connection("dataflow", project_id=project_id)
            if conn is None:
                return {}
            try:
                cur = conn.cursor()
                # 先检测 dvs_task_graph_sessions 表是否存在
                cur.execute("SHOW TABLES LIKE 'dvs_task_graph_sessions'")
                if cur.fetchone() is None:
                    # 旧库无此表，降级到 orchestration（但 orchestration 无 session_kind）
                    # 无法提取 analysisType，返回空 dict（文件名提取是主要来源）
                    cur.close()
                    return {}
                # 查询 session_kind
                placeholders = ", ".join(["%s"] * len(session_ids))
                sql = (
                    f"SELECT session_relpath, session_kind "
                    f"FROM dvs_task_graph_sessions "
                    f"WHERE session_relpath IN ({placeholders}) "
                    f"AND session_kind IS NOT NULL"
                )
                cur.execute(sql, session_ids)
                rows = cur.fetchall()
                result: dict[str, str] = {}
                for row in rows:
                    sid = row[0]
                    kind = row[1]
                    if sid and kind:
                        result[sid] = str(kind)
                cur.close()
                return result
            finally:
                conn.close()
        except Exception as e:
            _log.debug("DataflowVulnScan _query_session_kind_from_db failed: %s",
                       str(e)[:200])
            return {}

    def _extract_project_id(self, trace_source: dict) -> str | None:
        """从 trace_source 的 source_uri 或 original_source_uri 推导 project_id。

        路径格式：/data/files/{project_id}/tasks/{task_id}/session/dataflow_vuln_scan
        """
        for key in ("source_uri", "original_source_uri"):
            uri = trace_source.get(key)
            if not uri:
                continue
            parts = uri.replace("\\", "/").rstrip("/").split("/")
            if "files" not in parts:
                continue
            idx = parts.index("files")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return None

    def label_session_phases(
        self, events: list[RawEvent], session_meta: dict
    ) -> tuple[dict[str, str], dict[str, str]]:
        """标注 session 的业务阶段。

        实现三层标注架构的第一层+第二层（程序确定性部分）。
        第三层 LLM 细分由 lifecycle 分析模块在 build_data_pack() 之后统一执行。

        流程（来自 docs/agent-session-phase-classification.md §3.4）：
        1. 从 JSONL 文件名（session_id）解析 analysisType 字段
           格式：d{depth}-{func}-{analysisType}-{taint}-{NN}
        2. 按 §3.4 的映射表将 analysisType → 业务阶段
        3. 如果文件名无法提取 analysisType，用 AgentDBManager 查询
           dvs_task_graph_sessions 表的 session_kind 字段（session_kind = analysisType）
           旧库无此表时降级（orchestration 表无 session_kind，从文件名提取即可）
        4. 返回 (session_phase_labels, session_phase_source)

        返回:
            session_phase_labels: session_id -> 业务阶段名称
            session_phase_source: session_id -> 标注来源标识符（analysisType 值）
        """
        session_phase_labels: dict[str, str] = {}
        session_phase_source: dict[str, str] = {}

        # 收集所有 session_id
        all_sids = {ev.session_id for ev in events if ev.session_id}

        # Step 1: 从 session_id（文件名）提取 analysisType
        session_analysis_types: dict[str, str] = {}
        for sid in all_sids:
            at = self._extract_analysis_type_from_session_id(sid)
            if at:
                session_analysis_types[sid] = at

        # Step 2: 对未从文件名提取到 analysisType 的 session，查 DVS MySQL
        missing_sids = [sid for sid in all_sids if sid not in session_analysis_types]
        if missing_sids:
            # 从 session_meta 或 trace_source 推导 project_id
            # session_meta 是 load_session() 返回的 dict，不含 project_id
            # 尝试从 _original_uri 推导
            project_id = None
            if self._original_uri:
                parts = self._original_uri.replace("\\", "/").rstrip("/").split("/")
                if "files" in parts:
                    idx = parts.index("files")
                    if idx + 1 < len(parts):
                        project_id = parts[idx + 1]

            db_analysis_types = self._query_session_kind_from_db(missing_sids, project_id)
            for sid, kind in db_analysis_types.items():
                session_analysis_types[sid] = kind

        # Step 3: 按 analysisType → 业务阶段映射
        for sid, analysis_type in session_analysis_types.items():
            phase = self._ANALYSIS_TYPE_PHASE_MAP.get(analysis_type)
            if phase:
                session_phase_labels[sid] = phase
                session_phase_source[sid] = analysis_type
            else:
                # 未知 analysisType：不标注阶段
                session_phase_source[sid] = analysis_type

        return session_phase_labels, session_phase_source
