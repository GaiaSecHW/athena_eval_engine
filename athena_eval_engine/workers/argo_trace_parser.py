"""ArgoTraceParser — Claude Code JSONL session 日志 → Canonical RawEvent。

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
from ..domain.raw_event import RawEvent
from ..domain.resolvers import TraceParser
from .parse_utils import attach_event_indices, _extract_json_objects_from_text


# Claude Code 工具名 → 小写
_TOOL_MAP = {
    "Bash": "bash", "Read": "read", "Grep": "grep", "Glob": "glob",
    "Write": "write", "Edit": "edit", "Task": "task", "Skill": "skill",
}


class ArgoTraceParser(TraceParser):
    """解析 Argo（Claude Code CLI）JSONL session 日志。"""

    def __init__(self, parser_version: str = "argo-1.0"):
        self.parser_version = parser_version

    @staticmethod
    def _is_finding_tool(tool_name: str) -> bool:
        """Argo 平台 finding 提交工具。"""
        return tool_name in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding")

    @staticmethod
    def _resolve_jsonl_files(uri: str) -> list[str]:
        """解析 .jsonl 文件列表。

        Argo session 的 .jsonl 固定在 uri/argo/ 目录下（Claude Code 标准布局），
        含 argo/ 下的子目录（子 session）。
        """
        if not os.path.isdir(uri):
            return [uri]
        argo_dir = os.path.join(uri, "argo")
        if not os.path.isdir(argo_dir):
            return []
        # argo/ 下所有 .jsonl（含子目录）
        return sorted(glob.glob(os.path.join(argo_dir, "**", "*.jsonl"), recursive=True))

    def parse(self, trace_source) -> Iterator[RawEvent]:
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
                    for ev in self._obj_to_events(d, trace_id, sid, line_no, tool_use_kg, tool_use_mem, tool_use_names):
                        yield ev

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
                    from ..domain.raw_event import detect_memory_flags
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
                evs.append(RawEvent(
                    event_id=f"{eid}-res", trace_id=trace_id, session_id=session_id,
                    event_type="TOOL_RESULT", timestamp_ms=ts,
                    message_id=d.get("uuid"), part_id=f"{eid}-res",
                    step_no=None, tool_name=tn, input_json=None, output_json=out_str,
                    raw_type="toolUseResult", parse_status="OK",
                    source_table="jsonl", source_row_id=f"{eid}-res",
                    parser_version=self.parser_version,
                    call_id=tid,
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
                                from ..domain.raw_event import usage_numbers
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

    def build_session_graph(self, events):
        """构建 session 关系图（Argo 特有逻辑）。

        Argo (Claude Code) 的 session 结构：
        - investigate session：挖掘代码，提交 finding（TEXT 事件 {"accepted": true, "data": {"findings": [...]}}）
        - verify session：验证 finding，给出 verdict（SYSTEM_EVENT 含 finding metadata + TEXT 事件含 verdict）
        - 通过共享文件、fact ID、finding 提交/验证关联

        Session 关系：
        - investigate → verify：通过 finding key (cwe, file, line_range) 匹配
        - session ↔ session：通过共享文件/fact 关联
        """
        from collections import defaultdict as _dd
        import time as _time
        from ..infrastructure.log_util import log as _log
        _MAX_SESSIONS_PER_LINK = 5
        graph = {
            'sessions': {},
            'file_to_sessions': _dd(set),
            'fact_to_sessions': _dd(set),
            'finding_to_investigate': _dd(set),  # finding_key -> investigate session_ids
            'finding_to_verify': _dd(set),        # finding_key -> verify session_ids
            'edges': _dd(set),
            'parent_map': {},
        }

        _n = len(events)
        _start = _time.time()
        for idx, ev in enumerate(events):
            if idx > 0 and idx % 50000 == 0:
                _log("SINK_MATCH", f"argo.build_session_graph {idx}/{_n} elapsed={int(_time.time()-_start)}s")
            sid = ev.session_id
            if not sid:
                continue
            if sid not in graph['sessions']:
                graph['sessions'][sid] = {
                    'files': set(), 'facts': set(), 'athena_qs': [],
                    'session_type': None,  # 'investigate' / 'verify'
                    'finding_keys': set(),
                }
            sg = graph['sessions'][sid]

            # SYSTEM_EVENT: verify session system prompt，含 finding metadata
            if ev.event_type == "SYSTEM_EVENT" and ev.output_json:
                content = str(ev.output_json)
                if "## Finding to Verify" in content or "# Verify:" in content:
                    sg['session_type'] = 'verify'
                    meta = self._extract_finding_meta_from_sysprompt(content)
                    if meta:
                        key = self._finding_key(meta)
                        if key and key != "(,,)":
                            sg['finding_keys'].add(key)
                            graph['finding_to_verify'][key].add(sid)
                # fact 引用
                for fid in re.findall(r'(f\d{3,5})\s+(?:found|concluded|reported|discovered|noted|observed|identified)', str(ev.output_json)):
                    if fid != 'f001':
                        sg['facts'].add(fid)
                        graph['fact_to_sessions'][fid].add(sid)
                continue

            # TEXT 事件: investigate finding 提交
            if ev.event_type == "TEXT" and ev.output_json:
                txt = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
                if '"accepted"' in txt:
                    for payload in self._extract_accepted_payloads(txt):
                        data = payload.get("data", payload)
                        if not isinstance(data, dict):
                            continue
                        if "findings" in data:
                            sg['session_type'] = 'investigate'
                            for f in data.get("findings", []):
                                if not isinstance(f, dict):
                                    continue
                                key = self._finding_key(f)
                                if key and key != "(,,)":
                                    sg['finding_keys'].add(key)
                                    graph['finding_to_investigate'][key].add(sid)

            if not ev.is_tool_call():
                continue

            tool = ev.tool_name or ""
            inp = ev.input_json or {}

            if tool == "bash":
                cmd = str(inp.get("command", ""))
                # argo.memory get fXXX → fact 关联
                if "argo.memory" in cmd and " get" in cmd:
                    for fid in re.findall(r'f\d{3,5}', cmd):
                        if fid != 'f001':
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

        # 构建边
        # 不建 finding investigate↔verify 边：挖掘与验证是独立评测，无交叉分析场景。
        # 1. 共享 fact 的 session 关联
        for fid, sids in graph['fact_to_sessions'].items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            graph['edges'][s1].add(s2)

        # 2. 共享文件的 session 关联
        for fm, sids in graph['file_to_sessions'].items():
            if 1 < len(sids) <= _MAX_SESSIONS_PER_LINK:
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            graph['edges'][s1].add(s2)

        # 3. parent_map: investigate session 是 verify session 的上级
        #    同一 finding_key 出现在 investigate 和 verify → investigate 是父
        for key, inv_sids in graph['finding_to_investigate'].items():
            ver_sids = graph['finding_to_verify'].get(key, set())
            if not inv_sids or not ver_sids:
                continue
            inv_first = sorted(inv_sids)[0]
            for vsid in ver_sids:
                graph['parent_map'][vsid] = inv_first

        return graph

    def _extract_action(self, ev):
        """Argo 平台挖掘行为：TEXT 事件含 accepted=true payload 为结论点。"""
        if ev.event_type == "TEXT" and ev.output_json:
            txt = ev.output_json if isinstance(ev.output_json, str) else str(ev.output_json)
            if '"accepted"' in txt and '"findings"' in txt:
                return {"tool": "finding", "action": "accepted_payload",
                        "session_id": ev.session_id, "ts": ev.timestamp_ms or 0}
        return super()._extract_action(ev)

    # ------------------------------------------------------------------
    # finding 提取
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

    @staticmethod
    def _try_parse_json_lenient(text: str) -> dict | None:
        """尝试解析 JSON，自动补全缺失的闭合花括号。

        Agent 输出的 JSON 有时会少一个闭合 }（如 entry_reachability 对象未关闭），
        导致 json.loads 失败。此方法检测花括号不匹配并自动补全。
        """
        text = text.strip()
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
        # 统计未匹配的花括号
        depth = 0
        in_str = False
        esc = False
        for ch in text:
            if esc:
                esc = False
                continue
            if ch == '\\':
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
        if depth > 0:
            fixed = text + '}' * depth
            try:
                obj = json.loads(fixed)
                return obj if isinstance(obj, dict) else None
            except json.JSONDecodeError:
                pass
        return None

    @staticmethod
    def _extract_accepted_payloads(text: str) -> list[dict]:
        """从文本中提取 JSON payload。

        nazhua 平台的 validate_verify_payload 不要求 accepted: true，
        没有 accepted 字段时直接用 payload 本身作为 data。
        因此本方法只过滤 accepted:false，其余全部保留（含裸 payload）。

        两种策略：
        1. ```json 代码块中的 JSON 对象（raw_decode + 容错补全）
        2. 文本中直接出现的 JSON 对象（花括号匹配 + 容错补全），
           搜索关键词：accepted, verdict, findings
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
            obj = ArgoTraceParser._try_parse_json_lenient(json_str)
            if obj:
                _add(obj)
            search_start = close_idx + 3
        if results:
            return results

        # 策略 2: 直接在文本中搜索关键词并做花括号匹配
        # 预计算所有顶层 { 的位置（depth=0），用于找到包含关键词的最外层对象
        top_level_opens: list[int] = []
        depth = 0
        in_str = False
        esc = False
        for j, ch in enumerate(text):
            if esc:
                esc = False
                continue
            if ch == '\\':
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == '{':
                if depth == 0:
                    top_level_opens.append(j)
                depth += 1
            elif ch == '}':
                depth -= 1

        for keyword in ('"verdict"', '"findings"'):
            search_start = 0
            while True:
                idx = text.find(keyword, search_start)
                if idx < 0:
                    break
                # 找到关键词之前的最后一个顶层 {
                brace_start = -1
                for tb in top_level_opens:
                    if tb <= idx:
                        brace_start = tb
                    else:
                        break
                if brace_start < 0:
                    search_start = idx + 1
                    continue
                depth = 0
                in_string = False
                escape = False
                end_idx = -1
                for j in range(brace_start, len(text)):
                    ch = text[j]
                    if escape:
                        escape = False
                        continue
                    if ch == '\\':
                        escape = True
                        continue
                    if ch == '"':
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            end_idx = j + 1
                            break
                if end_idx > 0:
                    try:
                        payload = json.loads(text[brace_start:end_idx])
                        if isinstance(payload, dict):
                            _add(payload)
                    except json.JSONDecodeError:
                        pass
                    search_start = end_idx
                else:
                    close_idx = text.find('```', brace_start)
                    if close_idx < 0:
                        close_idx = len(text)
                    json_str = text[brace_start:close_idx]
                    obj = ArgoTraceParser._try_parse_json_lenient(json_str)
                    if obj:
                        _add(obj)
                    search_start = close_idx

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
                for payload in self._extract_accepted_payloads(txt):
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
