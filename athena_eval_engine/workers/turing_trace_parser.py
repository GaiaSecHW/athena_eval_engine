"""TuringTraceParser — Turing opencode.db SQLite → Canonical RawEvent。

Trace 路径：/data/files/{project_id}/tasks/{task_id}/tools/Turing-*/session/opencode/opencode.db

基于 Turing agent 源代码全面分析重写，覆盖三个领域：
1. 漏洞/非漏洞数据提交的所有通道
2. 会话调用链关系（跨多个 session）
3. 知识/记忆访问方式

== 数据提交通道（从 agent 源代码确认）==

Turing agent 通过以下通道提交漏洞/非漏洞数据：

A. MCP 工具调用（主通道，opencode.db 中 type="tool" 的 part）：
   - vuln_hunt_insert_finding     → 创建 finding（初始状态 pending_validation）
   - vuln_hunt_update_finding     → 更新 finding 验证结果（CONFIRMED/UNCERTAIN/FALSE_POSITIVE）
   - vuln_hunt_mark_finding_invalid → 标记 finding 为重复（等效 FALSE_POSITIVE）
   - vuln_hunt_insert_detection   → 创建探测记录（非 finding，但有关联）
   - vuln_hunt_insert_investigation → 创建调查记录（深挖链路）
   - vuln_hunt_update_detection_status → 更新探测状态
   - vuln_hunt_submit_artifact    → 旧版兼容入口，artifact_type 路由到上述各工具
   - vuln_hunt_submit_knowledge   → 知识提交（写入 blackboard + 旁路 Athena）

B. HTTP 绕过（MCP 失败时 agent 用 bash + curl/python3 urllib 直接调 MCP server HTTP 接口）：
   - insert_finding 绕过：output 含 "Finding" + "inserted" + UUID
   - update_finding 绕过：output 含 "validated as 'CONFIRMED/FALSE_POSITIVE/...'" + UUID
   - insert_detection 绕过：output 含 "Detection" + UUID
   - insert_investigation 绕过：output 含 "Investigation" + UUID

C. 验证结果通过 submit_artifact(artifact_type="validation") 提交（旧版兼容路径）

== 会话调用链（从 agent 源代码确认）==

opencode.db session 表：
- id: session UUID
- parent_id: 父 session UUID（agent spawn subagent 时创建子 session）
- agent: agent 名称（标识 session 所属阶段：app-mine-fast/app-validate/...）
- model: 模型名

session 调用链构建：
1. session.parent_id → 父子 session 边（已有）
2. session.agent → 标识 session 角色（新增：用于理解链路中每个 session 的职责）
3. investigation 链：insert_investigation → deep_mine 任务 → 新 session
   通过 investigation 中的 origin_detection_id 和 parent_investigation_id 关联

== 知识/记忆访问方式（从 agent 源代码确认）==

1. athena MCP ask 工具：tool_name="athena_ask" 或 "ask"（KG 检索）
2. bash athena CLI：command 含 "athena" 脚本路径（KG 检索）
3. bash mem.sh：command 含 "mem" 脚本路径（memengine 记忆读写）
4. vuln_hunt_submit_knowledge：知识提交到 blackboard + 旁路 Athena
5. read/grep 工具读取 memengine 目录：通过 detect_memory_flags 检测
6. 系统提示注入：opencode_executor.prompt(system=memory_system) — 不可从工具调用检测
"""
from __future__ import annotations
import json
import re
import sqlite3
from typing import Iterator
from ..domain.raw_event import RawEvent, EVENT_TYPES, detect_memory_flags
from ..domain.resolvers import TraceParser
from .parse_utils import attach_event_indices
# part.type → event_type 映射
TYPE_MAP = {
    "tool": None,  # 需看 input/output 判 TOOL_CALL / TOOL_RESULT，由 _classify_tool 决定
    "step-start": "STEP_START",
    "step-finish": "STEP_FINISH",
    "text": "TEXT",
    "reasoning": "REASONING",
}

# ===== MCP 工具名归一化 =====
# opencode 注册的 MCP 工具名带 vuln_hunt_ 前缀，但 agent 有时用 vuln-hunt_ 前缀
_TOOL_ALIASES = {
    "vuln-hunt_insert_finding": "vuln_hunt_insert_finding",
    "vuln-hunt_update_finding": "vuln_hunt_update_finding",
    "vuln-hunt_mark_finding_invalid": "vuln_hunt_mark_finding_invalid",
    "vuln-hunt_insert_detection": "vuln_hunt_insert_detection",
    "vuln-hunt_insert_investigation": "vuln_hunt_insert_investigation",
    "vuln-hunt_update_detection_status": "vuln_hunt_update_detection_status",
    "vuln-hunt_submit_artifact": "vuln_hunt_submit_artifact",
    "vuln-hunt_submit_knowledge": "vuln_hunt_submit_knowledge",
    "vuln-hunt_query_detection": "vuln_hunt_query_detection",
    "vuln-hunt_query_finding": "vuln_hunt_query_finding",
    "vuln-hunt_get_findings_detail": "vuln_hunt_get_findings_detail",
    "vuln-hunt_query_investigation": "vuln_hunt_query_investigation",
    "vuln-hunt_update_investigation_status": "vuln_hunt_update_investigation_status",
    "vuln-hunt_submit_preprocess_result": "vuln_hunt_submit_preprocess_result",
    # athena MCP 的 ask 工具
    "athena_ask": "athena_ask",
    "ask": "athena_ask",
}

# ===== HTTP 绕过检测模式 =====
# agent 用 bash + curl/python3 urllib 调 MCP server HTTP 接口时的 output 特征
_HTTP_BYPASS_PATTERNS = {
    # insert_finding 的 HTTP 响应特征
    "insert_finding": re.compile(
        r"Finding\s+(\S+)\s+\(id=([a-f0-9-]{36})\)|"
        r"inserted.*finding.*id=([a-f0-9-]{36})",
        re.IGNORECASE,
    ),
    # update_finding 的 HTTP 响应特征
    "update_finding": re.compile(
        r"validated as '(\w+)'.*?([a-f0-9-]{36})|"
        r"([a-f0-9-]{36}).*?validated as '(\w+)'",
        re.IGNORECASE,
    ),
    # mark_finding_invalid 的 HTTP 响应特征
    "mark_finding_invalid": re.compile(
        r"invalidated|duplicated|marked.*invalid",
        re.IGNORECASE,
    ),
    # insert_detection 的 HTTP 响应特征
    "insert_detection": re.compile(
        r"Detection\s+(\S+)\s+\(id=([a-f0-9-]{36})\)|"
        r"detection.*id=([a-f0-9-]{36})",
        re.IGNORECASE,
    ),
    # insert_investigation 的 HTTP 响应特征
    "insert_investigation": re.compile(
        r"Investigation\s+(\S+)\s+\(id=([a-f0-9-]{36})\)|"
        r"investigation.*id=([a-f0-9-]{36})",
        re.IGNORECASE,
    ),
}

# MCP server HTTP 端点特征（command 中检测）
_MCP_HTTP_INDICATORS = re.compile(
    r"mcp|vulnhunt|vuln.hunt|turing.app.security|"
    r"/submit.artifact|/insert.finding|/update.finding|"
    r"/insert.detection|/insert.investigation",
    re.IGNORECASE,
)

# ===== 知识/记忆检测模式 =====
# Athena CLI 脚本路径特征
_ATHENA_CLI_RE = re.compile(
    r"scripts/athena|athena\.py|athena\s+ask|athena_cli",
    re.IGNORECASE,
)
# mem.sh 脚本路径特征（memengine CLI 封装）
_MEM_CLI_RE = re.compile(
    r"\bmem\b\s+(?:recall|get|search|list|query|find|suggestions|save|store|add|write|insert|update)|"
    r"mem\.sh|memengine.*(?:recall|get|search|save|store)",
    re.IGNORECASE,
)
# Athena 知识库响应特征
_ATHENA_RESULT_RE = re.compile(r"知识库|athena.*result|retrieved.*knowledge", re.IGNORECASE)

# UUID 正则
_UUID_RE = re.compile(
    r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    re.IGNORECASE,
)

# validation_result 枚举
_VR_ENUM = {"CONFIRMED", "UNCERTAIN", "FALSE_POSITIVE", "LIKELY", "POSSIBLE"}


class TuringTraceParser(TraceParser):
    """Turing opencode.db SQLite → RawEvent。

    读 session 表 + part 表（data JSON）。
    Schema Gate：required=[session, part], optional=[event]。part 表缺失 → BLOCK。
    单条 part.data 损坏 → 该 Event INVALID + Parser Error，继续解析其他。
    """

    def __init__(self, parser_version: str = "2.0"):
        self.parser_version = parser_version
        # parse() 顺带缓存的 step/token 统计，供 load_session() 复用
        self._cached_n_start = None
        self._cached_n_finish = None
        self._cached_ti = None
        self._cached_to = None
        self._cached_tr = None
        self._cached_tcr = None

    @staticmethod
    def _connect(uri: str) -> sqlite3.Connection:
        """以只读模式打开 opencode.db（避免锁大库）。"""
        return sqlite3.connect(f"file:{uri}?immutable=1", uri=True)

    @staticmethod
    def _check_schema(conn):
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r["name"] for r in cur.fetchall()}
        if "part" not in tables or "session" not in tables:
            raise RuntimeError(f"Schema Gate BLOCK: required tables [session, part] missing, got {tables}")

    @staticmethod
    def _is_finding_tool(tool_name: str) -> bool:
        """Turing 平台 finding 提交工具——仅 update_finding 是结论写入工具。"""
        return tool_name == "vuln_hunt_update_finding"

    # ==================================================================
    # parse — SQLite → RawEvent 流
    # ==================================================================

    def parse(self, trace_source) -> Iterator[RawEvent]:
        """trace_source: dict {trace_id, source_uri(.db path), session_id?}"""
        self._source_uri = trace_source["source_uri"]
        uri = self._source_uri
        trace_id = trace_source["trace_id"]
        fallback_sid = trace_source.get("turing_session_id") or trace_source.get("session_id") or ""

        # 初始化 step/token 缓存，与 load_session 逻辑一致
        self._cached_n_start = 0
        self._cached_n_finish = 0
        self._cached_ti = self._cached_to = self._cached_tr = self._cached_tcr = 0

        conn = self._connect(uri)
        conn.row_factory = sqlite3.Row
        try:
            self._check_schema(conn)
            for row in conn.execute("SELECT * FROM part ORDER BY id"):
                # 累计 step/token 统计（避免 load_session 二次全表扫描）
                cols = row.keys() if hasattr(row, "keys") else []
                t = str(row["type"] or "") if "type" in cols else ""
                if not t:
                    try:
                        d = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
                        if isinstance(d, dict):
                            t = str(d.get("type") or "")
                    except Exception:
                        pass
                if t == "step-start":
                    self._cached_n_start += 1
                elif t == "step-finish":
                    self._cached_n_finish += 1
                    try:
                        d = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
                        if isinstance(d, dict):
                            tk = d.get("tokens", {})
                            self._cached_ti += tk.get("input", 0) or 0
                            self._cached_to += tk.get("output", 0) or 0
                            self._cached_tr += tk.get("reasoning", 0) or 0
                            self._cached_tcr += (tk.get("cache", {}).get("read", 0) if isinstance(tk.get("cache"), dict) else 0) or 0
                    except Exception:
                        pass

                row_sid = str(row["session_id"]) if "session_id" in row.keys() and row["session_id"] else fallback_sid
                yield self._part_to_event(row, trace_id, row_sid)
        finally:
            conn.close()

    # ==================================================================
    # build_session_graph — 会话调用链
    # ==================================================================

    def build_session_graph(self, events):
        """Turing (opencode) 特有：在基类图基础上加 parent_id 父子边 + agent 角色。

        不建 finding_id 边（insert_finding session ↔ update_finding session）：
        挖掘与验证是独立评测，无交叉分析场景。finding_id 边会把验证 session
        拉入挖掘的 chain_actions，导致数据膨胀和 LLM 分析噪音。

        三层关联：
        1. parent_id 父子边（session 表）+ agent 角色标注
        2. 基类共享文件/fact 边
        """
        graph = super().build_session_graph(events)

        # === parent_id 父子边 + agent 角色标注（从 SQLite session 表）===
        uri = getattr(self, '_source_uri', None)
        if not uri:
            return graph
        try:
            conn = self._connect(uri)
            conn.row_factory = sqlite3.Row
            # parent_id 父子边
            for row in conn.execute("SELECT id, parent_id, agent FROM session WHERE parent_id IS NOT NULL"):
                sid = row["id"]
                pid = row["parent_id"]
                agent = row["agent"] if "agent" in row.keys() else ""
                # 标注 session 的 agent 角色
                if sid in graph['sessions']:
                    graph['sessions'][sid]['agent'] = agent
                # 父子边
                if sid in graph['sessions'] and pid in graph['sessions']:
                    graph['edges'][sid].add(pid)
                    graph['edges'][pid].add(sid)
                    graph['parent_map'][sid] = pid
            # 补充标注所有 session 的 agent 角色（非仅 parent_id 非空的）
            for row in conn.execute("SELECT id, agent FROM session"):
                sid = row["id"]
                agent = row["agent"] if "agent" in row.keys() else ""
                if sid in graph['sessions'] and 'agent' not in graph['sessions'][sid]:
                    graph['sessions'][sid]['agent'] = agent
            conn.close()
        except Exception:
            pass
        return graph

    # ==================================================================
    # load_session — 读 session 表元数据
    # ==================================================================

    def load_session(self, trace_source) -> dict:
        """读 session 表元数据 + 复用 parse() 缓存的 step/token 统计。

        parse() 已在遍历 part 表时顺带累计了 step-start/step-finish 计数和
        token 总量，此处直接复用，避免对 1.5GB+ 的 part 表做第二次全表扫描。
        """
        uri = trace_source["source_uri"]
        conn = self._connect(uri)
        conn.row_factory = sqlite3.Row
        try:
            self._check_schema(conn)
            row = conn.execute("SELECT * FROM session LIMIT 1").fetchone()
            sess = dict(row) if row else {}

            if self._cached_n_start is not None:
                # parse() 已缓存 → 直接复用
                sess["_step_start_count"] = self._cached_n_start
                sess["_step_finish_count"] = self._cached_n_finish
                if (not sess.get("tokens_input") and not sess.get("tokens_output")) and (self._cached_ti or self._cached_to):
                    sess["tokens_input"] = self._cached_ti
                    sess["tokens_output"] = self._cached_to
                    sess["tokens_reasoning"] = self._cached_tr
                    sess["cache_read_tokens"] = self._cached_tcr
            else:
                # 降级：parse() 未调用过，走原始全表扫描
                n_start = n_finish = 0
                ti = to = tr = tcr = 0
                for r in conn.execute("SELECT * FROM part"):
                    cols = r.keys() if hasattr(r, "keys") else []
                    t = str(r["type"]) if "type" in cols else ""
                    d = None
                    try:
                        d = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
                    except Exception:
                        d = None
                    if not t and isinstance(d, dict):
                        t = str(d.get("type") or "")
                    if t == "step-start":
                        n_start += 1
                    elif t == "step-finish":
                        n_finish += 1
                        if isinstance(d, dict):
                            tk = d.get("tokens", {})
                            ti += tk.get("input", 0) or 0
                            to += tk.get("output", 0) or 0
                            tr += tk.get("reasoning", 0) or 0
                            tcr += (tk.get("cache", {}).get("read", 0) if isinstance(tk.get("cache"), dict) else 0) or 0
                sess["_step_start_count"] = n_start
                sess["_step_finish_count"] = n_finish
                if (not sess.get("tokens_input") and not sess.get("tokens_output")) and (ti or to):
                    sess["tokens_input"] = ti
                    sess["tokens_output"] = to
                    sess["tokens_reasoning"] = tr
                    sess["cache_read_tokens"] = tcr
            return sess
        finally:
            conn.close()

    # ==================================================================
    # _part_to_event — 单行 part → RawEvent（含所有通道归一化）
    # ==================================================================

    def _part_to_event(self, row, trace_id, session_id) -> RawEvent:
        cols = row.keys() if hasattr(row, "keys") else []
        raw_type = str(row["type"] or "") if "type" in cols else ""
        part_id = str(row["id"])
        data = {}
        parse_status = "OK"
        parse_error = None
        raw_data = row["data"]
        if isinstance(raw_data, str):
            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError as e:
                parse_status = "PARTIAL"
                parse_error = f"json_decode: {e}"
                data = self._regex_extract_partial(raw_data)
        elif isinstance(raw_data, (bytes, bytearray)):
            try:
                data = json.loads(raw_data.decode("utf-8"))
            except Exception as e:
                parse_status = "PARTIAL"
                parse_error = f"json_decode_bytes: {e}"
                data = self._regex_extract_partial(raw_data.decode("utf-8", errors="replace"))
        elif raw_data is not None and isinstance(raw_data, dict):
            data = raw_data

        # 若 part 表无 type 列，type 从 data JSON 取（opencode 格式）
        if not raw_type and isinstance(data, dict):
            raw_type = str(data.get("type") or "")

        event_type = self._classify(raw_type, data)

        # timestamp
        ts = None
        if isinstance(data, dict):
            t = data.get("time")
            if isinstance(t, dict):
                ts = t.get("start")
            if ts is None:
                ts = data.get("timestamp_ms")
        if ts is None and "time_created" in cols:
            ts = row["time_created"]

        msg_id = str(row["message_id"]) if "message_id" in cols and row["message_id"] else (
            data.get("message_id") if isinstance(data, dict) else None
        )
        step_no = data.get("step_no") if isinstance(data, dict) else None

        # tool 信息提取
        tool_name = None
        inp = None
        outp = None
        if isinstance(data, dict):
            tool_name = data.get("tool") or data.get("tool_name")
            state = data.get("state") if isinstance(data.get("state"), dict) else {}
            inp = state.get("input") if state else data.get("input")
            outp = state.get("output") if state else data.get("output")

        # 工具名归一化（vuln-hunt_ → vuln_hunt_ 等）
        if tool_name:
            tool_name = _TOOL_ALIASES.get(tool_name, tool_name)

        # ===== HTTP 绕过归一化 =====
        # agent 用 bash + curl/python3 urllib 调 MCP server HTTP 接口时，
        # 将 bash 工具调用归一化为对应的 MCP 工具调用
        if tool_name == "bash" and isinstance(inp, dict):
            cmd = str(inp.get("command", ""))
            tool_name, inp, outp = self._normalize_http_bypass(cmd, inp, outp, tool_name)

        # ===== 知识图谱交互检测 =====
        is_kg = self._detect_kg_interaction(tool_name, inp, outp)

        # ===== 记忆交互检测 =====
        is_mem, is_mem_w = detect_memory_flags(tool_name, inp)

        # ===== submit_artifact 归一化 =====
        # submit_artifact 是旧版兼容入口，按 artifact_type 路由到具体工具
        if tool_name == "vuln_hunt_submit_artifact" and isinstance(inp, dict):
            tool_name, inp = self._normalize_submit_artifact(inp)

        # ===== finding 提交标记 =====
        is_finding = self._is_finding_tool(tool_name) if event_type == "TOOL_CALL" else False

        return RawEvent(
            event_id=f"evt-{trace_id}-{part_id}",
            trace_id=trace_id,
            session_id=session_id,
            event_type=event_type,
            timestamp_ms=int(ts) if ts is not None else None,
            message_id=str(msg_id) if msg_id else None,
            part_id=part_id,
            step_no=int(step_no) if step_no is not None else None,
            tool_name=tool_name,
            input_json=inp,
            output_json=outp,
            raw_type=raw_type,
            parse_status=parse_status,
            parse_error=parse_error,
            source_table="part",
            source_row_id=part_id,
            parser_version=self.parser_version,
            is_kg_interaction=is_kg,
            is_memory_interaction=is_mem,
            is_memory_write=is_mem_w,
            is_finding_submission=is_finding,
        )

    # ==================================================================
    # _normalize_http_bypass — HTTP 绕过检测与归一化
    # ==================================================================

    def _normalize_http_bypass(self, cmd: str, inp: dict, outp, tool_name: str):
        """检测 bash 命令是否为 MCP HTTP 绕过调用，归一化为对应工具名。

        Turing agent 在 MCP 工具调用失败时，用 bash + curl 或 python3 urllib.request
        直接调 MCP server 的 HTTP 接口（/submit-artifact 等）。
        从 command 和 output 中提取工具参数，归一化为标准 MCP 工具调用。

        检测策略：
        1. command 含 MCP server HTTP 端点特征（mcp/vulnhunt/turing-app-security/submit-artifact/...）
        2. 从 output 中匹配各工具的响应特征（insert_finding/update_finding/...）
        3. 提取 finding_id/detection_id/UUID 等参数
        """
        cmd_l = cmd.lower()
        if not _MCP_HTTP_INDICATORS.search(cmd_l):
            return tool_name, inp, outp

        outp_str = str(outp) if outp else ""

        # insert_finding 绕过：output 含 "Finding {display} (id={uuid}) inserted"
        m = _HTTP_BYPASS_PATTERNS["insert_finding"].search(outp_str)
        if m:
            # 提取 UUID
            uuid_val = None
            for g in m.groups():
                if g and _UUID_RE.match(g):
                    uuid_val = g
                    break
            if uuid_val:
                # 从 command 中尝试提取 insert_finding 的参数
                params = self._extract_finding_params_from_cmd(cmd)
                params["finding_id"] = uuid_val
                return "vuln_hunt_insert_finding", {**inp, **params}, outp

        # update_finding 绕过：output 含 "validated as 'CONFIRMED'"
        m = _HTTP_BYPASS_PATTERNS["update_finding"].search(outp_str)
        if m:
            vr = None
            fid = None
            for i, g in enumerate(m.groups()):
                if g and g.upper() in _VR_ENUM:
                    vr = g.upper()
                elif g and _UUID_RE.match(g):
                    fid = g
            if vr and fid:
                vr_norm = "CONFIRMED" if vr in ("CONFIRMED", "LIKELY", "POSSIBLE") else vr
                return "vuln_hunt_update_finding", {
                    **inp,
                    "finding_id": fid,
                    "validation_result": vr_norm,
                }, outp

        # mark_finding_invalid 绕过
        if _HTTP_BYPASS_PATTERNS["mark_finding_invalid"].search(outp_str):
            fid = _UUID_RE.search(outp_str)
            if fid:
                return "vuln_hunt_mark_finding_invalid", {
                    **inp,
                    "finding_id": fid.group(0),
                }, outp

        # insert_detection 绕过
        m = _HTTP_BYPASS_PATTERNS["insert_detection"].search(outp_str)
        if m:
            uuid_val = None
            for g in m.groups():
                if g and _UUID_RE.match(g):
                    uuid_val = g
                    break
            if uuid_val:
                return "vuln_hunt_insert_detection", {**inp, "detection_id": uuid_val}, outp

        # insert_investigation 绕过
        m = _HTTP_BYPASS_PATTERNS["insert_investigation"].search(outp_str)
        if m:
            uuid_val = None
            for g in m.groups():
                if g and _UUID_RE.match(g):
                    uuid_val = g
                    break
            if uuid_val:
                return "vuln_hunt_insert_investigation", {**inp, "investigation_id": uuid_val}, outp

        # 未匹配到具体模式但确认是 MCP HTTP 调用，保留原样
        return tool_name, inp, outp

    def _extract_finding_params_from_cmd(self, cmd: str) -> dict:
        """从 HTTP 绕过命令中提取 insert_finding 的参数。

        agent 用 curl/python3 构造 HTTP 请求时，参数在 JSON body 中。
        尝试从命令字符串中提取 JSON 并解析 finding 相关字段。
        """
        params = {}
        # 尝试提取 JSON body（curl -d '...' 或 python3 -c '...data=...'）
        # 方法1：寻找 JSON 对象
        json_match = re.search(r'\{[^{}]*"vuln_type"[^{}]*\}', cmd, re.DOTALL)
        if json_match:
            try:
                body = json.loads(json_match.group(0))
                for k in ("title", "vuln_type", "severity", "description",
                          "detection_id", "source", "sink", "url", "call_chain"):
                    if k in body:
                        params[k] = body[k]
            except json.JSONDecodeError:
                pass

        # 方法2：正则逐字段提取
        if not params:
            for field in ("title", "vuln_type", "severity", "description", "detection_id"):
                m = re.search(r'"%s"\s*:\s*"([^"]*)"' % field, cmd)
                if m:
                    params[field] = m.group(1)

        return params

    # ==================================================================
    # _normalize_submit_artifact — submit_artifact 路由归一化
    # ==================================================================

    def _normalize_submit_artifact(self, inp: dict) -> tuple:
        """将 submit_artifact 调用按 artifact_type 归一化为具体工具调用。

        submit_artifact 是旧版兼容入口，DataStore.persist() 按 artifact_type 路由：
        - "discovery"    → insert_detection
        - "vulnerability" → insert_finding
        - "validation"   → update_finding
        - "investigation" → insert_investigation
        - "knowledge"    → submit_knowledge（保留原名）
        - "strategy"     → insert_strategy（保留原名）
        """
        artifact_type = str(inp.get("artifact_type", "")).strip().lower()
        data = inp.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                data = {}
        if not isinstance(data, dict):
            data = {}

        if artifact_type == "vulnerability":
            return "vuln_hunt_insert_finding", {**inp, **data}
        elif artifact_type == "validation":
            return "vuln_hunt_update_finding", {**inp, **data}
        elif artifact_type == "discovery":
            return "vuln_hunt_insert_detection", {**inp, **data}
        elif artifact_type == "investigation":
            return "vuln_hunt_insert_investigation", {**inp, **data}
        # knowledge/strategy 等保留原名
        return "vuln_hunt_submit_artifact", inp

    # ==================================================================
    # _detect_kg_interaction — 知识图谱/记忆交互检测
    # ==================================================================

    def _detect_kg_interaction(self, tool_name: str, inp, outp) -> bool:
        """检测是否为知识图谱交互。

        Turing 的知识/记忆访问通道（从 agent 源代码确认）：
        1. athena MCP ask 工具：tool_name="athena_ask" 或 "ask"
        2. bash athena CLI：command 含 athena 脚本路径
        3. bash mem.sh：command 含 mem 脚本路径（memengine CLI 封装）
        4. vuln_hunt_submit_knowledge：知识提交到 blackboard + 旁路 Athena
        5. Athena 检索结果：output 含 "知识库"
        """
        tn = (tool_name or "").lower()

        # 1. athena MCP ask 工具
        if tn in ("athena_ask", "ask"):
            return True

        # 2. vuln_hunt_submit_knowledge（知识提交也算 KG 交互）
        if tn == "vuln_hunt_submit_knowledge":
            return True

        # 3. bash 中的 athena CLI 和 mem.sh
        if tn == "bash" and isinstance(inp, dict):
            cmd = str(inp.get("command", ""))
            cmd_l = cmd.lower()

            # athena CLI 脚本
            has_athena = bool(_ATHENA_CLI_RE.search(cmd_l))
            is_view = cmd_l.strip().startswith(("head", "cat ", "grep ", "ls "))
            if has_athena and not is_view:
                return True

            # mem.sh CLI（memengine 记忆读写）
            if _MEM_CLI_RE.search(cmd_l):
                return True

        # 4. Athena 检索结果特征
        if tn == "bash" and outp and isinstance(outp, str):
            if _ATHENA_RESULT_RE.search(outp):
                return True

        return False

    # ==================================================================
    # _regex_extract_partial — JSON 解析失败时的正则兜底
    # ==================================================================

    def _regex_extract_partial(self, raw_data: str) -> dict:
        """JSON 解析失败时，用正则从畸形 JSON 中提取关键字段。

        opencode.db 中 LLM 生成的 tool input JSON 有时引号丢失
        （如 validation_result 值缺少引号、或 finding_id 值的闭合引号
        丢失导致后续字段被吞入），使 json.loads 失败。
        """
        data: dict = {}
        m = re.search(r'"type"\s*:\s*"([^"]+)"', raw_data)
        if m:
            data["type"] = m.group(1)
        m = re.search(r'"tool"\s*:\s*"([^"]+)"', raw_data)
        if m:
            data["tool"] = m.group(1)

        inp: dict = {}
        # finding_id: UUID 专用模式
        m = re.search(
            r'"finding_id"\s*:\s*"?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
            raw_data, re.IGNORECASE,
        )
        if m:
            inp["finding_id"] = m.group(1)

        # validation_result: 匹配已知枚举值
        m = re.search(
            r'"validation_result"\s*:\s*"?(FALSE_POSITIVE|CONFIRMED|UNCERTAIN|LIKELY|POSSIBLE)',
            raw_data, re.IGNORECASE,
        )
        if m:
            inp["validation_result"] = m.group(1).upper()

        # detection_id
        m = re.search(
            r'"detection_id"\s*:\s*"?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
            raw_data, re.IGNORECASE,
        )
        if m:
            inp["detection_id"] = m.group(1)

        # 通用字段
        for field in ("title", "vuln_type", "severity", "description",
                       "source", "sink", "call_chain", "url"):
            m = re.search(r'"%s"\s*:\s*"([^"]*)"' % field, raw_data)
            if m:
                inp[field] = m.group(1)

        if inp:
            data["state"] = {"input": inp}

        # output
        m = re.search(r'"output"\s*:\s*"([^"]*)"', raw_data)
        if m:
            data.setdefault("state", {})["output"] = m.group(1)

        return data

    # ==================================================================
    # _classify — part.type → event_type
    # ==================================================================

    def _classify(self, raw_type: str, data: dict) -> str:
        """part.type → event_type。opencode tool part（含 state）= 单个 TOOL_CALL 事件。"""
        if raw_type == "tool":
            if isinstance(data, dict) and isinstance(data.get("state"), dict):
                return "TOOL_CALL"
            if isinstance(data, dict) and data.get("output") is not None and data.get("input") is None:
                return "TOOL_RESULT"
            return "TOOL_CALL"
        m = {
            "step-start": "STEP_START",
            "step-finish": "STEP_FINISH",
            "text": "TEXT",
            "reasoning": "REASONING",
        }
        if raw_type in m:
            return m[raw_type]
        if raw_type == "session-start":
            return "SESSION_START"
        if raw_type == "session-end":
            return "SESSION_END"
        return "UNKNOWN"

    # ==================================================================
    # _extract_action — 挖掘行为提取
    # ==================================================================

    def _extract_action(self, ev):
        """Turing 平台挖掘行为：追加 finding/detection/investigation 提交为结论点。"""
        tool = ev.tool_name or ""
        ts = ev.timestamp_ms or 0

        if tool == "vuln_hunt_insert_finding":
            inp = ev.input_json or {}
            title = str(inp.get("title", "") or inp.get("vuln_type", ""))
            return {"tool": "finding", "action": title, "session_id": ev.session_id, "ts": ts}

        if tool == "vuln_hunt_insert_detection":
            inp = ev.input_json or {}
            file = str(inp.get("file", ""))
            detect_type = str(inp.get("detect_type", ""))
            return {"tool": "detection", "action": f"{detect_type}: {file}", "session_id": ev.session_id, "ts": ts}

        if tool == "vuln_hunt_insert_investigation":
            inp = ev.input_json or {}
            reason = str(inp.get("reason", ""))[:100]
            boundary = str(inp.get("boundary_type", ""))
            return {"tool": "investigation", "action": f"{boundary}: {reason}", "session_id": ev.session_id, "ts": ts}

        if tool == "vuln_hunt_update_finding":
            inp = ev.input_json or {}
            vr = str(inp.get("validation_result", ""))
            return {"tool": "validate", "action": vr, "session_id": ev.session_id, "ts": ts}

        if tool == "vuln_hunt_mark_finding_invalid":
            return {"tool": "mark_invalid", "action": "duplicated", "session_id": ev.session_id, "ts": ts}

        if tool == "vuln_hunt_submit_knowledge":
            inp = ev.input_json or {}
            scope = str(inp.get("scope", ""))
            return {"tool": "knowledge", "action": scope, "session_id": ev.session_id, "ts": ts}

        return super()._extract_action(ev)

    # ==================================================================
    # extract_findings — 漏洞/非漏洞数据提取
    # ==================================================================

    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """提取 Turing 平台的 finding。

        识别方法唯一：insert_finding + update_finding 双门禁——
        必须先通过 insert_finding 正式提交到平台（平台分配数字 vulnerability_id
        并创建 T002 验证任务），再通过 update_finding 写入 validation_result。
        HTTP 绕过 update_finding（无 insert_finding）平台无记录，不计入。

        从 agent 源代码确认：
        - insert_finding 创建 pending_validation 状态的待验证记录（不含漏洞/非漏洞判定）
        - update_finding 写入 validation_result（CONFIRMED/UNCERTAIN/FALSE_POSITIVE）
          ——验证技能明确："第 3 步 vuln_hunt_update_finding 是唯一写入路径，不调用 = 全部结果丢失"
        - 验证四维度（0-3 门禁 + 4 评分）决定 validation_result：
          CONFIRMED=漏洞，FALSE_POSITIVE=非漏洞，UNCERTAIN=存疑
        - "仅对 CONFIRMED 和 UNCERTAIN 进行 CVSS 打分"

        insert_finding 是 finding 的提交门禁（平台只认 insert 创建的记录），
        同时作为 finding 详情（title/vuln_type/call_chain 等）的补充来源。
        mark_finding_invalid 标记已识别的 finding 为 FALSE_POSITIVE（重复）。
        """
        # ===== Phase 1: 收集 insert_finding 详情（按 finding_id 索引，供 Phase 2 补充）=====
        insert_details: dict[str, dict] = {}
        for e in events:
            if not e.is_tool_call():
                continue
            if (e.tool_name or "") != "vuln_hunt_insert_finding":
                continue

            inp = e.input_json or {}
            out_str = ""
            if e.output_json is not None:
                out_str = e.output_json if isinstance(e.output_json, str) else json.dumps(
                    e.output_json, ensure_ascii=False
                )

            # finding_id：HTTP 绕过已注入 input，MCP 工具从 output 提取
            fid = str(inp.get("finding_id", "")).strip()
            if not fid:
                m = re.search(r"id=([a-f0-9-]+)", out_str)
                fid = m.group(1) if m else ""
            if not fid:
                continue

            display = ""
            m = re.search(r"Finding\s+(\S+)", out_str)
            if m:
                display = m.group(1)

            # call_chain 归一化
            call_chain = inp.get("call_chain", [])
            if isinstance(call_chain, str):
                try:
                    call_chain = json.loads(call_chain)
                except (json.JSONDecodeError, TypeError):
                    call_chain = []

            # source/sink 归一化（可能是 dict 或 str）
            source = inp.get("source", "")
            sink = inp.get("sink", "")
            if isinstance(source, dict):
                source = json.dumps(source, ensure_ascii=False)
            if isinstance(sink, dict):
                sink = json.dumps(sink, ensure_ascii=False)

            insert_details[fid] = {
                "display_id": display,
                "title": inp.get("title", ""),
                "description": inp.get("description", ""),
                "vuln_type": inp.get("vuln_type", ""),
                "severity": inp.get("severity", ""),
                "source": str(source),
                "sink": str(sink),
                "url": inp.get("url", ""),
                "call_chain": call_chain,
                "detection_id": inp.get("detection_id", ""),
                "_insert_session": e.session_id,
                "_insert_ts": e.timestamp_ms,
            }

        # ===== Phase 2: update_finding → 创建 finding 条目（唯一识别入口）=====
        findings: dict[str, dict] = {}
        for _ei, e in enumerate(events):
            if not e.is_tool_call():
                continue
            if (e.tool_name or "") != "vuln_hunt_update_finding":
                continue

            inp = e.input_json or {}
            fid = str(inp.get("finding_id", "")).strip()
            vr = str(inp.get("validation_result", "")).upper()

            if not fid or vr not in _VR_ENUM:
                continue

            # insert_finding 门禁：HTTP 绕过 update_finding（无 insert）平台无记录，不计入
            if fid not in insert_details:
                continue

            vr_norm = "CONFIRMED" if vr in ("CONFIRMED", "LIKELY", "POSSIBLE") else vr

            # 从 insert_finding 详情中补充 finding 信息
            details = insert_details.get(fid, {})

            findings[fid] = {
                "finding_id": fid,
                "display_id": details.get("display_id", ""),
                "title": details.get("title", ""),
                "description": details.get("description", ""),
                "vuln_type": details.get("vuln_type", ""),
                "severity": details.get("severity", ""),
                "source": details.get("source", ""),
                "sink": details.get("sink", ""),
                "url": details.get("url", ""),
                "call_chain": details.get("call_chain", []),
                "detection_id": details.get("detection_id", ""),
                "validation_result": vr_norm,
                "platform": "turing",
                "session_id": e.session_id,
                "_event_idx": _ei,
                "_insert_ts": details.get("_insert_ts"),
                "_validate_ts": e.timestamp_ms,
                "_verify_session_id": e.session_id,
            }

            if inp.get("analysis"):
                findings[fid]["analysis"] = inp["analysis"]
            if inp.get("cvss_score") is not None:
                findings[fid]["cvss_score"] = inp["cvss_score"]
            if inp.get("cvss_vector"):
                findings[fid]["cvss_vector"] = inp["cvss_vector"]

        # ===== Phase 3: mark_finding_invalid → 标记 FALSE_POSITIVE（只更新已识别的）=====
        for e in events:
            if not e.is_tool_call():
                continue
            if (e.tool_name or "") != "vuln_hunt_mark_finding_invalid":
                continue

            inp = e.input_json or {}
            fid = str(inp.get("finding_id", "")).strip()
            if not fid or fid not in findings:
                continue

            findings[fid]["validation_result"] = "FALSE_POSITIVE"
            findings[fid]["_invalid_reason"] = inp.get("reason", "duplicated")
            if inp.get("duplicate_of_id"):
                findings[fid]["_duplicate_of"] = inp["duplicate_of_id"]

        attach_event_indices(findings, events)
        return list(findings.values())
