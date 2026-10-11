"""Canonical Raw Event（§8.2）— Parser 输出，Resolver 输入。

Metric Engine 永不直接读 SQLite。TuringTraceParser 把 SQLite part 行解析为 RawEvent。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

# §8.2 event_type 枚举
EVENT_TYPES = {
    "SESSION_START", "SESSION_END", "MESSAGE", "TEXT", "REASONING",
    "TOOL_CALL", "TOOL_RESULT", "STEP_START", "STEP_FINISH",
    "SYSTEM_EVENT", "UNKNOWN",
}


@dataclass
class RawEvent:
    event_id: str
    trace_id: str
    session_id: str
    event_type: str            # EVENT_TYPES 之一；未识别 → UNKNOWN
    timestamp_ms: int | None
    message_id: str | None
    part_id: str | None
    step_no: int | None
    tool_name: str | None
    input_json: dict | None
    output_json: dict | None
    raw_type: str              # 原始 part.type（如 'tool' / 'step-start' / 'text'）
    parse_status: str = "OK"  # OK / PARTIAL / INVALID
    parse_error: str | None = None
    source_table: str = "part"  # 'part' / 'session' / 'event'
    source_row_id: str = ""
    parser_version: str = "1.0"
    is_kg_interaction: bool = False  # parser 标记：是否为知识图谱交互（Athena 检索/知识查询）
    is_memory_interaction: bool = False  # parser 标记：是否为记忆交互（memengine/argo.memory 读取/检索）
    is_memory_write: bool = False  # parser 标记：是否为记忆写入（mem save 等；不纳入访问统计）
    is_finding_submission: bool = False  # parser 标记：是否为漏洞发现提交（各 parser 在 parse 时设置）
    call_id: str = ""           # 工具调用 ID（trace 原始 ID，用于 CALL-RESULT 精确配对）

    def is_tool_call(self) -> bool:
        return self.event_type == "TOOL_CALL"

    def is_tool_result(self) -> bool:
        return self.event_type == "TOOL_RESULT"


# ===== 记忆交互检测（各 parser 共用）=====
import re as _re

# 记忆读取（CLI 命令）：argo.memory get/search/recall 等，总是算记忆交互
_MEMORY_CLI_RE = _re.compile(
    r"argo\.memory\s+(get|search|recall|list|query|find|suggestions)"  # Argo: argo.memory get/search/recall/suggestions
    r"|mem\s+(recall|get|search|list|query|find|suggestions)",  # memengine: mem recall/get/search/suggestions
    _re.IGNORECASE,
)
# 记忆读取（路径引用）：memengine 或 /app/memory/ 目录
_MEMORY_PATH_RE = _re.compile(
    r"[\\/]memengine(?:-[^\\/\s]+)?[\\/](?:seeddir)?"  # memengine 目录路径（含 seeddir 子目录和根目录）
    r"|[\\/]app[\\/]memory[\\/]",  # /app/memory/ 目录
    _re.IGNORECASE,
)
# 内容读取命令（cat/head/tail/grep/rg 等；不含 ls/find/wc/stat 等纯列文件命令）
_MEMORY_CONTENT_READ_RE = _re.compile(
    r"\b(?:cat|head|tail|grep|sed|awk|less|more|for|rg)\b",
    _re.IGNORECASE,
)
# 记忆写入：不算记忆访问（用户口径：只看读取/检索）
_MEMORY_WRITE_RE = _re.compile(
    r"mem\s+(?:save|store|add|write|insert|update)"
    r"|argo\.memory\s+(?:save|store|add)"
    r"|>>?\s*[^\s|]*[\\/]memengine"  # 重定向写入 memengine 路径（cat > / echo >）
    r"|mkdir\s+[^|]*[\\/]memengine"  # mkdir 创建 memengine 目录
    r"|>>?\s*[^\s|]*[\\/]app[\\/]memory"  # 重定向写入 /app/memory/ 路径（WebVulnVerify）
    r"|mkdir\s+[^|]*[\\/]app[\\/]memory",  # mkdir 创建 /app/memory/ 目录
    _re.IGNORECASE,
)


def detect_memory_flags(tool_name: str, input_json) -> tuple[bool, bool]:
    """检测工具调用是否为记忆读取/写入。返回 (is_memory_interaction, is_memory_write)。

    记忆只看获取的（读取、检索），不看写入 —— 与用户口径一致。
    ls/find/wc/stat 等纯列文件命令不算记忆读取（没有任务含义）。
    read 工具直读记忆文件算记忆读取；grep 工具搜索记忆目录也算。
    glob 工具只列文件不算。
    各 parser 构造 RawEvent 时调用：
        is_mem, is_mem_w = detect_memory_flags(tool_name, inp)
    """
    tn = (tool_name or "").lower()

    # bash 工具：检查命令内容
    if tn in ("bash", "bash_tool", "shell"):
        cmd = str((input_json or {}).get("command", "")) if isinstance(input_json, dict) else str(input_json or "")
        if not cmd:
            return False, False
        cmd_l = cmd.lower()
        if _MEMORY_WRITE_RE.search(cmd_l):
            return False, True   # 写入：标记 write，不算访问
        # CLI 命令（argo.memory/mem recall 等）：总是算记忆读取
        if _MEMORY_CLI_RE.search(cmd_l):
            return True, False
        # 路径引用（memengine/app/memory）：仅当含内容读取命令时算
        if _MEMORY_PATH_RE.search(cmd_l) and _MEMORY_CONTENT_READ_RE.search(cmd_l):
            # ls/find/wc/stat 等纯列文件命令不含 cat 时不算
            first_token = cmd_l.strip().split()[0] if cmd_l.strip() else ""
            if first_token in ("ls", "find", "wc", "stat", "file", "du", "tree") and "cat" not in cmd_l:
                return False, False
            return True, False
        return False, False

    # read 工具：检查 file_path 是否指向记忆目录（直读文件内容，算记忆读取）
    if tn in ("read", "readfile"):
        if not isinstance(input_json, dict):
            return False, False
        fp = str(input_json.get("file_path", "") or input_json.get("path", ""))
        if fp and _MEMORY_PATH_RE.search(fp.lower()):
            return True, False
        return False, False

    # grep 工具：检查 path 是否指向记忆目录（搜索文件内容，算记忆读取）
    if tn in ("grep", "rg"):
        if not isinstance(input_json, dict):
            return False, False
        path = str(input_json.get("path", "") or input_json.get("cwd", ""))
        if path and _MEMORY_PATH_RE.search(path.lower()):
            return True, False
        return False, False

    # write/edit 工具：检查 file_path 是否指向记忆目录（算写入）
    if tn in ("write", "edit"):
        if not isinstance(input_json, dict):
            return False, False
        fp = str(input_json.get("file_path", ""))
        if fp and _MEMORY_PATH_RE.search(fp.lower()):
            return False, True
        return False, False

    # glob 等其他工具：只列文件不读内容，不算
    return False, False


def usage_numbers(usage: dict) -> tuple[int, int, int, int]:
    """从 usage dict 提取 token 数，兼容多种键名格式。

    各 agent trace 的 usage 键名不同：
    - Claude Code / SecMate: input_tokens, output_tokens, cache_read_input_tokens
    - WebVulnVerify:          input_tokens, output_tokens, cache_read_tokens
    - CVulnVerify / Dataflow: input, output, cacheRead, reasoning

    返回 (input, output, reasoning, cache_read)。
    """
    if not isinstance(usage, dict):
        return 0, 0, 0, 0

    def num(*keys) -> int:
        for k in keys:
            v = usage.get(k)
            if isinstance(v, (int, float)):
                return int(v)
        return 0

    ti = num("input_tokens", "input")
    to = num("output_tokens", "output")
    tr = num("reasoning_tokens", "reasoning")
    tcr = num("cache_read_tokens", "cacheRead", "cache_read_input_tokens", "cache_read")
    return ti, to, tr, tcr
