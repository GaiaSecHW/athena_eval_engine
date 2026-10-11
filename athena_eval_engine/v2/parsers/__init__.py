"""Parser 注册与选择。

设计参考 docs/v2-architecture-design.md §4.4。

6 个 parser 在 #48 中实现，此处先写注册框架 + get_parser 路径推断逻辑。
parser 的 import 放在函数内部延迟加载，避免模块加载时 ImportError。
"""
from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING

from .base import BaseParser

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Parser 注册表：agent_type -> parser 类名
# parser 实际类在 #48 中实现，此处记录类名供延迟加载
PARSER_REGISTRY: dict[str, str] = {
    "turing": "TuringParser",
    "argo": "ArgoParser",
    "secmate": "SecMateParser",
    "cvuln_verify": "CVulnVerifyParser",
    "webvuln_verify": "WebVulnVerifyParser",
    "dataflow": "DataflowVulnScanParser",
}

# trace_kind 别名 -> agent_type（兼容老代码的 trace_kind 值）
_TRACE_KIND_ALIASES: dict[str, str] = {
    "turing": "turing",
    "argo": "argo",
    "secmate": "secmate",
    "cvuln_verify": "cvuln_verify",
    "webvulnverify": "webvuln_verify",
    "dataflow": "dataflow",
}


def _load_parser_class(agent_type: str) -> type[BaseParser]:
    """延迟加载 parser 类。parser 在 #48 中实现。"""
    if agent_type == "turing":
        from .turing import TuringParser
        return TuringParser
    if agent_type == "argo":
        from .argo import ArgoParser
        return ArgoParser
    if agent_type == "secmate":
        from .secmate import SecMateParser
        return SecMateParser
    if agent_type == "cvuln_verify":
        from .cvuln_verify import CVulnVerifyParser
        return CVulnVerifyParser
    if agent_type == "webvuln_verify":
        from .webvuln_verify import WebVulnVerifyParser
        return WebVulnVerifyParser
    if agent_type == "dataflow":
        from .dataflow import DataflowVulnScanParser
        return DataflowVulnScanParser
    raise ValueError(f"unknown agent_type: {agent_type}")


def _is_webvulnverify_trace(path: str) -> bool:
    """检测 JSONL 是否为 WebVulnVerify 格式（含 session_meta 行类型）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                return d.get("type") == "session_meta"
    except Exception:
        return False
    return False


def _is_secmate_trace(path: str) -> bool:
    """检测路径是否为 SecMate trace 格式。"""
    try:
        from .secmate import is_secmate_trace
        return is_secmate_trace(path)
    except ImportError:
        # parser 尚未实现，用启发式规则
        check_path = path
        if os.path.isdir(path):
            import glob
            jfiles = sorted(glob.glob(os.path.join(path, "*.jsonl")))
            check_path = jfiles[0] if jfiles else ""
        if not check_path:
            return False
        try:
            with open(check_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    # SecMate trace 的特征：persona / store_finding
                    s = json.dumps(d)
                    return "persona" in s or "store_finding" in s
        except Exception:
            return False
    return False


def get_parser(trace_kind: str | None, source_uri: str) -> BaseParser:
    """根据 trace_kind 或路径推断选择 parser。

    优先使用 trace_kind（显式指定），无 trace_kind 时按路径特征推断。
    路径推断逻辑从老代码 ``evaluation_service._get_parser()`` 拷贝，适配 v2 结构。
    """
    # 1. 显式 trace_kind
    if trace_kind:
        agent_type = _TRACE_KIND_ALIASES.get(trace_kind, trace_kind)
        cls = _load_parser_class(agent_type)
        return cls()

    # 2. 路径推断
    p = os.path.normpath(source_uri)
    cvuln_suffix = os.path.join("tasks", "c_vuln_verify")
    argo_suffix = os.path.join("session", "argo")
    dataflow_suffix = os.path.join("session", "dataflow_vuln_scan")

    # 2a. SecMate 目录特征
    if p.replace("\\", "/").endswith("/session/secmate"):
        cls = _load_parser_class("secmate")
        return cls()

    # 2b. CVulnVerify 目录特征
    if os.path.isdir(p) and p.endswith(cvuln_suffix):
        cls = _load_parser_class("cvuln_verify")
        return cls()

    # 2c. Argo 目录特征
    if os.path.isdir(p) and p.endswith(argo_suffix):
        cls = _load_parser_class("argo")
        return cls()

    # 2d. Dataflow 目录特征
    if os.path.isdir(p) and (p.endswith(dataflow_suffix) or "dataflow_vuln_scan" in p):
        cls = _load_parser_class("dataflow")
        return cls()

    # 2e. Dataflow 单个 JSONL 文件
    if "dataflow_vuln_scan" in p and (p.endswith(".jsonl") or os.path.isdir(p)):
        cls = _load_parser_class("dataflow")
        return cls()

    # 2f. Turing SQLite 文件
    if p.endswith("opencode.db"):
        cls = _load_parser_class("turing")
        return cls()

    # 2g. 目录或 JSONL 文件——需要内容检测区分 SecMate / WebVulnVerify / Argo
    if os.path.isdir(p) or p.endswith(".jsonl"):
        if _is_secmate_trace(p):
            cls = _load_parser_class("secmate")
            return cls()

        # 检测 WebVulnVerify 格式（需读第一个 .jsonl 文件）
        check_path = p
        if os.path.isdir(p):
            import glob
            jfiles = sorted(glob.glob(os.path.join(p, "*.jsonl")))
            check_path = jfiles[0] if jfiles else ""
        if check_path and _is_webvulnverify_trace(check_path):
            cls = _load_parser_class("webvuln_verify")
            return cls()

        # 默认 Argo（JSONL 目录，非 SecMate/WebVulnVerify）
        cls = _load_parser_class("argo")
        return cls()

    # 2h. 兜底：Turing
    cls = _load_parser_class("turing")
    return cls()
