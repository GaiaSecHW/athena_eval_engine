"""Finding 提取策略包。

每个 agent 一个 FindingExtractor 实现类（turing/argo/webvuln_verify/
cvuln_verify），通过 base 工厂按 agent_type 路由。新增 agent 只需：
1. 在 findings/ 下新建 <agent>.py，实现 FindingExtractor 并 @register("<agent>")
2. 无需改动匹配主逻辑

导出：get_finding_extractor（工厂）、FindingExtractor（基类）。
"""
from __future__ import annotations

from .base import (
    FindingExtractor,
    all_agent_types,
    get_finding_extractor,
    register,
)
from . import turing, argo, webvuln_verify, cvuln_verify  # noqa: F401  注册副作用
from .turing import collect_turing_finding_sids

__all__ = [
    "FindingExtractor",
    "get_finding_extractor",
    "all_agent_types",
    "register",
    "collect_turing_finding_sids",
]
