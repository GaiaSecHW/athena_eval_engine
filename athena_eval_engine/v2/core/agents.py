"""Agent 类型集中配置。

所有 agent 类型的列表、分类、显示名、顺序在此统一定义，
后端各模块 import 本模块，不再各自维护 agent 字面量。
新增 agent 只需在此文件加一行，所有下游自动生效。

Agent 分类：
- 挖掘 agent（MINING）：turing / argo / secmate / dataflow —— 漏洞挖掘
- 验证 agent（VERIFY）：cvuln_verify / webvuln_verify —— 漏洞验证
"""
from __future__ import annotations

# ── Agent 类型分类 ──

#: 挖掘 agent 类型（漏洞挖掘）
MINING_AGENT_TYPES: list[str] = [
    "turing", "argo", "secmate", "dataflow",
]

#: 验证 agent 类型（漏洞验证）
VERIFY_AGENT_TYPES: list[str] = [
    "cvuln_verify", "webvuln_verify",
]

#: 全部 agent 类型（挖掘 + 验证，展示顺序）
ALL_AGENT_TYPES: list[str] = MINING_AGENT_TYPES + VERIFY_AGENT_TYPES

#: 挖掘 agent 集合（用于成员判断，O(1)）
MINING_AGENT_SET: set[str] = set(MINING_AGENT_TYPES)

#: 验证 agent 集合
VERIFY_AGENT_SET: set[str] = set(VERIFY_AGENT_TYPES)

#: 全部 agent 集合
ALL_AGENT_SET: set[str] = set(ALL_AGENT_TYPES)

# ── 显示名映射 ──

#: agent_type → 中文显示名（含角色，用于问题单/报告）
AGENT_DISPLAY_NAMES: dict[str, str] = {
    "turing": "挖掘Agent(Turing)",
    "argo": "挖掘Agent(Argo)",
    "secmate": "挖掘Agent(SecMate)",
    "dataflow": "挖掘Agent(Dataflow)",
    "webvuln_verify": "验证Agent(WebVulnVerify)",
    "cvuln_verify": "验证Agent(CVulnVerify)",
}

#: agent_type → 短标签（用于看板/图表轴标签）
AGENT_SHORT_LABELS: dict[str, str] = {
    "turing": "Turing",
    "argo": "Argo",
    "secmate": "SecMate",
    "dataflow": "Dataflow",
    "webvuln_verify": "WebVulnVerify",
    "cvuln_verify": "CVulnVerify",
}


def is_mining(agent_type: str) -> bool:
    """判断是否为挖掘 agent。"""
    return agent_type in MINING_AGENT_SET


def is_verify(agent_type: str) -> bool:
    """判断是否为验证 agent。"""
    return agent_type in VERIFY_AGENT_SET


def display_name(agent_type: str) -> str:
    """返回 agent 中文显示名，未知类型返回原值。"""
    return AGENT_DISPLAY_NAMES.get(agent_type, agent_type or "—")


def short_label(agent_type: str) -> str:
    """返回 agent 短标签，未知类型返回原值。"""
    return AGENT_SHORT_LABELS.get(agent_type, agent_type or "-")
