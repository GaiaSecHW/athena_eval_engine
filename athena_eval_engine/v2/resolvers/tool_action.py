"""ToolActionResolver — 从 events 提取工具调用分布（§8.9）。

按 CanonicalAction 分类（KG > CODE > SHELL > OTHER）。
平台无关：只依赖 RawEvent 的 is_kg_interaction flag。

从老代码拷贝，去掉对 parse_utils 的依赖。
"""
from __future__ import annotations

import re

from ..core.raw_event import RawEvent
from ..core.task_run import TaskRun
from ..core.facts import ToolActionFact
from ..core.enums import CanonicalAction


def _path_of(e: RawEvent) -> str:
    """从 input_json 提取路径（read/bash 的 file_path / command）。"""
    d = e.input_json or {}
    return str(d.get("file_path") or d.get("path") or d.get("command") or "")


class ToolActionResolver:
    """从 events 提取工具调用分布。

    Canonical Action v1.0 优先级：KG > CODE > SHELL > OTHER

    分类规则：
    - KG: parser 标记的 is_kg_interaction，或 config 配置的 skill/path/command 模式
    - CODE: read/grep/glob（非 wiki）
    - SHELL: bash（非 wiki）
    - OTHER: 其他

    config 结构（可选，向后兼容）：
        access_rules:
            skill_names: list[str]      # skill 工具名
            path_patterns: list[str]    # 路径模式
            command_patterns: list[str] # 命令正则
    """

    ACTION_SCHEMA = "1.0"

    def __init__(self, config: dict | None = None):
        self.access_rules = (config or {}).get("access_rules", {})

    def resolve(self, task_run: TaskRun, events: list[RawEvent], schema=None) -> ToolActionFact:
        counts = {a.value: 0 for a in CanonicalAction}

        for e in events:
            if not e.is_tool_call():
                continue
            action = self._classify(e)
            counts[action] += 1

        total = sum(counts.values())
        return ToolActionFact(
            tool_action_fact_id=f"taf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            action_schema_version=self.ACTION_SCHEMA,
            kg_count=counts["KG"],
            code_count=counts["CODE"], shell_count=counts["SHELL"],
            other_count=counts["OTHER"],
            total_tool_calls=total, action_distribution=counts,
        )

    def _classify(self, e: RawEvent) -> str:
        """按优先级分类：KG > CODE > SHELL > OTHER。"""
        tool = e.tool_name or ""
        path = _path_of(e)
        skill_name = str((e.input_json or {}).get("name") or "")

        # KG：parser 已标记的知识图谱交互
        if e.is_kg_interaction:
            return "KG"

        # KG：config 配置的 skill / path / command 模式（向后兼容）
        if skill_name in set(self.access_rules.get("skill_names", [])):
            return "KG"
        for p in self.access_rules.get("path_patterns", []):
            if p in path:
                return "KG"
        for c in self.access_rules.get("command_patterns", []):
            if re.search(c, path):
                return "KG"

        if tool in ("read", "grep", "glob") and "wiki" not in path:
            return "CODE"
        if tool == "bash" and "wiki" not in path:
            return "SHELL"
        return "OTHER"
