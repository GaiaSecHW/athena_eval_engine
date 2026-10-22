"""Turing 平台 finding 提取器。

从 vuln-hunt-validate session 的 finding 工具调用 output 提取 title+description。
"""
from __future__ import annotations

import json

from ...core.data_pack import DataPack
from .base import FindingExtractor, register

# Turing 平台：含漏洞 finding 的 session agent 名（挖掘 agent 内部阶段）
_TURING_FINDING_AGENTS = {
    "vuln-hunt-validate",  # 旧版命名
    "web-validate",        # 新版命名
}

#: Turing 平台：提取 finding 的工具名（已归一化，横线→下划线）
_TURING_FINDING_TOOLS = {
    "vuln_hunt_query_finding",
    "vuln_hunt_update_finding",
}


@register("turing")
class TuringFindingExtractor(FindingExtractor):
    """Turing 挖掘 agent 的 finding 提取。

    finding 工具调用 vuln_hunt_query_finding / vuln_hunt_update_finding
    的 output_json 含 {"result": "...JSON..."}，其中 JSON 含 title/description。
    """

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                if turing_finding_sids and ev.session_id not in turing_finding_sids:
                    continue
                tool = ev.tool_name or ""
                if tool not in _TURING_FINDING_TOOLS:
                    continue
                title, desc = self._extract_title_desc(ev)
                if title:
                    sid = ev.session_id or ""
                    if sid:
                        entry = (sid, desc, dp.agent_type)
                        if entry not in self._index[title]:
                            self._index[title].append(entry)

    @staticmethod
    def _extract_title_desc(ev) -> tuple[str, str]:
        """从 Turing 工具调用事件中提取漏洞 title + description。

        vuln_hunt_query_finding 的 output_json 结构：
        {"result": "{...JSON string with title/description...}"}
        或直接是 JSON 字符串
        """
        outp = ev.output_json
        if not outp:
            return "", ""

        if isinstance(outp, str):
            try:
                outp = json.loads(outp)
            except (json.JSONDecodeError, ValueError):
                return "", ""
        if not isinstance(outp, dict):
            return "", ""

        result_str = outp.get("result", "")
        if isinstance(result_str, str):
            try:
                result = json.loads(result_str)
            except (json.JSONDecodeError, ValueError):
                return "", ""
        elif isinstance(result_str, dict):
            result = result_str
        else:
            return "", ""

        if not isinstance(result, dict):
            return "", ""

        title = result.get("title") or ""
        desc = result.get("description") or ""
        return (str(title) if title else "", str(desc) if desc else "")


def collect_turing_finding_sids(mining_packs: list[DataPack]) -> set[str]:
    """收集 Turing 内部含 finding 的 session（vuln-hunt-validate/web-validate）。

    这些是挖掘 agent 内部的验证阶段 session，归类为挖掘 agent session。
    """
    sids: set[str] = set()
    for dp in mining_packs:
        if dp.agent_type != "turing":
            continue
        for sid, sdata in (dp.session_graph.get("sessions") or {}).items():
            if sdata.get("agent") in _TURING_FINDING_AGENTS:
                sids.add(sid)
    return sids
