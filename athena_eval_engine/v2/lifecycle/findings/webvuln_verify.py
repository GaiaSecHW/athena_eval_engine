"""WebVulnVerify 平台 finding 提取器。

从验证工具调用 input_json 提取 title + description。
"""
from __future__ import annotations

import re

from ...core.data_pack import DataPack
from .base import FindingExtractor, register

#: WebVulnVerify 平台：提取 finding 的工具名
_WEBVV_FINDING_TOOLS = {
    "vulnerability_analyze",
    "vulnerability_verify",
}


@register("webvuln_verify")
class WebVulnVerifyFindingExtractor(FindingExtractor):
    """WebVulnVerify 验证 agent 的 finding 提取。

    vulnerability_analyze / vulnerability_verify 的 input_json 含：
    - result: 验证报告文本（含"一句话结论"或"漏洞类型"表格行）
    - category: 漏洞分类标签
    - description: 漏洞描述

    优先从 result 提取一句话结论作为 title，
    其次提取漏洞类型表格行，回退到 category。
    """

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in _WEBVV_FINDING_TOOLS:
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
        """从 WebVulnVerify 工具调用事件中提取漏洞 title + description。"""
        inp = ev.input_json
        if not isinstance(inp, dict):
            return "", ""

        desc = str(inp.get("description", "") or "")

        result_text = str(inp.get("result", "") or "")
        if result_text:
            m = re.search(
                r'一句话结论[：:]\s*(.+?)(?=\n\n|\n#|\n-|\Z)',
                result_text, re.DOTALL,
            )
            if m:
                return m.group(1).strip(), desc
            m = re.search(r'漏洞类型\s*\|\s*(.+?)\s*\|', result_text)
            if m:
                return m.group(1).strip(), desc

        category = inp.get("category", "") or inp.get("vuln_type", "") or ""
        return (str(category) if category else "", desc)
