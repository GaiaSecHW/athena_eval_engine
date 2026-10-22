"""CVulnVerify 平台 finding 提取器。

从验证工具调用 input_json 提取 vulnerability_id / case_id 作为索引键。
"""
from __future__ import annotations

from ...core.data_pack import DataPack
from .base import FindingExtractor, register

#: CVulnVerify 平台：提取 finding 的工具名
_CVULN_FINDING_TOOLS = {
    "vulnerability_verify",
    "vulnerability_cvss",
    "vulnerability_analyze",
}


@register("cvuln_verify")
class CVulnVerifyFindingExtractor(FindingExtractor):
    """CVulnVerify 验证 agent 的 finding 提取。

    用 input_json 的 vulnerability_id / case_id 作索引键
    （cvuln 的 finding 通过漏洞 ID 关联 case）。
    """

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in _CVULN_FINDING_TOOLS:
                    continue
                inp = ev.input_json or {}
                key = (
                    inp.get("vulnerability_id")
                    or inp.get("case_id")
                    or ""
                )
                if key:
                    sid = ev.session_id or ""
                    if sid:
                        entry = (sid, "", dp.agent_type)
                        if entry not in self._index[str(key)]:
                            self._index[str(key)].append(entry)
