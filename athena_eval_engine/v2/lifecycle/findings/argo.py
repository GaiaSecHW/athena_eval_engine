"""Argo 平台 finding 提取器。

Argo finding 无 title，只有 description + (cwe, file, line) key。
运行态下 finding 上报漏洞中心，description 成为漏洞中心 case 的 vuln_title，
用 description 作索引键（等价于 turing 的 title 位置）。
"""
from __future__ import annotations

from ...core.data_pack import DataPack
from .base import FindingExtractor, register


@register("argo")
class ArgoFindingExtractor(FindingExtractor):
    """Argo 挖掘 agent 的 finding 提取。

    parser 已把 finding description 存进 session_graph.sessions[sid].finding_descs
    （investigate accepted payload + verify queue Description 两种来源）。
    """

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            sessions = (dp.session_graph or {}).get("sessions", {}) if isinstance(dp.session_graph, dict) else {}
            for sid, sdata in sessions.items():
                sdata_d = sdata if isinstance(sdata, dict) else {}
                fdescs = sdata_d.get("finding_descs", {})
                if not fdescs:
                    continue
                for fkey, fdesc in fdescs.items():
                    fdesc = str(fdesc or "").strip()
                    if not fdesc:
                        continue
                    entry = (sid, fkey, dp.agent_type)
                    if entry not in self._index[fdesc]:
                        self._index[fdesc].append(entry)
