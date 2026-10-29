"""SecMate 平台 finding 提取器。

SecMate finding 无 title，只有 description + vuln_type（findings.db 的
findings 表）。parser 已把 finding description 存进
session_graph.sessions[sid].finding_descs（key="<vuln_type>:<desc>"），
本 extractor 直接从 session_graph 读取建索引，description 作索引键
（等价于 turing 的 title 位置）。
"""
from __future__ import annotations

from ...core.data_pack import DataPack
from .base import FindingExtractor, register


@register("secmate")
class SecMateFindingExtractor(FindingExtractor):
    """SecMate 挖掘 agent 的 finding 提取。

    从 session_graph.sessions[sid].finding_descs 读取（parser 已从
    findings.db 预填），每条 finding 的 description 作为索引键。
    """

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            sessions = (dp.session_graph or {}).get(
                "sessions", {}) if isinstance(dp.session_graph, dict) else {}
            for sid, sdata in sessions.items():
                sdata_d = sdata if isinstance(sdata, dict) else {}
                fdescs = sdata_d.get("finding_descs", {})
                if not fdescs:
                    continue
                for fkey, fdesc in fdescs.items():
                    fdesc = str(fdesc or "").strip()
                    if not fdesc:
                        continue
                    # key 形如 "vuln_type:description"，跳过无内容 key
                    if not fkey:
                        continue
                    entry = (sid, fkey, dp.agent_type)
                    if entry not in self._index[fdesc]:
                        self._index[fdesc].append(entry)
