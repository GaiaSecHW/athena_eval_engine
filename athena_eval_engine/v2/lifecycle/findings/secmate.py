"""SecMate 平台 finding 提取器。

SecMate finding 权威源是 secmate MySQL 的 finding 表（title + source_finding_id +
report_state=reported）。parser 已通过 source_finding_id 桥接 findings.db 的
source_session_id，把 title 存进 session_graph.sessions[sid].finding_descs
（key=title，与 turing 的 title 索引一致）。

本 extractor 直接从 session_graph 读取，title 作索引键。
"""
from __future__ import annotations

from ...core.data_pack import DataPack
from .base import FindingExtractor, register


@register("secmate")
class SecMateFindingExtractor(FindingExtractor):
    """SecMate 挖掘 agent 的 finding 提取。

    从 session_graph.sessions[sid].finding_descs 读取（parser 已从
    secmate MySQL finding 表预填 title），每条 title 作为索引键。
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
                    entry = (sid, fkey, dp.agent_type)
                    if entry not in self._index[fdesc]:
                        self._index[fdesc].append(entry)
