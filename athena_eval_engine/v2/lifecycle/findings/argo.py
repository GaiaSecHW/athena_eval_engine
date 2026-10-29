"""Argo 平台 finding 提取器。

Argo finding 无 title，只有 description + (cwe, file, line) key。
运行态下 finding 上报漏洞中心，description 成为漏洞中心 case 的 vuln_title，
用 description 作索引键（等价于 turing 的 title 位置）。

finding 来源：
1. session_graph.sessions[sid].finding_descs（investigate accepted payload）
2. argo board facts 表 fallback——上报 session 文件丢失时（intent 表的
   session_id 在 trace 里不存在），从 MySQL facts 表读 finding description，
   并标记 session_lost 注明 session 丢失。
"""
from __future__ import annotations

import logging

from ...core.data_pack import DataPack
from .base import FindingExtractor, register

_log = logging.getLogger(__name__)


@register("argo")
class ArgoFindingExtractor(FindingExtractor):
    """Argo 挖掘 agent 的 finding 提取。

    parser 已把 finding description 存进 session_graph.sessions[sid].finding_descs
    （investigate accepted payload）。上报 session 文件丢失时从 facts 表 fallback。
    """

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            sessions = (dp.session_graph or {}).get("sessions", {}) if isinstance(dp.session_graph, dict) else {}
            # 1. 从 session finding_descs 提取（正常路径）
            for sid, sdata in sessions.items():
                sdata_d = sdata if isinstance(sdata, dict) else {}
                # 只提取 investigate（挖掘）session 的 finding——只有 investigate
                # 上报漏洞（accepted data.findings），verify 的 finding_descs 是
                # queue prompt 里"要验证的 finding"，不是上报，不应进索引。
                st = sdata_d.get("session_type") or sdata_d.get("task_type") or ""
                if str(st).lower() == "verify":
                    continue
                fdescs = sdata_d.get("finding_descs", {})
                if not fdescs:
                    continue
                for fkey, fdesc in fdescs.items():
                    fdesc = str(fdesc or "").strip()
                    if not fdesc:
                        continue
                    # 跳过 verify 前缀 key（verify queue Description，非上报）
                    if str(fkey).startswith("verify:"):
                        continue
                    entry = (sid, fkey, dp.agent_type)
                    if entry not in self._index[fdesc]:
                        self._index[fdesc].append(entry)

            # 2. facts 表 fallback：上报 session 文件丢失的 finding
            #    （从 argo board MySQL facts 表读 description）
            self._extract_from_facts_db(dp)

    def _extract_from_facts_db(self, dp: DataPack):
        """从 argo board facts 表读 finding description 建索引。

        仅处理 trace 中找不到上报 session 的 finding——intent 表的
        session_id 指向的 trace 文件缺失（session 丢失）时，parser 提取
        不到 finding_descs。从 facts 表直接读 description 兜底，并标记
        session_lost 注明。

        finding 的产出 session 由 intent_outputs 关联：
        fact_id -> intent(session_id)，若 session_id 不在 trace sessions 里
        即为丢失。
        """
        sg = dp.session_graph or {}
        if not isinstance(sg, dict):
            return
        project_id = sg.get("project_id", "") or ""
        if not project_id:
            return
        # trace 中存在的 session 集合（用于判断上报 session 是否丢失）
        trace_sids = set((sg.get("sessions") or {}).keys())
        try:
            from ...infra.agent_db import AgentDBManager
            mgr = AgentDBManager()
            conn = mgr.get_connection("argo")
            if conn is None:
                return
            try:
                cur = conn.cursor()
                # 该 project 的全部 finding 类型 fact
                cur.execute(
                    "SELECT f.id, f.description, o.intent_id, i.session_id "
                    "FROM facts f "
                    "LEFT JOIN intent_outputs o ON o.fact_id = f.id "
                    "  AND o.project_id = f.project_id "
                    "LEFT JOIN intents i ON i.id = o.intent_id "
                    "  AND i.project_id = f.project_id "
                    "WHERE f.project_id = %s AND f.type = 'finding'",
                    (project_id,),
                )
                rows = cur.fetchall()
                cur.close()
                # 对每个 finding：description 未被任何 session 提取过 且
                # 上报 session 不在 trace 中 → fallback 建索引
                # entry sid 为空字符串——_classify_session 不加入 mining_sessions
                # （mining_sessions 不放占位符），case_matching 仍能匹配上 vuln_title
                for fid, fdesc, intent_id, session_id in rows:
                    fdesc = str(fdesc or "").strip()
                    if not fdesc:
                        continue
                    # description 已从 session 提取过 → 跳过
                    if fdesc in self._index:
                        continue
                    # 上报 session 丢失：session_id 不在 trace sessions 里
                    if session_id and session_id not in trace_sids:
                        entry = ("", f"fact:{fid}", dp.agent_type)
                        if entry not in self._index[fdesc]:
                            self._index[fdesc].append(entry)
                            _log.warning(
                                "Argo finding %s 上报 session %s 丢失"
                                "（trace 中不存在），facts 表 fallback 建索引"
                                "（mining_sessions 不放占位符）",
                                fid, session_id,
                            )
            finally:
                conn.close()
        except Exception as e:
            _log.warning("Argo _extract_from_facts_db failed: %s", str(e)[:200])
