"""DataflowVulnScan 平台 finding 提取器。

从 dataflow 的 vuln_intake_result 事件提取 case_id 作为索引键。
dataflow parser 把每个 status=reported 的 vuln_intake_result 解析成
TEXT 事件，output_json 形如 {"findings": [{"finding_id", "case_id",
"function_name", "line", "title", "vuln_type", ...}]}，
session_id 形如 dvs_{run_id}/intake-result（parser 合成的占位 session，
不写入 session_graph；extract 时映射到真实 scan session，见下）。

基线 case_id（如 case-20260917-232842-xxx）与上报的 case_id 一致，
作为索引键精确匹配；title 同时入索引，供 raw_title/vuln_title 匹配路径。

intake 事件的 session_id 形如 dvs_{run_id}/intake-result（parser 合成），
extract 时通过 run_id 映射到同 run_id 下的真实 scan session
（dvs_{run_id}/dxx-...-taint-00），保证下游能回溯真实挖掘 session，
与 turing/argo 的处理一致（匹配真实 session 而非合成占位）。
"""
from __future__ import annotations

import json

from ...core.data_pack import DataPack
from .base import FindingExtractor, register


@register("dataflow")
class DataflowFindingExtractor(FindingExtractor):
    """DataflowVulnScan 挖掘 agent 的 finding 提取。"""

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            # 该 pack 全部真实 session_id（供 intake 上报 → 真实 scan session 映射）
            real_sids = self._collect_real_sids(dp)
            for ev in (dp.events or []):
                out = ev.output_json
                if not out:
                    continue
                # output_json 可能是 dict 或 JSON 字符串
                data = out
                if isinstance(out, str):
                    try:
                        data = json.loads(out)
                    except (json.JSONDecodeError, TypeError):
                        continue
                if not isinstance(data, dict):
                    continue
                for f in (data.get("findings") or []):
                    if not isinstance(f, dict):
                        continue
                    key = str(f.get("case_id", "") or "")
                    title = str(f.get("title", "") or "")
                    if not key:
                        continue
                    sid = self._map_to_real_session(ev.session_id or "", real_sids)
                    if not sid:
                        continue
                    entry = (sid, title, dp.agent_type)
                    # case_id 索引：供 case_id/vuln_id 精确匹配路径
                    if entry not in self._index[key]:
                        self._index[key].append(entry)
                    # title 索引：供 raw_title / vuln_title 匹配路径
                    if title and entry not in self._index[title]:
                        self._index[title].append(entry)

    @staticmethod
    def _collect_real_sids(dp: DataPack) -> dict:
        """收集 dvs_run_id → [叶子 session_id] 映射（intake → scan 关联用）。

        session_id 形如 dvs_{run_id}/dxx-...-taint-00，取 / 前段作 run_id。
        只收集**叶子节点**（调用链最末端）——parent_map 中没有任何子 session
        指向它的 session（如 ...-vuln-report-00 / ...-vuln-judge-00）。
        匹配用叶子而非根节点，保证问题单调用链显示最下游的分析/上报 session。
        """
        mapping: dict[str, list[str]] = {}
        sg = dp.session_graph or {}
        sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
        parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}
        # 收集所有被指向的 session（作为子节点出现过的）——非叶子
        has_children: set[str] = set()
        if isinstance(parent_map, dict):
            has_children = set(parent_map.values())
        for sid in sessions:
            if not sid:
                continue
            run_id = str(sid).split("/")[0]
            if not run_id:
                continue
            # 叶子：不是任何 session 的父节点
            if sid in has_children:
                continue
            mapping.setdefault(run_id, []).append(str(sid))
        return mapping

    @staticmethod
    def _map_to_real_session(ev_sid: str, real_sids: dict) -> str:
        """把 intake 事件的 session_id（dvs_{run_id}/intake-result）映射到叶子 scan session。

        返回同 run_id 下第一个叶子节点（调用链最末端）；无映射返回空（不建索引）。
        """
        if not ev_sid:
            return ""
        run_id = str(ev_sid).split("/")[0]
        if not run_id:
            return ""
        sids = real_sids.get(run_id, [])
        return sids[0] if sids else ""
