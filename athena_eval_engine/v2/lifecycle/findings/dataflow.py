"""DataflowVulnScan 平台 finding 提取器。

从 dataflow 的 vuln_intake_result 事件提取 case_id 作为索引键。
dataflow parser 把每个 status=reported 的 vuln_intake_result 解析成
TEXT 事件，output_json 形如 {"findings": [{"finding_id", "case_id",
"function", "line", "title", "vuln_type", ...}]}，
session_id 形如 dvs_{run_id}/intake-result（parser 合成的占位 session，
不写入 session_graph；extract 时映射到真实 scan session，见下）。

基线 case_id（如 case-20260917-232842-xxx）与上报的 case_id 一致，
作为索引键精确匹配；title 同时入索引，供 raw_title/vuln_title 匹配路径。

intake 上报的 run 与分析漏洞的 run 可能不一致（intake 事件在 events.jsonl
记录于上报 run，但精确分析链 taint→judge→report 在另一个 run）。
因此映射不能用 intake 的 run_id 取叶子，必须用 finding 的 function
跨全部 run 匹配精确分析链（dvs_{run}/d{depth}-{function}-...-vuln-report-00），
匹配不到才回退 intake run 的第一个叶子。
"""
from __future__ import annotations

import json
import re

from ...core.data_pack import DataPack
from .base import FindingExtractor, register

#: session_id 中函数段的提取：dvs_{run}/d{depth}-{function}-{analysis_type}-...
_SESSION_FUNC_RE = re.compile(r"^dvs_[^/]+/d\d+-(.+?)-\w+")

#: 精确分析链末端分析类型（优先级从高到低，取最下游）
_REPORT_TYPES = ("vuln-report", "vuln-false-positive-judge", "vuln-judge")


@register("dataflow")
class DataflowFindingExtractor(FindingExtractor):
    """DataflowVulnScan 挖掘 agent 的 finding 提取。"""

    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        # 收集全部 session 的 function 索引（跨 run 精确匹配分析链用）
        func_to_sessions = self._collect_func_sessions(packs)
        for dp in packs:
            if dp.agent_type != self.agent_type:
                continue
            real_sids = self._collect_real_sids(dp)
            for ev in (dp.events or []):
                out = ev.output_json
                if not out:
                    continue
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
                    function = str(f.get("function", "") or "")
                    sid = self._map_to_real_session(
                        ev.session_id or "", real_sids,
                        function=function, func_to_sessions=func_to_sessions,
                    )
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
    def _collect_func_sessions(packs: list[DataPack]) -> dict:
        """收集 function → [叶子分析 session] 索引（跨全部 run）。

        session_id 形如 dvs_{run}/d{depth}-{function}-{analysis_type}-...-00，
        提取 function 段（如 upload_file_uploading）。只保留分析链末端的
        session（vuln-report / vuln-false-positive-judge / vuln-judge 结尾），
        它们是漏洞判定的最下游，是 case 真正对应的分析 session。
        """
        func_map: dict[str, list[str]] = {}
        for dp in packs:
            if dp.agent_type != "dataflow":
                continue
            sg = dp.session_graph or {}
            sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
            for sid in sessions:
                if not sid or "/intake-result" in sid:
                    continue
                m = _SESSION_FUNC_RE.match(str(sid))
                if not m:
                    continue
                function = m.group(1)
                # 只保留分析链末端（含 vuln-report / vuln-false-positive-judge / vuln-judge）
                if not any(t in sid for t in _REPORT_TYPES):
                    continue
                if sid not in func_map.setdefault(function, []):
                    func_map[function].append(str(sid))
        return func_map

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
        has_children: set[str] = set()
        if isinstance(parent_map, dict):
            has_children = set(parent_map.values())
        for sid in sessions:
            if not sid or "/intake-result" in sid:
                continue
            run_id = str(sid).split("/")[0]
            if not run_id:
                continue
            if sid in has_children:
                continue
            mapping.setdefault(run_id, []).append(str(sid))
        return mapping

    @staticmethod
    def _map_to_real_session(
        ev_sid: str, real_sids: dict,
        function: str = "", func_to_sessions: dict | None = None,
    ) -> str:
        """把 intake 事件映射到 case 对应的真实分析 session。

        优先：用 finding 的 function 跨全部 run 匹配精确分析链末端
        （dvs_{run}/d{depth}-{function}-...-vuln-report-00）——intake 上报
        run 与分析 run 可能不同，不能只看 intake 的 run。
        回退：intake 所在 run 的第一个叶子节点。
        """
        # 1. function 精确匹配（跨 run）
        if function and func_to_sessions:
            candidates = func_to_sessions.get(function, [])
            if candidates:
                return candidates[0]
        # 2. 回退：intake run 的第一个叶子
        if not ev_sid:
            return ""
        run_id = str(ev_sid).split("/")[0]
        if not run_id:
            return ""
        sids = real_sids.get(run_id, [])
        return sids[0] if sids else ""
