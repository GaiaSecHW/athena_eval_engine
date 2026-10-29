"""DataflowVulnScan 平台 finding 提取器。

从 dataflow 的 vuln_intake_result 事件提取 case_id 作为索引键。
dataflow parser 把每个 status=reported 的 vuln_intake_result 解析成
TEXT 事件，output_json 形如 {"findings": [{"finding_id", "case_id",
"function_name", "line", "title", "vuln_type", ...}]}，
session_id 为 "dvs-intake-result"（见 v2/parsers/dataflow/parser.py
_parse_intake_events）。

基线 case_id（如 case-20260917-232842-xxx）与上报的 case_id 一致，
作为索引键精确匹配；title 同时入索引，供 raw_title/vuln_title 匹配路径。
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
                    sid = ev.session_id or ""
                    if not key or not sid:
                        continue
                    entry = (sid, title, dp.agent_type)
                    # case_id 索引：供 case_id/vuln_id 精确匹配路径
                    if entry not in self._index[key]:
                        self._index[key].append(entry)
                    # title 索引：供 raw_title / vuln_title 匹配路径
                    if title and entry not in self._index[title]:
                        self._index[title].append(entry)
