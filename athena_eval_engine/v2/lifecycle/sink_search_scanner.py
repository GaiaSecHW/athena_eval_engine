"""Sink 点搜索扫描器 — FN case 的 session 定位。

对每个 FN case（基线 VULNERABLE + 原始数据无匹配），
拿基线 sink 点的 source_file 去原始数据 trace 中搜索，
找到搜索了该文件的 session，用于根因分析。

匹配规则：source_file 精确匹配（作为完整字符串出现在事件文本中）。
"""
from __future__ import annotations

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log


class SinkSearchScanner:
    """用基线 sink 点扫描 trace，定位搜索了该 sink 文件的 session。"""

    def scan(
        self,
        source_file: str,
        data_packs: list[DataPack],
    ) -> dict[str, list[str]]:
        """扫描全部 DataPack 的 events，找到搜索了 source_file 的 session。

        Args:
            source_file: 基线 sink 点文件路径
            data_packs: 全部 DataPack（挖掘 + 验证 agent）

        Returns:
            {agent_type: [session_id, ...]} 找到的 session，按 agent_type 分组
        """
        if not source_file:
            return {}

        hits: dict[str, set[str]] = {}

        for dp in data_packs:
            agent_type = dp.agent_type or ""
            for ev in (dp.events or []):
                if self._event_contains_source_file(ev, source_file):
                    sid = ev.session_id or ""
                    if sid:
                        hits.setdefault(agent_type, set()).add(sid)

        result = {at: sorted(sids) for at, sids in hits.items()}
        total = sum(len(sids) for sids in result.values())
        log("SINK_SCAN",
            f"source_file={source_file}: {total} sessions "
            f"in {len(result)} agent_types",
            eval_id="")
        return result

    @staticmethod
    def _event_contains_source_file(ev, source_file: str) -> bool:
        """检查 RawEvent 的 input_json/output_json 中是否出现 source_file。

        精确匹配：source_file 作为完整字符串出现在字段值中。
        """
        if not source_file:
            return False

        def _search_in_obj(obj) -> bool:
            if obj is None:
                return False
            if isinstance(obj, str):
                return source_file in obj
            if isinstance(obj, dict):
                for v in obj.values():
                    if _search_in_obj(v):
                        return True
                return False
            if isinstance(obj, list):
                for item in obj:
                    if _search_in_obj(item):
                        return True
                return False
            return False

        if _search_in_obj(ev.input_json):
            return True
        if _search_in_obj(ev.output_json):
            return True
        return False
