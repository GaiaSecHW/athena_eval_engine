"""Sink 点搜索扫描器 — FN case 的 session 定位。

对每个 FN case（基线 VULNERABLE + 原始数据无匹配），
拿基线 sink 点的 source_file 去原始数据 trace 中搜索，
找到搜索了该文件的 session，用于根因分析。

匹配规则：basename 匹配 + 完整路径匹配。
基线 source_file 路径（如 scanroot/MM26/src/.../Foo.java）与
trace 中路径（如 /data/files/.../output/source/.../Foo.java）前缀不同，
完整路径匹配会失败。先用 basename 匹配（Foo.java），再用完整路径作为 fallback。
"""
from __future__ import annotations

import os

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

        # basename 匹配 + 完整路径匹配
        # 基线路径 scanroot/MM26/src/.../Foo.java 与 trace 路径
        # /data/files/.../output/source/.../Foo.java 前缀不同，
        # 完整路径匹配会失败，basename 匹配兜底。
        basename = os.path.basename(source_file)

        hits: dict[str, set[str]] = {}

        for dp in data_packs:
            agent_type = dp.agent_type or ""
            for ev in (dp.events or []):
                if self._event_contains_source_file(ev, source_file, basename):
                    sid = ev.session_id or ""
                    if sid:
                        hits.setdefault(agent_type, set()).add(sid)

        result = {at: sorted(sids) for at, sids in hits.items()}
        total = sum(len(sids) for sids in result.values())
        log("SINK_SCAN",
            f"source_file={source_file} (basename={basename}): {total} sessions "
            f"in {len(result)} agent types",
            eval_id="")
        return result

    def scan_detailed(
        self,
        source_file: str,
        data_packs: list[DataPack],
    ) -> dict:
        """扫描全部 DataPack 的 events，返回详细的命中信息。

        与 scan() 不同，本方法返回命中的 event 上下文（tool_name、
        event_type、input/output 摘要），供 FN 漏报分析使用。

        Args:
            source_file: 基线 sink 点文件路径
            data_packs: 全部 DataPack（挖掘 + 验证 agent）

        Returns:
            {
                "source_file": str,
                "basename": str,
                "found": bool,
                "hits_by_agent": {
                    agent_type: [
                        {
                            "session_id": str,
                            "event_type": str,
                            "tool_name": str,
                            "input_preview": str,  # 前 200 字符
                            "output_preview": str,  # 前 200 字符
                            "matched_field": "input" | "output" | "both",
                            "match_type": "full_path" | "basename",
                        },
                        ...
                    ]
                },
                "hit_sessions": {agent_type: [session_id, ...]},
                "total_hits": int,
            }
        """
        if not source_file:
            return {
                "source_file": "",
                "basename": "",
                "found": False,
                "hits_by_agent": {},
                "hit_sessions": {},
                "total_hits": 0,
            }

        basename = os.path.basename(source_file)
        hits_by_agent: dict[str, list[dict]] = {}
        hit_sessions: dict[str, set[str]] = {}

        for dp in data_packs:
            agent_type = dp.agent_type or ""
            for ev in (dp.events or []):
                matched_field, match_type = self._find_match_location(
                    ev, source_file, basename)
                if matched_field is None:
                    continue
                sid = ev.session_id or ""
                if not sid:
                    continue
                hits_by_agent.setdefault(agent_type, []).append({
                    "session_id": sid,
                    "event_type": ev.event_type or "",
                    "tool_name": ev.tool_name or "",
                    "input_preview": _truncate_str(
                        _obj_to_str(ev.input_json), 200),
                    "output_preview": _truncate_str(
                        _obj_to_str(ev.output_json), 200),
                    "matched_field": matched_field,
                    "match_type": match_type,
                })
                hit_sessions.setdefault(agent_type, set()).add(sid)

        hit_sessions_result = {
            at: sorted(sids) for at, sids in hit_sessions.items()
        }
        total = sum(len(sids) for sids in hit_sessions_result.values())

        log("SINK_SCAN",
            f"scan_detailed source_file={source_file} "
            f"(basename={basename}): {total} sessions in "
            f"{len(hit_sessions_result)} agent types, "
            f"{sum(len(v) for v in hits_by_agent.values())} hit events",
            eval_id="")

        return {
            "source_file": source_file,
            "basename": basename,
            "found": total > 0,
            "hits_by_agent": hits_by_agent,
            "hit_sessions": hit_sessions_result,
            "total_hits": total,
        }

    @staticmethod
    def _find_match_location(
        ev, source_file: str, basename: str,
    ) -> tuple[str | None, str | None]:
        """返回命中的字段位置和匹配类型。

        Returns:
            (matched_field, match_type)
            - matched_field: "input" | "output" | "both" | None
            - match_type: "full_path" | "basename" | None
        """
        if not source_file:
            return None, None

        def _search_in_obj(obj, target: str) -> bool:
            if obj is None:
                return False
            if isinstance(obj, str):
                return target in obj
            if isinstance(obj, dict):
                for v in obj.values():
                    if _search_in_obj(v, target):
                        return True
                return False
            if isinstance(obj, list):
                for item in obj:
                    if _search_in_obj(item, target):
                        return True
                return False
            return False

        # 1. 完整路径匹配（优先）
        in_full = _search_in_obj(ev.input_json, source_file)
        out_full = _search_in_obj(ev.output_json, source_file)
        if in_full and out_full:
            return "both", "full_path"
        if in_full:
            return "input", "full_path"
        if out_full:
            return "output", "full_path"

        # 2. basename 匹配（兜底）
        if basename and basename != source_file:
            in_base = _search_in_obj(ev.input_json, basename)
            out_base = _search_in_obj(ev.output_json, basename)
            if in_base and out_base:
                return "both", "basename"
            if in_base:
                return "input", "basename"
            if out_base:
                return "output", "basename"

        return None, None

    @staticmethod
    def _event_contains_source_file(ev, source_file: str, basename: str) -> bool:
        """检查 RawEvent 的 input_json/output_json 中是否出现 source_file。

        匹配策略：
        1. 完整路径匹配：source_file 作为完整字符串出现在字段值中
        2. basename 匹配：basename（如 Foo.java）作为完整字符串出现在字段值中
           基线路径与 trace 路径前缀不同时，完整路径匹配失败，basename 兜底。
        """
        if not source_file:
            return False

        def _search_in_obj(obj, target: str) -> bool:
            if obj is None:
                return False
            if isinstance(obj, str):
                return target in obj
            if isinstance(obj, dict):
                for v in obj.values():
                    if _search_in_obj(v, target):
                        return True
                return False
            if isinstance(obj, list):
                for item in obj:
                    if _search_in_obj(item, target):
                        return True
                return False
            return False

        # 1. 完整路径匹配（优先）
        if _search_in_obj(ev.input_json, source_file):
            return True
        if _search_in_obj(ev.output_json, source_file):
            return True
        # 2. basename 匹配（兜底，处理路径前缀不同的情况）
        if basename and basename != source_file:
            if _search_in_obj(ev.input_json, basename):
                return True
            if _search_in_obj(ev.output_json, basename):
                return True
        return False


def _truncate_str(s: str, n: int) -> str:
    """截断字符串到 n 字符，加 ... 标记。"""
    if not s:
        return ""
    if len(s) <= n:
        return s
    return s[:n] + "..."


def _obj_to_str(obj) -> str:
    """将任意对象转为字符串（dict/list 转 JSON）。"""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    try:
        import json
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)
