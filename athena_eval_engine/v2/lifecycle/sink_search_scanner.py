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

    def scan_with_sink_info(
        self,
        sink_info: dict,
        data_packs: list[DataPack],
    ) -> dict:
        """用 LLM 提取的结构化 sink 信息做精确匹配。

        三级匹配精度：
        1. **精确命中**（function 或 line）：event 的 input/output 中
           - 出现 sink 文件 + sink 函数名 → agent 读到了 sink 函数代码
           - 或 出现 sink 文件 + sink 行号在范围内 → agent 读到了 sink 行附近代码
           （XML 等配置文件没有函数，行号匹配是主要精确手段）
        2. **文件级命中**（file）：event 中只出现 sink 文件路径/basename，
           没有出现 sink 函数名也没有 sink 行号 → agent 读了文件但可能没碰到 sink 点
        3. **未命中**：event 中没有出现任何 sink 文件

        精确命中是"sink 找到"的强信号；文件级命中是弱信号。

        Args:
            sink_info: SinkInfoExtractor.extract() 返回的结构化 sink 信息
                {
                    "sink_files": [str],
                    "sink_functions": [str],
                    "sink_lines": [str],   # 行号或行号区间，如 ["1022", "1022-1042"]
                    "sink_description": str,
                    "confidence": float,
                    "source_file_raw": str,
                }
            data_packs: 全部 DataPack（挖掘 + 验证 agent）

        Returns:
            {
                "sink_info": dict,
                "found": bool,
                "found_precise": bool,      # 是否有精确命中（函数或行号级）
                "hits_by_agent": {
                    agent_type: [
                        {
                            "session_id": str,
                            "event_type": str,
                            "tool_name": str,
                            "input_preview": str,
                            "output_preview": str,
                            "matched_field": str,
                            "match_precision": "precise" | "file",
                            "matched_functions": [str],
                            "matched_lines": [str],   # 命中的行号
                        }
                    ]
                },
                "hit_sessions": {agent_type: [session_id, ...]},
                "precise_sessions": {agent_type: [session_id, ...]},
                "file_level_sessions": {agent_type: [session_id, ...]},
                "total_sessions": int,
                "total_precise": int,
                "total_file_level": int,
            }
        """
        sink_files = sink_info.get("sink_files") or []
        sink_functions = sink_info.get("sink_functions") or []
        sink_lines = sink_info.get("sink_lines") or []
        # 合并 source_file_raw 作为兜底文件
        source_file_raw = sink_info.get("source_file_raw") or ""
        if source_file_raw and source_file_raw not in sink_files:
            sink_files = sink_files + [source_file_raw]

        if not sink_files:
            return {
                "sink_info": sink_info,
                "found": False,
                "found_precise": False,
                "hits_by_agent": {},
                "hit_sessions": {},
                "precise_sessions": {},
                "file_level_sessions": {},
                "total_sessions": 0,
                "total_precise": 0,
                "total_file_level": 0,
            }

        # 预计算 basenames
        basenames = [os.path.basename(f) for f in sink_files if f]
        # 预解析行号区间为 (start, end) 列表
        parsed_lines = _parse_sink_lines(sink_lines)

        hits_by_agent: dict[str, list[dict]] = {}
        hit_sessions: dict[str, set[str]] = {}
        precise_sessions: dict[str, set[str]] = {}
        file_level_sessions: dict[str, set[str]] = {}

        for dp in data_packs:
            agent_type = dp.agent_type or ""
            for ev in (dp.events or []):
                # 1. 检查文件是否命中
                file_matched, file_field = self._check_files_in_event(
                    ev, sink_files, basenames)
                if not file_matched:
                    continue

                # 2. 检查函数是否命中
                matched_funcs = self._check_functions_in_event(
                    ev, sink_functions) if sink_functions else []

                # 3. 检查行号是否命中
                matched_lines = self._check_lines_in_event(
                    ev, parsed_lines) if parsed_lines else []

                # 4. 确定匹配精度
                if matched_funcs or matched_lines:
                    precision = "precise"
                else:
                    precision = "file"

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
                    "matched_field": file_field,
                    "match_precision": precision,
                    "matched_functions": matched_funcs,
                    "matched_lines": matched_lines,
                })
                hit_sessions.setdefault(agent_type, set()).add(sid)
                if precision == "precise":
                    precise_sessions.setdefault(agent_type, set()).add(sid)
                else:
                    file_level_sessions.setdefault(agent_type, set()).add(sid)

        hit_sessions_result = {
            at: sorted(sids) for at, sids in hit_sessions.items()
        }
        precise_result = {
            at: sorted(sids) for at, sids in precise_sessions.items()
        }
        file_level_result = {
            at: sorted(sids) for at, sids in file_level_sessions.items()
        }
        total = sum(len(sids) for sids in hit_sessions_result.values())
        total_precise = sum(len(sids) for sids in precise_result.values())
        total_file = sum(len(sids) for sids in file_level_result.values())

        log("SINK_SCAN",
            f"scan_with_sink_info files={len(sink_files)} "
            f"funcs={len(sink_functions)} lines={len(sink_lines)}: "
            f"{total} sessions "
            f"(precise={total_precise}, file_level={total_file})",
            eval_id="")

        return {
            "sink_info": sink_info,
            "found": total > 0,
            "found_precise": total_precise > 0,
            "hits_by_agent": hits_by_agent,
            "hit_sessions": hit_sessions_result,
            "precise_sessions": precise_result,
            "file_level_sessions": file_level_result,
            "total_sessions": total,
            "total_precise": total_precise,
            "total_file_level": total_file,
        }

    @staticmethod
    def _check_files_in_event(
        ev, sink_files: list[str], basenames: list[str],
    ) -> tuple[bool, str]:
        """检查 event 中是否出现 sink 文件。

        Returns:
            (matched, field) — matched=True 时 field 为 "input"/"output"/"both"
        """
        in_matched = False
        out_matched = False
        for i, sf in enumerate(sink_files):
            if not sf:
                continue
            bn = basenames[i] if i < len(basenames) else os.path.basename(sf)
            if not in_matched and _search_in_obj(ev.input_json, sf):
                in_matched = True
            if not in_matched and bn and bn != sf:
                if _search_in_obj(ev.input_json, bn):
                    in_matched = True
            if not out_matched and _search_in_obj(ev.output_json, sf):
                out_matched = True
            if not out_matched and bn and bn != sf:
                if _search_in_obj(ev.output_json, bn):
                    out_matched = True
            if in_matched and out_matched:
                break

        if in_matched and out_matched:
            return True, "both"
        if in_matched:
            return True, "input"
        if out_matched:
            return True, "output"
        return False, ""

    @staticmethod
    def _check_functions_in_event(
        ev, sink_functions: list[str],
    ) -> list[str]:
        """检查 event 中是否出现 sink 函数名，返回命中的函数名列表。

        匹配策略：
        1. 完整方法引用匹配（如 ClassName.methodName）
        2. 简单方法名匹配（如 methodName）—— 只匹配 sink_functions
           中提取出的方法名部分（去掉类名前缀和括号）
        """
        if not sink_functions:
            return []

        matched: list[str] = []
        in_str = _obj_to_str(ev.input_json)
        out_str = _obj_to_str(ev.output_json)
        combined = in_str + out_str
        if not combined:
            return []

        for func in sink_functions:
            if not func:
                continue
            # 完整方法引用匹配
            if func in combined:
                matched.append(func)
                continue
            # 简单方法名匹配：提取方法名部分（去掉类名前缀和括号）
            simple_name = func
            if "." in func:
                simple_name = func.rsplit(".", 1)[-1]
            if "(" in simple_name:
                simple_name = simple_name.split("(")[0]
            if simple_name and simple_name != func:
                if simple_name in combined:
                    matched.append(func)
                    continue

        return matched

    @staticmethod
    def _check_lines_in_event(
        ev, parsed_lines: list[tuple[int, int, str]],
    ) -> list[str]:
        """检查 event 中是否出现 sink 行号，返回命中的行号列表。

        行号匹配策略：trace event 的 input/output 中常出现行号引用
        （如 "line 1022"、":1022"、"行 1022" 等）。提取 event 文本中
        的数字行号，检查是否落在 sink 行号区间内。

        Args:
            parsed_lines: _parse_sink_lines() 返回的 (start, end, original) 列表

        Returns:
            命中的原始行号字符串列表（如 ["1022", "1022-1042"]）
        """
        if not parsed_lines:
            return []

        combined = _obj_to_str(ev.input_json) + _obj_to_str(ev.output_json)
        if not combined:
            return []

        # 提取 event 文本中所有数字（前后可能有冒号、空格等）
        import re
        # 匹配独立的行号数字：前后非数字字符（避免匹配到 10222 中的 1022）
        numbers = set()
        for m in re.finditer(r'(?<!\d)(\d{1,6})(?!\d)', combined):
            try:
                num = int(m.group(1))
                if 0 < num < 1_000_000:  # 合理行号范围
                    numbers.add(num)
            except ValueError:
                continue

        if not numbers:
            return []

        matched: list[str] = []
        for start, end, original in parsed_lines:
            # 检查 event 中是否有数字落在 [start, end] 区间内
            for num in numbers:
                if start <= num <= end:
                    matched.append(original)
                    break

        return matched

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


def _search_in_obj(obj, target: str) -> bool:
    """递归搜索 obj 中是否包含 target 字符串。

    obj 可以是 str/dict/list/None，递归搜索所有字符串值。
    """
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


def _parse_sink_lines(sink_lines: list[str]) -> list[tuple[int, int, str]]:
    """解析 sink 行号列表，返回 (start, end, original) 列表。

    支持格式：
    - "1022" → (1022, 1022, "1022")
    - "1022-1042" → (1022, 1042, "1022-1042")
    - "1022~1042" → (1022, 1042, "1022~1042")
    """
    import re
    parsed: list[tuple[int, int, str]] = []
    for line_str in sink_lines:
        if not line_str:
            continue
        s = str(line_str).strip()
        # 区间格式：1022-1042 或 1022~1042
        m = re.match(r'^(\d+)\s*[-~]\s*(\d+)$', s)
        if m:
            try:
                start = int(m.group(1))
                end = int(m.group(2))
                if start <= end and 0 < start < 1_000_000:
                    parsed.append((start, end, s))
                continue
            except ValueError:
                pass
        # 单行号
        m = re.match(r'^(\d+)$', s)
        if m:
            try:
                num = int(m.group(1))
                if 0 < num < 1_000_000:
                    parsed.append((num, num, s))
                continue
            except ValueError:
                pass
    return parsed


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
