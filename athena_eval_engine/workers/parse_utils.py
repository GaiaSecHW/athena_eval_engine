"""Parser 共享工具函数。

各 trace parser 的 extract_findings 方法共用的通用逻辑。
平台特定逻辑不应放在此处，应留在各 parser 内部。
"""
from __future__ import annotations
import json


def _extract_json_objects_from_text(text: str) -> list[dict]:
    """Extract JSON objects from text containing ```json blocks.

    Uses json.JSONDecoder().raw_decode() to handle JSON values that
    contain backticks (e.g., `` `memcpy_s` `` in string values), which
    would break regex-based extraction that looks for closing ``` markers.
    """
    decoder = json.JSONDecoder()
    results: list[dict] = []
    search_start = 0
    marker = '```json'
    while True:
        idx = text.find(marker, search_start)
        if idx == -1:
            break
        brace_idx = text.find('{', idx + len(marker))
        if brace_idx == -1:
            break
        try:
            obj, end_pos = decoder.raw_decode(text, brace_idx)
            if isinstance(obj, dict):
                results.append(obj)
            search_start = end_pos
        except json.JSONDecodeError:
            search_start = idx + len(marker)
    return results


def attach_event_indices(findings: dict[str, dict], events: list) -> None:
    """为每个 finding 关联提交事件索引（用于后续提取挖掘过程上下文）。

    在 events 中搜索包含该 finding_id 的事件，记录其索引。
    各 parser 的 extract_findings 末尾调用此函数。
    """
    for fid, f in findings.items():
        if "_event_idx" not in f:
            for i, e in enumerate(events):
                combined = str(e.input_json or "") + str(e.output_json or "")
                if fid and fid != "?" and fid in combined:
                    f["_event_idx"] = i
                    break
            else:
                f["_event_idx"] = 0
