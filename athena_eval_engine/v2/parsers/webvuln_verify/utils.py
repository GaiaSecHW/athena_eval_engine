"""WebVulnVerify parser 专用工具函数。

从老代码 ``workers/parse_utils.py`` 拷贝 WebVulnVerify parser 实际用到的函数：
- ``attach_event_indices`` — 为 finding 关联提交事件索引
"""
from __future__ import annotations


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
