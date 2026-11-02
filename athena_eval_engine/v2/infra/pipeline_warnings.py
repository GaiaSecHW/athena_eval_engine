"""Pipeline 数据质量告警收集器。

线程安全的告警收集器，在 pipeline 执行过程中记录外部数据源失败
（VULN_CENTER 404、KB_VERIFY Athena API 404、LLM 降级等），
最终写入报告 JSON 的 ``data_quality_warnings`` 字段，使报告读者能看到
数据质量问题，而非误以为所有结果都完全可信。

用法::

    from ..infra.pipeline_warnings import warnings_collector as wc

    # 记录告警
    wc.add("vuln_center", "fetch_failed", "warning",
           f"case {cid} 原始报告获取失败: 404", case_id=cid)

    # 读取全部告警（报告组装时调用）
    warnings = wc.drain()  # list[dict]
    wc.reset()             # 新评测前清空
"""
from __future__ import annotations

import threading
import time

# 告警结构: {source, type, severity, message, case_id, timestamp}
# severity: "warning"（数据降级但评测继续）| "error"（数据缺失影响结果可信度）

_lock = threading.Lock()
_warnings: list[dict] = []


def add(
    source: str,
    type_: str,
    severity: str,
    message: str,
    case_id: str = "",
):
    """记录一条数据质量告警。

    Args:
        source: 告警来源模块（如 "vuln_center"、"kb_verify"、"llm"）。
        type_: 告警类型（如 "fetch_failed"、"api_404"、"degraded"）。
        severity: 严重程度（"warning" 或 "error"）。
        message: 人类可读的告警描述。
        case_id: 关联的 case ID（可选）。
    """
    with _lock:
        _warnings.append({
            "source": source,
            "type": type_,
            "severity": severity,
            "message": message,
            "case_id": case_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })


def drain() -> list[dict]:
    """读取并清空全部告警（报告组装时调用）。"""
    with _lock:
        result = list(_warnings)
        _warnings.clear()
        return result


def peek() -> list[dict]:
    """读取告警列表（不清空，用于判断是否有告警）。"""
    with _lock:
        return list(_warnings)


def reset():
    """清空告警（新评测开始前调用）。"""
    with _lock:
        _warnings.clear()


def has_warnings() -> bool:
    """是否有告警。"""
    with _lock:
        return len(_warnings) > 0
