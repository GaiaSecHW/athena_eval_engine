"""Pipeline 数据质量告警收集器。

线程安全的告警收集器，在 pipeline 执行过程中记录外部数据源失败
（VULN_CENTER 404、KB_VERIFY Athena API 404、LLM 降级等），
最终写入报告 JSON 的 ``data_quality_warnings`` 字段，使报告读者能看到
数据质量问题，而非误以为所有结果都完全可信。

按 ``evaluation_id`` 隔离——并发评测各自维护独立的告警列表，
互不干扰。

用法::

    from ..infra.pipeline_warnings import add, drain, reset

    # 记录告警（需传 evaluation_id）
    add("EV-20261021150914-9775",
        "vuln_center", "fetch_failed", "warning",
        f"case {cid} 原始报告获取失败: 404", case_id=cid)

    # 读取该评测的全部告警（报告组装时调用）
    warnings = drain("EV-20261021150914-9775")  # list[dict]
    reset("EV-20261021150914-9775")              # 新评测前清空
"""
from __future__ import annotations

import threading
import time

# 告警结构: {source, type, severity, message, case_id, timestamp}
# severity: "warning"（数据降级但评测继续）| "error"（数据缺失影响结果可信度）

_lock = threading.Lock()
_warnings: dict[str, list[dict]] = {}


def add(
    evaluation_id: str,
    source: str,
    type_: str,
    severity: str,
    message: str,
    case_id: str = "",
):
    """记录一条数据质量告警。

    Args:
        evaluation_id: 评测 ID，用于隔离不同评测的告警。
        source: 告警来源模块（如 "vuln_center"、"kb_verify"、"llm"）。
        type_: 告警类型（如 "fetch_failed"、"api_404"、"degraded"）。
        severity: 严重程度（"warning" 或 "error"）。
        message: 人类可读的告警描述。
        case_id: 关联的 case ID（可选）。
    """
    with _lock:
        _warnings.setdefault(evaluation_id, []).append({
            "source": source,
            "type": type_,
            "severity": severity,
            "message": message,
            "case_id": case_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })


def drain(evaluation_id: str) -> list[dict]:
    """读取并清空指定评测的全部告警（报告组装时调用）。"""
    with _lock:
        result = _warnings.pop(evaluation_id, [])
        return result


def peek(evaluation_id: str) -> list[dict]:
    """读取指定评测的告警列表（不清空，用于判断是否有告警）。"""
    with _lock:
        return list(_warnings.get(evaluation_id, []))


def reset(evaluation_id: str):
    """清空指定评测的告警（新评测开始前调用）。"""
    with _lock:
        _warnings.pop(evaluation_id, None)


def has_warnings(evaluation_id: str) -> bool:
    """指定评测是否有告警。"""
    with _lock:
        return len(_warnings.get(evaluation_id, [])) > 0


def add_trace_file_skip(agent_type: str, path: str,
                        error: object = None) -> None:
    """记录 trace 文件缺失/不可读告警（解析继续，不中断评测）。

    供各 parser 在单个 session/文件缺失时调用，口径与 WebVulnVerify
    的「缺 session 文件只告警」一致。
    """
    from .log_util import get_eval_ctx  # 延迟导入，避免循环依赖
    eid = get_eval_ctx()
    if not eid:
        return
    msg = f"trace 文件不可读，已跳过：{path}"
    if error is not None:
        msg += f"（{error}）"
    add(eid, agent_type or "trace", "session_file_missing", "warning", msg)
