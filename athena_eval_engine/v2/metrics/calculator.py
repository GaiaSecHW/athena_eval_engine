"""Metric calculator — 统一入口，跑全部指标 M5–M13 + M15–M21 / M26。

本文件扩展 ``m5_m13.run_all_metrics``，新增 ``knowledge_access_details`` 参数。
当传入 ``knowledge_access_details`` 时，在 M5–M13 计算后追加 M15–M21 / M26。
"""
from __future__ import annotations

from .m5_m13 import run_all_metrics as _run_m5_m13, PairView
from .m15_m26 import calc_all_lifecycle_metrics


def run_all_metrics(
    pairs: list[PairView],
    *,
    confusion_pairs=None,
    kg_access=0,
    kg_valid=0,
    kg_delivery=0,
    access=0,
    kg_access_events=0,
    kg_successful_reads=0,
    mem_read_count=0,
    mem_successful_reads=0,
    kg_tool_calls=0,
    total_tool_calls=0,
    seed=42,
    knowledge_access_details: list[dict] | None = None,
) -> dict:
    """跑全部指标 M5–M13 + M15–M21 / M26。

    参数:
        pairs: 配对视图列表（保留兼容，当前方案不使用配对）。
        knowledge_access_details: ``knowledge_access_detail`` 记录列表（M15–M26 用）。
            为 None 或空列表时不计算 M15–M26，返回结果中不含 lifecycle_metrics。
        其余参数同 ``m5_m13.run_all_metrics``。

    返回::

        {
            "metric_results": [...],      # M5–M13 MetricResult 列表
            "statistical_results": [...], # M5–M13 StatisticalResult 列表
            "lifecycle_metrics": [...],   # M15–M26 dict 列表（仅当传入 knowledge_access_details）
        }
    """
    # 1. 计算现有 M5–M13
    base = _run_m5_m13(
        pairs,
        confusion_pairs=confusion_pairs,
        kg_access=kg_access,
        kg_valid=kg_valid,
        kg_delivery=kg_delivery,
        access=access,
        kg_access_events=kg_access_events,
        kg_successful_reads=kg_successful_reads,
        mem_read_count=mem_read_count,
        mem_successful_reads=mem_successful_reads,
        kg_tool_calls=kg_tool_calls,
        total_tool_calls=total_tool_calls,
        seed=seed,
    )

    # 2. 追加 M15–M26（仅当传入 knowledge_access_details）
    if knowledge_access_details:
        base["lifecycle_metrics"] = calc_all_lifecycle_metrics(knowledge_access_details)
    else:
        base["lifecycle_metrics"] = []

    return base
