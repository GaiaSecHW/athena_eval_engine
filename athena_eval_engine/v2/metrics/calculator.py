"""Metric calculator — 统一入口，跑全部指标 M5–M13。

本文件包装 ``m5_m13.run_all_metrics``，保持调用接口稳定。
"""
from __future__ import annotations

from .m5_m13 import run_all_metrics as _run_m5_m13


def run_all_metrics(
    *,
    kg_access_events=0,
    kg_successful_reads=0,
    mem_read_count=0,
    mem_successful_reads=0,
    kg_tool_calls=0,
    total_tool_calls=0,
    seed=42,
    knowledge_access_details: list[dict] | None = None,
) -> dict:
    """跑全部指标 M5–M13。

    参数:
        knowledge_access_details: 保留接口兼容，当前不使用。
            召回率/准确率在 REPORTING 阶段从漏洞中心终审数据计算。
        其余参数同 ``m5_m13.run_all_metrics``。

    返回::

        {
            "metric_results": [...],      # M5–M13 MetricResult 列表
            "statistical_results": [...], # M5–M13 StatisticalResult 列表
        }
    """
    return _run_m5_m13(
        kg_access_events=kg_access_events,
        kg_successful_reads=kg_successful_reads,
        mem_read_count=mem_read_count,
        mem_successful_reads=mem_successful_reads,
        kg_tool_calls=kg_tool_calls,
        total_tool_calls=total_tool_calls,
        seed=seed,
    )
