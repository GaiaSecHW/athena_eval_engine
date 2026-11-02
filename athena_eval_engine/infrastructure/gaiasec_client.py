"""gaiasec-server HTTP 客户端 — WebVulnVerify 权威 case↔session 关系源。

WebVulnVerify 的 AI session 父子关系**不在 WebVulnVerify 自己的 postgres**（
vuln_verify_task/attempt 模型无 session 字段），存在漏洞中心库（gaiasec-server
API 暴露）。eval-engine 对每个 case 调用权威 API 取：

- ``ai_analysis_session_id``  — WebVulnVerify 内部"分析"阶段 session（父）
- ``ai_verification_session_id`` — WebVulnVerify 内部"验证"阶段 session（子）

WebVulnVerify 是验证 agent，内部又分"分析"与"验证"两个阶段；两个 session 都
属于 webvuln_verify 的 trace，都进 ``verify_sessions``。父子关系（验证阶段 session
的父 = 分析阶段 session）通过 ``parent_map`` 表达。

API 路径：``GET http://gaiasec-server/api/vulnerabilities/chimera/{case_id}``，
响应体 ``data`` 字段含 ``ai_analysis_session_id`` / ``ai_verification_session_id``。

失败策略：API 调用失败抛异常（不降级、不跳过——铁律）。
"""
from __future__ import annotations

import json
import os
import urllib.parse

from .log_util import log
from .http_client import http_get_raw
from ..config_loader import GAISEC_SERVER_URL


# gaiasec-server 基础 URL（从 config_loader 统一读取）
_GAISEC_SERVER_URL = GAISEC_SERVER_URL.rstrip("/")

# API 超时（秒）。单 case 调用，6s 够返回（响应体几 KB）。
_API_TIMEOUT = 10

# 重试（网络瞬时抖动，非 API 业务错误）
_MAX_RETRIES = 3
_RETRY_DELAY = 2.0


def fetch_case_session_map(case_id: str) -> dict:
    """查询单个 case 的权威 AI session 关系。

    Args:
        case_id: 原始数据的 case_id（chimera 案件 ID，如
                 ``case-20260918-222631-727e476dad``）。

    Returns:
        ``{
            "case_id": str,
            "ai_analysis_session_id": str,      # 分析阶段 session（父）
            "ai_verification_session_id": str,  # 验证阶段 session（子）
            "chimera_task_id": str,             # task 关联（可选，便于诊断）
            "ai_analysis_status": str,           # 分析阶段结论（VULNERABLE/...）
            "ai_verification_status": str,      # 验证阶段结论
            "title": str,                        # 漏洞标题（诊断用）
        }``

    Raises:
        RuntimeError: API 调用失败（HTTP 非 200/网络错误/响应解析失败）。
                     调用方必须让评测 FAILED，不降级。
    """
    if not case_id:
        raise RuntimeError("fetch_case_session_map: case_id 为空")

    url = f"{_GAISEC_SERVER_URL}/api/vulnerabilities/chimera/{urllib.parse.quote(case_id)}"
    data = http_get_raw(
        url,
        headers={"Accept": "application/json"},
        retries=_MAX_RETRIES,
        retry_delay=_RETRY_DELAY,
        timeout=_API_TIMEOUT,
        log_tag="GAISEC_API",
    )
    if not isinstance(data, dict) or not data.get("success"):
        raise RuntimeError(
            f"fetch_case_session_map case={case_id} API 响应非 success: {str(data)[:200]}"
        )
    payload = data.get("data") or {}
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"fetch_case_session_map case={case_id} API 响应 data 非 dict: {str(data)[:200]}"
        )
    analysis_sid = payload.get("ai_analysis_session_id") or ""
    verification_sid = payload.get("ai_verification_session_id") or ""
    # API 权威契约：API 调用成功（200 + success=True）即视为权威数据，
    # 即使 analysis_session 为空也返回记录（case 数据本身的状态——
    # 如 analysis_status=UNDETERMINED/PENDING 时 analysis_session 为空，
    # 表示该 case 的分析未启动或被 stopped）。
    # 这种"数据不完整"不是 API 失败，不抛异常、不中止评测。
    # 调用方（matcher）按 analysis_session 是否为空决定是否用此映射。
    if not analysis_sid:
        log("GAISEC_API",
            f"case={case_id} API 返回 analysis_session 为空 "
            f"(analysis_status={payload.get('ai_analysis_status')}, "
            f"verification_status={payload.get('ai_verification_status')})"
            f"—— case 数据状态不完整（如分析被 stopped），跳过 verify_sessions")
    return {
        "case_id": case_id,
        "ai_analysis_session_id": analysis_sid,
        "ai_verification_session_id": verification_sid,
        "chimera_task_id": payload.get("chimera_task_id") or "",
        "ai_analysis_status": payload.get("ai_analysis_status") or "",
        "ai_verification_status": payload.get("ai_verification_status") or "",
        "title": payload.get("title") or "",
    }


def fetch_case_session_map_batch(
    case_ids: list[str], cancel_cb=None,
) -> dict[str, dict]:
    """批量查询 case_id → {analysis_session, verification_session} 映射。

    Args:
        case_ids: 原始数据 case_id 列表。
        cancel_cb: 取消回调（每个 case 调用前检查）。

    Returns:
        ``{case_id: {ai_analysis_session_id, ai_verification_session_id, ...}}``

    Raises:
        RuntimeError: 任一 case 查询失败 → 抛异常，调用方让评测 FAILED。
    """
    if not case_ids:
        return {}
    result: dict[str, dict] = {}
    log("GAISEC_API",
        f"批量查询 {len(case_ids)} 个 case 的 webvuln session 关系")
    for i, cid in enumerate(case_ids, 1):
        if cancel_cb:
            cancel_cb()
        if not cid:
            continue
        log("GAISEC_API",
            f"查询 case {i}/{len(case_ids)}: {cid}")
        info = fetch_case_session_map(cid)
        result[cid] = info
    log("GAISEC_API",
        f"批量查询完成: {len(result)}/{len(case_ids)} case 查到 webvuln session")
    return result
