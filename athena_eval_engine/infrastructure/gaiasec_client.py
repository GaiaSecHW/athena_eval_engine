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
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

from .log_util import log


# gaiasec-server 基础 URL（k8s 内部服务名，eval-engine 同 namespace 直接访问）
# 环境变量 EVAL_GAISEC_SERVER_URL 可覆盖（dev/prod 切换）。
_GAISEC_SERVER_URL = os.environ.get(
    "EVAL_GAISEC_SERVER_URL", "http://gaiasec-server"
).rstrip("/")

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
    last_err: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            req = urllib.request.Request(
                url, headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as r:
                body = r.read().decode("utf-8")
            data = json.loads(body)
            if not isinstance(data, dict) or not data.get("success"):
                last_err = RuntimeError(
                    f"API 响应非 success: {body[:200]}"
                )
                log("GAISEC_API",
                    f"fetch_case_session_map case={case_id} 非成功响应，"
                    f"重试 {attempt + 1}/{_MAX_RETRIES}: {body[:200]}")
                if attempt + 1 < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY)
                continue
            payload = data.get("data") or {}
            if not isinstance(payload, dict):
                last_err = RuntimeError(
                    f"API 响应 data 非 dict: {body[:200]}"
                )
                if attempt + 1 < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY)
                continue
            analysis_sid = payload.get("ai_analysis_session_id") or ""
            verification_sid = payload.get("ai_verification_session_id") or ""
            # API 权威契约：每个 case 应同时登记 analysis + verification session
            # （任一缺失即数据不完整，按铁律抛异常不降级）
            if not analysis_sid or not verification_sid:
                raise RuntimeError(
                    f"API 返回 case={case_id} 缺 session 字段: "
                    f"analysis={analysis_sid!r} verification={verification_sid!r}"
                )
            return {
                "case_id": case_id,
                "ai_analysis_session_id": analysis_sid,
                "ai_verification_session_id": verification_sid,
                "chimera_task_id": payload.get("chimera_task_id") or "",
                "ai_analysis_status": payload.get("ai_analysis_status") or "",
                "ai_verification_status": payload.get("ai_verification_status") or "",
                "title": payload.get("title") or "",
            }
        except (URLError, TimeoutError, OSError) as e:
            last_err = e
            log("GAISEC_API",
                f"fetch_case_session_map case={case_id} 网络错误，"
                f"重试 {attempt + 1}/{_MAX_RETRIES}: {e}")
            if attempt + 1 < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)
        except HTTPError as e:
            last_err = e
            log("GAISEC_API",
                f"fetch_case_session_map case={case_id} HTTP {e.code}，"
                f"重试 {attempt + 1}/{_MAX_RETRIES}: {e}")
            # 404 表示 case 不存在（数据不完整）；5xx 表示服务错误。两者都重试
            # 直到耗尽——耗尽后抛异常由调用方 FAILED，不静默降级。
            if attempt + 1 < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)
        except json.JSONDecodeError as e:
            last_err = e
            log("GAISEC_API",
                f"fetch_case_session_map case={case_id} JSON 解析失败，"
                f"重试 {attempt + 1}/{_MAX_RETRIES}: {e}")
            if attempt + 1 < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)

    raise RuntimeError(
        f"fetch_case_session_map case={case_id} {__format_err(last_err)}"
    )


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


def _format_err(e: Exception | None) -> str:
    if e is None:
        return "未知错误"
    if isinstance(e, HTTPError):
        return f"HTTP {e.code} {e.reason}"
    return f"{type(e).__name__}: {e}"
