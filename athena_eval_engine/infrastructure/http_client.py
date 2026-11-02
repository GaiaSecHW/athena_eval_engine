"""统一 HTTP GET 客户端 — bearer token 认证 + 重试。

提取自 vbench_client / vuln_center_client / platform_service 三处重复实现。
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

from ..config_loader import PLATFORM_TOKEN
from .log_util import log


def http_get(
    url: str,
    *,
    params: dict | None = None,
    retries: int = 20,
    retry_delay: float = 5.0,
    timeout: float = 180,
    log_tag: str = "HTTP",
) -> dict | list:
    """带 bearer token 的 GET，返回 JSON。

    内部 Service 短暂抖动时固定退避重试。
    """
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"Authorization": f"Bearer {PLATFORM_TOKEN}"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            last_err = e
            log(log_tag, f"HTTP {e.code} 重试 {attempt+1}/{retries}: {url}")
            if attempt + 1 < retries:
                time.sleep(retry_delay)
        except (URLError, TimeoutError, OSError) as e:
            last_err = e
            log(log_tag, f"网络错误重试 {attempt+1}/{retries}: {url} → {e}")
            if attempt + 1 < retries:
                time.sleep(retry_delay)
    log(log_tag, f"❌ {retries} 次重试全部失败: {url} → {last_err}")
    raise last_err
