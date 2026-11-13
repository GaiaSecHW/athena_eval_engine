"""小鲁班消息发送。

    POST http://xiaoluban.rnd.huawei.com:80/
    {"content": "...", "receiver": "工号或群号", "auth": "小鲁班 token"}

token 存 system_config.xiaoluban_token，在 /eval/system 页面维护。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from ...config_loader import XIAOLUBAN_URL
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

MAX_CHARS = 3800
RETRIES = 3


def get_token() -> str:
    """读取 system_config.xiaoluban_token。"""
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='xiaoluban_token'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    return _db_query(_do)


def split_text(text: str, limit: int = MAX_CHARS) -> list[str]:
    """按行切分，保证每段不超过 limit；单行超长时硬切。"""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in text.splitlines():
        if len(line) > limit:
            if current:
                chunks.append("\n".join(current))
                current, current_len = [], 0
            for i in range(0, len(line), limit):
                chunks.append(line[i:i + limit])
            continue
        add = len(line) + (1 if current else 0)
        if current and current_len + add > limit:
            chunks.append("\n".join(current))
            current, current_len = [line], len(line)
        else:
            current.append(line)
            current_len += add
    if current:
        chunks.append("\n".join(current))
    return chunks


def _send_once(url: str, auth: str, receiver: str,
               content: str) -> tuple[bool, str, bool]:
    """发送一条消息，返回 (成功, 详情, 是否鉴权失败)。"""
    payload = {"content": content, "receiver": receiver, "auth": auth}
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:300]}"
        return False, detail, exc.code in (401, 403)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, str(exc), False

    try:
        data = json.loads(body)
    except ValueError:
        return True, body[:300], False
    if isinstance(data, dict) and data.get("code") not in (None, 0, "0"):
        msg = str(data.get("msg") or data)
        auth_failed = "401" in msg or "auth" in msg.lower() or "token" in msg.lower()
        return False, msg[:300], auth_failed
    return True, body[:300], False


def _send_with_retry(url: str, auth: str, receiver: str,
                     content: str) -> tuple[bool, str]:
    last_detail = ""
    for attempt in range(RETRIES):
        ok, detail, auth_failed = _send_once(url, auth, receiver, content)
        if ok:
            return True, detail
        last_detail = detail
        log("NOTIFY", f"小鲁班发送失败 ({attempt + 1}/{RETRIES}): {detail}")
        if auth_failed:
            log("NOTIFY", "小鲁班 token 可能已失效，请在 WeLink 找小鲁班重新"
                          "发送“获取发送token”，并在系统设置页更新")
            return False, detail
        if attempt + 1 < RETRIES:
            time.sleep(2 * (attempt + 1))
    return False, last_detail


def send_message(receiver: str, text: str,
                 url: str = XIAOLUBAN_URL,
                 token: str | None = None) -> tuple[bool, str]:
    """发送一条完整消息；超过 MAX_CHARS 自动分条。"""
    auth = token if token is not None else get_token()
    if not auth:
        return False, "小鲁班 token 未配置"
    if not receiver:
        return False, "receiver 为空"

    chunks = split_text(text)
    total = len(chunks)
    for idx, chunk in enumerate(chunks, 1):
        content = f"（{idx}/{total}）\n{chunk}" if total > 1 else chunk
        ok, detail = _send_with_retry(url, auth, receiver, content)
        if not ok:
            return False, detail
    return True, f"sent {total} chunk(s)"
