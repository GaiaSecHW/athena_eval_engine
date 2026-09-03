"""LLM 客户端（OpenAI 兼容）— 用于 AI FindingBenchmarkMatch + 叙述性结论。

配置来自 config_loader。失败自动重试（最多 3 次），应对算力紧张导致的间歇性失败。
chat_json 的 JSON 解析失败也纳入重试（deepseek 非确定性，重试可能返回有效 JSON）。
"""
from __future__ import annotations
import json
import time
import http.client
from urllib.parse import urlparse
from ..config_loader import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY

DEFAULT_API_BASE = LLM_BASE_URL
DEFAULT_MODEL = LLM_MODEL
DEFAULT_API_KEY = LLM_API_KEY

MAX_RETRIES = 3
RETRY_DELAY = 5  # 秒，重试间隔


def _chat_once(messages, *, model=None, temperature=0, max_tokens=8000,
            api_base=None, api_key=None, timeout=60) -> str:
    """单次 LLM 调用，不重试。"""
    base = api_base or DEFAULT_API_BASE
    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path.rstrip("/") + "/chat/completions"

    body = json.dumps({
        "model": model or DEFAULT_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key or DEFAULT_API_KEY}",
        "Content-Length": str(len(body)),
    }

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        result = json.loads(data)
    finally:
        conn.close()

    msg = result["choices"][0]["message"]
    content = msg.get("content")
    if not content and msg.get("reasoning_content"):
        content = msg["reasoning_content"]
    if content:
        return content
    raise RuntimeError("content 为空（reasoning 占满 max_tokens）")


def chat(messages, **kwargs) -> str:
    """OpenAI-compatible chat completion。返回 assistant 消息文本。

    失败自动重试（网络失败、空 content、JSON 解析失败）。
    """
    last_err = None
    for attempt in range(kwargs.get("retries", MAX_RETRIES)):
        try:
            return _chat_once(messages, **{k: v for k, v in kwargs.items() if k != "retries"})
        except Exception as e:
            last_err = str(e)[:200]
            if attempt < kwargs.get("retries", MAX_RETRIES) - 1:
                time.sleep(RETRY_DELAY)
    raise RuntimeError(f"LLM 调用失败（{kwargs.get('retries', MAX_RETRIES)} 次重试后）: {last_err}")


def chat_json(messages, **kwargs) -> dict:
    """chat 但要求 JSON 输出，自动解析。

    LLM 调用 + JSON 解析整体重试：网络失败、空 content、JSON 解析失败 都触发重试。
    deepseek 模型非确定性，重试可能返回有效 JSON。
    """
    msgs = list(messages)
    if not any("json" in str(m.get("content", "")).lower() for m in msgs):
        msgs.append({"role": "user", "content": "只返回 JSON，不要任何额外文字。"})
    last_err = None
    for attempt in range(kwargs.get("retries", MAX_RETRIES)):
        try:
            raw = _chat_once(msgs, **{k: v for k, v in kwargs.items() if k != "retries"})
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            try:
                return json.loads(raw.strip())
            except json.JSONDecodeError:
                start = raw.find("{")
                end = raw.rfind("}")
                if start >= 0 and end > start:
                    return json.loads(raw[start:end + 1])
                raise RuntimeError("JSON 解析失败")
        except Exception as e:
            last_err = str(e)[:200]
            if attempt < kwargs.get("retries", MAX_RETRIES) - 1:
                time.sleep(RETRY_DELAY)
    raise RuntimeError(f"chat_json 失败（{kwargs.get('retries', MAX_RETRIES)} 次重试后）: {last_err}")
