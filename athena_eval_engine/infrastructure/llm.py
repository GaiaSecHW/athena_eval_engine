"""LLM 客户端（OpenAI 兼容，SSE 流式）— 用于 AI FindingBenchmarkMatch + 叙述性结论。

配置来自 config_loader。失败自动重试（最多 3 次）。
SSE 流式读取：首 token 超时 5 分钟，后续 token 断流超时 10 分钟。
429 限流：持续重试，间隔 3 秒（不占用 MAX_RETRIES 额度）。
每个评测任务内 LLM 并发上限由信号量控制（默认 6）。
"""
from __future__ import annotations
import json
import time
import socket
import threading
import http.client
from urllib.parse import urlparse
from ..config_loader import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY, LLM_ENABLED

DEFAULT_API_BASE = LLM_BASE_URL
DEFAULT_MODEL = LLM_MODEL
DEFAULT_API_KEY = LLM_API_KEY

MAX_RETRIES = 3
RETRY_DELAY = 5  # 秒，重试间隔

# SSE 流式超时（秒）
FIRST_TOKEN_TIMEOUT = 360   # 首 token 超时：6 分钟
STREAM_TIMEOUT = 600        # 后续 token 断流超时：10 分钟

# 每个评测任务内 LLM 并发上限（信号量）
# 由 evaluation_service.run() 在每个评测启动时 set_max_concurrency 设置
_MAX_CONCURRENCY = 6
_llm_semaphore: threading.Semaphore | None = None


def is_enabled() -> bool:
    """是否允许发起 LLM 请求（开发环境可显式关闭）。"""
    return LLM_ENABLED


def set_max_concurrency(n: int):
    """评测启动时调用，设置本评测的 LLM 并发上限。"""
    global _llm_semaphore
    _llm_semaphore = threading.Semaphore(n)


def _chat_once(messages, *, model=None, temperature=0, max_tokens=8000,
            api_base=None, api_key=None, **_unused) -> str:
    """单次 LLM 调用（SSE 流式），不重试。

    首 token 超时 5 分钟，后续 token 断流超时 10 分钟。
    429 限流持续重试（3 秒间隔，不占用 MAX_RETRIES 额度）。
    LLM 并发受信号量控制（每评测最多 6 个）。
    """
    base = api_base or DEFAULT_API_BASE
    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path.rstrip("/") + "/chat/completions"
    _model = model or DEFAULT_MODEL
    print(f"[LLM] POST {base}{path} model={_model} msgs={len(messages)} "
          f"stream=True first_token={FIRST_TOKEN_TIMEOUT}s stream_gap={STREAM_TIMEOUT}s", flush=True)

    body = json.dumps({
        "model": _model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": True,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key or DEFAULT_API_KEY}",
        "Content-Length": str(len(body)),
        "Accept": "text/event-stream",
    }

    # 获取 LLM 并发槽位（信号量控制每评测最多 6 个并发）
    if _llm_semaphore is not None:
        _llm_semaphore.acquire()
    conn = None
    try:
        # ── Phase 1: 发请求，429 限流持续重试，拿到 200 响应头 ──
        # ── Phase 1: 发请求，429 限流重试（最多 500 次），首 token 超时也重试 ──
        for _attempt in range(500):
            conn = http.client.HTTPConnection(host, port, timeout=FIRST_TOKEN_TIMEOUT)
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
            except (socket.timeout, TimeoutError) as e:
                conn.close()
                conn = None
                print(f"[LLM] 首 token 超时（{FIRST_TOKEN_TIMEOUT}s, attempt {_attempt+1}/500）: {e}", flush=True)
                if _attempt < 499:
                    time.sleep(RETRY_DELAY)
                    continue
                raise RuntimeError(f"LLM 首 token 超时（{FIRST_TOKEN_TIMEOUT}s × 500 次）")
            status = resp.status
            if status == 429:
                retry_after = resp.getheader("Retry-After")
                delay = 3
                if retry_after:
                    try: delay = int(retry_after)
                    except ValueError: pass
                print(f"[LLM] 429 rate limited, retry in {delay}s", flush=True)
                conn.close()
                conn = None
                time.sleep(delay)
                continue
            if status != 200:
                data = resp.read().decode("utf-8")
                err_preview = data[:500]
                print(f"[LLM] HTTP {status} from {base}: {err_preview}", flush=True)
                conn.close()
                conn = None
                raise RuntimeError(f"LLM HTTP {status}: {err_preview}")
            break  # 200，进入 SSE 读取

        # ── Phase 2: 逐行读 SSE 流 ──
        content_parts = []
        reasoning_parts = []
        first_token = True

        while True:
            line = resp.readline()
            if not line:
                break  # 连接关闭
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue  # SSE 事件分隔空行
            if not line_str.startswith("data: "):
                continue  # 非 data 行
            data_str = line_str[6:]
            if data_str == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            # 首 token 到达后，切换到后续 token 断流超时
            if first_token:
                first_token = False
                if conn.sock:
                    conn.sock.settimeout(STREAM_TIMEOUT)
                print(f"[LLM] first token received, stream timeout -> {STREAM_TIMEOUT}s", flush=True)
            choices = chunk.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}
            if delta.get("content"):
                content_parts.append(delta["content"])
            if delta.get("reasoning_content"):
                reasoning_parts.append(delta["reasoning_content"])

        content = "".join(content_parts)
        if not content and reasoning_parts:
            content = "".join(reasoning_parts)

        if content:
            print(f"[LLM] OK stream done content_len={len(content)}", flush=True)
            return content
        raise RuntimeError("content 为空（reasoning 占满 max_tokens）")
    except (socket.timeout, TimeoutError) as e:
        phase = "首 token" if first_token else "后续 token 断流"
        print(f"[LLM] {phase}超时: {e}", flush=True)
        raise RuntimeError(f"LLM {phase}超时（{FIRST_TOKEN_TIMEOUT if first_token else STREAM_TIMEOUT}s）")
    finally:
        if conn:
            conn.close()
        if _llm_semaphore is not None:
            _llm_semaphore.release()


def chat(messages, **kwargs) -> str:
    """OpenAI-compatible chat completion（SSE 流式）。返回 assistant 消息文本。"""
    if not is_enabled():
        raise RuntimeError("LLM 未启用（设置 EVAL_LLM_ENABLED=true 后才会发起请求）")
    last_err = None
    retries = kwargs.get("retries", MAX_RETRIES)
    for attempt in range(retries):
        try:
            return _chat_once(messages, **{k: v for k, v in kwargs.items() if k != "retries"})
        except Exception as e:
            last_err = str(e)[:300]
            print(f"[LLM] chat attempt {attempt+1}/{retries} failed: {last_err}", flush=True)
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
    print(f"[LLM] chat exhausted {retries} retries: {last_err}", flush=True)
    raise RuntimeError(f"LLM 调用失败（{retries} 次重试后）: {last_err}")


def chat_json(messages, **kwargs) -> dict:
    """chat 但要求 JSON 输出，自动解析。"""
    if not is_enabled():
        raise RuntimeError("LLM 未启用（设置 EVAL_LLM_ENABLED=true 后才会发起请求）")
    msgs = list(messages)
    if not any("json" in str(m.get("content", "")).lower() for m in msgs):
        msgs.append({"role": "user", "content": "只返回 JSON，不要任何额外文字。"})
    last_err = None
    retries = kwargs.get("retries", MAX_RETRIES)
    for attempt in range(retries):
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
                raise RuntimeError(f"JSON 解析失败: {raw[:200]}")
        except Exception as e:
            last_err = str(e)[:300]
            print(f"[LLM] chat_json attempt {attempt+1}/{retries} failed: {last_err}", flush=True)
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
    print(f"[LLM] chat_json exhausted {retries} retries: {last_err}", flush=True)
    raise RuntimeError(f"chat_json 失败（{retries} 次重试后）: {last_err}")
