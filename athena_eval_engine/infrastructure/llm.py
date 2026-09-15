"""LLM 客户端（OpenAI 兼容，SSE 流式）— 用于 AI FindingBenchmarkMatch + 叙述性结论。

配置来自 config_loader。失败自动重试（最多 3 次）。
SSE 流式读取：首 token 超时 2 分钟，后续 token 断流超时 10 分钟。
429 限流：有限重试，间隔 3 秒（不占用 MAX_RETRIES 额度）。
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
from .log_util import log

DEFAULT_API_BASE = LLM_BASE_URL
DEFAULT_MODEL = LLM_MODEL
DEFAULT_API_KEY = LLM_API_KEY

MAX_RETRIES = 20
RETRY_DELAY = 5  # 秒，重试间隔

# SSE 流式超时（秒）
FIRST_TOKEN_TIMEOUT = 300   # 首 token 超时：5 分钟（大 prompt 需要更长时间处理）
STREAM_TIMEOUT = 600        # 后续 token 断流超时：10 分钟
MAX_RATE_LIMIT_RETRIES = 20

# LLM 全局并发上限（信号量）
# 3 个评测 × 每评测 8 并发 = 24
_MAX_CONCURRENCY = 24
_llm_semaphore: threading.Semaphore | None = None

# LLM token 用量累积器（线程安全，跨所有线程共享）
_token_lock = threading.Lock()
_token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "call_count": 0}


def reset_token_usage():
    """重置 token 计数器（评测开始前调用）。"""
    with _token_lock:
        _token_usage["prompt_tokens"] = 0
        _token_usage["completion_tokens"] = 0
        _token_usage["total_tokens"] = 0
        _token_usage["call_count"] = 0


def get_token_usage() -> dict:
    """获取当前累积的 LLM token 用量。"""
    with _token_lock:
        return dict(_token_usage)


def is_enabled() -> bool:
    """是否允许发起 LLM 请求（开发环境可显式关闭）。"""
    return LLM_ENABLED


def set_max_concurrency(n: int):
    """进程启动时调用一次，设置全局 LLM 并发上限。后续调用不替换已有信号量。"""
    global _llm_semaphore
    if _llm_semaphore is None:
        _llm_semaphore = threading.Semaphore(n)


def _chat_once(messages, *, model=None, temperature=0, max_tokens=16000,
            api_base=None, api_key=None, timeout=None, **_unused) -> str:
    """单次 LLM 调用（SSE 流式），不重试。

    ``timeout`` 可覆盖首 token 超时；后续 token 仍使用 STREAM_TIMEOUT。
    429 限流最多重试 MAX_RATE_LIMIT_RETRIES 次（3 秒间隔，不占用 MAX_RETRIES 额度）。
    LLM 并发受全局信号量控制（上限 24 = 3 评测 × 8 并发）。
    """
    base = api_base or DEFAULT_API_BASE
    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path.rstrip("/") + "/chat/completions"
    _model = model or DEFAULT_MODEL
    first_token_timeout = timeout if timeout is not None else FIRST_TOKEN_TIMEOUT
    log("LLM", f"POST {base}{path} model={_model} msgs={len(messages)} "
          f"stream=True first_token={first_token_timeout}s stream_gap={STREAM_TIMEOUT}s")

    body = json.dumps({
        "model": _model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": True,
        "stream_options": {"include_usage": True},
        # 关闭推理模式（兼容各厂商参数，换模型无需改代码）
        "thinking": {"type": "disabled"},
        "chat_template_kwargs": {"enable_thinking": False},
        "thinking_budget": 0,
        "enable_thinking": False,
        "reasoning_effort": "none",
        "reasoning_split": False,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key or DEFAULT_API_KEY}",
        "Content-Length": str(len(body)),
        "Accept": "text/event-stream",
    }

    # 获取 LLM 并发槽位（全局信号量上限 24）
    if _llm_semaphore is not None:
        _llm_semaphore.acquire()
    conn = None
    first_token = True
    try:
        # ── Phase 1: 发请求，429 限流有限重试，拿到 200 响应头 ──
        _req_ts = time.time()
        for _attempt in range(MAX_RATE_LIMIT_RETRIES):
            conn = http.client.HTTPConnection(host, port, timeout=first_token_timeout)
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
            except (socket.timeout, TimeoutError) as e:
                conn.close()
                conn = None
                log("LLM", f"首 token 超时（{first_token_timeout}s）: {e}")
                raise RuntimeError(f"LLM 首 token 超时（{first_token_timeout}s）") from e
            status = resp.status
            if status == 429:
                retry_after = resp.getheader("Retry-After")
                delay = 3
                if retry_after:
                    try: delay = int(retry_after)
                    except ValueError: pass
                log("LLM", f"429 rate limited, retry in {delay}s")
                conn.close()
                conn = None
                time.sleep(delay)
                continue
            if status != 200:
                data = resp.read().decode("utf-8")
                err_preview = data[:500]
                log("LLM", f"HTTP {status} from {base}: {err_preview}")
                conn.close()
                conn = None
                raise RuntimeError(f"LLM HTTP {status}: {err_preview}")
            break  # 200，进入 SSE 读取
        else:
            raise RuntimeError(f"LLM 429 限流重试耗尽（{MAX_RATE_LIMIT_RETRIES} 次）")

        # ── Phase 2: 逐行读 SSE 流 ──
        content_parts = []
        reasoning_parts = []
        finish_reason = None
        _last_content_ts = time.time()  # 从 Phase 2 开始计时，keepalive 不重置
        while True:
            line = resp.readline()
            if not line:
                break  # 连接关闭
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue  # SSE 事件分隔空行
            if not line_str.startswith("data: "):
                continue  # 非 data 行（含 SSE keepalive 注释）
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
                _last_content_ts = time.time()
                log("LLM", f"first token in {time.time()-_req_ts:.1f}s, stream gap timeout -> {STREAM_TIMEOUT}s")
            # 提取 token 用量（usage 通常在最后一个 chunk，choices 为空）
            usage = chunk.get("usage")
            if usage:
                with _token_lock:
                    _token_usage["prompt_tokens"] += usage.get("prompt_tokens", 0)
                    _token_usage["completion_tokens"] += usage.get("completion_tokens", 0)
                    _token_usage["total_tokens"] += usage.get("total_tokens", 0)
                    _token_usage["call_count"] += 1
            choices = chunk.get("choices") or []
            if not choices:
                # 无 choices 的 keepalive chunk 不重置内容计时器
                _timeout = first_token_timeout if first_token else STREAM_TIMEOUT
                if time.time() - _last_content_ts > _timeout:
                    _phase = "首 token" if first_token else "后续 token 断流"
                    log("LLM", f"stream content stall ({_timeout}s no content, {_phase}), aborting")
                    raise RuntimeError(f"LLM {_phase}超时（{_timeout}s 无实际内容，keepalive 不重置）")
                continue
            delta = choices[0].get("delta") or {}
            if delta.get("content"):
                content_parts.append(delta["content"])
                _last_content_ts = time.time()
            # 兼容不同 reasoning 字段名：reasoning_content / reasoning / thinking
            rc = delta.get("reasoning_content") or delta.get("reasoning") or delta.get("thinking")
            if rc:
                reasoning_parts.append(rc)
                _last_content_ts = time.time()
            # 捕获 finish_reason（stop=正常，length=max_tokens 截断，content_filter=被过滤）
            fr = choices[0].get("finish_reason")
            if fr:
                finish_reason = fr
                _last_content_ts = time.time()

        content = "".join(content_parts)
        if not content and reasoning_parts:
            # reasoning 占满 max_tokens 时，用 reasoning 文本作为回退
            content = "".join(reasoning_parts)

        if finish_reason and finish_reason != "stop":
            log("LLM", f"非正常结束 finish_reason={finish_reason} content_len={len(content)} max_tokens={max_tokens}")

        if content:
            log("LLM", f"OK stream done content_len={len(content)} elapsed={time.time()-_req_ts:.1f}s")
            return content
        raise RuntimeError("content 为空（reasoning 占满 max_tokens）")
    except (socket.timeout, TimeoutError) as e:
        phase = "首 token" if first_token else "后续 token 断流"
        log("LLM", f"{phase}超时: {e}")
        raise RuntimeError(f"LLM {phase}超时（{first_token_timeout if first_token else STREAM_TIMEOUT}s）") from e
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
            log("LLM", f"chat attempt {attempt+1}/{retries} failed: {last_err}")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
    log("LLM", f"chat exhausted {retries} retries: {last_err}")
    raise RuntimeError(f"LLM 调用失败（{retries} 次重试后）: {last_err}")


def chat_json(messages, **kwargs) -> dict:
    """chat 但要求 JSON 输出，自动解析。JSON 解析失败时将错误反馈给 LLM 让其自我修正。"""
    if not is_enabled():
        raise RuntimeError("LLM 未启用（设置 EVAL_LLM_ENABLED=true 后才会发起请求）")
    msgs = list(messages)
    if not any("json" in str(m.get("content", "")).lower() for m in msgs):
        msgs.append({"role": "user", "content": "只返回 JSON，不要任何额外文字。"})
    last_err = None
    retries = kwargs.get("retries", MAX_RETRIES)
    for attempt in range(retries):
        # ── LLM 调用（网络/超时错误走原重试逻辑）──
        try:
            raw = _chat_once(msgs, **{k: v for k, v in kwargs.items() if k != "retries"})
        except Exception as e:
            last_err = str(e)[:300]
            err_lower = last_err.lower()
            # "content 为空" 是 reasoning 偶发问题，需要重试（不是输入超限）
            # context length / token limit 错误是确定性的，重试无意义
            if "content 为空" not in err_lower and any(kw in err_lower for kw in (
                "context length", "too long", "maximum context",
                "token limit", "context_window",
                "input too long", "prompt too long",
            )):
                log("LLM", f"chat_json 输入超限，跳过重试: {last_err}")
                break
            log("LLM", f"chat_json attempt {attempt+1}/{retries} LLM error: {last_err}")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
            continue
        # ── JSON 解析（失败时将错误反馈给 LLM 让它重新生成）──
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        parsed = None
        json_err = None
        _decoder = json.JSONDecoder()
        # raw_decode 只解析第一个完整 JSON 值，忽略尾部额外内容（不抛 "Extra data"）
        try:
            parsed, _end = _decoder.raw_decode(raw)
        except json.JSONDecodeError as je:
            json_err = je
        if parsed is None:
            # 开头有非 JSON 文字，从第一个 { 开始解析
            start = raw.find("{")
            if start >= 0:
                try:
                    parsed, _end = _decoder.raw_decode(raw[start:])
                except json.JSONDecodeError as je:
                    json_err = je
        if parsed is None:
            # 尝试从第一个 [ 解析数组
            start = raw.find("[")
            if start >= 0:
                try:
                    parsed, _end = _decoder.raw_decode(raw[start:])
                except json.JSONDecodeError as je:
                    json_err = je
        if parsed is not None and isinstance(parsed, dict):
            return parsed
        # parsed 是 list 或 None → 视为解析失败，反馈给 LLM 重试
        # JSON 解析失败 — 将错误信息反馈给 LLM，让它修正后重新生成
        err_detail = f"{json_err.msg}（line {json_err.lineno} column {json_err.colno}）" if json_err else "未知错误"
        log("LLM", f"chat_json attempt {attempt+1}/{retries} JSON parse failed: {err_detail}, feeding back to LLM")
        msgs.append({"role": "assistant", "content": raw})
        msgs.append({"role": "user", "content": f"你返回的 JSON 有语法错误：{err_detail}。请修复并只返回完整正确的 JSON。"})
        last_err = f"JSON 解析失败: {err_detail}"
    log("LLM", f"chat_json exhausted {retries} retries: {last_err}")
    raise RuntimeError(f"chat_json 失败（{retries} 次重试后）: {last_err}")
