"""LLM 客户端（OpenAI 兼容，SSE 流式）— 用于 AI FindingBenchmarkMatch + 叙述性结论。

配置来自 config_loader。失败自动重试（最多 3 次）。
SSE 流式读取：首 token 超时 2 分钟，后续 token 断流超时 10 分钟。
429 限流：有限重试，间隔 3 秒（不占用 MAX_RETRIES 额度）。
LLM 全局并发上限由信号量控制（默认 50）。
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

# LLM 全局并发上限（信号量，模块加载时即创建）
_MAX_CONCURRENCY = 50
_llm_semaphore = threading.Semaphore(_MAX_CONCURRENCY)

# LLM 当前并发计数器（线程安全）
_active_lock = threading.Lock()
_active_count = 0

# LLM token 用量累积器（线程安全，跨所有线程共享）
_token_lock = threading.Lock()
_token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "call_count": 0}

# 从 400 错误中收集的 max context tokens 和 chars/token 换算率
_max_context_tokens = None
_chars_per_token = 3.0  # 默认值，400 错误后用实际数据更新

def get_max_context_tokens():
    """返回从 400 错误中收集的 max context tokens，未收集时返回 None。"""
    return _max_context_tokens

def get_chars_per_token():
    """返回 chars/token 换算率，默认 3.0，400 错误后用实际数据更新。"""
    return _chars_per_token

def _collect_max_tokens(error_text, messages):
    """从 LLM 400 错误响应中解析 max context tokens 和实际 token 数，
    结合当时 messages 的字符数计算 chars/token 换算率。"""
    global _max_context_tokens, _chars_per_token
    import re
    # 提取 max context tokens: "maximum context length is 131072 tokens"
    m = re.search(r'maximum context (?:length|window) is (\d+) tokens', error_text, re.IGNORECASE)
    if not m:
        m = re.search(r'max_?context_?(?:length|tokens|window)\D{0,5}(\d{4,})', error_text, re.IGNORECASE)
    if m:
        _max_context_tokens = int(m.group(1))
    # 提取实际 token 数: "your messages resulted in 150000 tokens"
    m2 = re.search(r'(?:resulted in|have )(\d+) tokens', error_text, re.IGNORECASE)
    if m2:
        actual_tokens = int(m2.group(1))
        msg_chars = sum(len(str(msg.get("content", ""))) for msg in messages)
        if actual_tokens > 0 and msg_chars > 0:
            _chars_per_token = msg_chars / actual_tokens
    if _max_context_tokens:
        log("LLM", f"从 400 错误中收集 max_context_tokens={_max_context_tokens} chars_per_token={_chars_per_token:.2f}")


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
    return _runtime_cfg["llm_enabled"]


def set_max_concurrency(n: int):
    """设置全局 LLM 并发上限。运行时可调用，替换信号量。

    替换前释放旧信号量的全部许可，避免等待中的线程被永久搁置。
    """
    global _llm_semaphore, _MAX_CONCURRENCY
    n = max(1, min(n, 200))
    if n == 20:
        import traceback
        log("LLM", f"⚠ set_max_concurrency(20) 被调用！调用栈:\n{''.join(traceback.format_stack())}")
    old = _llm_semaphore
    _MAX_CONCURRENCY = n
    _llm_semaphore = threading.Semaphore(n)
    if old is not None:
        for _ in range(_MAX_CONCURRENCY):
            old.release()


def get_max_concurrency() -> int:
    return _MAX_CONCURRENCY


def get_active_concurrency() -> int:
    """返回当前正在进行的 LLM 调用数。"""
    with _active_lock:
        return _active_count


# 运行时可调配置
_runtime_cfg = {
    "llm_enabled": LLM_ENABLED,
}


def get_runtime_config() -> dict:
    return dict(_runtime_cfg)


def set_runtime_config(**kwargs):
    for k, v in kwargs.items():
        if k in _runtime_cfg:
            _runtime_cfg[k] = v


def _chat_once(messages, *, model=None, temperature=0, max_tokens=None,
            api_base=None, api_key=None, timeout=None, **_unused) -> tuple[str, str | None]:
    """单次 LLM 调用（SSE 流式），不重试。返回 (content, finish_reason)。

    ``timeout`` 可覆盖首 token 超时；后续 token 仍使用 STREAM_TIMEOUT。
    429 限流最多重试 MAX_RATE_LIMIT_RETRIES 次（3 秒间隔，不占用 MAX_RETRIES 额度）。
    LLM 并发受全局信号量控制（上限 50）。
    """
    base = api_base or DEFAULT_API_BASE
    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path.rstrip("/") + "/chat/completions"
    _model = model or DEFAULT_MODEL
    first_token_timeout = timeout if timeout is not None else FIRST_TOKEN_TIMEOUT
    log("LLM", f"POST {host}:{port}{path} model={_model} msgs={len(messages)} "
          f"stream=True first_token={first_token_timeout}s stream_gap={STREAM_TIMEOUT}s")

    _payload = {
        "model": _model,
        "messages": messages,
        "temperature": temperature,
        "stream": True,
        "stream_options": {"include_usage": True},
        # 关闭推理模式（兼容各厂商参数，换模型无需改代码）
        "thinking": {"type": "disabled"},
        "chat_template_kwargs": {"enable_thinking": False},
        "thinking_budget": 0,
        "enable_thinking": False,
        "reasoning_effort": "none",
        "reasoning_split": False,
    }
    if max_tokens is not None:
        _payload["max_tokens"] = max_tokens
    body = json.dumps(_payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key or DEFAULT_API_KEY}",
        "Content-Length": str(len(body)),
        "Accept": "text/event-stream",
    }

    # 获取 LLM 并发槽位（全局信号量）
    # 保存引用，确保 acquire/release 在同一个信号量对象上
    _sem = _llm_semaphore
    if _sem is not None:
        _sem.acquire()
    global _active_count
    with _active_lock:
        _active_count += 1
    conn = None
    first_token = True
    try:
        # ── Phase 1: 发请求，429 限流 / 500 服务端错误有限重试，拿到 200 响应头 ──
        _req_ts = time.time()
        _429_count = 0
        _500_count = 0
        MAX_500_RETRIES = 50
        while True:
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
                if _429_count >= MAX_RATE_LIMIT_RETRIES:
                    conn.close()
                    conn = None
                    raise RuntimeError(f"LLM 429 限流重试耗尽（{MAX_RATE_LIMIT_RETRIES} 次）")
                _429_count += 1
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
            if status == 500:
                if _500_count >= MAX_500_RETRIES:
                    data = resp.read().decode("utf-8")
                    err_preview = data[:500]
                    log("LLM", f"HTTP 500 重试耗尽（{MAX_500_RETRIES} 次）: {err_preview}")
                    conn.close()
                    conn = None
                    raise RuntimeError(f"LLM HTTP 500 重试耗尽（{MAX_500_RETRIES} 次）: {err_preview}")
                _500_count += 1
                data = resp.read().decode("utf-8")
                err_preview = data[:200]
                log("LLM", f"HTTP 500 from {base}, retry {_500_count}/{MAX_500_RETRIES} in 5s: {err_preview}")
                conn.close()
                conn = None
                time.sleep(5)
                continue
            if status != 200:
                data = resp.read().decode("utf-8")
                err_preview = data[:500]
                if status == 400:
                    _collect_max_tokens(data, messages)
                log("LLM", f"HTTP {status} from {base}: {err_preview}")
                conn.close()
                conn = None
                raise RuntimeError(f"LLM HTTP {status}: {err_preview}")
            break  # 200，进入 SSE 读取

        # ── Phase 2: 逐行读 SSE 流 ──
        content_parts = []
        reasoning_parts = []
        finish_reason = None
        _last_content_ts = time.time()  # 从 Phase 2 开始计时，keepalive 不重置
        while True:
            line = resp.readline()
            if not line:
                break  # 连接关闭
            # ── 内容超时检查（放在所有 continue 之前，确保每行都检查）──
            # 防止 LLM 网关持续发 keepalive/空 delta 的 chunk 导致无限循环
            _timeout = first_token_timeout if first_token else STREAM_TIMEOUT
            if time.time() - _last_content_ts > _timeout:
                _phase = "首 token" if first_token else "后续 token 断流"
                log("LLM", f"stream content stall ({_timeout}s no content, {_phase}), aborting")
                raise RuntimeError(f"LLM {_phase}超时（{_timeout}s 无实际内容）")
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
            return content, finish_reason
        raise RuntimeError("content 为空（reasoning 占满 max_tokens）")
    except (socket.timeout, TimeoutError) as e:
        phase = "首 token" if first_token else "后续 token 断流"
        log("LLM", f"{phase}超时: {e}")
        raise RuntimeError(f"LLM {phase}超时（{first_token_timeout if first_token else STREAM_TIMEOUT}s）") from e
    finally:
        if conn:
            conn.close()
        with _active_lock:
            _active_count -= 1
        if _sem is not None:
            _sem.release()


def chat(messages, **kwargs) -> str:
    """OpenAI-compatible chat completion（SSE 流式）。返回 assistant 消息文本。"""
    if not is_enabled():
        raise RuntimeError("LLM 未启用（设置 EVAL_LLM_ENABLED=true 后才会发起请求）")
    last_err = None
    retries = kwargs.get("retries", MAX_RETRIES)
    for attempt in range(retries):
        try:
            return _chat_once(messages, **{k: v for k, v in kwargs.items() if k != "retries"})[0]
        except Exception as e:
            last_err = str(e)[:300]
            log("LLM", f"chat attempt {attempt+1}/{retries} failed: {last_err}")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
    log("LLM", f"chat exhausted {retries} retries: {last_err}")
    raise RuntimeError(f"LLM 调用失败（{retries} 次重试后）: {last_err}")


def _try_repair_backslash_quote(text):
    """修复 JSON 常见错误 + 结构补全。

    Step 1: 修复 \\" 转义错误（escaped backslash + unescaped quote → escaped quote）。
    当 JSON 字符串值中出现 \\" 时，\\ 被解析为转义反斜杠，后面的 " 变成
    未转义引号，提前终止字符串。利用 json 解析器的错误位置逐个修复。

    Step 2: 结构修复。在错误位置尝试插入缺失的分隔符（逗号、闭合括号）。
    当 LLM 漏掉 ], 或漏掉逗号时，解析器报 "Expecting ',' delimiter"。
    逐个尝试在错误位置插入 ], ],} 等修复方案。

    Step 3: 花括号+方括号补全。在 repaired 文本上统计深度并补全缺失的 } 和 ]。
    """
    decoder = json.JSONDecoder()
    repaired = text
    # Step 1: 修复 \\" 转义错误
    for _ in range(50):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            # e.pos 指向导致错误的字符，e.pos-1 是提前终止字符串的 "
            if (e.pos >= 3
                    and repaired[e.pos - 1] == '"'
                    and repaired[e.pos - 3:e.pos - 1] == '\\\\'):
                # 将 \\ 替换为 \，使后面的 " 变成 \"
                repaired = repaired[:e.pos - 3] + '\\' + repaired[e.pos - 1:]
            else:
                break
    # Step 2: 结构修复（在错误位置插入缺失的分隔符/闭合符）
    for _ in range(50):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            if e.msg.startswith("Expecting ',' delimiter") or e.msg.startswith("Expecting ':' delimiter"):
                # 尝试在错误位置插入各种修复字符
                fixes = []
                if e.msg.startswith("Expecting ',' delimiter"):
                    # 解析器在数组/对象中期望逗号，但找到了 } 或其他字符
                    # 可能是缺逗号、缺 ]、或缺 ]},
                    fixes = [
                        repaired[:e.pos] + ',' + repaired[e.pos:],      # 缺逗号
                        repaired[:e.pos] + ']' + repaired[e.pos:],      # 缺 ]（数组未闭合）
                        repaired[:e.pos] + ']}' + repaired[e.pos:],     # 缺 ]}（数组+对象未闭合）
                        repaired[:e.pos] + ']},' + repaired[e.pos:],    # 缺 ]},（数组+对象+逗号）
                    ]
                elif e.msg.startswith("Expecting ':' delimiter"):
                    fixes = [
                        repaired[:e.pos] + ':' + repaired[e.pos:],      # 缺冒号
                    ]
                fixed_one = False
                for fixed in fixes:
                    try:
                        obj, _ = decoder.raw_decode(fixed)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                # 如果没有快速修复命中，尝试逐步插入 ] 直到解析成功
                # （处理多层嵌套数组未闭合的情况）
                for extra_brackets in [']', ']]', ']]]', ']', ']}', ']]}']:
                    fixed = repaired[:e.pos] + extra_brackets + repaired[e.pos:]
                    try:
                        obj, _ = decoder.raw_decode(fixed)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                break  # 结构修复无法命中，跳出
            else:
                break
    # Step 3: 花括号+方括号补全（在 repaired 文本上统计深度）
    brace_depth = 0
    bracket_depth = 0
    in_str = False
    esc = False
    for ch in repaired:
        if esc:
            esc = False
            continue
        if ch == '\\':
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == '{':
            brace_depth += 1
        elif ch == '}':
            brace_depth -= 1
        elif ch == '[':
            bracket_depth += 1
        elif ch == ']':
            bracket_depth -= 1
    if brace_depth > 0 or bracket_depth > 0:
        suffix = ']' * max(bracket_depth, 0) + '}' * max(brace_depth, 0)
        fixed = repaired + suffix
        try:
            obj = json.loads(fixed)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
    return None


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
            raw, _fr = _chat_once(msgs, **{k: v for k, v in kwargs.items() if k != "retries"})
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
        # 尝试修复 \\" 转义错误（LLM 无法修复此类问题，原样复制）
        repaired = _try_repair_backslash_quote(raw)
        if repaired is not None:
            log("LLM", f"chat_json JSON 转义修复成功 content_len={len(raw)}")
            return repaired
        # parsed 是 list 或 None → 视为解析失败
        # finish_reason=length 意味着 max_tokens 截断了输出，correction 重试只会重复截断
        if _fr == "length":
            log("LLM", f"chat_json JSON 截断（finish_reason=length, content_len={len(raw)}），跳过 correction 重试")
            last_err = f"JSON 被 max_tokens 截断（finish_reason=length, content_len={len(raw)}）"
            break
        # JSON 解析失败 — 将错误信息反馈给 LLM，让它修正后重新生成
        err_detail = f"{json_err.msg}（line {json_err.lineno} column {json_err.colno}）" if json_err else "未知错误"
        _head = raw[:200].replace("\n", "\\n")
        _tail = raw[-200:].replace("\n", "\\n")
        log("LLM", f"chat_json attempt {attempt+1}/{retries} JSON parse failed: {err_detail} "
              f"finish_reason={_fr} content_len={len(raw)} | head: {_head} | tail: {_tail}")
        msgs.append({"role": "assistant", "content": raw})
        msgs.append({"role": "user", "content": f"你返回的 JSON 有语法错误：{err_detail}。请修复并只返回完整正确的 JSON。"})
        last_err = f"JSON 解析失败: {err_detail}"
    log("LLM", f"chat_json exhausted {retries} retries: {last_err}")
    raise RuntimeError(f"chat_json 失败（{retries} 次重试后）: {last_err}")
