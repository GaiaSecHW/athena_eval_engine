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
import select
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
MAX_NETWORK_RETRIES = 3  # chat_json 对网络错误的重试次数（不叠加 _chat_once 内部的 429/500 重试）

# SSE 流式超时（秒）
FIRST_TOKEN_TIMEOUT = 300   # 首 token 超时：5 分钟（大 prompt 需要更长时间处理）
STREAM_TIMEOUT = 600        # 后续 token 断流超时：10 分钟
MAX_RATE_LIMIT_RETRIES = 100

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
    n = max(1, min(n, 1000))
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
            api_base=None, api_key=None, timeout=None, reasoning_effort="low",
            cancel_cb=None, **_unused) -> tuple[str, str | None]:
    """单次 LLM 调用（SSE 流式），不重试。返回 (content, finish_reason)。

    ``timeout`` 可覆盖首 token 超时；后续 token 仍使用 STREAM_TIMEOUT。
    ``reasoning_effort`` 控制 LLM 推理深度（"high"/"medium"/"low"），简单匹配任务
    传 "low" 可将 80s/次降至 ~10s/次，避免线程堆积导致服务停止。
    ``cancel_cb`` 可选，在 SSE 读取循环中每 5 秒检查一次，被取消时立即抛 TaskCancelledError。
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
    _first_token_ts = None

    _payload = {
        "model": _model,
        "messages": messages,
        "temperature": temperature,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if reasoning_effort and reasoning_effort != "none":
        # 开启推理模式（兼容各厂商参数，换模型无需改代码）
        _payload["thinking"] = {"type": "enabled"}
        _payload["chat_template_kwargs"] = {"enable_thinking": True}
        _payload["enable_thinking"] = True
        _payload["reasoning_effort"] = reasoning_effort
        _payload["reasoning_split"] = True
    elif reasoning_effort == "none":
        # 显式关闭推理（reasoning 占满 max_tokens 时使用）
        _payload["thinking"] = {"type": "disabled"}
        _payload["chat_template_kwargs"] = {"enable_thinking": False}
        _payload["enable_thinking"] = False
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
    conn = None
    first_token = True
    _counted = False
    try:
        with _active_lock:
            _active_count += 1
            _counted = True
        # ── Phase 1: 发请求，429 限流 / 500 服务端错误有限重试，拿到 200 响应头 ──
        _req_ts = time.time()
        _429_count = 0
        _500_count = 0
        MAX_500_RETRIES = 50
        while True:
            _phase1_elapsed = time.time() - _req_ts
            if _phase1_elapsed > first_token_timeout:
                log("LLM", f"Phase 1 总超时（{first_token_timeout}s，含 429/500 重试），放弃")
                raise RuntimeError(f"LLM Phase 1 总超时（{first_token_timeout}s，含 {_429_count} 次 429 + {_500_count} 次 500 重试）")
            # 用短 timeout 创建连接，配合应用层总超时计时
            # socket.timeout 是 per-recv 的，TCP keepalive 会导致永不超时
            # 所以用 min(剩余时间, 30) 作为 socket timeout，确保不会在单个 recv 上无限阻塞
            _phase1_remaining = first_token_timeout - _phase1_elapsed
            _conn_timeout = min(_phase1_remaining, 30)
            conn = http.client.HTTPConnection(host, port, timeout=_conn_timeout)
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
            except (socket.timeout, TimeoutError) as e:
                conn.close()
                conn = None
                _phase1_elapsed = time.time() - _req_ts
                if _phase1_elapsed > first_token_timeout:
                    log("LLM", f"Phase 1 总超时（{first_token_timeout}s）: {e}")
                    raise RuntimeError(f"LLM Phase 1 总超时（{first_token_timeout}s）") from e
                # 未超总时间，可能是 per-recv 超时，重试连接
                log("LLM", f"连接超时（{_conn_timeout}s），总已用 {_phase1_elapsed:.1f}s/{first_token_timeout}s，重试连接")
                continue
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
            _timeout = first_token_timeout if first_token else STREAM_TIMEOUT
            _elapsed = time.time() - _last_content_ts
            if _elapsed > _timeout:
                _phase = "首 token" if first_token else "后续 token 断流"
                log("LLM", f"stream content stall ({_timeout}s no content, {_phase}), aborting")
                raise RuntimeError(f"LLM {_phase}超时（{_timeout}s 无实际内容）")
            # ── 用 select 等待数据可用，避免 readline() 无限阻塞 ──
            # socket.timeout 是 per-recv 的，readline 逐字节读取时每次 recv 都重置计时器，
            # 导致整体永不超时。select 带剩余超时确保即使无数据也能在超时后退出。
            _remaining = _timeout - _elapsed
            _sock = conn.sock
            if _sock is not None:
                _ready, _, _ = select.select([_sock], [], [], min(_remaining, 5))
                if not _ready:
                    # select 超时期间检查取消信号
                    if cancel_cb:
                        cancel_cb()
                    continue  # select 超时，回到循环顶部检查总超时
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
                _first_token_ts = time.time()
                _last_content_ts = _first_token_ts
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

        if finish_reason and finish_reason != "stop":
            _rl = len("".join(reasoning_parts)) if reasoning_parts else 0
            log("LLM", f"非正常结束 finish_reason={finish_reason} content_len={len(content)} reasoning_len={_rl} max_tokens={max_tokens}")

        if content:
            _ft = f"first_token={_first_token_ts - _req_ts:.1f}s" if _first_token_ts else "first_token=N/A"
            log("LLM", f"done model={_model} msgs={len(messages)} {_ft} content_len={len(content)} elapsed={time.time()-_req_ts:.1f}s")
            return content, finish_reason
        # content 为空但 reasoning 有内容 — reasoning 占满 max_tokens
        _rl = len("".join(reasoning_parts)) if reasoning_parts else 0
        raise RuntimeError(f"content 为空（reasoning 占满 max_tokens, reasoning_len={_rl}）")
    except (socket.timeout, TimeoutError) as e:
        phase = "首 token" if first_token else "后续 token 断流"
        log("LLM", f"{phase}超时: {e}")
        raise RuntimeError(f"LLM {phase}超时（{first_token_timeout if first_token else STREAM_TIMEOUT}s）") from e
    finally:
        if conn:
            conn.close()
        if _counted:
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
    _cancel_cb = kwargs.get("cancel_cb")
    for attempt in range(retries):
        if _cancel_cb:
            _cancel_cb()
        try:
            return _chat_once(messages, **{k: v for k, v in kwargs.items() if k != "retries"})[0]
        except Exception as e:
            last_err = str(e)[:300]
            log("LLM", f"chat attempt {attempt+1}/{retries} failed: {last_err}")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
    log("LLM", f"chat exhausted {retries} retries: {last_err}")
    raise RuntimeError(f"LLM 调用失败（{retries} 次重试后）: {last_err}")


def _escape_control_chars_in_strings(text: str) -> str:
    """将 JSON 字符串值中的字面控制字符转义。

    LLM 有时在 JSON 字符串值中输出原始换行符/制表符等控制字符，
    导致 json.loads 报 "Invalid control character at"。
    遍历文本，跟踪字符串状态，将字符串内的控制字符替换为转义形式。
    """
    _escape_map = {
        '\n': '\\n', '\r': '\\r', '\t': '\\t',
        '\b': '\\b', '\f': '\\f',
    }
    out: list[str] = []
    in_str = False
    esc = False
    for ch in text:
        if esc:
            esc = False
            out.append(ch)
            continue
        if ch == '\\':
            esc = True
            out.append(ch)
            continue
        if ch == '"':
            in_str = not in_str
            out.append(ch)
            continue
        if in_str and ord(ch) < 0x20:
            out.append(_escape_map.get(ch, f'\\u{ord(ch):04x}'))
        else:
            out.append(ch)
    return ''.join(out)


def _try_repair_backslash_quote(text):
    """修复 JSON 常见错误 + 结构补全。

    Step 0: 修复字符串值中的字面控制字符（原始换行符/制表符 → 转义）。
    Step 1: 修复 \\" 转义错误（escaped backslash + unescaped quote → escaped quote）。
    当 JSON 字符串值中出现 \\" 时，\\ 被解析为转义反斜杠，后面的 " 变成
    未转义引号，提前终止字符串。利用 json 解析器的错误位置逐个修复。

    Step 1b: 修复无效 escape（backslash + 非 JSON 转义字符）。
    LLM 在字符串值中输出正则表达式、路径等含反斜杠的内容时，反斜杠
    后跟非 JSON 转义字符导致解析失败。修复：在反斜杠前再插入一个反斜杠。

    Step 2: 结构修复。在错误位置尝试插入缺失的分隔符（逗号、闭合括号）。
    当 LLM 漏掉 ], 或漏掉逗号时，解析器报 "Expecting ',' delimiter"。
    逐个尝试在错误位置插入 ], ],} 等修复方案。

    Step 2b: 修复未转义引号。当 "Expecting ',' delimiter" 不是缺逗号
    而是字符串值中含未转义的 " 导致字符串提前关闭时，从错误位置向前
    找到提前关闭字符串的 " 并转义为 \"。迭代修复多个未转义引号。

    Step 3: 花括号+方括号补全。在 repaired 文本上统计深度并补全缺失的 } 和 ]。
    """
    _valid_escapes = set('"\\/bfnrtu')
    decoder = json.JSONDecoder()
    # Step 0: 修复字符串值中的字面控制字符
    repaired = _escape_control_chars_in_strings(text)
    # Step 1: 修复 \\" 转义错误 + Step 1b: 修复无效 \escape
    for _ in range(100):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            # Step 1: \\" 转义错误
            if (e.pos >= 3
                    and repaired[e.pos - 1] == '"'
                    and repaired[e.pos - 3:e.pos - 1] == '\\\\'):
                repaired = repaired[:e.pos - 3] + '\\' + repaired[e.pos - 1:]
                continue
            # Step 1b: 无效 \escape（\d \s \w 等）
            if (e.msg.startswith("Invalid \\escape")
                    and e.pos < len(repaired)
                    and repaired[e.pos] == '\\'
                    and e.pos + 1 < len(repaired)
                    and repaired[e.pos + 1] not in _valid_escapes):
                # 在反斜杠前插入另一个反斜杠：\d → \\d
                repaired = repaired[:e.pos] + '\\' + repaired[e.pos:]
                continue
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
    # Step 2b: 修复未转义引号（"Expecting ',' delimiter" 由未转义 " 导致）
    for _ in range(50):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            if not e.msg.startswith("Expecting ',' delimiter"):
                break
            # 从错误位置向前跳过空白，找到提前关闭字符串的 "
            i = e.pos - 1
            while i >= 0 and repaired[i] in ' \t\n\r':
                i -= 1
            if i < 0 or repaired[i] != '"':
                break
            # 已转义的 " 不是问题所在
            if i > 0 and repaired[i - 1] == '\\':
                break
            # 转义这个引号
            repaired = repaired[:i] + '\\"' + repaired[i + 1:]
            continue
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
    _cancel_cb = kwargs.get("cancel_cb")
    _prev_raw = None
    _repeat_count = 0
    _prev_err = None
    _empty_repeat = 0
    _no_reasoning = False  # reasoning 占满后关闭推理重试
    _network_retries = 0  # 网络错误重试计数（不叠加 _chat_once 内部的 429/500 重试）
    for attempt in range(retries):
        # 取消检查：外部超时后立即停止重试，释放信号量
        if _cancel_cb:
            _cancel_cb()
        # ── LLM 调用（网络/超时错误走原重试逻辑）──
        _call_kwargs = {k: v for k, v in kwargs.items() if k != "retries"}
        if _no_reasoning:
            _call_kwargs["reasoning_effort"] = "none"
        try:
            raw, _fr = _chat_once(msgs, **_call_kwargs)
        except Exception as e:
            last_err = str(e)[:300]
            err_lower = last_err.lower()
            # context length / token limit 错误是确定性的，重试无意义
            if any(kw in err_lower for kw in (
                "context length", "too long", "maximum context",
                "token limit", "context_window",
                "input too long", "prompt too long",
            )):
                log("LLM", f"chat_json 输入超限，跳过重试: {last_err}")
                break
            # content 为空 = reasoning 占满，下次关闭推理重试
            if "content 为空" in err_lower:
                _msg_chars = sum(len(str(m.get("content", ""))) for m in msgs)
                _sys_msg = str(msgs[0].get("content", ""))[:80] if msgs else ""
                if not _no_reasoning:
                    _no_reasoning = True
                    log("LLM", f"chat_json reasoning 占满 max_tokens，下次关闭推理重试 "
                          f"attempt={attempt+1}/{retries} msgs={len(msgs)} input_chars={_msg_chars} "
                          f"max_tokens={kwargs.get('max_tokens')} sys_prompt=\"{_sys_msg}\"")
                    time.sleep(1)
                    continue
                # 关闭推理后仍 content 为空
                log("LLM", f"chat_json 关闭推理后仍 content 为空 "
                      f"attempt={attempt+1}/{retries} input_chars={_msg_chars} "
                      f"reasoning_len={last_err}")
                if last_err == _prev_err:
                    _empty_repeat += 1
                    if _empty_repeat >= 2:
                        log("LLM", f"chat_json 关闭推理后连续 {_empty_repeat} 次 content 为空，停止重试")
                        break
                else:
                    _empty_repeat = 0
                _prev_err = last_err
                if attempt < retries - 1:
                    time.sleep(RETRY_DELAY)
                continue
            # 网络错误重试不叠加 _chat_once 内部的 429/500 重试
            _network_retries += 1
            if _network_retries > MAX_NETWORK_RETRIES:
                log("LLM", f"chat_json 网络错误重试耗尽（{MAX_NETWORK_RETRIES} 次，不叠加 _chat_once 内部重试）: {last_err}")
                break
            log("LLM", f"chat_json attempt {attempt+1}/{retries} 网络错误（{_network_retries}/{MAX_NETWORK_RETRIES}）: {last_err}")
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
        # 检测 LLM 是否连续返回相同内容（correction 无效）
        if raw == _prev_raw:
            _repeat_count += 1
            if _repeat_count >= 3:
                log("LLM", f"chat_json LLM 连续 {_repeat_count} 次返回相同内容，correction 无效，停止重试")
                last_err = f"JSON 解析失败（LLM 连续 {_repeat_count} 次返回相同内容）: {err_detail}"
                break
        else:
            _repeat_count = 0
        _prev_raw = raw
        # 提取出错位置附近的上下文，帮 LLM 定位具体问题
        _err_ctx = ""
        if json_err:
            _lines = raw.split("\n")
            _el = json_err.lineno - 1
            if 0 <= _el < len(_lines):
                _err_ctx = _lines[_el].strip()[:300]
        msgs.append({"role": "assistant", "content": raw})
        _ctx_hint = f"出错行内容：{_err_ctx}。" if _err_ctx else ""
        msgs.append({"role": "user", "content": (
            f"你返回的 JSON 有语法错误：{err_detail}。"
            f"{_ctx_hint}"
            "常见原因：字符串值中包含未转义的双引号、反斜杠或换行符。"
            "请修复后只返回完整正确的 JSON。"
        )})
        last_err = f"JSON 解析失败: {err_detail}"
    log("LLM", f"chat_json exhausted {retries} retries: {last_err}")
    raise RuntimeError(f"chat_json 失败（{retries} 次重试后）: {last_err}")
