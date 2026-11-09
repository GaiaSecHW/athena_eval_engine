"""LLM 客户端（OpenAI 兼容，SSE 流式）— 用于 AI FindingBenchmarkMatch + 叙述性结论。

配置来自 config_loader。失败自动重试（最多 3 次）。
SSE 流式读取：首 token 超时 2 分钟，后续 token 断流超时 10 分钟。
429 限流：有限重试，间隔 3 秒（不占用 MAX_RETRIES 额度）。
LLM 线程按需创建，用 dict 管理（tid→Thread），map 最大 1000，实际并发由 gate 控制（DB 配 llm_max_concurrency）。
LLM 调用通过 submit_llm_batch（逐个提交+gate 控制）或 submit_pool（编排函数不占 gate）提交。
"""
from __future__ import annotations
import json
import re
import time
import socket
import select
import threading
import http.client
from concurrent.futures import Future
from urllib.parse import urlparse
from ...config_loader import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY, LLM_ENABLED
from .log_util import log

DEFAULT_API_BASE = LLM_BASE_URL
DEFAULT_MODEL = LLM_MODEL
DEFAULT_API_KEY = LLM_API_KEY

MAX_RETRIES = 20
RETRY_DELAY = 5  # 秒，重试间隔

# 上下文超限重试：网关按别名随机分发后端模型（实测 pro/mini/max/ds-v4-flush
# 都会落到 1M 的 DeepSeek-V4 或 204800 的 GLM-V5.1）。遇到输入超限时重试，
# 每次重试都会重新路由，有概率命中 1M 后端，而不是直接失败。
CONTEXT_OVERRIDE_RETRIES = 15   # 最多重试次数
CONTEXT_OVERRIDE_DELAY = 2      # 秒

# LLM 输出预留占上下文窗口的比例。必须显式声明，不能依赖网关按
# 「剩余空间」分配——输入吃到接近上限时剩余空间极小，JSON 输出会被
# max_tokens 截断（实测 session 压缩输出达 178K~310K 字符，约 7~12 万 token）。
# 按比例而非固定值：1M 上下文留 20%（约 21 万 token），204800 留 20%（约 4 万）。
LLM_RESPONSE_RESERVE_RATIO = 0.2
# 预留下限：小上下文模型（如 204800）也要保证至少这么多输出空间
LLM_RESPONSE_RESERVE_FLOOR = 32768


def get_response_reserve_tokens(max_ctx: int | None = None) -> int:
    """按上下文窗口比例计算输出预留 token 数。

    Args:
        max_ctx: 上下文上限，None 时取当前全局值。

    Returns:
        int(max_ctx * LLM_RESPONSE_RESERVE_RATIO)，但不低于
        LLM_RESPONSE_RESERVE_FLOOR。
    """
    if max_ctx is None:
        max_ctx = _max_context_tokens
    if not max_ctx:
        max_ctx = 204800
    return max(int(max_ctx * LLM_RESPONSE_RESERVE_RATIO),
               LLM_RESPONSE_RESERVE_FLOOR)

# 判定「输入超限」错误的关键词（两类后端报错文案不同）
_CTX_OVERFLOW_KW = (
    "context length", "too long", "maximum context",
    "token limit", "context_window", "context window",
    "input too long", "prompt too long",
    "max_model_len", "max_total_tokens",
    "contains at least", "maximum context length",
)


def is_context_overflow_error(err) -> bool:
    """判断异常是否为「输入超出模型上下文」。"""
    s = str(err).lower()
    return any(kw in s for kw in _CTX_OVERFLOW_KW)


# 网关报错："max_tokens=209715 cannot be greater than
#           max_model_len=max_total_tokens=204800"
_MAX_TOKENS_TOO_LARGE_RE = re.compile(
    r"max_tokens=(\d+) cannot be greater than "
    r"max_model_len=max_total_tokens=(\d+)", re.IGNORECASE)

# 按上下文预留比例计算的 max_tokens 可能超过本次路由到的后端上限
# （1M 后端算出 209715，204800 后端只允许 204800）。收到该报错时
# 把 max_tokens 收缩到后端允许值再重试，而不是死等一个能容纳它的后端。
_MAX_TOKENS_CLAMP_MARGIN = 4096


def clamp_max_tokens_from_error(err, current_max_tokens: int | None):
    """从「max_tokens 超过后端上限」的 400 报错中收缩 max_tokens。

    Returns:
        新的 max_tokens（int）；无法解析或无需收缩时返回 None。
    """
    if current_max_tokens is None:
        return None
    m = _MAX_TOKENS_TOO_LARGE_RE.search(str(err))
    if not m:
        return None
    limit = int(m.group(2))
    clamped = max(limit - _MAX_TOKENS_CLAMP_MARGIN, 1)
    if clamped >= current_max_tokens:
        return None
    return clamped


# 输入 + 输出 + 该余量必须 ≤ 上下文上限。
# 网关自身在 prompt 编码后还会预留 4096 safety-buffer（报错原文：
# "the proxy reserves 4096 safety-buffer tokens after ... prompt encoding"），
# 所以这里必须 > 4096，再留一倍余量避免边界抖动。
_MAX_TOKENS_SAFETY_MARGIN = 8192


def _count_input_tokens(messages) -> int:
    """统计 messages 的输入 token 数（本地 tokenizer）。"""
    try:
        from .token_counter import count_tokens
        return sum(count_tokens(str(m.get("content", ""))) for m in messages)
    except Exception:
        return 0


def _clamp_max_tokens_for_input(messages, requested: int) -> int:
    """按「上下文上限 - 实际输入 - 余量」给出本次可用的输出空间。

    两件事同时做：
    1. **上限收缩**：输入很大时，requested（如 20% 算出的 209715）可能让
       输入+输出超过上下文，必须收到 available。
    2. **下限放宽**：输入很小时，20% 的预留过于保守——实测输出需求可达
       26 万 token，被 209715 卡住截断（finish_reason=length）。
       此时应放宽到 available，让模型能写完整结果。

    requested 仍作为上限参与计算：调用方（或 clamp_max_tokens_from_error
    按后端报错收缩后的值）可以主动压低 max_tokens，此时不能被重新放大，
    否则重试会一直用同一个值反复失败。
    """
    max_ctx = _max_context_tokens
    if not max_ctx:
        return requested
    try:
        from .token_counter import count_tokens
        input_tokens = sum(
            count_tokens(str(m.get("content", ""))) for m in messages)
    except Exception:
        return requested
    available = max_ctx - input_tokens - _MAX_TOKENS_SAFETY_MARGIN
    if available <= 0:
        # 输入已经吃满上下文：返回最小值，让网关报输入超限，
        # 由 chat/chat_json 的重试换后端逻辑处理
        return 1
    if requested:
        # 调用方给的上限更严时以它为准（不放大）
        available = min(available, requested)
    # 输出不超过上下文的一半（防止把整窗都留给输出导致输入被挤压）
    return max(min(available, max_ctx // 2), 1)


def _worth_retry_for_larger_ctx(messages) -> bool:
    """输入是否小到可能被最大上下文后端（1M）接受。

    输入本身就超过最大后端上限时，再怎么切换后端都会超限，直接失败更省时。
    """
    try:
        from .token_counter import count_tokens
        total = sum(count_tokens(str(m.get("content", ""))) for m in messages)
    except Exception:
        return True
    return total < _max_context_tokens

# SSE 流式超时（秒）
FIRST_TOKEN_TIMEOUT = 350   # 首 token 超时：5 分 50 秒
STREAM_TIMEOUT = 600        # 后续 token 断流超时：10 分钟
MAX_RATE_LIMIT_RETRIES = 100

# 连通性测试超时（秒）。网关排队/推理模型 thinking 时，一个 max_tokens=5 的请求
# 也可能耗时 60s 以上（实测 gaiasec-llm-gateway 约 60~80s），30s 会误报超时。
TEST_TIMEOUT = 300

# LLM 线程按需创建，用 dict 管理（tid→Thread），map 最大 1000
# 实际并发由 _llm_gate 控制（DB 配 llm_max_concurrency）
# 线程执行完自动从 dict 移除；watchdog 定期清理卡死的线程
_MAX_THREADS = 1000
_llm_threads: dict[int, threading.Thread] = {}
_llm_threads_lock = threading.Lock()
# 线程创建时间，用于 watchdog 检测卡死线程
_thread_start_ts: dict[int, float] = {}
# 线程执行状态：0=等待gate, 1=执行中, 2=已完成(待清理)
_thread_state: dict[int, int] = {}
# 线程关联的 Future，watchdog 清理时设异常防止编排线程永久阻塞
_thread_futures: dict[int, Future] = {}
# watchdog 只清理已结束的线程（is_alive()=False），不清理活线程。
# LLM 自身有 SSE 超时保护（FIRST_TOKEN_TIMEOUT=350s + STREAM_TIMEOUT=600s）。


class LLMOutputTruncatedError(RuntimeError):
    """输出被 max_tokens 截断（finish_reason=length）。

    这不是「调用失败」，而是「本次输入对应的输出写不完」——
    重试同样的输入只会重复截断。调用方应把输入切得更小后重试
    （如 root_cause_analyzer 的 session 压缩按事件再二分）。
    """

    def __init__(self, message: str, content_len: int = 0):
        super().__init__(message)
        self.content_len = content_len


class _DynamicGate:
    """可动态调整上限的并发门控。

    与 threading.Semaphore 的区别：
    - 上限可运行时调整（增大立即放行等待者，减小等运行数降到新上限后才放行）
    - 同一个对象，acquire/release 始终在同一实例上（不像 Semaphore 替换会丢失旧许可）

    语义（用户需求）：
    - 线程按需创建，gate 控制实际并发
    - DB 设 300，正在运行 200 → 新任务直接进入
    - DB 设 300，正在运行 300 → 新任务等待
    - DB 从 300→100，正在运行 200 → 等运行数降到 <100 才放行新任务
    """

    def __init__(self, limit: int):
        self._limit = limit
        self._active = 0
        self._cond = threading.Condition(threading.Lock())

    def acquire(self):
        """获取许可。如果当前运行数 >= limit，阻塞等待。"""
        with self._cond:
            while self._active >= self._limit:
                self._cond.wait()
            self._active += 1

    def try_acquire(self) -> bool:
        """非阻塞获取许可。成功返回 True，满返回 False。"""
        with self._cond:
            if self._active >= self._limit:
                return False
            self._active += 1
            return True

    def release(self):
        """释放许可。如果有等待者且运行数 < limit，唤醒一个。"""
        with self._cond:
            self._active -= 1
            self._cond.notify()

    def set_limit(self, new_limit: int):
        """调整上限。

        增大：立即唤醒等待者（新上限 > 运行数时放行）。
        减小：不主动阻塞已运行的，但新任务会等到运行数降到新上限以下。
        """
        with self._cond:
            old = self._limit
            self._limit = new_limit
            if new_limit > old:
                # 增大：唤醒所有等待者，它们会重新检查 _active < _limit
                self._cond.notify_all()
            # 减小：不唤醒，等待者继续等，直到运行数自然降到新上限以下

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def active(self) -> int:
        return self._active


# LLM 并发门控（DB 可配，控制实际 LLM 调用数）
_MAX_CONCURRENCY = 50
_llm_gate = _DynamicGate(_MAX_CONCURRENCY)

# 线程本地：标记当前线程是否已持有 gate 许可（submit_llm/try_submit_llm 预获取）
_gate_holder = threading.local()

# LLM 当前并发计数器（线程安全）
_active_lock = threading.Lock()
_active_count = 0

# LLM token 用量累积器（线程安全，跨所有线程共享）
_token_lock = threading.Lock()
_token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "call_count": 0}

# 从 400 错误中收集的 max context tokens
# 默认值取 DeepSeek-V4 的 1048576（网关实测：DeepSeek-V4 报 1048576，
# GLM-V5.1 报 204800）。网关按别名随机分发后端模型，所以 400 错误后
# 自适应更新会把该值降到实际路由模型的上限。
_max_context_tokens = 1048576

def get_max_context_tokens():
    """返回 LLM 最大上下文 token 数。默认 1048576，400 错误后用实际数据更新。"""
    return _max_context_tokens


def estimate_tokens(text: str) -> int:
    """计算文本的 token 数（本地 DeepSeek V4 tokenizer 精确计算）。"""
    if not text:
        return 0
    from .token_counter import count_tokens
    return count_tokens(text)


def would_exceed_context(messages: list[dict],
                         reserved_tokens: int | None = None) -> bool:
    """预判 messages 是否会超过 LLM 上下文限制。

    reserved_tokens: 为 LLM 响应预留的 token 数。None 时按上下文窗口的
    20% 动态计算（get_response_reserve_tokens）。预留太小会导致输入吃满
    上下文、输出被 max_tokens 截断。

    用本地 DeepSeek V4 tokenizer 精确计算，不做 chars/token 估算。
    在发送前调用，避免撞 400 错误或输出截断。
    """
    max_ctx = _max_context_tokens
    if max_ctx is None:
        return False  # 未收集过上限，无法预判，让 LLM 自己报错
    if reserved_tokens is None:
        reserved_tokens = get_response_reserve_tokens(max_ctx)
    from .token_counter import count_tokens
    total = sum(count_tokens(str(m.get("content", ""))) for m in messages)
    return total + reserved_tokens > max_ctx

def _collect_max_tokens(error_text, messages):
    """解析 400 错误中「本次实际路由到的后端模型」的上下文上限，仅用于日志。

    不修改全局 _max_context_tokens：网关按别名随机分发后端（1M 的 DeepSeek-V4
    或 204800 的 GLM-V5.1），单次报错只代表这一次路由到的模型。用它覆盖全局值
    会让后续所有请求都按小上下文保守切分。超限处理由 chat/chat_json 的
    重试切换后端机制负责。
    """
    import re
    # "Decoder's maximum context length is 1048576 tokens"
    m = re.search(r'maximum context (?:length|window) is (\d+) tokens', error_text, re.IGNORECASE)
    observed = None
    if m:
        observed = int(m.group(1))
    else:
        # "max_tokens=2000000 cannot be greater than max_model_len=max_total_tokens=204800"
        m = re.search(r'max_model_len=max_total_tokens=(\d+)', error_text)
        if m:
            observed = int(m.group(1))
        else:
            m = re.search(r'max_?context_?(?:length|tokens|window)\D{0,5}(\d{4,})', error_text, re.IGNORECASE)
            if m:
                observed = int(m.group(1))
    if observed:
        log("LLM", f"本次路由模型的上下文上限={observed} "
                  f"(全局默认值保持 {_max_context_tokens})")


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


def _create_thread(target, name="llm-worker") -> threading.Thread:
    """创建线程并存入 dict 管理。dict 满时拒绝（返回 None）。

    线程必须先 start() 才有 ident，所以先创建+启动，再存入 dict。
    线程可能在线程被加入 dict 前就执行完毕，_remove_thread 用 pop(tid, None) 安全处理。

    竞态处理：如果 _wrapper 在 _create_thread 获取锁之前已执行完毕并 _remove_thread，
    此时 t.ident 不在 dict 中，_create_thread 会重新插入——但线程已结束，
    is_alive()=False，watchdog 下一轮就会清理。不会误判为 state=0 卡死。
    """
    with _llm_threads_lock:
        _cleanup_finished_locked()
        if len(_llm_threads) >= _MAX_THREADS:
            return None
    t = threading.Thread(target=target, name=name, daemon=True)
    t.start()
    # start() 后 ident 才有值；线程可能已执行完毕，_remove_thread 的 pop(tid, None) 安全
    with _llm_threads_lock:
        # 竞态防护：如果 _wrapper 已执行完毕并 _remove_thread，
        # t.ident 不在 dict 中，但线程可能即将结束。
        # 只在线程仍存活且不在 dict 中时插入，避免幽灵记录。
        if t.ident not in _llm_threads and t.is_alive():
            _llm_threads[t.ident] = t
            _thread_start_ts[t.ident] = time.time()
            _thread_state[t.ident] = 0
    return t


def _remove_thread(tid: int):
    """线程执行完毕后从 dict 移除。"""
    with _llm_threads_lock:
        _llm_threads.pop(tid, None)
        _thread_start_ts.pop(tid, None)
        _thread_state.pop(tid, None)
        _thread_futures.pop(tid, None)


def _cleanup_finished_locked():
    """清理已结束的线程（调用方需持有 _llm_threads_lock）。

    只清理 is_alive()=False 的线程。
    活线程一律不清理——LLM 自身有 SSE 超时保护
    （FIRST_TOKEN_TIMEOUT + STREAM_TIMEOUT），不需要 watchdog 重复管。
    watchdog 的职责仅是回收已结束线程的 dict 槽位。
    """
    for tid, t in list(_llm_threads.items()):
        if not t.is_alive():
            _llm_threads.pop(tid, None)
            _thread_start_ts.pop(tid, None)
            _thread_state.pop(tid, None)
            _thread_futures.pop(tid, None)


def watchdog_cleanup():
    """定期清理已完成/卡死的线程。由外部 watchdog 调用。"""
    with _llm_threads_lock:
        _cleanup_finished_locked()
    alive = len(_llm_threads)
    if alive > 0:
        log("LLM", f"watchdog: dict 中 {alive} 个线程, gate active={_llm_gate.active}")


def get_thread_count() -> int:
    """返回 dict 中当前线程数。"""
    with _llm_threads_lock:
        return len(_llm_threads)


def set_max_concurrency(n: int):
    """设置全局 LLM 并发上限。运行时可调用，不重建线程。

    线程按需创建，gate 控制实际能进入 LLM 调用的数量。
    增大：立即放行等待者。
    减小：等运行数降到新上限以下才放行新任务。
    """
    global _MAX_CONCURRENCY
    n = max(1, min(n, _MAX_THREADS))
    old_n = _MAX_CONCURRENCY
    _MAX_CONCURRENCY = n
    _llm_gate.set_limit(n)
    log("LLM", f"set_max_concurrency: {old_n} → {n} (gate adjusted, threads on-demand)")


def get_max_concurrency() -> int:
    return _MAX_CONCURRENCY


def submit_llm(fn, *args, **kwargs) -> Future:
    """提交一个 LLM 调用任务（阻塞式获取 gate）。

    线程按需创建，存入 dict 管理，map 最大 1000。
    提交前先 acquire gate（DB 配 llm_max_concurrency），拿到才创建线程。
    线程执行 fn → fn 调用 chat_json/chat → _chat_once 检测到已持有 gate，跳过 acquire。
    fn 执行完后释放 gate，线程从 dict 自动移除。

    注意：此函数适用于 fn 内部直接调 chat_json/chat 的场景。
    如果 fn 内部会再次调 submit_llm/submit_llm_batch，请用 submit_pool（不占 gate）避免死锁。
    """
    _llm_gate.acquire()

    fut: Future = Future()
    fut.set_running_or_notify_cancel()  # 标记为已运行，cancel() 会返回 False

    def _wrapper():
        tid = threading.current_thread().ident
        with _llm_threads_lock:
            _thread_state[tid] = 1  # 执行中
        _gate_holder.held = True
        try:
            result = fn(*args, **kwargs)
            fut.set_result(result)
        except BaseException as e:
            fut.set_exception(e)
        finally:
            _gate_holder.held = False
            _llm_gate.release()
            with _llm_threads_lock:
                _thread_state[tid] = 2  # 已完成
            _remove_thread(tid)

    t = _create_thread(_wrapper)
    if t is None:
        # dict 满，释放 gate 并抛异常
        _llm_gate.release()
        raise RuntimeError("LLM 线程 dict 已满（1000），无法创建新线程")
    # 存入 Future，watchdog 清理时设异常防止编排线程永久阻塞
    if t.ident is not None:
        with _llm_threads_lock:
            _thread_futures[t.ident] = fut
    return fut


def submit_pool(fn, *args, **kwargs) -> Future:
    """提交编排任务到裸线程，不占 gate、不占 dict。

    适用于编排函数：fn 内部会调 submit_llm_batch/submit_llm 提交子任务。
    如果用 submit_llm 提交编排函数，外层占 gate + 内层也要 gate → 死锁。
    submit_pool 不占 gate，fn 内部的 chat_json/chat 会自行 acquire gate。

    编排线程不纳入 dict 管理：它们不执行 LLM 调用，只是协调子任务。
    dict 只管理实际执行 LLM 调用的线程（submit_llm/try_submit_llm）。
    """
    fut: Future = Future()
    fut.set_running_or_notify_cancel()

    def _wrapper():
        try:
            result = fn(*args, **kwargs)
            fut.set_result(result)
        except BaseException as e:
            fut.set_exception(e)

    t = threading.Thread(target=_wrapper, name="llm-pool", daemon=True)
    t.start()
    return fut


def try_submit_llm(fn, *args, **kwargs) -> Future | None:
    """尝试提交一个 LLM 调用任务（非阻塞获取 gate）。

    gate 满 → 返回 None（调用方应 sleep 后重试）。
    gate 有空位 → 创建线程，返回 Future。
    """
    if not _llm_gate.try_acquire():
        return None

    fut: Future = Future()
    fut.set_running_or_notify_cancel()

    def _wrapper():
        tid = threading.current_thread().ident
        with _llm_threads_lock:
            _thread_state[tid] = 1
        _gate_holder.held = True
        try:
            result = fn(*args, **kwargs)
            fut.set_result(result)
        except BaseException as e:
            fut.set_exception(e)
        finally:
            _gate_holder.held = False
            _llm_gate.release()
            with _llm_threads_lock:
                _thread_state[tid] = 2
            _remove_thread(tid)

    t = _create_thread(_wrapper)
    if t is None:
        _llm_gate.release()
        return None
    if t.ident is not None:
        with _llm_threads_lock:
            _thread_futures[t.ident] = fut
    return fut


def submit_llm_batch(fn, items, *, args_fn=None, kwargs_fn=None,
                     cancel_cb=None) -> list[Future]:
    """逐个提交 LLM 任务，gate 满则阻塞等待（Condition.wait），直到全部提交成功。

    fn: 要执行的函数
    items: 可迭代对象，每个元素对应一个任务
    args_fn(item): 可选，返回 fn 的位置参数 tuple。无则用 (item,)
    kwargs_fn(item): 可选，返回 fn 的关键字参数 dict
    cancel_cb: 可选，取消检查回调，被取消时立即停止提交

    返回 Future 列表（与 items 等长，顺序对应）。
    cancel_cb 抛异常时，已提交的 future 会被 cancel 后再传播异常。

    用 submit_llm（阻塞式 acquire）替代 try_submit_llm + sleep(1) 轮询：
    gate 释放时 Condition.notify 立即唤醒等待线程，零空窗。
    """
    futures = []
    try:
        for item in items:
            if cancel_cb:
                cancel_cb()
            _args = args_fn(item) if args_fn else (item,)
            _kwargs = kwargs_fn(item) if kwargs_fn else {}
            fut = submit_llm(fn, *_args, **_kwargs)
            futures.append(fut)
    except Exception:
        for f in futures:
            f.cancel()
        raise
    return futures


def get_active_concurrency() -> int:
    """返回当前正在进行的 LLM 调用数。"""
    with _active_lock:
        return _active_count


# 运行时可调配置
_runtime_cfg = {
    "llm_enabled": LLM_ENABLED,
    "reasoning_effort": "none",  # "none" | "low" | "high" | "max"
    "model": DEFAULT_MODEL,
    "temperature": 0.0,          # 默认 0；调用方显式传值时以调用方为准
    "seed": None,                # None = 不发送 seed；整数 = 固定种子
}


def get_runtime_config() -> dict:
    return dict(_runtime_cfg)


def set_runtime_config(**kwargs):
    for k, v in kwargs.items():
        if k in _runtime_cfg:
            _runtime_cfg[k] = v


def get_model() -> str:
    """返回当前使用的 LLM 模型名。"""
    return _runtime_cfg.get("model", DEFAULT_MODEL)


def set_model(model: str):
    """运行时切换 LLM 模型。"""
    global DEFAULT_MODEL
    old = _runtime_cfg.get("model", DEFAULT_MODEL)
    _runtime_cfg["model"] = model
    # DEFAULT_MODEL 被 _chat_once 的 `model or DEFAULT_MODEL` 引用，
    # 但 _chat_once 传 model 参数时优先用传入值，不传时用 DEFAULT_MODEL。
    # 更新 DEFAULT_MODEL 使不传 model 参数的调用也生效。
    DEFAULT_MODEL = model
    log("LLM", f"set_model: {old} → {model}")


def test_connection(api_base: str = "", api_key: str = "", model: str = "") -> dict:
    """测试 LLM 网关联通性。

    发送一个极简请求（max_tokens=5），检查是否能正常返回。
    不占用 gate，不创建线程，直接同步调用。

    Args:
        api_base: 可选，覆盖默认 base_url。空则用当前配置。
        api_key: 可选，覆盖默认 api_key。空则用当前配置。
        model: 可选，覆盖默认 model。空则用当前配置。

    Returns:
        {"success": bool, "latency_ms": int, "model": str, "error": str}
    """
    base = api_base or DEFAULT_API_BASE
    key = api_key or DEFAULT_API_KEY
    mdl = model or get_model()

    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path.rstrip("/") + "/chat/completions"

    payload = json.dumps({
        "model": mdl,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 5,
        "stream": False,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "Content-Length": str(len(payload)),
    }

    t0 = time.time()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=TEST_TIMEOUT)
        conn.request("POST", path, body=payload, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read().decode("utf-8", errors="replace")
        conn.close()

        latency_ms = int((time.time() - t0) * 1000)

        if resp.status == 200:
            try:
                result = json.loads(resp_body)
                msg = (result.get("choices") or [{}])[0].get("message") or {}
                # 推理模型（如 deepseek_v4_flash_0731）正文可能全在 reasoning 里、
                # content 为 null；两者都取，避免测试成功却显示空响应或原始 JSON。
                content = msg.get("content") or msg.get("reasoning") or ""
                return {
                    "success": True,
                    "latency_ms": latency_ms,
                    "model": mdl,
                    "response": content,
                    "error": "",
                }
            except Exception:
                return {
                    "success": True,
                    "latency_ms": latency_ms,
                    "model": mdl,
                    "response": resp_body,
                    "error": "",
                }
        else:
            err_msg = resp_body
            try:
                err_json = json.loads(resp_body)
                err_msg = err_json.get("error", {}).get("message", err_msg)
            except Exception:
                pass
            return {
                "success": False,
                "latency_ms": latency_ms,
                "model": mdl,
                "response": "",
                "error": f"HTTP {resp.status}: {err_msg}",
            }
    except Exception as e:
        latency_ms = int((time.time() - t0) * 1000)
        return {
            "success": False,
            "latency_ms": latency_ms,
            "model": mdl,
            "response": "",
            "error": str(e),
        }


def _chat_once(messages, *, model=None, temperature=None, max_tokens=None,
            api_base=None, api_key=None, timeout=None, reasoning_effort=None,
            cancel_cb=None, seed=None, **_unused) -> tuple[str, str | None]:
    """单次 LLM 调用（SSE 流式），不重试。返回 (content, finish_reason)。

    ``timeout`` 可覆盖首 token 超时；后续 token 仍使用 STREAM_TIMEOUT。
    ``reasoning_effort`` 控制 LLM 推理深度（"none"/"low"/"high"/"max"），None 时
    从 _runtime_cfg["reasoning_effort"] 读取全局设置。
    ``temperature`` / ``seed`` 为 None 时从 _runtime_cfg 读取系统配置；
    调用方显式传值则以调用方为准（如 case matcher 固定 0）。
    ``cancel_cb`` 可选，在 SSE 读取循环中每 5 秒检查一次，被取消时立即抛 TaskCancelledError。
    429 限流最多重试 MAX_RATE_LIMIT_RETRIES 次（3 秒间隔，不占用 MAX_RETRIES 额度）。
    LLM 并发受全局 gate 控制（DB 配 llm_max_concurrency）。
    """
    if reasoning_effort is None:
        reasoning_effort = _runtime_cfg.get("reasoning_effort", "none")
    if temperature is None:
        temperature = _runtime_cfg.get("temperature", 0.0)
    if seed is None:
        seed = _runtime_cfg.get("seed")
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
    if seed is not None:
        _payload["seed"] = seed
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
    _input_tokens = 0
    if max_tokens is not None:
        # 动态收缩：实际可用输出 = 上下文上限 - 输入 token - 安全余量。
        # 固定的 max_tokens（如按 20% 算出的 209715）在输入很大时会超过
        # 实际可用空间，网关按该值截断输出（finish_reason=length）。
        _requested_max_tokens = max_tokens
        _input_tokens = _count_input_tokens(messages)
        max_tokens = _clamp_max_tokens_for_input(messages, max_tokens)
        _payload["max_tokens"] = max_tokens
        # 诊断日志：定位 finish_reason=length 时必须知道三个数
        # （输入 token / 实际 max_tokens / 全局上下文上限）
        log("LLM", f"请求参数 input_tokens={_input_tokens} "
                   f"max_tokens={max_tokens}（原 {_requested_max_tokens}）"
                   f" max_ctx={_max_context_tokens}")
    body = json.dumps(_payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key or DEFAULT_API_KEY}",
        "Content-Length": str(len(body)),
        "Accept": "text/event-stream",
    }

    # 获取 LLM 并发槽位（gate，DB 可配）
    # submit_llm/try_submit_llm 已预获取 gate 时跳过（线程本地标记）
    _gate_already_held = getattr(_gate_holder, 'held', False)
    if not _gate_already_held:
        _llm_gate.acquire()
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
            # socket.timeout 是 per-recv 的，TCP keepalive 会导致永不超时
            # 用 first_token_timeout 作为 socket timeout，Phase 1 应用层总超时检查作为安全网
            _conn_ts = time.time()
            conn = http.client.HTTPConnection(host, port, timeout=first_token_timeout)
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
            except (socket.timeout, TimeoutError) as e:
                conn.close()
                conn = None
                _conn_elapsed = time.time() - _conn_ts
                _phase1_elapsed = time.time() - _req_ts
                if _phase1_elapsed > first_token_timeout:
                    log("LLM", f"Phase 1 总超时（{first_token_timeout}s）: {e}")
                    raise RuntimeError(f"LLM Phase 1 总超时（{first_token_timeout}s）") from e
                # 本次连接耗时 vs Phase 1 累计耗时
                # 本次连接耗时 ≈ socket timeout → recv 卡住
                # 本次连接耗时远小于 socket timeout → OS 层 connect 超时（SYN 重传耗尽）
                log("LLM", f"连接超时：本次连接 {_conn_elapsed:.1f}s（socket_timeout={first_token_timeout}s），"
                    f"Phase 1 累计 {_phase1_elapsed:.1f}s/{first_token_timeout}s，"
                    f"异常={type(e).__name__}: {e}，重试连接")
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
                    err_preview = data
                    log("LLM", f"HTTP 500 重试耗尽（{MAX_500_RETRIES} 次）: {err_preview}")
                    conn.close()
                    conn = None
                    raise RuntimeError(f"LLM HTTP 500 重试耗尽（{MAX_500_RETRIES} 次）: {err_preview}")
                _500_count += 1
                data = resp.read().decode("utf-8")
                err_preview = data
                log("LLM", f"HTTP 500 from {base}, retry {_500_count}/{MAX_500_RETRIES} in 5s: {err_preview}")
                conn.close()
                conn = None
                time.sleep(5)
                continue
            if status != 200:
                data = resp.read().decode("utf-8")
                err_preview = data
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
        _last_usage = None  # 后端返回的 usage（诊断 finish_reason=length 用）
        _last_content_ts = time.time()  # 从 Phase 2 开始计时，keepalive 不重置
        _stream_start_ts = None  # 首 token 到达时间，用于总超时
        STREAM_TOTAL_TIMEOUT = 1800  # 首 token 后 30 分钟内必须完成全部输出
        while True:
            _timeout = first_token_timeout if first_token else STREAM_TIMEOUT
            _elapsed = time.time() - _last_content_ts
            if _elapsed > _timeout:
                _phase = "首 token" if first_token else "后续 token 断流"
                log("LLM", f"stream content stall ({_timeout}s no content, {_phase}), aborting")
                raise RuntimeError(f"LLM {_phase}超时（{_timeout}s 无实际内容）")
            # 首 token 后总超时：10 分钟内必须完成
            if _stream_start_ts is not None:
                _stream_elapsed = time.time() - _stream_start_ts
                if _stream_elapsed > STREAM_TOTAL_TIMEOUT:
                    _c = len("".join(content_parts))
                    _r = len("".join(reasoning_parts)) if reasoning_parts else 0
                    log("LLM", f"stream 总超时（{STREAM_TOTAL_TIMEOUT}s，首 token 后未完成），content_len={_c} reasoning_len={_r}，aborting")
                    raise RuntimeError(f"LLM stream 总超时（{STREAM_TOTAL_TIMEOUT}s，首 token 后未完成）")
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
            # SSE 规范中 `data:` 后的空格是可选的。本网关返回 `data:{...}`
            # （冒号后无空格），硬要求 "data: " 会把所有数据行丢弃，
            # 导致 content 和 reasoning 全为空 → 压缩全部失败。
            if not line_str.startswith("data:"):
                continue  # 非 data 行（含 SSE keepalive 注释）
            data_str = line_str[5:].strip()
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
                _stream_start_ts = _first_token_ts
            # 提取 token 用量（usage 通常在最后一个 chunk，choices 为空）
            usage = chunk.get("usage")
            if usage:
                _last_usage = usage
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
            _u = _last_usage or {}
            log("LLM", f"非正常结束 finish_reason={finish_reason} "
                       f"content_len={len(content)} reasoning_len={_rl} "
                       f"max_tokens={max_tokens} "
                       f"input_tokens={_input_tokens} "
                       f"prompt_tokens={_u.get('prompt_tokens')} "
                       f"completion_tokens={_u.get('completion_tokens')} "
                       f"total_tokens={_u.get('total_tokens')}")

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
        if not _gate_already_held:
            _llm_gate.release()


def chat(messages, **kwargs) -> str:
    """OpenAI-compatible chat completion（SSE 流式）。返回 assistant 消息文本。"""
    if not is_enabled():
        raise RuntimeError("LLM 未启用（设置 EVAL_LLM_ENABLED=true 后才会发起请求）")
    last_err = None
    retries = kwargs.get("retries", MAX_RETRIES)
    _cancel_cb = kwargs.get("cancel_cb")
    _no_reasoning = False  # reasoning 过长后关闭推理重试
    _ctx_retries = 0       # 上下文超限的重试计数（独立于 retries）
    for attempt in range(retries):
        if _cancel_cb:
            _cancel_cb()
        _call_kwargs = {k: v for k, v in kwargs.items() if k != "retries"}
        if _no_reasoning:
            _call_kwargs["reasoning_effort"] = "none"
        try:
            return _chat_once(messages, **_call_kwargs)[0]
        except Exception as e:
            last_err = str(e)
            err_lower = last_err.lower()
            # 输入超限：网关随机路由到小上下文后端。重试会重新路由，
            # 可能命中 1M 后端，而不是直接失败。
            if is_context_overflow_error(last_err):
                # max_tokens 超过本次后端上限 → 收缩后立即重试
                _clamped = clamp_max_tokens_from_error(
                    last_err, _call_kwargs.get("max_tokens"))
                if _clamped is not None:
                    log("LLM", f"chat max_tokens 超过后端上限，"
                               f"收缩 {_call_kwargs.get('max_tokens')} → {_clamped} 重试")
                    kwargs["max_tokens"] = _clamped
                    continue
                if (not _worth_retry_for_larger_ctx(messages)
                        or _ctx_retries >= CONTEXT_OVERRIDE_RETRIES):
                    log("LLM", f"chat 输入超限，不再重试"
                               f"(重试={_ctx_retries}): {last_err}")
                    raise RuntimeError(f"chat 输入超限: {last_err}")
                _ctx_retries += 1
                log("LLM", f"chat 输入超限，重试切换后端 "
                      f"({_ctx_retries}/{CONTEXT_OVERRIDE_RETRIES}): {last_err}")
                time.sleep(CONTEXT_OVERRIDE_DELAY)
                continue
            if "content 为空" in err_lower or "stream 总超时" in err_lower:
                if not _no_reasoning:
                    _no_reasoning = True
                    log("LLM", f"chat reasoning 过长，下次关闭推理重试 attempt={attempt+1}/{retries}")
                    time.sleep(1)
                    continue
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


def _balanced_object_slices(text):
    """扫描文本中的顶层平衡 {} 切片，返回 [(start, end)]，按跨度降序。

    "平衡"指花括号深度从 0 回到 0，跳过字符串字面量内的括号。
    只返回顶层对象，嵌套对象不单独返回（其内容已包含在父切片中）。
    """
    out = []
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
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
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                out.append((start, i + 1))
                start = -1
    out.sort(key=lambda p: p[1] - p[0], reverse=True)
    return out


def _quick_parse_keys(chunk):
    """尝试解析一个 {} 切片，返回其顶层字段名列表（失败返回空列表）。"""
    decoder = json.JSONDecoder()
    for cand in (chunk, _escape_control_chars_in_strings(chunk)):
        try:
            obj, _ = decoder.raw_decode(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return list(obj)
    return []


def _parse_json_dict_candidates(text, required_keys=None):
    """从文本中解析所有顶层 JSON dict 候选，返回 [(start, obj)]。

    LLM 常在 JSON 前输出散文，散文里可能内嵌小的合法 JSON（如工具入参
    `{"file_path": "..."}`）。若只取第一个 `{` 解析，会静默返回这个内嵌
    小对象，调用方拿不到真正的结果字段。

    策略：对每个顶层平衡 {} 切片尝试解析（原样 → 控制字符转义），
    按"含 required_keys 优先、跨度降序"排序。required_keys 为空时只按跨度降序。
    """
    decoder = json.JSONDecoder()
    cands = []
    for start, end in _balanced_object_slices(text):
        chunk = text[start:end]
        obj = None
        try:
            obj, _ = decoder.raw_decode(chunk)
        except json.JSONDecodeError:
            try:
                obj, _ = decoder.raw_decode(_escape_control_chars_in_strings(chunk))
            except json.JSONDecodeError:
                obj = None
        if isinstance(obj, dict):
            cands.append((start, end, obj))
    if not cands:
        return []
    if required_keys:
        want = set(required_keys)
        cands = [c for c in cands if want <= set(c[2])]
    return [(start, obj) for start, _end, obj in cands]


def _try_repair_backslash_quote(text, required_keys=None):
    """修复 JSON 常见错误 + 结构补全。

    Step -1: 截取 JSON 部分。LLM（尤其推理模型）可能在 JSON 前输出
    思考过程（如 "We need answer in Chinese JSON..."），导致从头解析
    立即失败。从第一个 { 开始截取，丢弃前置非 JSON 文本。

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
    # Step -1: 截取 JSON 部分（丢弃 LLM 前置思考过程）
    # 优先取最大的顶层平衡 {} 切片——散文里可能内嵌小的合法 JSON（如工具入参），
    # 取第一个 { 会命中那个小对象而不是真正的结果 JSON。
    # 无平衡切片（JSON 被截断/括号不闭合）时退回第一个 {，交给后续结构补全。
    stripped = text.lstrip()
    if not stripped.startswith('{') and not stripped.startswith('['):
        slices = _balanced_object_slices(text)
        if required_keys and slices:
            # 优先选含期望字段的切片（散文里内嵌的工具入参小对象不含这些字段）
            want = set(required_keys)
            picked = [s for s in slices
                      if want <= set(_quick_parse_keys(text[s[0]:s[1]]))]
            if picked:
                slices = picked
        if slices:
            text = text[slices[0][0]:slices[0][1]]
        else:
            idx = text.find('{')
            if idx < 0:
                idx = text.find('[')
            if idx > 0:
                text = text[idx:]
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
    """chat 但要求 JSON 输出，自动解析。JSON 解析失败时将错误反馈给 LLM 让其自我修正。

    Args:
        required_keys: 期望结果 JSON 必含的顶层字段（如 ["summary"]）。
            传入后只有包含这些字段的 dict 才被接受——避免把散文里内嵌的
            工具入参小对象（如 {"file_path": "..."}）误当成结果返回。
    """
    if not is_enabled():
        raise RuntimeError("LLM 未启用（设置 EVAL_LLM_ENABLED=true 后才会发起请求）")
    required_keys = kwargs.pop("required_keys", None)
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
    _ctx_retries = 0       # 上下文超限的重试计数（独立于 retries）
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
            last_err = str(e)
            err_lower = last_err.lower()
            # 输入超限：网关随机路由到小上下文后端。重试会重新路由，
            # 可能命中 1M 后端，而不是直接失败。
            if is_context_overflow_error(last_err):
                # 情况 A：max_tokens 超过本次后端上限（如 1M 算出的 209715
                # 落到 204800 的 GLM）→ 收缩 max_tokens 立即重试，不必换后端
                _clamped = clamp_max_tokens_from_error(
                    last_err, _call_kwargs.get("max_tokens"))
                if _clamped is not None:
                    log("LLM", f"chat_json max_tokens 超过后端上限，"
                               f"收缩 {_call_kwargs.get('max_tokens')} → {_clamped} 重试")
                    kwargs["max_tokens"] = _clamped
                    continue
                # 情况 B：输入本身超限 → 重试换后端
                if (not _worth_retry_for_larger_ctx(msgs)
                        or _ctx_retries >= CONTEXT_OVERRIDE_RETRIES):
                    log("LLM", f"chat_json 输入超限，不再重试"
                               f"(重试={_ctx_retries}): {last_err}")
                    raise RuntimeError(f"chat_json 输入超限: {last_err}")
                _ctx_retries += 1
                log("LLM", f"chat_json 输入超限，重试切换后端 "
                      f"({_ctx_retries}/{CONTEXT_OVERRIDE_RETRIES}): {last_err}")
                time.sleep(CONTEXT_OVERRIDE_DELAY)
                continue
            # content 为空 或 stream 总超时 = reasoning 太长，下次关闭推理重试
            if "content 为空" in err_lower or "stream 总超时" in err_lower:
                _msg_chars = sum(len(str(m.get("content", ""))) for m in msgs)
                _sys_msg = str(msgs[0].get("content", "")) if msgs else ""
                if not _no_reasoning:
                    _no_reasoning = True
                    log("LLM", f"chat_json reasoning 过长，下次关闭推理重试 "
                          f"attempt={attempt+1}/{retries} msgs={len(msgs)} input_chars={_msg_chars} "
                          f"max_tokens={kwargs.get('max_tokens')} sys_prompt=\"{_sys_msg}\"")
                    time.sleep(1)
                    continue
                # 关闭推理后仍失败
                log("LLM", f"chat_json 关闭推理后仍失败 "
                      f"attempt={attempt+1}/{retries} input_chars={_msg_chars} "
                      f"err={last_err}")
                if last_err == _prev_err:
                    _empty_repeat += 1
                    if _empty_repeat >= 2:
                        log("LLM", f"chat_json 关闭推理后连续 {_empty_repeat} 次失败，停止重试")
                        break
                else:
                    _empty_repeat = 0
                _prev_err = last_err
                if attempt < retries - 1:
                    time.sleep(RETRY_DELAY)
                continue
            log("LLM", f"chat_json attempt {attempt+1}/{retries} LLM error: {last_err}")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
            continue
        # ── JSON 解析（失败时将错误反馈给 LLM 让它重新生成）──
        raw = raw.strip()
        # 剥离 markdown code fence（```json ... ``` 或 ``` ... ```）
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        parsed = None
        json_err = None
        _decoder = json.JSONDecoder()
        # 记录 JSON 实际起始位置（用于 correction 时定位出错行的真实内容）
        _json_start = 0
        # raw_decode 只解析第一个完整 JSON 值，忽略尾部额外内容（不抛 "Extra data"）
        try:
            parsed, _end = _decoder.raw_decode(raw)
        except json.JSONDecodeError as je:
            json_err = je
        _missing_keys_err = None
        if parsed is not None and required_keys and not (
            isinstance(parsed, dict) and set(required_keys) <= set(parsed)
        ):
            # 解析到的 dict 缺期望字段（例如只有 {"file_path": ...}）——视为失败
            _missing_keys_err = (
                f"JSON 缺少必需字段 {list(required_keys)}，"
                f"实际字段 {list(parsed) if isinstance(parsed, dict) else type(parsed).__name__}"
            )
            parsed = None
        if parsed is None:
            # 开头有非 JSON 文字（LLM 加了自然语言分析）。
            # 不能只取第一个 {：散文里可能内嵌小的合法 JSON（工具入参），
            # 那会静默返回错误对象。改为扫描所有顶层平衡 {} 切片，取最大且
            # 解析成功的那个。
            _cands = _parse_json_dict_candidates(raw, required_keys)
            if _cands:
                _json_start, parsed = _cands[0]
        if parsed is None:
            # 尝试从第一个 [ 解析数组
            _json_start = raw.find("[")
            if _json_start >= 0:
                try:
                    parsed, _end = _decoder.raw_decode(raw[_json_start:])
                except json.JSONDecodeError as je:
                    json_err = je
        if parsed is not None and isinstance(parsed, dict):
            return parsed
        # 尝试修复 \\" 转义错误（LLM 无法修复此类问题，原样复制）
        repaired = _try_repair_backslash_quote(raw, required_keys=required_keys)
        if repaired is not None and (
            not required_keys or set(required_keys) <= set(repaired)
        ):
            log("LLM", f"chat_json JSON 转义修复成功 content_len={len(raw)}")
            return repaired
        # parsed 是 list 或 None → 视为解析失败
        # finish_reason=length 意味着 max_tokens 截断了输出，correction 重试只会重复截断
        if _fr == "length":
            # 输出被截断：抛专用异常让业务层区分「输出写不完」与「调用失败」，
            # 由业务层决定是否重发（网关随机分发后端，重试可能命中更大上下文）。
            log("LLM", f"chat_json JSON 截断（finish_reason=length, "
                       f"content_len={len(raw)}），交由调用方处理")
            raise LLMOutputTruncatedError(
                f"JSON 被 max_tokens 截断（finish_reason=length, "
                f"content_len={len(raw)}）",
                content_len=len(raw),
            )
        # JSON 解析失败 — 将错误信息反馈给 LLM，让它修正后重新生成
        if _missing_keys_err:
            err_detail = _missing_keys_err
        elif json_err:
            err_detail = f"{json_err.msg}（line {json_err.lineno} column {json_err.colno}）"
        else:
            err_detail = "未知错误"
        _raw_escaped = raw.replace("\n", "\\n")
        log("LLM", f"chat_json attempt {attempt+1}/{retries} JSON parse failed: {err_detail} "
              f"finish_reason={_fr} content_len={len(raw)} | raw: {_raw_escaped}")
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
        # 从 JSON 实际内容（去掉自然语言前缀）中取出错行，避免行号错位
        _err_ctx = ""
        if json_err:
            _json_content = raw[_json_start:] if _json_start > 0 else raw
            _lines = _json_content.split("\n")
            _el = json_err.lineno - 1
            if 0 <= _el < len(_lines):
                _err_ctx = _lines[_el].strip()
        msgs.append({"role": "assistant", "content": raw})
        _ctx_hint = f"出错行内容（第{json_err.lineno}行）：{_err_ctx}。" if _err_ctx else ""
        msgs.append({"role": "user", "content": (
            f"你返回的 JSON 有语法错误：{err_detail}。"
            f"{_ctx_hint}"
            "请根据以上错误信息修复 JSON 语法问题，只返回完整正确的 JSON。"
        )})
        last_err = f"JSON 解析失败: {err_detail}"
    log("LLM", f"chat_json exhausted after {attempt+1} attempts (max={retries}): {last_err}")
    raise RuntimeError(f"chat_json 失败（{attempt+1} 次重试后）: {last_err}")
