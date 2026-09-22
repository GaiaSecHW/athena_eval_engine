"""并发工具：替代 as_completed，支持取消信号检查和单任务超时。

解决的问题：
1. cancel_cb 只在 future 完成时检查 → 1 个 future 卡住时取消信号永远不被检查
2. 单个 LLM 调用卡死整个 group → per_task_timeout 秒后标记超时，调用方可降级
3. 超时后自动重试（max_retries + resubmit_fn），重试耗尽才 yield timeout=True
"""
import time
from concurrent.futures import wait, FIRST_COMPLETED
from .log_util import log


def iter_completed(futures, *, cancel_cb=None, wait_timeout=10, per_task_timeout=0,
                   max_retries=0, resubmit_fn=None, log_tag="TASK"):
    """替代 ``as_completed``。

    每次 ``wait_timeout`` 秒检查一次 cancel_cb（而非只在 future 完成时）。
    ``per_task_timeout`` 秒后仍未完成的 future 被标记超时。
    超时时先尝试重试（max_retries 次），重试耗尽才 yield timeout=True。

    Args:
        futures: Future 集合（set / list / dict_keys）
        cancel_cb: 取消检查函数（每次循环调用，抛异常则中止）
        wait_timeout: 每次 wait 超时秒数（cancel_cb 检查间隔）
        per_task_timeout: 单任务超时秒数（0 = 不检查超时）
        max_retries: 超时后最大重试次数（0=不重试，直接 yield timeout=True）
        resubmit_fn: 重试函数，接收 timed_out future，返回新 future；None 时不重试
        log_tag: 日志标签，用于标识超时的任务类型

    Yields:
        (future, timed_out: bool) — future 正常完成时 False，超时时 True
    """
    remaining = set(futures)
    submit_ts = {}  # future → 开始执行时间（RUNNING 时才记录）
    retry_count: dict = {f: 0 for f in remaining} if max_retries > 0 else {}
    while remaining:
        if cancel_cb:
            cancel_cb()
        done, _ = wait(remaining, timeout=wait_timeout, return_when=FIRST_COMPLETED)
        for fut in done:
            remaining.discard(fut)
            yield fut, False
        if per_task_timeout > 0:
            now = time.time()
            for fut in list(remaining):
                # 排队中（PENDING）不计入超时，只从开始执行（RUNNING）计时
                if fut._state == 'PENDING':
                    continue
                if fut not in submit_ts:
                    submit_ts[fut] = now  # 首次发现 RUNNING，记录开始时间
                elapsed = now - submit_ts[fut]
                if elapsed > per_task_timeout:
                    remaining.discard(fut)
                    _retries = retry_count.get(fut, 0)
                    if (max_retries > 0 and resubmit_fn
                            and _retries < max_retries):
                        log("TIMEOUT", f"[{log_tag}] 任务超时（{elapsed:.0f}s），"
                            f"重试 {_retries + 1}/{max_retries}")
                        fut.cancel()
                        try:
                            new_fut = resubmit_fn(fut)
                        except Exception as e:
                            log("TIMEOUT", f"[{log_tag}] 重试提交失败: {e}")
                            yield fut, True
                            continue
                        remaining.add(new_fut)
                        retry_count[new_fut] = _retries + 1
                    else:
                        if max_retries > 0:
                            log("TIMEOUT", f"[{log_tag}] 任务超时（{elapsed:.0f}s），"
                                f"重试耗尽（{max_retries}次），放弃")
                        else:
                            log("TIMEOUT", f"[{log_tag}] 任务超时（{elapsed:.0f}s）")
                        yield fut, True
