"""并发工具：替代 as_completed，支持取消信号检查和单任务超时。

解决的问题：
1. cancel_cb 只在 future 完成时检查 → 1 个 future 卡住时取消信号永远不被检查
2. 单个 LLM 调用卡死整个 group → per_task_timeout 秒后标记超时，调用方降级
"""
import time
from concurrent.futures import wait, FIRST_COMPLETED


def iter_completed(futures, *, cancel_cb=None, wait_timeout=10, per_task_timeout=0):
    """替代 ``as_completed``。

    每次 ``wait_timeout`` 秒检查一次 cancel_cb（而非只在 future 完成时）。
    ``per_task_timeout`` 秒后仍未完成的 future 被标记超时，调用方可降级。

    Args:
        futures: Future 集合（set / list / dict_keys）
        cancel_cb: 取消检查函数（每次循环调用，抛异常则中止）
        wait_timeout: 每次 wait 超时秒数（cancel_cb 检查间隔）
        per_task_timeout: 单任务超时秒数（0 = 不检查超时）

    Yields:
        (future, timed_out: bool) — future 正常完成时 False，超时时 True
    """
    remaining = set(futures)
    submit_ts = {f: time.time() for f in remaining} if per_task_timeout > 0 else {}
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
                if now - submit_ts[fut] > per_task_timeout:
                    remaining.discard(fut)
                    yield fut, True
