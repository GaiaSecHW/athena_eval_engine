"""并发工具：替代 as_completed，支持取消信号检查。

解决的问题：
1. cancel_cb 只在 future 完成时检查 → 1 个 future 卡住时取消信号永远不被检查
"""
import time
from concurrent.futures import wait, FIRST_COMPLETED


def iter_completed(futures, *, cancel_cb=None, wait_timeout=10, **_unused):
    """替代 ``as_completed``。

    每次 ``wait_timeout`` 秒检查一次 cancel_cb（而非只在 future 完成时）。

    Args:
        futures: Future 集合（set / list / dict_keys）
        cancel_cb: 取消检查函数（每次循环调用，抛异常则中止）
        wait_timeout: 每次 wait 超时秒数（cancel_cb 检查间隔）

    Yields:
        (future, False) — 兼容旧调用方签名
    """
    remaining = set(futures)
    while remaining:
        if cancel_cb:
            cancel_cb()
        done, _ = wait(remaining, timeout=wait_timeout, return_when=FIRST_COMPLETED)
        for fut in done:
            remaining.discard(fut)
            yield fut, False
