"""统一日志工具 — 带时间戳 + 评测 ID 上下文。

用法:
    from ..infrastructure.log_util import log, set_eval_ctx, clear_eval_ctx

    set_eval_ctx("EV-20260909182604-5811")   # 评测开始时设置
    log("MATCH", f"bench_items={n} starting...")
    clear_eval_ctx()                          # 评测结束时清理
"""
from __future__ import annotations
import threading
from datetime import datetime

_ctx = threading.local()


def set_eval_ctx(evaluation_id: str):
    """设置当前线程的评测 ID 上下文。"""
    _ctx.eval_id = evaluation_id


def get_eval_ctx() -> str:
    """获取当前线程的评测 ID。"""
    return getattr(_ctx, "eval_id", "")


def clear_eval_ctx():
    """清理当前线程的评测 ID 上下文。"""
    _ctx.eval_id = ""


def log(tag: str, msg: str, *, eval_id: str = ""):
    """带时间戳 + 评测 ID 的日志输出。

    格式: [2026-09-11 10:23:45.123] [TAG] [EV-xxx] message
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    eid = eval_id or get_eval_ctx()
    parts = [f"[{ts}]", f"[{tag}]"]
    if eid:
        parts.append(f"[{eid}]")
    parts.append(msg)
    print(" ".join(parts), flush=True)
