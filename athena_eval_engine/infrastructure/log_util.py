"""统一日志工具 — 带时间戳 + 评测 ID 上下文。

用法:
    from ..infrastructure.log_util import log, set_eval_ctx, clear_eval_ctx

    set_eval_ctx("EV-20260909182604-5811")   # 评测开始时设置
    log("MATCH", f"bench_items={n} starting...")
    clear_eval_ctx()                          # 评测结束时清理
"""
from __future__ import annotations
import os
import threading
import traceback
from datetime import datetime

_ctx = threading.local()

# 异常日志文件路径（k8s 中通过环境变量配置，默认 /app/logs/eval_errors.log）
_ERROR_LOG_PATH = os.environ.get("EVAL_ERROR_LOG", "/app/logs/eval_errors.log")
_error_log_lock = threading.Lock()


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


def log_error(evaluation_id: str, source: str, error: Exception):
    """将异常信息写入独立日志文件（只写异常，不影响正常日志流）。

    格式: [2026-09-11 10:23:45.123] [SOURCE] [EV-xxx] ErrorType: message
          + 完整 traceback
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    tb = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    line = f"[{ts}] [{source}] [{evaluation_id}] {type(error).__name__}: {error}\n{tb}\n"
    try:
        with _error_log_lock:
            os.makedirs(os.path.dirname(_ERROR_LOG_PATH), exist_ok=True)
            with open(_ERROR_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass  # 写日志失败不能影响主流程
    # 同时输出到控制台
    print(line, flush=True)
