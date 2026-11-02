"""评测进度追踪 — 内存字典，pod 重启后重跑无需持久化。

从 v1 evaluation_service.py 提取，消除 v2→v1 循环依赖。

两层进度：
- 阶段级（_progress_phase）：解析/写入/配对等
- 任务级（_progress_tasks）：多 task_run 并行各自独立
"""
from __future__ import annotations

import threading

_progress_phase: dict[str, str] = {}
_progress_tasks: dict[str, dict[str, str]] = {}
_progress_lock = threading.Lock()


def set_progress(evaluation_id: str, text: str):
    """设置阶段级进度（覆盖任务级进度）。"""
    with _progress_lock:
        _progress_phase[evaluation_id] = text
        _progress_tasks.pop(evaluation_id, None)


def set_task_progress(evaluation_id: str, task_run_id: str, text: str):
    """设置任务级进度（多任务并行时各自独立，互不覆盖）。"""
    with _progress_lock:
        _progress_tasks.setdefault(evaluation_id, {})[task_run_id] = text


def get_progress(evaluation_id: str) -> str:
    with _progress_lock:
        tasks = _progress_tasks.get(evaluation_id, {})
        if tasks:
            return " | ".join(tasks.values())
        return _progress_phase.get(evaluation_id, "")


def clear_progress(evaluation_id: str):
    with _progress_lock:
        _progress_phase.pop(evaluation_id, None)
        _progress_tasks.pop(evaluation_id, None)
