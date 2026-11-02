"""统一并发配置 — 所有线程池大小的单一数据源。

用法:
    from ..infrastructure.concurrency import get, set_val, get_keys

    pool = ThreadPoolExecutor(max_workers=get("ai_match_workers"))
    set_val("ai_match_workers", 30)  # 运行时动态修改

系统配置 API 修改后，config watcher 逐 key 调 set_val() 更新内存值，
新创建的线程池立即使用新值。
"""
from __future__ import annotations
import threading

# 所有并发参数的默认值
_defaults = {
    # ── 全局 ──
    "llm_max_concurrency": 50,       # LLM 并发门控上限（DB 可配，池固定 1000 线程）
    "max_concurrent_evals": 3,       # 最大并发评测数
    "eval_pool_max": 10,             # 评测线程池上界

    # ── PARSING 阶段 ──
    "parse_workers": 4,              # Trace 解析并行（非 LLM）
}

_config = dict(_defaults)
_lock = threading.Lock()

# 参数范围限制
_RANGES = {
    "llm_max_concurrency": (1, 1000),
    "max_concurrent_evals": (1, 10),
    "eval_pool_max": (1, 50),
    "parse_workers": (1, 50),
}


def get(key: str) -> int:
    """获取某个并发参数的当前值。"""
    with _lock:
        return _config.get(key, _defaults.get(key, 50))


def set_val(key: str, value: int):
    """设置某个并发参数（带范围限制）。"""
    lo, hi = _RANGES.get(key, (1, 200))
    v = max(lo, min(value, hi))
    with _lock:
        _config[key] = v


def get_keys() -> set:
    """返回所有可配置参数名的集合。"""
    return set(_defaults)
