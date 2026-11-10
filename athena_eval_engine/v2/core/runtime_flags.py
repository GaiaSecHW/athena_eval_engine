"""运行时开关——由 system_config 表持久化，供分析流程按需开启。

与 infrastructure/concurrency 的区别：那里只放线程池并发数（int），
这里放布尔开关，避免把 bool 塞进并发参数的范围校验里。
"""
from __future__ import annotations

import threading

_defaults: dict[str, bool] = {
    # 是否把实际喂给 LLM 的 session 文本写成内容寻址快照
    # （{eid}_trace_{case_id}_{chain}_{hash}.json）。
    # 指纹始终记录；关闭后不落盘全文，只保留可对比的哈希。
    "trace_snapshot": True,
}

_flags = dict(_defaults)
_lock = threading.Lock()


def get_flag(key: str, default: bool | None = None) -> bool:
    with _lock:
        if key in _flags:
            return _flags[key]
        return _defaults.get(key, bool(default))


def set_flag(key: str, value) -> None:
    """设置开关；value 支持 bool / "true"/"false" / 0/1。"""
    if isinstance(value, str):
        v = value.strip().lower() in ("1", "true", "yes", "on")
    else:
        v = bool(value)
    with _lock:
        _flags[key] = v


def flag_keys() -> set[str]:
    return set(_defaults)
