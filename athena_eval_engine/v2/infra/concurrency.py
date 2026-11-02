"""统一并发配置 — re-export infrastructure/concurrency.py。

v2 迁移期创建的副本已与 v1 逐字节相同。
合并为单一来源，确保配置状态真正单例。
"""
from ...infrastructure.concurrency import (  # noqa: F401
    get,
    set_val,
    get_all,
    set_all,
    get_keys,
)
