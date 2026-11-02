"""MySQL 连接池 — re-export infrastructure/database.py。

v2 迁移期创建的副本已与 v1 逐字节相同（仅 import 深度不同）。
合并为单一来源，确保连接池真正单例。
"""
from ...infrastructure.database import (  # noqa: F401
    connect,
    _get_pool,
    _pool,
)
