"""MySQL 连接池（企业级：连接复用 + ping 保活检测）。

PooledDB 配置：
- mincached=2: 预热 2 个连接
- maxcached=10: 池中最多缓存 10 个空闲连接
- maxconnections=50: 最多 50 个并发连接
- ping=1: 从池取连接前 ping 检测，死了自动丢弃换新的
- blocking=True: 池满时等待，不报错
"""
from __future__ import annotations
import os
import pymysql
from dbutils.pooled_db import PooledDB
from ..config_loader import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_DATABASE, DB_SSL_DISABLED


DEFAULTS = {
    "host": DB_HOST,
    "port": DB_PORT,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_DATABASE,
}

# 连接池（模块级单例，线程安全）
_pool: PooledDB | None = None


def _get_pool() -> PooledDB:
    global _pool
    if _pool is None:
        _pool = PooledDB(
            creator=pymysql,
            mincached=2,
            maxcached=10,
            maxconnections=50,
            blocking=True,
            ping=1,  # 取连接前 ping 检测，死连接自动丢弃
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE,
            charset="utf8mb4",
            autocommit=True,  # 默认 autocommit，少数需要事务的调用方自行 conn.autocommit(False)
            connect_timeout=30,
            read_timeout=600,
            write_timeout=600,
            ssl_disabled=DB_SSL_DISABLED,
        )
    return _pool


def connect(autocommit: bool = True):
    """从连接池获取连接。

    autocommit=True（默认）: 每条 SQL 自动提交。
    autocommit=False: 需调用方手动 conn.commit() / conn.rollback()。
    conn.close() 将连接归还池（不真正关闭）。
    """
    conn = _get_pool().connection()
    conn.autocommit(autocommit)  # 显式设置，防止池中连接残留上次设置
    return conn


def ensure_schema():
    """Create tables from schema.sql (idempotent)."""
    import re
    from ..config_loader import SCHEMA_SQL
    sql_path = SCHEMA_SQL
    if not os.path.isabs(sql_path):
        sql_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), sql_path)
    lines = open(sql_path, "r", encoding="utf-8").read().splitlines()
    clean = [re.sub(r"--.*$", "", ln) for ln in lines]
    stmts = [s.strip() for s in "\n".join(clean).split(";") if s.strip()]
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        for s in stmts:
            try:
                cur.execute(s)
            except Exception as e:
                # CREATE TABLE IF NOT EXISTS 幂等，ALTER 可能已应用
                if not s.upper().startswith("ALTER"):
                    raise
                print(f"[SCHEMA] migration skipped (may already applied): {str(e)[:120]}")
    finally:
        conn.close()
