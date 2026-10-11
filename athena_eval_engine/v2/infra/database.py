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
from ...config_loader import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_DATABASE, DB_SSL_DISABLED


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

    注意：连接池复用连接，上一次使用的 session 变量（如 autocommit）会残留。
    因此每次取连接后必须显式 SET autocommit，确保状态正确。
    """
    conn = _get_pool().connection()
    cur = conn.cursor()
    cur.execute("SET autocommit=" + ("1" if autocommit else "0"))
    cur.close()
    return conn


def direct_connect(autocommit: bool = True):
    """创建直连（绕过连接池），用于大 INSERT 等场景。

    长时间 LLM 操作后连接池中的空闲连接可能已被网络层关闭，
    但 ping 检测（小包）无法发现半断连，导致大 INSERT 失败。
    直连每次创建新 TCP 连接，避免复用 stale 连接。
    conn.close() 真正关闭连接（不归还池）。
    """
    from ...config_loader import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_DATABASE, DB_SSL_DISABLED
    conn = pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
        database=DB_DATABASE, charset="utf8mb4", autocommit=autocommit,
        connect_timeout=30, read_timeout=600, write_timeout=600,
        ssl_disabled=DB_SSL_DISABLED,
    )
    return conn


def drain_idle_connections():
    """排空连接池中的空闲连接。

    在长时间无 DB 操作（如 LLM 调用）前调用，
    防止空闲连接被网络层关闭后仍被池复用。
    """
    global _pool
    if _pool is None:
        return
    # PooledDB 内部用 _idle_cache 列表缓存空闲 SteadyDBConnection
    idle = getattr(_pool, '_idle_cache', None)
    if idle is None:
        return
    while idle:
        try:
            conn = idle.pop(0)
            conn._close()
        except Exception:
            pass


def ensure_schema():
    """Create tables from schema.sql (idempotent)."""
    import re
    from ...config_loader import SCHEMA_SQL
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
