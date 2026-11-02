"""MySQL 短连接 + 指数退避重试包装器。

2006/2013（连接丢失）时指数退避重试，其他错误直接抛出。
从 orchestrator/dts_repo/kad_repo/evaluation_service 四处重复实现中提取。
"""
from __future__ import annotations

import time

import pymysql

from ...infrastructure.database import connect
from ...infrastructure.log_util import log
from ...infrastructure.log_util import log_to_file


def db_query(fn, _retries: int = 8):
    """短连接 + 重试包装器。

    2006/2013（连接丢失）时指数退避重试，其他错误直接抛出。
    """
    last_err = None
    for attempt in range(_retries):
        conn = None
        try:
            conn = connect(autocommit=True)
            return fn(conn.cursor())
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
            last_err = e
            # 强制关闭底层 pymysql 连接，防止池复用坏连接
            if conn:
                try:
                    inner = getattr(conn, "_con", None)
                    if inner is not None and not getattr(inner, "_closed", True):
                        inner.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            if e.args and e.args[0] in (2013, 2006) and attempt < _retries - 1:
                _wait = min(2 * (attempt + 1), 30)
                log("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]}, retry in {_wait}s...")
                log_to_file("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]} {e}, retry in {_wait}s...")
                time.sleep(_wait)
                continue
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    raise last_err  # type: ignore[misc]
