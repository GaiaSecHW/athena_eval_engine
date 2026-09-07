"""MySQL connection + config (dev: port-forward / k8s: ConfigMap)."""
from __future__ import annotations
import os
import time
import pymysql
from ..config_loader import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_DATABASE, DB_SSL_DISABLED


DEFAULTS = {
    "host": DB_HOST,
    "port": DB_PORT,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_DATABASE,
}

# Retry config: port-forward may briefly drop; retry before giving up.
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds


def connect(autocommit: bool = False):
    cfg = {
        "host": DB_HOST,
        "port": DB_PORT,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "database": DB_DATABASE,
        "autocommit": autocommit,
        "charset": "utf8mb4",
        "connect_timeout": 30,
        "read_timeout": 600,
        "write_timeout": 600,
        "ssl_disabled": DB_SSL_DISABLED,  # 可配: dev port-forward 防 SSL reset 时设 true; k8s 默认 false 走 TLS 隧道
    }
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return pymysql.connect(**cfg)
        except (pymysql.err.OperationalError, OSError) as e:
            last_err = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    raise last_err


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
            cur.execute(s)
    finally:
        conn.close()
