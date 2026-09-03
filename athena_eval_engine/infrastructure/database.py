"""MySQL 连接 + 配置（dev: port-forward / k8s: ConfigMap 注入）。"""
from __future__ import annotations
import os
import pymysql
from ..config_loader import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_DATABASE


DEFAULTS = {
    "host": DB_HOST,
    "port": DB_PORT,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_DATABASE,
}


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
        "ssl_disabled": True,  # 防止防火墙 reset SSL 连接
    }
    return pymysql.connect(**cfg)


def ensure_schema():
    """从 schema.sql 建表（幂等）。"""
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
