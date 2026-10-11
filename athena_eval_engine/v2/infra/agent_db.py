"""Agent 数据库连接管理。

管理 6 个 Agent（turing / argo / secmate / dataflow / cvuln_verify / webvuln_verify）
的数据库连接配置，支持 MySQL + PostgreSQL 双驱动、环境变量覆盖、连接测试。

- MySQL: 复用 v2/infra/database.py 的短连接（direct_connect 风格）+ 重试
- PostgreSQL: psycopg2 短连接 + 重试
- none: WebVulnVerify 无独立 DB，返回 None
"""
from __future__ import annotations

import json
import os
import time
import traceback

import pymysql

from .database import connect as eval_connect, direct_connect as eval_direct_connect
from ...infrastructure.log_util import log, log_error

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

#: agent_type → 环境变量前缀映射（webvuln_verify 无 DB，不需要环境变量）
AGENT_ENV_PREFIX = {
    "turing": "EVAL_TURING_DB",
    "argo": "EVAL_ARGO_DB",
    "secmate": "EVAL_SECMATE_DB",
    "dataflow": "EVAL_DATAFLOW_DB",
    "cvuln_verify": "EVAL_CVULN_DB",
    # webvuln_verify 无 DB，不需要环境变量
}

#: 环境变量 KEY 后缀 → 配置字段名映射
_ENV_KEY_MAP = {
    "HOST": "host",
    "PORT": "port",
    "USER": "username",
    "PASSWORD": "password",
    "NAME": "database_name",
}

#: 重试次数（MySQL 2006/2013 断连重试）
_MAX_RETRIES = 3
#: 重试退避基数（秒）
_RETRY_BACKOFF_BASE = 0.5

#: pymysql 可重试错误码（连接丢失）
_RETRYABLE_MYSQL_ERRORS = (2006, 2013)


# ---------------------------------------------------------------------------
# AgentDBManager
# ---------------------------------------------------------------------------

class AgentDBManager:
    """管理 6 个 Agent 的数据库连接配置。

    所有方法通过 eval-engine 自身的 MySQL（``v2/infra/database.py``）读取
    ``agent_datasource_config`` 表获取 Agent DB 配置，然后按 ``db_type``
    创建到目标 Agent DB 的短连接。
    """

    # -----------------------------------------------------------------------
    # 内部工具
    # -----------------------------------------------------------------------

    @staticmethod
    def _apply_env_overrides(agent_type: str, config: dict) -> dict:
        """用环境变量覆盖 DB 配置（优先级：环境变量 > DB 配置）。

        命名规则 ``EVAL_{AGENT}_DB_{KEY}``，KEY ∈ HOST/PORT/USER/PASSWORD/NAME。
        """
        prefix = AGENT_ENV_PREFIX.get(agent_type)
        if prefix is None:
            return config  # webvuln_verify 等无环境变量覆盖

        for suffix, field in _ENV_KEY_MAP.items():
            env_key = f"{prefix}_{suffix}"
            val = os.environ.get(env_key)
            if val is None or val == "":
                continue
            if field == "port":
                try:
                    config[field] = int(val)
                except ValueError:
                    pass
            else:
                config[field] = val

        return config

    @staticmethod
    def _row_to_config(row: tuple, columns: list[str]) -> dict:
        """将 DB 行转换为配置字典。"""
        config = dict(zip(columns, row))
        # 解析 JSON 字段
        for json_field in ("relation_tables", "phase_identifier"):
            raw = config.get(json_field)
            if raw is None:
                config[json_field] = None
            elif isinstance(raw, str):
                try:
                    config[json_field] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    config[json_field] = raw
            # dict / list 类型已经是解析后的，保持不变
        # enabled 转 bool
        config["enabled"] = bool(config.get("enabled", True))
        return config

    @staticmethod
    def _resolve_db_name(config: dict, project_id: str | None) -> str | None:
        """处理 database_name 占位符替换。

        DataflowVulnScan 的 database_name 是模板 ``dvs_{project_id}``，
        运行时用 project_id 替换。
        """
        db_name = config.get("database_name")
        if db_name is None:
            return None
        if "{project_id}" in db_name and project_id:
            db_name = db_name.replace("{project_id}", project_id)
        return db_name

    # -----------------------------------------------------------------------
    # 公开 API
    # -----------------------------------------------------------------------

    def get_config(self, agent_type: str) -> dict | None:
        """从 agent_datasource_config 表读取指定 agent 的配置。

        环境变量覆盖 DB 配置（``EVAL_{AGENT}_DB_{KEY}`` 格式）。

        返回::

            {
                "agent_type": str,
                "display_name": str,
                "db_type": str,           # mysql / postgresql / none
                "host": str | None,
                "port": int | None,
                "username": str | None,
                "password": str | None,
                "database_name": str | None,   # 模板可能含 {project_id}
                "relation_tables": dict | None,
                "phase_identifier": dict | None,
                "enabled": bool,
                "last_connected_at": datetime | None,
                "last_error": str | None,
                "_version": int,
            }

        不存在或 DB 不可用时返回 None。
        """
        sql = (
            "SELECT agent_type, display_name, db_type, host, port, "
            "username, password, database_name, relation_tables, "
            "phase_identifier, enabled, last_connected_at, last_error, _version "
            "FROM agent_datasource_config WHERE agent_type = %s"
        )
        try:
            conn = eval_connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute(sql, (agent_type,))
                row = cur.fetchone()
                if row is None:
                    return None
                columns = [
                    "agent_type", "display_name", "db_type", "host", "port",
                    "username", "password", "database_name", "relation_tables",
                    "phase_identifier", "enabled", "last_connected_at",
                    "last_error", "_version",
                ]
                config = self._row_to_config(row, columns)
                # 环境变量覆盖
                config = self._apply_env_overrides(agent_type, config)
                return config
            finally:
                conn.close()
        except Exception as e:
            log("AGENT_DB", f"get_config({agent_type}) 失败: {e}")
            return None

    def get_connection(self, agent_type: str, project_id: str | None = None):
        """获取指定 agent 的数据库连接。

        - **MySQL**: 用 pymysql 短连接（复用 v2/infra/database.py 的短连接+重试模式）
        - **PostgreSQL**: 用 psycopg2 短连接（connect_timeout=10）+ 重试
        - **none**: 返回 None（WebVulnVerify 无 DB）
        - ``database_name`` 含 ``{project_id}`` 占位符时用 project_id 替换

        调用方负责 ``conn.close()``。

        :raises RuntimeError: 配置不存在或未启用
        :raises pymysql.err.OperationalError: MySQL 连接失败（重试耗尽）
        :raises psycopg2.OperationalError: PostgreSQL 连接失败（重试耗尽）
        """
        config = self.get_config(agent_type)
        if config is None:
            raise RuntimeError(f"Agent '{agent_type}' 配置不存在")
        if not config.get("enabled", True):
            raise RuntimeError(f"Agent '{agent_type}' 数据源已禁用")

        db_type = config.get("db_type", "none")
        db_name = self._resolve_db_name(config, project_id)

        if db_type == "none":
            return None

        host = config.get("host")
        port = config.get("port")
        user = config.get("username")
        password = config.get("password")

        if db_type == "mysql":
            return self._connect_mysql(agent_type, host, port, user, password, db_name)
        elif db_type == "postgresql":
            return self._connect_postgresql(agent_type, host, port, user, password, db_name)
        else:
            raise RuntimeError(f"不支持的 db_type: {db_type}")

    def test_connection(self, agent_type: str, project_id: str | None = None) -> tuple[bool, str]:
        """测试连接，返回 ``(成功/失败, 错误信息)``。

        成功时更新 ``agent_datasource_config`` 表的 ``last_connected_at`` 和清空 ``last_error``。
        失败时更新 ``last_error``。

        对于 ``database_name`` 含 ``{project_id}`` 占位符的数据源（如 DataflowVulnScan），
        必须提供 ``project_id`` 参数才能测试连接。
        """
        config = self.get_config(agent_type)
        if config is None:
            err_msg = f"配置不存在: {agent_type}"
            self._update_conn_status(agent_type, success=False, error=err_msg)
            return False, err_msg
        db_name = config.get("database_name") or ""
        if "{project_id}" in db_name and not project_id:
            err_msg = f"database_name 含 {{project_id}} 占位符，需提供 project_id 参数（模板: {db_name}）"
            log("AGENT_DB", f"test_connection({agent_type}) 跳过: {err_msg}")
            self._update_conn_status(agent_type, success=False, error=err_msg)
            return False, err_msg
        try:
            conn = self.get_connection(agent_type, project_id)
        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}"
            log("AGENT_DB", f"test_connection({agent_type}) 失败: {err_msg}")
            self._update_conn_status(agent_type, success=False, error=err_msg)
            return False, err_msg

        if conn is None:
            # db_type=none（WebVulnVerify），视为成功
            msg = "无独立 DB（db_type=none），跳过连接测试"
            self._update_conn_status(agent_type, success=True, error=None)
            return True, msg

        try:
            cur = conn.cursor()
            if isinstance(conn, pymysql.connections.Connection):
                cur.execute("SELECT 1")
            else:
                # PostgreSQL
                cur.execute("SELECT 1")
            cur.close()
            conn.close()
            self._update_conn_status(agent_type, success=True, error=None)
            return True, "连接成功"
        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}"
            try:
                conn.close()
            except Exception:
                pass
            log("AGENT_DB", f"test_connection({agent_type}) 查询失败: {err_msg}")
            self._update_conn_status(agent_type, success=False, error=err_msg)
            return False, err_msg

    def update_config(self, agent_type: str, updates: dict) -> bool:
        """更新配置，递增 ``_version``。

        ``password`` 为 ``'***'`` 或空字符串时不更新密码（脱敏保护）。

        :returns: 更新是否成功
        """
        allowed_fields = {
            "host", "port", "username", "password",
            "database_name", "enabled",
        }
        # 过滤有效字段
        filtered = {k: v for k, v in updates.items() if k in allowed_fields}

        # 密码脱敏保护
        if "password" in filtered:
            pwd = filtered["password"]
            if pwd is None or pwd == "" or pwd == "***":
                del filtered["password"]
                log("AGENT_DB", f"update_config({agent_type}) 跳过密码更新（脱敏或空）")

        if not filtered:
            log("AGENT_DB", f"update_config({agent_type}) 无可更新字段")
            return True

        # 构造 SET 子句
        set_clauses = []
        params = []
        for field, value in filtered.items():
            if field == "enabled":
                set_clauses.append(f"{field} = %s")
                params.append(1 if value else 0)
            elif field == "port":
                set_clauses.append(f"{field} = %s")
                params.append(int(value))
            else:
                set_clauses.append(f"{field} = %s")
                params.append(value)

        # 递增 _version
        set_clauses.append("_version = _version + 1")
        params.append(agent_type)

        sql = (
            "UPDATE agent_datasource_config SET "
            + ", ".join(set_clauses)
            + " WHERE agent_type = %s"
        )

        try:
            conn = eval_connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                affected = cur.rowcount
                cur.close()
                if affected > 0:
                    log("AGENT_DB", f"update_config({agent_type}) 成功，已递增 _version")
                    return True
                else:
                    log("AGENT_DB", f"update_config({agent_type}) 未匹配到记录")
                    return False
            finally:
                conn.close()
        except Exception as e:
            log("AGENT_DB", f"update_config({agent_type}) 失败: {e}")
            return False

    def list_configs(self) -> list[dict]:
        """列出全部 agent 配置，password 脱敏为 ``'***'``。"""
        sql = (
            "SELECT agent_type, display_name, db_type, host, port, "
            "username, password, database_name, relation_tables, "
            "phase_identifier, enabled, last_connected_at, last_error, _version "
            "FROM agent_datasource_config ORDER BY id"
        )
        results: list[dict] = []
        try:
            conn = eval_connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute(sql)
                rows = cur.fetchall()
                columns = [
                    "agent_type", "display_name", "db_type", "host", "port",
                    "username", "password", "database_name", "relation_tables",
                    "phase_identifier", "enabled", "last_connected_at",
                    "last_error", "_version",
                ]
                for row in rows:
                    config = self._row_to_config(row, columns)
                    # 环境变量覆盖（list 也展示最终生效的配置）
                    agent_type = config.get("agent_type", "")
                    config = self._apply_env_overrides(agent_type, config)
                    # 密码脱敏
                    config["password"] = "***"
                    results.append(config)
            finally:
                conn.close()
        except Exception as e:
            log("AGENT_DB", f"list_configs 失败: {e}")
        return results

    # -----------------------------------------------------------------------
    # 内部：连接实现
    # -----------------------------------------------------------------------

    @staticmethod
    def _connect_mysql(
        agent_type: str,
        host: str | None,
        port: int | None,
        user: str | None,
        password: str | None,
        database: str | None,
    ):
        """创建 MySQL 短连接（pymysql 直连 + 重试）。

        复用 v2/infra/database.py 的短连接模式：每次创建新 TCP 连接，
        避免连接池复用 stale 连接。2006/2013 错误时指数退避重试。
        """
        last_err: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                conn = pymysql.connect(
                    host=host,
                    port=port or 3306,
                    user=user,
                    password=password,
                    database=database,
                    charset="utf8mb4",
                    autocommit=True,
                    connect_timeout=10,
                    read_timeout=600,
                    write_timeout=600,
                )
                return conn
            except pymysql.err.OperationalError as e:
                last_err = e
                code = e.args[0] if e.args else None
                if code in _RETRYABLE_MYSQL_ERRORS and attempt < _MAX_RETRIES - 1:
                    backoff = _RETRY_BACKOFF_BASE * (2 ** attempt)
                    log("AGENT_DB",
                        f"_connect_mysql({agent_type}) 断连重试 "
                        f"({attempt + 1}/{_MAX_RETRIES}): code={code}, backoff={backoff}s")
                    time.sleep(backoff)
                    continue
                raise
            except pymysql.err.InterfaceError as e:
                last_err = e
                if attempt < _MAX_RETRIES - 1:
                    backoff = _RETRY_BACKOFF_BASE * (2 ** attempt)
                    log("AGENT_DB",
                        f"_connect_mysql({agent_type}) InterfaceError 重试 "
                        f"({attempt + 1}/{_MAX_RETRIES}), backoff={backoff}s")
                    time.sleep(backoff)
                    continue
                raise
        # 重试耗尽
        raise last_err  # type: ignore[misc]

    @staticmethod
    def _connect_postgresql(
        agent_type: str,
        host: str | None,
        port: int | None,
        user: str | None,
        password: str | None,
        dbname: str | None,
    ):
        """创建 PostgreSQL 短连接（psycopg2 + 重试）。

        connect_timeout=10，OperationalError 时指数退避重试。
        """
        try:
            import psycopg2
        except ImportError:
            raise RuntimeError(
                "psycopg2 未安装。请安装: pip install psycopg2-binary"
            )

        last_err: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                conn = psycopg2.connect(
                    host=host,
                    port=port or 5432,
                    user=user,
                    password=password,
                    dbname=dbname,
                    connect_timeout=10,
                )
                # psycopg2 默认开启事务，设 autocommit 与 MySQL 一致
                conn.autocommit = True
                return conn
            except psycopg2.OperationalError as e:
                last_err = e
                if attempt < _MAX_RETRIES - 1:
                    backoff = _RETRY_BACKOFF_BASE * (2 ** attempt)
                    log("AGENT_DB",
                        f"_connect_postgresql({agent_type}) OperationalError 重试 "
                        f"({attempt + 1}/{_MAX_RETRIES}), backoff={backoff}s")
                    time.sleep(backoff)
                    continue
                raise
        raise last_err  # type: ignore[misc]

    # -----------------------------------------------------------------------
    # 内部：状态更新
    # -----------------------------------------------------------------------

    @staticmethod
    def _update_conn_status(agent_type: str, success: bool, error: str | None) -> None:
        """更新 agent_datasource_config 的连接状态。

        成功: last_connected_at = NOW(3), last_error = NULL
        失败: last_error = error, 递增 _version
        """
        if success:
            sql = (
                "UPDATE agent_datasource_config "
                "SET last_connected_at = NOW(3), last_error = NULL, "
                "_version = _version + 1 "
                "WHERE agent_type = %s"
            )
            params: tuple = (agent_type,)
        else:
            sql = (
                "UPDATE agent_datasource_config "
                "SET last_error = %s, _version = _version + 1 "
                "WHERE agent_type = %s"
            )
            err_truncated = (error or "")[:2000]  # TEXT 字段安全
            params = (err_truncated, agent_type)

        try:
            conn = eval_connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                cur.close()
            finally:
                conn.close()
        except Exception as e:
            log("AGENT_DB", f"_update_conn_status({agent_type}) 更新失败: {e}")
