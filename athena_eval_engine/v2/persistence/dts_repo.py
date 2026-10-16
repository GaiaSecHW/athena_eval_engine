"""问题单持久化模块。

DB CRUD 操作，短连接 + 重试模式（与 kad_repo 同模式）。
表：dts_issue（由 migration 010 创建）。
"""
from __future__ import annotations

import time

import pymysql

from ..infra.database import connect
from ...infrastructure.log_util import log, log_to_file

# ── 字段顺序（与 INSERT SQL 列顺序一致）──

_FIELD_ORDER = (
    "dts_id", "evaluation_id", "task_id", "case_id", "vuln_type", "agent_type",
    "case_type", "cause_code", "breakpoint_level",
    "breakpoint_desc", "evidence_uri",
    "root_cause", "solution", "replay_eval_id", "replay_result",
    "status", "responsibility",
)

_INSERT_SQL = (
    "INSERT INTO dts_issue ("
    "  dts_id, evaluation_id, task_id, case_id, vuln_type, agent_type,"
    "  case_type, cause_code, breakpoint_level,"
    "  breakpoint_desc, evidence_uri,"
    "  root_cause, solution, replay_eval_id, replay_result,"
    "  status, responsibility"
    ") VALUES ("
    "  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s"
    ") ON DUPLICATE KEY UPDATE"
    "  vuln_type=VALUES(vuln_type),"
    "  root_cause=VALUES(root_cause), solution=VALUES(solution),"
    "  status=VALUES(status), replay_eval_id=VALUES(replay_eval_id),"
    "  replay_result=VALUES(replay_result)"
)

# 列名→查询返回索引的映射（list_dts_issues / get_dts_issue 使用）
_SELECT_COLUMNS = (
    "dts_id, evaluation_id, task_id, case_id, vuln_type, agent_type,"
    " case_type, cause_code, breakpoint_level,"
    " breakpoint_desc, evidence_uri,"
    " root_cause, solution, replay_eval_id, replay_result,"
    " status, responsibility,"
    " created_at, updated_at, closed_at"
)


# ---------------------------------------------------------------------------
# DB 连接重试（与 kad_repo._db_query 同模式）
# ---------------------------------------------------------------------------

def _db_query(fn, _retries: int = 8):
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
                log("DTS_REPO", f"DB retry {attempt+1}/{_retries}: {e.args[0]}, retry in {_wait}s...")
                log_to_file("DTS_REPO", f"DB retry {attempt+1}/{_retries}: {e.args[0]} {e}, retry in {_wait}s...")
                time.sleep(_wait)
                continue
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# 行解析辅助
# ---------------------------------------------------------------------------

def _row_to_dict(row) -> dict:
    """将 SELECT 行转换为 dict。"""
    keys = (
        "dts_id", "evaluation_id", "task_id", "case_id", "vuln_type", "agent_type",
        "case_type", "cause_code", "breakpoint_level",
        "breakpoint_desc", "evidence_uri",
        "root_cause", "solution", "replay_eval_id", "replay_result",
        "status", "responsibility",
        "created_at", "updated_at", "closed_at",
    )
    return {k: row[i] for i, k in enumerate(keys)}


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------

def upsert_dts_issues(issues: list[dict], evaluation_id: str,
                      reports_dir: str) -> int:
    """批量写入问题单（幂等：ON DUPLICATE KEY UPDATE）。

    Args:
        issues: 问题单 dict 列表，每条含 dts_id、evaluation_id 等。
        evaluation_id: 评测 ID（仅用于日志）。
        reports_dir: 报告目录（保留参数，当前无大字段需写文件）。

    Returns:
        写入的记录条数。
    """
    if not issues:
        return 0

    def _do_insert(cur):
        args = [tuple(iss.get(k) for k in _FIELD_ORDER) for iss in issues]
        cur.executemany(_INSERT_SQL, args)
        return len(args)

    count = _db_query(_do_insert)
    log("DTS_REPO", f"upsert_dts_issues: wrote {count} issues for eval={evaluation_id}")
    return count


def get_dts_issue(dts_id: str) -> dict | None:
    """获取单个问题单详情。

    Args:
        dts_id: 问题单 ID。

    Returns:
        问题单 dict 或 None（不存在时）。
    """
    def _do_query(cur):
        cur.execute(f"SELECT {_SELECT_COLUMNS} FROM dts_issue WHERE dts_id = %s", (dts_id,))
        return cur.fetchone()

    row = _db_query(_do_query)
    if row is None:
        return None
    return _row_to_dict(row)


def list_dts_issues(
    evaluation_id: str | None = None,
    agent_type: str | None = None,
    status: str | None = None,
    cause_code: str | None = None,
    case_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """列出问题单（支持过滤 + 分页）。

    Returns:
        (问题单 dict 列表, 匹配总数)
    """
    where_parts: list[str] = []
    params: list = []

    if evaluation_id:
        where_parts.append("evaluation_id = %s")
        params.append(evaluation_id)
    if agent_type:
        where_parts.append("agent_type = %s")
        params.append(agent_type)
    if status:
        where_parts.append("status = %s")
        params.append(status)
    if cause_code:
        where_parts.append("cause_code = %s")
        params.append(cause_code)
    if case_type:
        where_parts.append("case_type = %s")
        params.append(case_type)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    def _do_query(cur):
        # 查总数
        cur.execute(f"SELECT COUNT(*) FROM dts_issue{where_clause}", tuple(params))
        total = cur.fetchone()[0]
        # 查当前页
        sql = (
            f"SELECT {_SELECT_COLUMNS} FROM dts_issue{where_clause}"
            f" ORDER BY created_at DESC LIMIT %s OFFSET %s"
        )
        cur.execute(sql, tuple(params + [limit, offset]))
        rows = cur.fetchall()
        return rows, total

    rows, total = _db_query(_do_query)
    return [_row_to_dict(r) for r in rows], total


def update_dts_issue(dts_id: str, updates: dict) -> bool:
    """更新问题单（root_cause / solution / status 等）。

    Args:
        dts_id: 问题单 ID。
        updates: 待更新字段 dict，支持 root_cause、solution、status、
                 replay_eval_id、replay_result。

    Returns:
        True 表示更新成功，False 表示记录不存在或无更新字段。
    """
    allowed = {
        "root_cause", "solution", "status",
        "replay_eval_id", "replay_result",
    }
    update_fields = {k: v for k, v in updates.items() if k in allowed}
    if not update_fields:
        return False

    set_parts = [f"{k} = %s" for k in update_fields]
    params = list(update_fields.values())
    params.append(dts_id)

    sql = f"UPDATE dts_issue SET {', '.join(set_parts)} WHERE dts_id = %s"

    def _do_update(cur):
        cur.execute(sql, tuple(params))
        return cur.rowcount

    rowcount = _db_query(_do_update)
    log("DTS_REPO", f"update_dts_issue: dts_id={dts_id}, updated={rowcount}")
    return rowcount > 0


def get_dts_stats(evaluation_id: str | None = None) -> dict:
    """聚合统计问题单（按 status 和 agent_type 分组）。

    Args:
        evaluation_id: 评测 ID 过滤（None 表示全部）。

    Returns:
        {
            "by_status": {"unlocated": N, "improving": N, ...},
            "by_agent_type": {"turing": N, "argo": N, ...},
            "by_cause_code": {"A": N, "B": N, ...},
            "total": N,
        }
    """
    where_clause = " WHERE evaluation_id = %s" if evaluation_id else ""
    params = (evaluation_id,) if evaluation_id else ()

    def _do_query(cur):
        # 按 status 分组
        cur.execute(
            f"SELECT status, COUNT(*) FROM dts_issue{where_clause}"
            f" GROUP BY status",
            params,
        )
        by_status = {row[0]: row[1] for row in cur.fetchall()}

        # 按 agent_type 分组
        cur.execute(
            f"SELECT agent_type, COUNT(*) FROM dts_issue{where_clause}"
            f" GROUP BY agent_type",
            params,
        )
        by_agent = {row[0]: row[1] for row in cur.fetchall()}

        # 按 cause_code 分组
        cur.execute(
            f"SELECT cause_code, COUNT(*) FROM dts_issue{where_clause}"
            f" GROUP BY cause_code",
            params,
        )
        by_cause = {row[0]: row[1] for row in cur.fetchall()}

        # 总数
        cur.execute(f"SELECT COUNT(*) FROM dts_issue{where_clause}", params)
        total = cur.fetchone()[0]

        return {
            "by_status": by_status,
            "by_agent_type": by_agent,
            "by_cause_code": by_cause,
            "total": total,
        }

    return _db_query(_do_query)


def list_dts_by_case(case_id: str) -> list[dict]:
    """列出某个 case 的全部问题单。

    Args:
        case_id: case ID。

    Returns:
        问题单 dict 列表。
    """
    sql = (
        f"SELECT {_SELECT_COLUMNS} FROM dts_issue"
        f" WHERE case_id = %s ORDER BY created_at ASC"
    )

    def _do_query(cur):
        cur.execute(sql, (case_id,))
        return cur.fetchall()

    rows = _db_query(_do_query)
    return [_row_to_dict(r) for r in rows]


def list_dts_by_task(task_id: str) -> list[dict]:
    """列出某个原始数据任务的全部问题单。

    Args:
        task_id: 原始数据任务 ID（manifest 中的 task_id）。

    Returns:
        问题单 dict 列表。
    """
    sql = (
        f"SELECT {_SELECT_COLUMNS} FROM dts_issue"
        f" WHERE task_id = %s ORDER BY created_at ASC"
    )

    def _do_query(cur):
        cur.execute(sql, (task_id,))
        return cur.fetchall()

    rows = _db_query(_do_query)
    return [_row_to_dict(r) for r in rows]


def get_closing_issues_by_case(case_id: str) -> list[dict]:
    """列出某个 case 中处于 'closing' 状态的问题单。

    用于回归验证触发检查：当 case 的所有问题单都进入 closing 状态时，
    触发回归测试。

    Args:
        case_id: case ID。

    Returns:
        closing 状态的问题单 dict 列表。
    """
    sql = (
        f"SELECT {_SELECT_COLUMNS} FROM dts_issue"
        f" WHERE case_id = %s AND status = 'closing'"
        f" ORDER BY created_at ASC"
    )

    def _do_query(cur):
        cur.execute(sql, (case_id,))
        return cur.fetchall()

    rows = _db_query(_do_query)
    return [_row_to_dict(r) for r in rows]
