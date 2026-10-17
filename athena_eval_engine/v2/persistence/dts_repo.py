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
    "dts_id", "evaluation_id", "task_id", "case_id", "vuln_title", "agent_type",
    "case_type", "cause_code", "breakpoint_level",
    "breakpoint_desc", "evidence_uri",
    "root_cause", "solution", "analysis_data_path",
    "replay_eval_id", "replay_result",
    "status", "responsibility",
)

_INSERT_SQL = (
    "INSERT INTO dts_issue ("
    "  dts_id, evaluation_id, task_id, case_id, vuln_title, agent_type,"
    "  case_type, cause_code, breakpoint_level,"
    "  breakpoint_desc, evidence_uri,"
    "  root_cause, solution, analysis_data_path,"
    "  replay_eval_id, replay_result,"
    "  status, responsibility"
    ") VALUES ("
    "  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s"
    ") ON DUPLICATE KEY UPDATE"
    "  vuln_title=VALUES(vuln_title),"
    "  root_cause=VALUES(root_cause), solution=VALUES(solution),"
    "  analysis_data_path=VALUES(analysis_data_path),"
    "  status=VALUES(status), replay_eval_id=VALUES(replay_eval_id),"
    "  replay_result=VALUES(replay_result)"
)

# 列名→查询返回索引的映射（list_dts_issues / get_dts_issue 使用）
_SELECT_COLUMNS = (
    "d.dts_id, d.evaluation_id, d.task_id, d.case_id, d.vuln_title, d.agent_type,"
    " d.case_type, d.cause_code, d.breakpoint_level,"
    " d.breakpoint_desc, d.evidence_uri,"
    " d.root_cause, d.solution, d.analysis_data_path,"
    " d.replay_eval_id, d.replay_result,"
    " d.status, d.responsibility,"
    " d.created_at, d.updated_at, d.closed_at,"
    " e.evaluation_name"
)

# JOIN evaluation 表获取评测名称
_FROM_JOIN = " dts_issue d LEFT JOIN evaluation e ON d.evaluation_id = e.evaluation_id"


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
        "dts_id", "evaluation_id", "task_id", "case_id", "vuln_title", "agent_type",
        "case_type", "cause_code", "breakpoint_level",
        "breakpoint_desc", "evidence_uri",
        "root_cause", "solution", "analysis_data_path",
        "replay_eval_id", "replay_result",
        "status", "responsibility",
        "created_at", "updated_at", "closed_at",
        "evaluation_name",
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

    返回值包含：
    - DTS issue 基本字段（dts_id、case_id、cause_code 等）
    - analysis_data：完整根因分析数据（从 analysis_data_path 指向的文件读取，
      含 session_chain、compressed_summaries、l0_l7_breakpoints、root_cause、
      fix_suggestion 等）
    - session_chains：session 调用链信息（从 session_graph 表查出，
      含每个 session 的 agent、parent_id、task_type 等，供前端展示调用树）

    Args:
        dts_id: 问题单 ID。

    Returns:
        问题单 dict 或 None（不存在时）。
    """
    def _do_query(cur):
        cur.execute(f"SELECT {_SELECT_COLUMNS} FROM{_FROM_JOIN} WHERE d.dts_id = %s", (dts_id,))
        return cur.fetchone()

    row = _db_query(_do_query)
    if row is None:
        return None
    result = _row_to_dict(row)

    # 读取完整根因分析数据文件
    analysis_data_path = result.get("analysis_data_path")
    if analysis_data_path:
        import os
        import json as _json
        reports_dir = os.environ.get("EVAL_REPORTS_DIR", "reports")
        file_path = os.path.join(reports_dir, analysis_data_path)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                result["analysis_data"] = _json.loads(f.read())
        except Exception as e:
            log("DTS_REPO", f"读取完整分析数据失败 dts_id={dts_id} path={analysis_data_path}: {str(e)[:200]}")
            result["analysis_data"] = None

    # 从 session_graph 表查 session 调用链信息
    # analysis_data 中的 mining.session_chain 和 verification.session_chain
    # 是 session_id 列表，需要从 DB 补充每个 session 的调用关系（parent_id、agent 等）
    result["session_chains"] = _query_session_chains(result)

    return result


def _query_session_chains(issue: dict) -> dict:
    """从 session_graph 表查询 issue 关联的 session 调用链信息。

    从 analysis_data 中提取 mining + verification 的 session_chain（session_id 列表），
    从 session_graph 表查出这些 session 的调用关系（parent_id、agent、task_type 等）。

    Returns:
        {
            "mining": [{"session_id":..., "agent":..., "parent_id":..., "task_type":...}, ...],
            "verification": [...],
            "parent_map": {"session_id": "parent_session_id", ...},
        }
    """
    analysis_data = issue.get("analysis_data") or {}
    evaluation_id = issue.get("evaluation_id", "")
    if not evaluation_id:
        return {"mining": [], "verification": [], "parent_map": {}}

    # 收集需要查询的 session_id
    target_ids: set[str] = set()
    for chain_type in ("mining", "verification"):
        chain_data = analysis_data.get(chain_type) or {}
        for sid in chain_data.get("session_chain") or []:
            if sid:
                target_ids.add(sid)

    if not target_ids:
        return {"mining": [], "verification": [], "parent_map": {}}

    import json as _json

    def _do_query(cur):
        cur.execute(
            "SELECT task_run_id, graph_json FROM session_graph "
            "WHERE evaluation_id = %s",
            (evaluation_id,),
        )
        return cur.fetchall()

    rows = _db_query(_do_query)

    sessions: dict[str, dict] = {}
    parent_map: dict[str, str] = {}

    for task_run_id, graph_json in rows:
        graph = _json.loads(graph_json) if isinstance(graph_json, str) else graph_json
        graph_sessions = graph.get("sessions", {}) or {}
        graph_parent_map = graph.get("parent_map", {}) or {}

        for sid in target_ids:
            if sid in graph_sessions and sid not in sessions:
                info = graph_sessions[sid]
                info_d = info if isinstance(info, dict) else {}
                sessions[sid] = {
                    "session_id": sid,
                    "agent": info_d.get("agent", ""),
                    "session_type": info_d.get("session_type", ""),
                    "task_type": info_d.get("task_type", ""),
                    "task_id": info_d.get("task_id", ""),
                    "status": info_d.get("status", ""),
                    "is_failed_task": info_d.get("is_failed_task", False),
                    "parent_id": graph_parent_map.get(sid, ""),
                    "task_run_id": task_run_id,
                }
            if sid in graph_parent_map and sid not in parent_map:
                parent_map[sid] = graph_parent_map[sid]

    # 按 mining / verification 分类返回
    def _chain_for(chain_type: str) -> list[dict]:
        chain_data = analysis_data.get(chain_type) or {}
        chain_ids = chain_data.get("session_chain") or []
        return [sessions[sid] for sid in chain_ids if sid in sessions]

    return {
        "mining": _chain_for("mining"),
        "verification": _chain_for("verification"),
        "parent_map": parent_map,
    }


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
        where_parts.append("d.evaluation_id = %s")
        params.append(evaluation_id)
    if agent_type:
        where_parts.append("d.agent_type = %s")
        params.append(agent_type)
    if status:
        where_parts.append("d.status = %s")
        params.append(status)
    if cause_code:
        where_parts.append("d.cause_code = %s")
        params.append(cause_code)
    if case_type:
        where_parts.append("d.case_type = %s")
        params.append(case_type)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    def _do_query(cur):
        # 查总数
        cur.execute(f"SELECT COUNT(*) FROM dts_issue d{where_clause}", tuple(params))
        total = cur.fetchone()[0]
        # 查当前页
        sql = (
            f"SELECT {_SELECT_COLUMNS} FROM{_FROM_JOIN}{where_clause}"
            f" ORDER BY d.created_at DESC LIMIT %s OFFSET %s"
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
    where_clause = " WHERE d.evaluation_id = %s" if evaluation_id else ""
    params = (evaluation_id,) if evaluation_id else ()

    def _do_query(cur):
        # 按 status 分组
        cur.execute(
            f"SELECT d.status, COUNT(*) FROM dts_issue d{where_clause}"
            f" GROUP BY d.status",
            params,
        )
        by_status = {row[0]: row[1] for row in cur.fetchall()}

        # 按 agent_type 分组
        cur.execute(
            f"SELECT d.agent_type, COUNT(*) FROM dts_issue d{where_clause}"
            f" GROUP BY d.agent_type",
            params,
        )
        by_agent = {row[0]: row[1] for row in cur.fetchall()}

        # 按 cause_code 分组
        cur.execute(
            f"SELECT d.cause_code, COUNT(*) FROM dts_issue d{where_clause}"
            f" GROUP BY d.cause_code",
            params,
        )
        by_cause = {row[0]: row[1] for row in cur.fetchall()}

        # 总数
        cur.execute(f"SELECT COUNT(*) FROM dts_issue d{where_clause}", params)
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
        f"SELECT {_SELECT_COLUMNS} FROM{_FROM_JOIN}"
        f" WHERE d.case_id = %s ORDER BY d.created_at ASC"
    )

    def _do_query(cur):
        cur.execute(sql, (case_id,))
        return cur.fetchall()

    rows = _db_query(_do_query)
    return [_row_to_dict(r) for r in rows]


def list_dts_by_task(task_id: str) -> list[dict]:
    """列出某个原始数据任务的全部问题单。

    同一个 case+cause_code+breakpoint_level 可能因多次评测产生多条记录，
    只返回最新评测的记录（按 created_at 降序去重）。

    Args:
        task_id: 原始数据任务 ID（manifest 中的 task_id）。

    Returns:
        问题单 dict 列表。
    """
    sql = (
        f"SELECT {_SELECT_COLUMNS} FROM{_FROM_JOIN}"
        f" WHERE d.task_id = %s"
        f" ORDER BY d.created_at DESC"
    )

    def _do_query(cur):
        cur.execute(sql, (task_id,))
        return cur.fetchall()

    rows = _db_query(_do_query)
    seen: set[tuple[str, str, str]] = set()
    result: list[dict] = []
    for r in rows:
        d = _row_to_dict(r)
        key = (d.get("case_id", ""), d.get("cause_code", ""),
               d.get("breakpoint_level", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(d)
    return result


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
        f"SELECT {_SELECT_COLUMNS} FROM{_FROM_JOIN}"
        f" WHERE d.case_id = %s AND d.status = 'closing'"
        f" ORDER BY d.created_at ASC"
    )

    def _do_query(cur):
        cur.execute(sql, (case_id,))
        return cur.fetchall()

    rows = _db_query(_do_query)
    return [_row_to_dict(r) for r in rows]
