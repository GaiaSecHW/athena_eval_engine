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
    "replay_eval_id", "replay_result", "replay_data",
    "status", "responsibility",
)

_INSERT_SQL = (
    "INSERT INTO dts_issue ("
    "  dts_id, evaluation_id, task_id, case_id, vuln_title, agent_type,"
    "  case_type, cause_code, breakpoint_level,"
    "  breakpoint_desc, evidence_uri,"
    "  root_cause, solution, analysis_data_path,"
    "  replay_eval_id, replay_result, replay_data,"
    "  status, responsibility"
    ") VALUES ("
    "  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s"
    ") ON DUPLICATE KEY UPDATE"
    "  vuln_title=VALUES(vuln_title),"
    "  root_cause=VALUES(root_cause), solution=VALUES(solution),"
    "  analysis_data_path=VALUES(analysis_data_path),"
    "  status=VALUES(status), replay_eval_id=VALUES(replay_eval_id),"
    "  replay_result=VALUES(replay_result),"
    "  replay_data=VALUES(replay_data)"
)

# 列名→查询返回索引的映射（list_dts_issues / get_dts_issue 使用）
_SELECT_COLUMNS = (
    "d.dts_id, d.evaluation_id, d.task_id, d.case_id, d.vuln_title, d.agent_type,"
    " d.case_type, d.cause_code, d.breakpoint_level,"
    " d.breakpoint_desc, d.evidence_uri,"
    " d.root_cause, d.solution, d.analysis_data_path,"
    " d.replay_eval_id, d.replay_result, d.replay_data,"
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
        "replay_eval_id", "replay_result", "replay_data",
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
    """从 session_graph 表查询 issue 关联的完整 session 调用链。

    从 analysis_data 中提取 mining + verification 的 session_chain（命中的 session_id），
    然后从 session_graph 表的 parent_map 展开完整调用链：
    - 向上：沿 parent_map 找所有祖先 session
    - 向下：找所有子孙 session（parent 指向当前 session 的）
    最终返回从根到命中 session 的完整调用链。

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

    # 收集命中的 session_id（调用链的种子节点）
    seed_ids: dict[str, set[str]] = {"mining": set(), "verification": set()}
    for chain_type in ("mining", "verification"):
        chain_data = analysis_data.get(chain_type) or {}
        for sid in chain_data.get("session_chain") or []:
            if sid:
                seed_ids[chain_type].add(sid)

    all_seeds = seed_ids["mining"] | seed_ids["verification"]
    if not all_seeds:
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

    # 合并所有 graph 的 sessions 和 parent_map
    all_sessions: dict[str, dict] = {}
    all_parent_map: dict[str, str] = {}
    all_children_map: dict[str, list[str]] = {}

    for task_run_id, graph_json in rows:
        graph = _json.loads(graph_json) if isinstance(graph_json, str) else graph_json
        graph_sessions = graph.get("sessions", {}) or {}
        graph_parent_map = graph.get("parent_map", {}) or {}

        for sid, info in graph_sessions.items():
            if sid not in all_sessions:
                info_d = info if isinstance(info, dict) else {}
                all_sessions[sid] = {
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

        for sid, pid in graph_parent_map.items():
            if sid not in all_parent_map:
                all_parent_map[sid] = pid
            if pid not in all_children_map:
                all_children_map[pid] = []
            if sid not in all_children_map[pid]:
                all_children_map[pid].append(sid)

    # 从种子节点展开完整调用链（祖先 + 子孙）
    def _expand_chain(seeds: set[str]) -> list[str]:
        """从种子 session 出发，向上找祖先、向下找子孙，返回完整调用链（根→叶子顺序）。"""
        chain_ids: set[str] = set()

        # 向上找祖先
        for sid in seeds:
            cur = sid
            while cur and cur in all_parent_map and cur not in chain_ids:
                chain_ids.add(cur)
                cur = all_parent_map[cur]
            if cur and cur not in chain_ids:
                chain_ids.add(cur)  # 根节点

        # 向下找子孙
        queue = list(seeds)
        while queue:
            sid = queue.pop(0)
            for child in all_children_map.get(sid, []):
                if child not in chain_ids:
                    chain_ids.add(child)
                    queue.append(child)

        # 按从根到叶子排序：找根节点（parent 不在链中的），BFS 往下
        roots = [sid for sid in chain_ids
                 if all_parent_map.get(sid, "") not in chain_ids]
        ordered: list[str] = []
        visited: set[str] = set()
        queue = sorted(roots)
        while queue:
            sid = queue.pop(0)
            if sid in visited:
                continue
            visited.add(sid)
            ordered.append(sid)
            children = [c for c in all_children_map.get(sid, []) if c in chain_ids]
            queue = sorted(children) + queue

        return ordered

    mining_chain_ids = _expand_chain(seed_ids["mining"])
    verify_chain_ids = _expand_chain(seed_ids["verification"])

    # 只返回链中 session 的信息
    def _sessions_for(ids: list[str]) -> list[dict]:
        return [all_sessions[sid] for sid in ids if sid in all_sessions]

    # parent_map 只包含链中的 session
    chain_all = set(mining_chain_ids) | set(verify_chain_ids)
    chain_parent_map = {sid: all_parent_map[sid]
                        for sid in chain_all if sid in all_parent_map}

    return {
        "mining": _sessions_for(mining_chain_ids),
        "verification": _sessions_for(verify_chain_ids),
        "parent_map": chain_parent_map,
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
        where_parts.append("FIND_IN_SET(%s, d.agent_type) > 0")
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
        "replay_eval_id", "replay_result", "replay_data",
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
            "by_status": {"open": N, "passed": N, "failed": N},
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


def get_post_regression_fpr(evaluation_id: str) -> dict:
    """计算回归后误报率。

    回归验证后，passed 表示误报已消除，failed 表示误报未消除。
    回归后误报率 = failed 数 / (passed + failed 数)。
    open 状态的问题单未参与回归验证，不计入分母。

    Args:
        evaluation_id: 评测 ID。

    Returns:
        {
            "post_regression_fpr": float | None,  # 0.0-1.0，无回归数据时 None
            "passed_count": int,
            "failed_count": int,
            "verified_total": int,  # passed + failed
            "open_count": int,       # 未参与回归验证
            "total": int,            # 全部问题单
        }
    """
    where_clause = " WHERE d.evaluation_id = %s"
    params = (evaluation_id,)

    def _do_query(cur):
        cur.execute(
            f"SELECT d.status, COUNT(*) FROM dts_issue d{where_clause}"
            f" GROUP BY d.status",
            params,
        )
        return cur.fetchall()

    rows = _db_query(_do_query)
    by_status = {row[0]: row[1] for row in rows} if rows else {}

    passed_count = by_status.get("passed", 0)
    failed_count = by_status.get("failed", 0)
    open_count = by_status.get("open", 0)
    total = passed_count + failed_count + open_count
    verified_total = passed_count + failed_count

    post_fpr = (failed_count / verified_total) if verified_total > 0 else None

    return {
        "post_regression_fpr": round(post_fpr, 4) if post_fpr is not None else None,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "verified_total": verified_total,
        "open_count": open_count,
        "total": total,
    }
