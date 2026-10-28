"""项目/任务误报率查询接口。

独立工具：选项目+任务 → 从漏洞中心拉取人工确认 case → 计算误报率。

误报率口径（与看板一致）：FP / (TP + FP)
- TP = 人工确认 vulnerable 的 case 数
- FP = 人工确认 not_vulnerable 的 case 数
- 误报率 = not_vulnerable / (vulnerable + not_vulnerable)
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ...application import platform_service as ps
from ...infrastructure import vuln_center_client as vc
from ...infrastructure.log_util import log
from ..persistence.dts_repo import _db_query

router = APIRouter(prefix="/api/v2/report", tags=["report"])


@router.get("/summary")
def summary(project_id: str | None = None, task_id: str | None = None,
            keyword: str | None = None, agent: str | None = None,
            sort_by: str = "fpr", sort_dir: str = "desc",
            page: int = 1, page_size: int = 20):
    """从数据库读取项目/任务漏洞统计汇总（定时采集写入）。

    支持按项目/任务/关键词过滤 + 分页：
    - project_id: 按项目 ID 精确过滤
    - task_id: 按任务 ID 精确过滤
    - keyword: 按项目名/任务名模糊搜索
    - page: 页码（默认 1）
    - page_size: 每页条数（默认 20，上限 200）

    返回:
        {
            "updated_at": str | None,   # 最近采集时间
            "total": int,               # 过滤后总条数
            "page": int, "page_size": int,
            "items": [
                {project_id, task_id, project_name, task_name, project_owner,
                 task_type, agent_type, task_created_at, task_updated_at,
                 task_started_at, task_finished_at,
                 vuln_total, unconfirmed_count, confirmed_vulnerable,
                 confirmed_not_vulnerable, confirmed_fp}, ...
            ]
        }
    """
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    where = []
    params: list = []

    def _do(cur):
        cur.execute("SELECT MAX(updated_at) FROM project_task_summary")
        row = cur.fetchone()
        updated_at = row[0]
        # 过滤后全量 KPI 聚合（项目数/任务数/漏洞总数/确认漏洞/确认误报）
        kpi_sql = (
            "SELECT COUNT(DISTINCT project_id), COUNT(*), "
            "COALESCE(SUM(vuln_total),0), "
            "COALESCE(SUM(confirmed_vulnerable),0), "
            "COALESCE(SUM(confirmed_fp),0) "
            "FROM project_task_summary"
        )
        if where:
            kpi_sql += " WHERE " + " AND ".join(where)
        cur.execute(kpi_sql, tuple(params))
        kpi_row = cur.fetchone()
        kpi = {
            "project_count": kpi_row[0],
            "task_count": kpi_row[1],
            "vuln_total": kpi_row[2],
            "confirmed_vulnerable": kpi_row[3],
            "confirmed_fp": kpi_row[4],
        }
        # 总数
        count_sql = "SELECT COUNT(*) FROM project_task_summary"
        if where:
            count_sql += " WHERE " + " AND ".join(where)
        cur.execute(count_sql, tuple(params))
        total = cur.fetchone()[0]
        # 分页数据
        sql = (
            "SELECT project_id, task_id, project_name, task_name, project_owner, "
            "task_type, agent_type, task_created_at, task_updated_at, "
            "task_started_at, task_finished_at, "
            "vuln_total, unconfirmed_count, confirmed_vulnerable, "
            "confirmed_not_vulnerable, confirmed_fp, analyzing_count "
            "FROM project_task_summary"
        )
        if where:
            sql += " WHERE " + " AND ".join(where)
        # 排序：fpr=误报率 FP/(TP+FP)（SQL 表达式），默认降序
        order_dir = "DESC" if sort_dir == "desc" else "ASC"
        if sort_by == "fpr":
            sql += (" ORDER BY (CASE WHEN (confirmed_vulnerable + confirmed_fp) > 0 "
                    "THEN confirmed_fp / (confirmed_vulnerable + confirmed_fp) ELSE NULL END) "
                    + order_dir + ", project_name, task_name")
        else:
            sql += " ORDER BY project_name, task_name"
        sql += " LIMIT %s OFFSET %s"
        cur.execute(sql, tuple(params) + (page_size, (page - 1) * page_size))
        cols = ["project_id", "task_id", "project_name", "task_name", "project_owner",
                "task_type", "agent_type", "task_created_at", "task_updated_at",
                "task_started_at", "task_finished_at",
                "vuln_total", "unconfirmed_count", "confirmed_vulnerable",
                "confirmed_not_vulnerable", "confirmed_fp", "analyzing_count"]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return updated_at, total, rows, kpi

    if project_id:
        where.append("project_id = %s")
        params.append(project_id)
    if task_id:
        where.append("task_id = %s")
        params.append(task_id)
    if keyword:
        kw = f"%{keyword}%"
        where.append("(project_name LIKE %s OR task_name LIKE %s)")
        params.extend([kw, kw])
    if agent:
        where.append("agent_type = %s")
        params.append(agent)

    try:
        updated_at, total, rows, kpi = _db_query(_do)
    except Exception as e:
        log("REPORT", f"读汇总失败: {str(e)[:200]}")
        return {"updated_at": None, "total": 0, "page": page,
                "page_size": page_size, "items": [], "all_agents": [],
                "kpi": {"project_count": 0, "task_count": 0, "vuln_total": 0,
                        "confirmed_vulnerable": 0, "confirmed_fp": 0}}

    # 关联评测：task_id → 最新评测（从 evaluation.task_id 直接反查，
    # 一个任务可能有多个评测取最新）
    eval_map: dict[str, dict] = {}
    try:
        def _do_eval(cur):
            cur.execute(
                "SELECT task_id, evaluation_id, evaluation_status, created_at "
                "FROM evaluation "
                "WHERE task_id != '' "
                "AND evaluation_status NOT IN "
                "('CREATED','QUEUED','CANCELLED')"
            )
            return cur.fetchall()
        eval_rows = _db_query(_do_eval)
    except Exception:
        eval_rows = []

    for tid, eid, status, created_at in eval_rows:
        cur = eval_map.get(tid)
        if cur is None or (created_at or "") > (cur.get("created_at") or ""):
            eval_map[tid] = {
                "evaluation_id": eid,
                "evaluation_status": status,
                "created_at": str(created_at) if created_at else "",
            }

    # 给每行补评测关联 + 误报率（运行态只有误报率，无漏报）
    for r in rows:
        ev = eval_map.get(r.get("task_id", "")) or {}
        r["evaluation_id"] = ev.get("evaluation_id", "")
        r["evaluation_status"] = ev.get("evaluation_status", "")
        # 误报率 = FP/(TP+FP)
        tp = r.get("confirmed_vulnerable") or 0
        fp = r.get("confirmed_fp") or 0
        fpr = (fp / (tp + fp)) if (tp + fp) > 0 else None
        r["fpr"] = round(fpr, 4) if fpr is not None else None

    # 全量 agent 列表（供前端筛选下拉）
    all_agents: list[str] = []
    try:
        def _do_agents(cur):
            cur.execute("SELECT DISTINCT agent_type FROM project_task_summary "
                        "WHERE agent_type != '' ORDER BY agent_type")
            return [r[0] for r in cur.fetchall()]
        all_agents = _db_query(_do_agents)
    except Exception:
        pass

    return {
        "updated_at": str(updated_at) if updated_at else None,
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": rows,
        "all_agents": all_agents,
        "kpi": kpi,
    }


@router.post("/sync")
def sync_now():
    """手动触发一次采集（全量项目/任务/漏洞统计 → 写库）。

    采集在后台线程执行（同步阻塞会卡住 HTTP 请求——425 项目 × 大量任务
    × 多次网络调用，可能耗时数分钟）。接口立即返回"采集中"。
    """
    import threading
    from ..sync.project_task_sync import sync_all, is_sync_running

    if is_sync_running():
        return {"status": "running", "message": "采集已在进行中"}

    def _run():
        try:
            sync_all()
        except Exception as e:
            log("REPORT", f"后台采集失败: {str(e)[:300]}")

    t = threading.Thread(target=_run, name="report-manual-sync", daemon=True)
    t.start()
    return {"status": "started", "message": "采集已启动（后台执行）"}


@router.get("/projects")
def projects():
    """项目列表（供误报率查询页选择）。"""
    try:
        return {"projects": ps.get_projects()}
    except Exception as e:
        log("REPORT", f"拉项目列表失败: {str(e)[:200]}")
        raise HTTPException(500, f"拉项目列表失败: {str(e)[:200]}")


@router.get("/tasks")
def tasks(project_id: str | None = None):
    """任务列表（供误报率查询页选择）。"""
    try:
        return {"tasks": ps.get_tasks(project_id)}
    except Exception as e:
        log("REPORT", f"拉任务列表失败: {str(e)[:200]}")
        raise HTTPException(500, f"拉任务列表失败: {str(e)[:200]}")


@router.get("/fpr/{project_id}/{task_id}")
def fpr(project_id: str, task_id: str):
    """计算指定项目+任务的人工确认误报率。

    从漏洞中心拉取该任务的人工确认 case（vulnerable / not_vulnerable），
    按口径 FP/(TP+FP) 计算：
    - TP = 确认 vulnerable 数
    - FP = 确认 not_vulnerable 数
    - 误报率 = FP / (TP + FP)
    - 漏报率 = FN / (TP + FN)，FN 取确认 vulnerable 但未参与确认的补充（无 trace 关联时 FN=0）

    返回：
        {
            "project_id", "task_id",
            "vulnerable_count", "not_vulnerable_count",
            "total", "fpr", "fnr",
            "cases": [...],   # 明细（可选截断）
        }
    """
    try:
        vuln_cases = vc.list_vuln_cases(
            project_id, source_task_id=task_id,
            confirmation_status="vulnerable",
        )
        nonvuln_cases = vc.list_vuln_cases(
            project_id, source_task_id=task_id,
            confirmation_status="not_vulnerable",
        )
    except Exception as e:
        log("REPORT", f"拉漏洞中心 case 失败: {str(e)[:200]}")
        raise HTTPException(500, f"拉漏洞中心 case 失败: {str(e)[:200]}")

    # TP = 人工确认漏洞（human_confirmation.result=vulnerable，API 已按 confirmation_status 过滤）
    tp = len(vuln_cases)
    # FP = 人工确认非漏洞，排除 false_positive_group=non_fp（非误报，不参与分析）
    fp_cases = [c for c in nonvuln_cases
                if c.get("false_positive_group") != "non_fp"]
    fp = len(fp_cases)
    total = tp + fp

    fpr = (fp / (tp + fp)) if (tp + fp) > 0 else None
    # 无 trace 关联，FN 无法判定，漏报率不计算（None）
    fnr = None

    # 明细（控制数量，避免大 payload；展示实际的人工确认状态）
    detail = []
    for c in (vuln_cases + fp_cases):
        hc = c.get("human_confirmation") or {}
        detail.append({
            "case_id": c.get("id") or c.get("case_id") or "",
            "title": c.get("title") or "",
            "confirmation_status": hc.get("result") or "",
            "false_positive_group": c.get("false_positive_group") or "",
            "human_confirmation_summary": hc.get("summary") or "",
        })

    return {
        "project_id": project_id,
        "task_id": task_id,
        "vulnerable_count": tp,
        "not_vulnerable_count": fp,
        "total": total,
        "excluded_non_fp": len(nonvuln_cases) - len(fp_cases),
        "fpr": round(fpr, 4) if fpr is not None else None,
        "fnr": fnr,
        "cases": detail,
    }
