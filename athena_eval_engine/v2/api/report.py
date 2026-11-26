"""项目/任务误报率查询接口。

独立工具：选项目+任务 → 从漏洞中心拉取人工确认 case → 计算误报率。

误报率口径（与看板一致）：FP / (TP + FP)
- TP = 人工确认 vulnerable 的 case 数
- FP = 人工确认 not_vulnerable 的 case 数
- 误报率 = not_vulnerable / (vulnerable + not_vulnerable)
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...application import platform_service as ps
from ...config_loader import DATA_ROOT
from ..infra import vuln_center_client as vc
from ..infra.log_util import log
from ..infra.db_utils import db_query as _db_query

router = APIRouter(prefix="/api/v2/report", tags=["report"])


def _dir_has_files(path: str) -> bool:
    """目录（含子目录）下是否至少有一个文件。"""
    for _, _, files in os.walk(path):
        if files:
            return True
    return False


def _source_exists(project_id: str, task_id: str,
                   source_paths: list[str] | None = None) -> bool | None:
    """源码目录是否存在且有文件；DATA_ROOT 不可用时返回 None（未知）。

    源码目录以平台任务 inputs 为准（code/software 的 target_path），
    兼容旧版 user_input/software/<task_id> 上传布局。
    """
    if not project_id or not task_id:
        return None
    root = os.path.abspath(DATA_ROOT)
    if not os.path.isdir(root):
        return None
    checked = source_paths
    if checked is None:
        try:
            checked = ps.get_task_source_paths(project_id, task_id)
        except Exception:
            checked = []
    for p in checked:
        d = p if os.path.isabs(p) else os.path.join(
            root, str(project_id), p.lstrip("/"))
        if os.path.isdir(d) and _dir_has_files(d):
            return True
    legacy_dir = os.path.join(root, str(project_id),
                              "user_input", "software", str(task_id))
    if os.path.isdir(legacy_dir):
        return _dir_has_files(legacy_dir)
    return False


@router.get("/summary")
def summary(project_id: str | None = None, task_id: str | None = None,
            keyword: str | None = None,
            project_keyword: str | None = None,
            task_keyword: str | None = None,
            agent: str | None = None,
            vuln_nonzero: bool = False,
            finished_from: str | None = None,
            finished_to: str | None = None,
            sort_by: str = "created_at", sort_dir: str = "desc",
            page: int = 1, page_size: int = 20, alive: bool = True):
    """从数据库读取项目/任务漏洞统计汇总（定时采集写入）。

    支持按项目/任务/关键词过滤 + 分页（全部 SQL 层 WHERE + LIMIT）：
    - project_id: 按项目 ID 精确过滤
    - task_id: 按任务 ID 精确过滤
    - keyword: 按项目名/任务名模糊搜索（单框合并搜索）
    - project_keyword / task_keyword: 项目名、任务名分开模糊搜索
      （前端两个输入框各自传参，不再共用一个 keyword 互相覆盖）
    - vuln_nonzero: 只列出漏洞总数 > 0 的记录
    - finished_from / finished_to: 任务结束时间范围
      （YYYY-MM-DD 扩成全天边界；KPI 聚合同过滤口径）
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
                 task_started_at, task_finished_at, project_last_finished_at,
                 source_exists,
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
        # 过滤后全量 KPI 聚合（项目数/任务数/漏洞总数/确认漏洞/确认非误报/确认误报）
        # 任务数只统计 task_id 非空行——无任务项目补的 0 行（task_id=''）不算任务
        kpi_sql = (
            "SELECT COUNT(DISTINCT project_id), "
            "COUNT(CASE WHEN task_id != '' THEN 1 END), "
            "COALESCE(SUM(vuln_total),0), "
            "COALESCE(SUM(confirmed_vulnerable),0), "
            "COALESCE(SUM(confirmed_not_vulnerable),0), "
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
            "confirmed_not_vulnerable": kpi_row[4],
            "confirmed_fp": kpi_row[5],
        }
        # 总数（不含无任务项目补的 0 行）
        count_sql = "SELECT COUNT(*) FROM project_task_summary WHERE task_id != ''"
        if where:
            count_sql += " AND " + " AND ".join(where)
        cur.execute(count_sql, tuple(params))
        total = cur.fetchone()[0]
        # 分页数据
        sql = (
            "SELECT s.project_id, s.task_id, s.project_name, s.department_name, "
            "s.task_name, s.project_owner, "
            "s.task_type, s.agent_type, s.task_created_at, s.task_updated_at, "
            "s.task_started_at, s.task_finished_at, "
            "s.vuln_total, s.unconfirmed_count, s.confirmed_vulnerable, "
            "s.confirmed_not_vulnerable, s.confirmed_fp, s.analyzing_count, "
            "s.confirm_rate, "
            "(SELECT MAX(p2.task_finished_at) FROM project_task_summary p2 "
            " WHERE p2.project_id = s.project_id AND p2.task_id != '' "
            " AND p2.task_finished_at != '') AS project_last_finished_at "
            "FROM project_task_summary s WHERE s.task_id != ''"
        )
        if where:
            sql += " AND " + " AND ".join(where)
        # 排序：fpr=误报率 FP/(TP+FP)（SQL 表达式）、任务时间列（创建/更新/开始/结束）
        order_dir = "DESC" if sort_dir == "desc" else "ASC"
        if sort_by == "fpr":
            sql += (" ORDER BY (CASE WHEN (confirmed_vulnerable + confirmed_fp) > 0 "
                    "THEN confirmed_fp / (confirmed_vulnerable + confirmed_fp) ELSE NULL END) "
                    + order_dir + ", project_name, task_name")
        elif sort_by == "confirm_rate":
            # confirm_rate 是 project_task_summary 的生成列。
            # 分母为 0 的行为 NULL，无论升降序都排在有值行之后；
            # 次级排序键跟随主方向，保证升降序是同一批数据的严格镜像。
            sql += (f" ORDER BY (confirm_rate IS NULL) ASC, confirm_rate {order_dir}"
                    f", project_name {order_dir}, task_name {order_dir}")
        elif sort_by in ("created_at", "updated_at", "started_at",
                         "finished_at"):
            sql += f" ORDER BY task_{sort_by} {order_dir}, project_name, task_name"
        else:
            sql += " ORDER BY project_name, task_name"
        sql += " LIMIT %s OFFSET %s"
        cur.execute(sql, tuple(params) + (page_size, (page - 1) * page_size))
        cols = ["project_id", "task_id", "project_name", "department_name",
                "task_name", "project_owner",
                "task_type", "agent_type", "task_created_at", "task_updated_at",
                "task_started_at", "task_finished_at",
                "vuln_total", "unconfirmed_count", "confirmed_vulnerable",
                "confirmed_not_vulnerable", "confirmed_fp", "analyzing_count",
                "confirm_rate", "project_last_finished_at"]
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
    if project_keyword:
        where.append("project_name LIKE %s")
        params.append(f"%{project_keyword}%")
    if task_keyword:
        where.append("task_name LIKE %s")
        params.append(f"%{task_keyword}%")
    if agent:
        where.append("agent_type = %s")
        params.append(agent)
    # 漏洞总数>0：只列出有漏洞的记录（无任务项目补的 0 行、0 漏洞任务排除）
    if vuln_nonzero:
        where.append("vuln_total > 0")

    def _norm_day(value: str | None, end: bool = False) -> str:
        """结束时间过滤值：日期（YYYY-MM-DD）扩成全天边界，含时刻则原样。"""
        v = str(value or "").strip()
        if not v:
            return ""
        if len(v) == 10:
            return f"{v} 23:59:59" if end else f"{v} 00:00:00"
        return v

    fin_from = _norm_day(finished_from)
    fin_to = _norm_day(finished_to, end=True)
    if fin_from:
        where.append("task_finished_at >= %s")
        params.append(fin_from)
    if fin_to:
        where.append("task_finished_at <= %s")
        params.append(fin_to)

    try:
        updated_at, total, rows, kpi = _db_query(_do)
    except Exception as e:
        log("REPORT", f"读汇总失败: {e}")
        return {"updated_at": None, "total": 0, "page": page,
                "page_size": page_size, "items": [], "all_agents": [],
                "kpi": {"project_count": 0, "task_count": 0, "vuln_total": 0,
                        "confirmed_vulnerable": 0, "confirmed_not_vulnerable": 0,
                        "confirmed_fp": 0}}

    # 关联评测：task_id → 最新评测（从 evaluation.task_id 直接反查，
    # 一个任务可能有多个评测取最新）
    eval_map: dict[str, dict] = {}
    try:
        def _do_eval(cur):
            cur.execute(
                "SELECT task_id, evaluation_id, evaluation_status, created_at "
                "FROM evaluation "
                "WHERE task_id != '' "
                "AND evaluation_status != 'CANCELLED'"
            )
            return cur.fetchall()
        eval_rows = _db_query(_do_eval)
    except Exception:
        eval_rows = []

    for tid, eid, status, created_at in eval_rows:
        cur = eval_map.get(tid)
        # created_at 是 datetime，map 里存的是 str，统一转成字符串再比较
        created_str = str(created_at) if created_at else ""
        if cur is None or created_str > (cur.get("created_at") or ""):
            eval_map[tid] = {
                "evaluation_id": eid,
                "evaluation_status": status,
                "created_at": created_str,
            }

    # 未评测但曾启动失败的任务：create() 在写 evaluation 行之前失败（如未发现
    # trace）时评测表没有记录，页面只能显示「未评测」，操作者会反复启动。
    # 失败信息单独记录在 evaluation_start_failure，按 (project, task) 挂到行上。
    start_failures: dict[tuple[str, str], dict] = {}
    try:
        _pids = sorted({r.get("project_id") for r in rows if r.get("project_id")})
        if _pids:
            _ph = ",".join(["%s"] * len(_pids))

            def _do_fail(cur):
                cur.execute(
                    "SELECT project_id, task_id, attempt_count, "
                    "last_evaluation_id, last_error, last_failed_at "
                    f"FROM evaluation_start_failure WHERE project_id IN ({_ph})",
                    tuple(_pids))
                return cur.fetchall()

            for pid, tid, cnt, eid, err, at in _db_query(_do_fail):
                start_failures[(pid, tid)] = {
                    "attempt_count": cnt,
                    "evaluation_id": eid or "",
                    "last_error": err or "",
                    "last_failed_at": str(at) if at else "",
                }
    except Exception as e:
        log("REPORT", f"读启动失败信息失败: {e}")

    # 标注变化检测：任务最新已完成评测落库的基线标注计数 vs 当前计数。
    # 不一致 → 评测完成后人工又改了标注，建议重新发起测评（新评测、新基线）。
    baseline_map: dict[str, dict] = {}
    try:
        _tids = sorted({str(r.get("task_id") or "") for r in rows
                        if r.get("task_id")})
        if _tids:
            _ph = ",".join(["%s"] * len(_tids))

            def _do_baseline(cur):
                cur.execute(
                    "SELECT s.task_id, s.baseline_vuln_total, "
                    "s.baseline_confirmed_vulnerable, "
                    "s.baseline_confirmed_fp, "
                    "s.baseline_confirmed_not_vulnerable, e.created_at "
                    f"FROM evaluation_summary s JOIN evaluation e "
                    f"ON e.evaluation_id = s.evaluation_id "
                    f"WHERE s.task_id != '' AND s.task_id IN ({_ph}) "
                    f"AND e.evaluation_status IN "
                    f"('COMPLETED','COMPLETED_WITH_WARNINGS') "
                    f"ORDER BY e.created_at",
                    tuple(_tids))
                return cur.fetchall()

            for (tid, b_total, b_vuln, b_fp, b_nonvuln, _created
                 ) in _db_query(_do_baseline):
                # 基线计数全 NULL（评测时任务未同步到）→ 未知，不参与判定
                if None in (b_total, b_vuln, b_fp, b_nonvuln):
                    continue
                # ORDER BY created_at 升序 → 后写覆盖 = 取最新已完成评测
                baseline_map[str(tid)] = {
                    "vuln_total": b_total,
                    "confirmed_vulnerable": b_vuln,
                    "confirmed_fp": b_fp,
                    "confirmed_not_vulnerable": b_nonvuln,
                }
    except Exception as e:
        log("REPORT", f"读评测基线标注失败: {e}")

    # 任务是否已从平台删除（与评测列表/漏洞中心同一口径：schedule batch-alive）
    # alive=False 时跳过（逐项目网络调用很慢），由前端异步补全 task_deleted。
    alive_by_proj: dict[str, set[str]] = {}
    if alive:
        by_proj: dict[str, set[str]] = {}
        for r in rows:
            _pid, _tid = r.get("project_id"), r.get("task_id")
            if _pid and _tid:
                by_proj.setdefault(_pid, set()).add(_tid)
        if by_proj:
            from concurrent.futures import ThreadPoolExecutor

            def _check_alive(item):
                _pid, _tids = item
                try:
                    return _pid, ps.filter_alive_tasks(
                        _pid, sorted(_tids), timeout=2.0, retries=1)
                except Exception as e:
                    log("REPORT", f"任务存活校验失败 project={_pid}: {e}")
                    return _pid, set(_tids)

            with ThreadPoolExecutor(max_workers=min(8, len(by_proj))) as pool:
                for _pid, _alive in pool.map(_check_alive, list(by_proj.items())):
                    alive_by_proj[_pid] = _alive

    # 源码存在性：平台任务 inputs 是权威来源（code/software 目录）。
    # 当前页任务并行拉详情；失败时 _source_exists 回退旧 upload 路径。
    source_paths_map: dict[tuple[str, str], list[str]] = {}
    _pairs = [(r.get("project_id") or "", r.get("task_id") or "")
              for r in rows]
    _pairs = [(p, t) for p, t in _pairs if p and t]
    if _pairs:
        from concurrent.futures import ThreadPoolExecutor

        def _fetch_source_paths(pair):
            try:
                return pair, ps.get_task_source_paths(pair[0], pair[1])
            except Exception:
                return pair, []

        with ThreadPoolExecutor(max_workers=min(8, len(_pairs))) as pool:
            for pair, paths in pool.map(_fetch_source_paths, _pairs):
                source_paths_map[pair] = paths

    # 给每行补评测关联 + 误报率（运行态只有误报率，无漏报）
    for r in rows:
        _pid, _tid = r.get("project_id"), r.get("task_id")
        r["task_deleted"] = bool(
            _pid and _tid and _tid not in alive_by_proj.get(_pid, set()))
        ev = eval_map.get(r.get("task_id", "")) or {}
        r["evaluation_id"] = ev.get("evaluation_id", "")
        r["evaluation_status"] = ev.get("evaluation_status", "")
        # 只对「未评测」行返回启动失败信息；已有评测记录的行以评测状态为准
        r["start_failure"] = (
            None if r["evaluation_status"]
            else start_failures.get((_pid, _tid)))
        # 误报率 = FP/(TP+FP)
        tp = r.get("confirmed_vulnerable") or 0
        fp = r.get("confirmed_fp") or 0
        fpr = (fp / (tp + fp)) if (tp + fp) > 0 else None
        r["fpr"] = round(fpr, 4) if fpr is not None else None
        # 人工确认率 = 人工已确认（漏洞+非漏洞+误报）/ 漏洞总数：
        # 由 project_task_summary 的 confirm_rate 生成列直接提供；
        # Decimal 转 float 便于 JSON 输出。
        if r.get("confirm_rate") is not None:
            r["confirm_rate"] = float(r["confirm_rate"])
        r["source_exists"] = _source_exists(
            _pid, _tid, source_paths_map.get((_pid, _tid)))
        # 标注变化：任一计数与基线不一致即视为变化；无基线（老评测/
        # 未同步到）= None（未知），不算变化
        base = baseline_map.get(str(_tid or ""))
        if not base:
            r["annotation_changed"] = None
        else:
            r["annotation_changed"] = any(
                int(cur or 0) != int(base.get(key) or 0)
                for cur, key in (
                    (r.get("vuln_total"), "vuln_total"),
                    (r.get("confirmed_vulnerable"), "confirmed_vulnerable"),
                    (r.get("confirmed_fp"), "confirmed_fp"),
                    (r.get("confirmed_not_vulnerable"),
                     "confirmed_not_vulnerable"),
                ))

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


@router.get("/alive")
def alive(pairs: str = ""):
    """批量校验 (project_id:task_id) 是否仍在平台存在。

    供列表页在渲染后异步补全 task_deleted，避免阻塞主列表请求。
    pairs 格式：`pid1:tid1,pid2:tid2`。
    """
    parsed: list[tuple[str, str]] = []
    for p in (pairs or "").split(","):
        p = p.strip()
        if ":" not in p:
            continue
        pid, tid = p.split(":", 1)
        if pid and tid:
            parsed.append((pid, tid))
    if not parsed:
        return {"deleted": {}}

    by_proj: dict[str, set[str]] = {}
    for pid, tid in parsed:
        by_proj.setdefault(pid, set()).add(tid)
    alive_by_proj: dict[str, set[str]] = {}

    from concurrent.futures import ThreadPoolExecutor

    def _check(item):
        pid, tids = item
        try:
            return pid, ps.filter_alive_tasks(
                pid, sorted(tids), timeout=2.0, retries=1)
        except Exception as e:
            log("REPORT", f"任务存活校验失败 project={pid}: {e}")
            return pid, set(tids)

    with ThreadPoolExecutor(max_workers=min(8, len(by_proj))) as pool:
        for pid, alive_ids in pool.map(_check, list(by_proj.items())):
            alive_by_proj[pid] = alive_ids

    return {
        "deleted": {
            f"{pid}:{tid}": tid not in alive_by_proj.get(pid, set())
            for pid, tid in parsed
        }
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
            log("REPORT", f"后台采集失败: {e}")

    t = threading.Thread(target=_run, name="report-manual-sync", daemon=True)
    t.start()
    return {"status": "started", "message": "采集已启动（后台执行）"}


@router.get("/projects")
def projects():
    """项目列表（供误报率查询页选择）。"""
    try:
        return {"projects": ps.get_projects()}
    except Exception as e:
        log("REPORT", f"拉项目列表失败: {e}")
        raise HTTPException(500, f"拉项目列表失败: {e}")


@router.get("/tasks")
def tasks(project_id: str | None = None):
    """任务列表（供误报率查询页选择）。"""
    try:
        return {"tasks": ps.get_tasks(project_id)}
    except Exception as e:
        log("REPORT", f"拉任务列表失败: {e}")
        raise HTTPException(500, f"拉任务列表失败: {e}")


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
        log("REPORT", f"拉漏洞中心 case 失败: {e}")
        raise HTTPException(500, f"拉漏洞中心 case 失败: {e}")

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


# ── 自动创建测评（system 页「自动化」tab）──


class AutoEvalUpdate(BaseModel):
    """自动创建测评配置：开关 + 确认率阈值 + 误报率阈值 + 结束窗口（可选更新）。"""
    enabled: bool | None = None
    min_confirm_rate: float | None = None
    min_fpr: float | None = None
    max_finished_days: int | None = None


@router.get("/auto-eval")
def get_auto_eval():
    """自动创建测评状态：配置 + 上次运行结果。"""
    from ..sync.auto_eval import get_config, get_last_run
    cfg = get_config()
    return {**cfg, "last_run": get_last_run()}


@router.put("/auto-eval")
def set_auto_eval(update: AutoEvalUpdate):
    """更新自动创建测评配置（只更新传入项，立即生效）。"""
    from ..sync.auto_eval import set_config
    if update.min_confirm_rate is not None and not (
            0.0 <= update.min_confirm_rate <= 1.0):
        raise HTTPException(status_code=400,
                            detail="min_confirm_rate 须在 0-1 之间")
    if update.min_fpr is not None and not (
            0.0 <= update.min_fpr <= 1.0):
        raise HTTPException(status_code=400,
                            detail="min_fpr 须在 0-1 之间")
    if update.max_finished_days is not None and not (
            1 <= update.max_finished_days <= 365):
        raise HTTPException(status_code=400,
                            detail="max_finished_days 须在 1-365 之间")
    cfg = set_config(enabled=update.enabled,
                     min_confirm_rate=update.min_confirm_rate,
                     min_fpr=update.min_fpr,
                     max_finished_days=update.max_finished_days)
    return {"status": "ok", **cfg}


@router.post("/auto-eval/run")
def run_auto_eval():
    """手动触发一次自动创建（异步；不受开关限制，结果看「上次运行」）。"""
    from ..sync.auto_eval import trigger_async
    result = trigger_async()
    if result.get("status") == "running":
        raise HTTPException(status_code=409, detail="自动创建正在运行")
    return result
