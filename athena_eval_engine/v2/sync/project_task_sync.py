"""项目/任务漏洞统计定时采集。

每天 6:00 / 12:00 / 17:00 触发：
1. 拉全量项目（platform API）
2. 每个项目拉全量任务（platform API）
3. 每个任务拉漏洞中心 case，统计：
   - vuln_total = 该任务全部 case 数
   - unconfirmed_count = 人工未确认数（human_confirmation 为空）
   - confirmed_vulnerable = 人工确认漏洞数
   - confirmed_not_vulnerable = 人工确认非漏洞数
   - confirmed_fp = 确认误报数（not_vulnerable 且 false_positive_group=confirmed_fp）
4. 写库：project_task_summary（任务级汇总）+ vuln_case_snapshot（case 明细）
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone, timedelta

from ...infrastructure.log_util import log
from ...application import platform_service as ps
from ...infrastructure import vuln_center_client as vc

# 每日触发时间（本地时区 HH:MM）
_SYNC_TIMES = ("06:00", "12:00", "17:00")
# 调度检查间隔（秒）
_SCHEDULE_CHECK_SECONDS = 60
# 拉取并发
_FETCH_WORKERS = 8

# 上次同步时间戳（内存态，进程内防重复触发）
_last_sync_ts: float = 0.0
_lock = threading.Lock()
# 采集运行状态（后台手动触发时置 True，防并发重复采集）
_sync_running = False


def is_sync_running() -> bool:
    """当前是否有采集在运行（防并发重复触发）。"""
    global _sync_running
    return _sync_running

# task_type → agent 映射（平台工具类型 → 评测 agent 名）
TASK_TYPE_TO_AGENT = {
    # 挖掘 agent
    "ai4web_fast": "turing",
    "ai4web_deep": "turing",
    "ai4app_fast": "turing",
    "ai4app_deep": "turing",
    "turing": "turing",
    "argo": "argo",
    "argo_full_c": "argo",
    "armo_full_c": "argo",
    "cairn_blackboard": "argo",
    "secmate": "secmate",
    "secmate_scan": "secmate",
    "dataflow": "dataflow",
    "dataflow_vuln_scan": "dataflow",
    # 验证 agent
    "cvuln_verify": "cvuln_verify",
    "webvuln_verify": "webvuln_verify",
    # 其他工具
    "ai4red": "红线扫描",
    "sec-design-review": "设计评审",
    "entry_analyse": "入口分析",
    "poc_gen": "POC生成",
    "aiforapkprivacyaudit": "APK隐私审计",
}


def _task_type_to_agent(task_type: str) -> str:
    """task_type 字符串 → agent 名。未知返回原值。"""
    if not task_type:
        return "unknown"
    tt = str(task_type).strip().lower()
    return TASK_TYPE_TO_AGENT.get(tt, tt)


def _is_sync_hour(now_local: datetime) -> bool:
    """判断当前时间是否落在触发时刻（±90 秒窗口，避免重复）。"""
    hm = now_local.strftime("%H:%M")
    return hm in _SYNC_TIMES


def _now_local() -> datetime:
    return datetime.now(timezone(timedelta(hours=8)))


def sync_all() -> dict:
    """全量采集：项目 → 任务 → 各任务漏洞统计 → 写库。

    Returns:
        {"projects": N, "tasks": N, "cases": N, "updated_at": str}
    """
    from ..persistence.dts_repo import _db_query
    from concurrent.futures import ThreadPoolExecutor

    t0 = time.time()
    global _sync_running
    if _sync_running:
        log("SYNC", "采集已在运行，跳过本次触发")
        return {"status": "running"}
    _sync_running = True

    def _write(rows_summary: list[dict]) -> int:
        """写库：先清空旧汇总（全量重建），再插入汇总。case 明细表已停用。"""
        def _do(cur):
            cur.execute("DELETE FROM project_task_summary")
            for r in rows_summary:
                cur.execute(
                    "INSERT INTO project_task_summary "
                    "(project_id, task_id, project_name, task_name, project_owner, "
                    " task_type, agent_type, task_created_at, task_updated_at, "
                    " task_started_at, task_finished_at,"
                    " vuln_total, unconfirmed_count, confirmed_vulnerable, "
                    " confirmed_not_vulnerable, confirmed_fp, "
                    " updated_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(3))",
                    (r["project_id"], r["task_id"], r["project_name"], r["task_name"],
                     r["project_owner"], r.get("task_type", ""), r.get("agent_type", ""),
                     r.get("task_created_at", ""), r.get("task_updated_at", ""),
                     r.get("task_started_at", ""), r.get("task_finished_at", ""),
                     r["vuln_total"], r["unconfirmed_count"],
                     r["confirmed_vulnerable"], r["confirmed_not_vulnerable"],
                     r["confirmed_fp"]),
                )
            # case 明细表停用：不拉全量 case，不再写入 vuln_case_snapshot
        return _db_query(_do)

    # 1. 项目列表
    projects = ps.get_projects()
    log("SYNC", f"拉取项目: {len(projects)} 个")

    # 2. 每个项目拉任务（并发 + 进度日志）
    tasks_all: list[dict] = []
    proj_name_map = {p["id"]: p["name"] for p in projects}
    proj_owner_map = {p["id"]: p.get("owner_name") or "" for p in projects}
    total_proj = len(projects)

    def _fetch_proj_tasks(p: dict) -> list[dict]:
        try:
            tasks = ps.get_tasks(p["id"])
            return [{"project_id": p["id"], **t} for t in tasks]
        except Exception as e:
            log("SYNC", f"项目 {p['id']} 拉任务失败: {str(e)[:200]}")
            return []

    with ThreadPoolExecutor(max_workers=_FETCH_WORKERS) as pool:
        for i, pt in enumerate(pool.map(_fetch_proj_tasks, projects), 1):
            tasks_all.extend(pt)
            if i % 50 == 0 or i == total_proj:
                log("SYNC", f"项目进度: {i}/{total_proj} 个项目, "
                            f"已获取 {len(tasks_all)} 个任务, "
                            f"耗时 {time.time()-t0:.0f}s")

    log("SYNC", f"拉取任务: {len(tasks_all)} 个")

    # 3. 每个任务拉漏洞中心汇总统计（list-stats，不拉全量 case）
    def _fetch_task(item: dict) -> dict | None:
        pid, tid = item["project_id"], item.get("id") or ""
        if not pid or not tid:
            return None
        try:
            stats = vc.list_stats(pid, source_task_id=tid)
            vuln_stats = vc.list_stats(pid, source_task_id=tid,
                                       confirmation_status="vulnerable")
            fp_stats = vc.list_stats(pid, source_task_id=tid,
                                     false_positive_group="confirmed_fp")
            nonfp_stats = vc.list_stats(pid, source_task_id=tid,
                                        false_positive_group="non_fp")
        except Exception as e:
            log("SYNC", f"任务 {tid} 拉统计失败: {str(e)[:200]}")
            return None

        # 字段映射（口径与漏洞中心一致，每任务 4 次查询）：
        # - vuln_total = 全部漏洞（list-stats 无过滤 total）
        # - confirmed_vulnerable = 是漏洞（confirmation_status=vulnerable 的 confirmed）
        # - confirmed_not_vulnerable = 确认非误报（false_positive_group=non_fp 的 ruled_out）
        # - confirmed_fp = 误报（false_positive_group=confirmed_fp 的 total），
        #     用于计算误报率 FP/(TP+FP)
        # - 未确认 = vuln_total - confirmed_vulnerable - confirmed_fp
        #     - confirmed_not_vulnerable（前端计算，含 analyzing）
        vuln_total = stats.get("total") or 0
        confirmed_vuln = vuln_stats.get("confirmed") or 0
        confirmed_nonvuln = nonfp_stats.get("ruled_out") or 0
        confirmed_fp = fp_stats.get("total") or 0
        unconfirmed = stats.get("inconclusive") or 0

        task_type = item.get("task_type") or ""
        return {
            "summary": {
                "project_id": pid,
                "task_id": tid,
                "project_name": proj_name_map.get(pid, ""),
                "task_name": item.get("name") or "",
                "project_owner": proj_owner_map.get(pid, ""),
                "task_type": task_type,
                "agent_type": _task_type_to_agent(task_type),
                "task_created_at": item.get("created_at") or "",
                "task_updated_at": item.get("updated_at") or "",
                "task_started_at": item.get("started_at") or "",
                "task_finished_at": item.get("finished_at") or "",
                "vuln_total": vuln_total,
                "unconfirmed_count": unconfirmed,
                "confirmed_vulnerable": confirmed_vuln,
                "confirmed_not_vulnerable": confirmed_nonvuln,
                "confirmed_fp": confirmed_fp,
            },
            "cases": [],
        }

    # 3b. 任务统计（带进度日志——425 项目×多任务×多次网络调用很慢，
    #     无日志会让用户误以为卡死）
    summaries: list[dict] = []
    total_tasks = len(tasks_all)
    with ThreadPoolExecutor(max_workers=_FETCH_WORKERS) as pool:
        for i, r in enumerate(pool.map(_fetch_task, tasks_all), 1):
            if r:
                summaries.append(r["summary"])
            if i % 50 == 0 or i == total_tasks:
                log("SYNC", f"统计进度: {i}/{total_tasks} 个任务 "
                            f"({i/total_tasks*100:.0f}%), 已耗时 {time.time()-t0:.0f}s")

    # 3c. 无任务项目补 0 行——保证项目数=平台全量（无任务项目不产生 summary）
    covered_proj = {s["project_id"] for s in summaries}
    for p in projects:
        pid = p["id"]
        if pid not in covered_proj:
            summaries.append({
                "project_id": pid,
                "task_id": "",
                "project_name": p.get("name") or "",
                "task_name": "",
                "project_owner": p.get("owner_name") or "",
                "task_type": "",
                "agent_type": "",
                "task_created_at": "",
                "task_updated_at": "",
                "task_started_at": "",
                "task_finished_at": "",
                "vuln_total": 0,
                "unconfirmed_count": 0,
                "confirmed_vulnerable": 0,
                "confirmed_not_vulnerable": 0,
                "confirmed_fp": 0,
            })

    # 4. 写库
    _write(summaries)

    elapsed = time.time() - t0
    _sync_running = False  # global 已在函数开头（99 行）声明
    log("SYNC", f"采集完成: 项目={len(projects)}, 任务={len(summaries)}, "
                f"耗时={elapsed:.1f}s")
    return {
        "projects": len(projects),
        "tasks": len(summaries),
        "cases": 0,
        "updated_at": _now_local().strftime("%Y-%m-%d %H:%M:%S"),
    }


def schedule_loop(stop_event: threading.Event | None = None) -> None:
    """定时调度循环：每天 6:00/12:00/17:00 触发 sync_all。

    后台线程运行。每 60 秒检查一次时间；命中触发时刻且该时刻未同步过
    （进程内 _last_sync_ts 防重复）则执行采集。
    """
    global _last_sync_ts
    log("SYNC", f"定时采集线程启动，计划时间: {_SYNC_TIMES}")
    while True:
        if stop_event is not None and stop_event.is_set():
            log("SYNC", "定时采集线程停止")
            return
        now = _now_local()
        if _is_sync_hour(now) and (now.timestamp() - _last_sync_ts) > 3600:
            with _lock:
                if (now.timestamp() - _last_sync_ts) > 3600:
                    _last_sync_ts = now.timestamp()
                    log("SYNC", f"到达计划时间 {now.strftime('%H:%M')}，触发采集")
                    try:
                        sync_all()
                    except Exception as e:
                        log("SYNC", f"定时采集失败: {str(e)[:300]}")
        time.sleep(_SCHEDULE_CHECK_SECONDS)
