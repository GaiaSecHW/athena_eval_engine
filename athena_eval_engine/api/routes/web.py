"""Web 展示路由（R6）— 静态 HTML dashboard + 评测列表。"""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from ...infrastructure.database import connect
from ...v2.infra.progress import get_progress
from ...config_loader import get_static_override_dir

router = APIRouter()
STATIC = Path(__file__).parent.parent.parent / "static"

# 可覆盖的静态文件目录（k8s 下 /data/static 可写，便于热更新 HTML 而无需重建镜像）
STATIC_OVERRIDE_DIR = Path(get_static_override_dir())


def _read_page(name: str) -> str:
    """读取静态页面（优先覆盖目录，回退打包目录）。"""
    override = STATIC_OVERRIDE_DIR / name
    if override.is_file():
        return override.read_text(encoding="utf-8")
    return (STATIC / name).read_text(encoding="utf-8")


@router.get("/", response_class=HTMLResponse)
def index():
    return _read_page("index.html")


@router.get("/evals", response_class=HTMLResponse)
def evals_page():
    """评测列表页。"""
    return _read_page("evals.html")


@router.get("/evals/{evaluation_id}", response_class=HTMLResponse)
def eval_detail_page(evaluation_id: str):
    """评测详情页。"""
    return _read_page("eval-detail.html")


@router.get("/dts", response_class=HTMLResponse)
def dts_page():
    """问题单列表页。"""
    return _read_page("dts.html")


@router.get("/dts/{dts_id}", response_class=HTMLResponse)
def dts_detail_page(dts_id: str):
    """问题单详情页。"""
    return _read_page("dts-detail.html")


@router.get("/create", response_class=HTMLResponse)
def create_page():
    """新建评测页。"""
    return _read_page("create.html")


@router.get("/system", response_class=HTMLResponse)
def system_page():
    """系统设置页。"""
    return _read_page("system.html")


@router.get("/report", response_class=HTMLResponse)
def report_page():
    """平台任务详情页（误报率查询独立页面：选项目/任务 → 漏洞中心人工确认 → 误报率）。"""
    return _read_page("report.html")


def _list_evaluations_sync(page: int, page_size: int, offset: int,
                           alive: bool = True) -> dict:
    """同步逻辑：查 DB + 解析 config_json + 组装响应。

    alive=False 时跳过平台任务存活校验（逐项目网络调用），列表立即返回，
    由前端另行请求 /api/v1/eval-alive-status 异步补全 task_deleted。
    """
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM evaluation")
        total = cur.fetchone()[0]
        cur.execute("SELECT e.evaluation_id, e.evaluation_name, e.evaluation_status, "
                    "e.benchmark_set_id, e.created_at, s.config_json "
                    "FROM evaluation e "
                    "LEFT JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
                    "ORDER BY e.created_at DESC LIMIT %s OFFSET %s",
                    (page_size, offset))
        rows = cur.fetchall()
        evals = []
        task_pairs: list[tuple[str, str]] = []
        for r in rows:
            kg_proj = kg_task = ""
            kg_proj_id = kg_task_id = ""
            kg_proj_name = kg_task_name = ""
            bm_source = ""
            eval_mode = "dev"
            vbench_project_name = ""
            vc_source_project_name = ""
            vc_source_task_name = ""
            if r[5]:
                try:
                    cfg = json.loads(r[5])
                    manifest = cfg.get("manifest", {})
                    bm_source = manifest.get("benchmark_source", "vbench_zip")
                    eval_mode = manifest.get("eval_mode", "dev")
                    vbench_project_name = manifest.get("vbench_project_name", "")
                    vc_source_project_name = manifest.get("vc_source_project_name", "")
                    vc_source_task_name = manifest.get("vc_source_task_name", "")
                    for e in manifest.get("entries", []):
                        if e.get("condition") == "KG" and not kg_proj:
                            kg_proj = e.get("project_id") or ""
                            kg_task = e.get("task_id_actual") or ""
                            kg_proj_name = e.get("project_name") or kg_proj
                            kg_task_name = e.get("task_name") or kg_task
                    kg_proj_id = manifest.get("kg_project_id") or kg_proj
                    kg_task_id = manifest.get("kg_task_id") or kg_task
                except (json.JSONDecodeError, TypeError):
                    pass
            task_pairs.append((kg_proj_id, kg_task_id))
            evals.append({"evaluation_id": r[0], "name": r[1], "status": r[2],
                          "benchmark_set_id": r[3],
                          "created_at": r[4].isoformat() if r[4] else "",
                          "kg_project": kg_proj_name, "kg_task": kg_task_name,
                          "benchmark_source": bm_source,
                          "eval_mode": eval_mode,
                          "vbench_project_name": vbench_project_name,
                          "vc_source_project_name": vc_source_project_name,
                          "vc_source_task_name": vc_source_task_name,
                          "progress": get_progress(r[0]) if r[2] not in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED") else ""})

        if alive:
            # 标记任务已从平台删除（与漏洞中心隐藏 case 同一口径：schedule batch-alive）。
            # 校验失败时不误标，保持 task_deleted=False。
            from ...application.platform_service import filter_alive_tasks
            from ...infrastructure.log_util import log as _log
            by_proj: dict[str, set[str]] = {}
            for pid, tid in task_pairs:
                if pid and tid:
                    by_proj.setdefault(pid, set()).add(tid)
            alive_by_proj: dict[str, set[str]] = {}
            if by_proj:
                from concurrent.futures import ThreadPoolExecutor

                def _check_alive(item):
                    pid, tids = item
                    try:
                        return pid, filter_alive_tasks(
                            pid, sorted(tids), timeout=2.0, retries=1)
                    except Exception as e:
                        _log("EVALS", f"任务存活校验失败 project={pid}: {e}")
                        return pid, set(tids)

                with ThreadPoolExecutor(max_workers=min(8, len(by_proj))) as pool:
                    for pid, alive_ids in pool.map(_check_alive, list(by_proj.items())):
                        alive_by_proj[pid] = alive_ids
            for ev, (pid, tid) in zip(evals, task_pairs):
                ev["task_deleted"] = bool(
                    pid and tid and tid not in alive_by_proj.get(pid, set()))
        else:
            for ev in evals:
                ev["task_deleted"] = False

        # 标注变化：该评测落库的基线标注计数（FINALIZE 时写入
        # evaluation_summary）vs 当前 project_task_summary 计数。
        # 不一致 → 评测完成后人工又改了标注，报告已过期
        # （重新测评入口在平台任务详情页）。
        try:
            _eids = [ev["evaluation_id"] for ev in evals]
            _tids = sorted({tid for _, tid in task_pairs if tid})
            # 基线计数（vuln_total, confirmed_vulnerable, confirmed_fp,
            # confirmed_not_vulnerable）——NULL 任一为空 = 未知，不参与判定
            baseline_by_eid: dict[str, tuple] = {}
            current_by_tid: dict[str, tuple] = {}
            if _eids:
                _ph_e = ",".join(["%s"] * len(_eids))
                cur.execute(
                    "SELECT evaluation_id, baseline_vuln_total, "
                    "baseline_confirmed_vulnerable, "
                    "baseline_confirmed_fp, "
                    "baseline_confirmed_not_vulnerable "
                    f"FROM evaluation_summary "
                    f"WHERE evaluation_id IN ({_ph_e})",
                    tuple(_eids))
                for eid, b1, b2, b3, b4 in cur.fetchall():
                    if None not in (b1, b2, b3, b4):
                        baseline_by_eid[eid] = (
                            int(b1), int(b2), int(b3), int(b4))
            if _tids:
                _ph_t = ",".join(["%s"] * len(_tids))
                cur.execute(
                    "SELECT task_id, vuln_total, confirmed_vulnerable, "
                    "confirmed_fp, confirmed_not_vulnerable "
                    f"FROM project_task_summary WHERE task_id IN ({_ph_t})",
                    tuple(_tids))
                for tid, c1, c2, c3, c4 in cur.fetchall():
                    current_by_tid[tid] = (
                        int(c1 or 0), int(c2 or 0),
                        int(c3 or 0), int(c4 or 0))
            for ev, (_pid, tid) in zip(evals, task_pairs):
                base = baseline_by_eid.get(ev["evaluation_id"])
                cur_counts = current_by_tid.get(tid)
                ev["annotation_changed"] = bool(
                    base is not None and cur_counts is not None
                    and base != cur_counts)
        except Exception:
            for ev in evals:
                ev.setdefault("annotation_changed", False)

        return {
            "evaluations": evals,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }
    finally:
        conn.close()


@router.get("/api/v1/evaluations")
async def list_evaluations(page: int = 1, page_size: int = 20, alive: bool = True):
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size
    return await asyncio.to_thread(
        _list_evaluations_sync, page, page_size, offset, alive)


def _eval_alive_status_sync(eids: list[str]) -> dict[str, bool]:
    """批量校验评测对应平台任务是否已删除，返回 {evaluation_id: deleted}。"""
    if not eids:
        return {}
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        placeholders = ",".join(["%s"] * len(eids))
        cur.execute(
            "SELECT e.evaluation_id, s.config_json FROM evaluation e "
            "LEFT JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
            f"WHERE e.evaluation_id IN ({placeholders})",
            tuple(eids),
        )
        pairs: list[tuple[str, str, str]] = []
        for eid, cfg in cur.fetchall():
            pid = tid = ""
            if cfg:
                try:
                    manifest = (json.loads(cfg) or {}).get("manifest", {})
                    pid = manifest.get("kg_project_id") or ""
                    tid = manifest.get("kg_task_id") or ""
                except (json.JSONDecodeError, TypeError):
                    pass
            pairs.append((eid, pid, tid))
    finally:
        conn.close()

    from ...application.platform_service import filter_alive_tasks
    from ...infrastructure.log_util import log as _log
    by_proj: dict[str, set[str]] = {}
    for _, pid, tid in pairs:
        if pid and tid:
            by_proj.setdefault(pid, set()).add(tid)
    alive_by_proj: dict[str, set[str]] = {}
    if by_proj:
        from concurrent.futures import ThreadPoolExecutor

        def _check_alive(item):
            pid, tids = item
            try:
                return pid, filter_alive_tasks(
                    pid, sorted(tids), timeout=2.0, retries=1)
            except Exception as e:
                _log("EVALS", f"任务存活校验失败 project={pid}: {e}")
                return pid, set(tids)

        with ThreadPoolExecutor(max_workers=min(8, len(by_proj))) as pool:
            for pid, alive_ids in pool.map(_check_alive, list(by_proj.items())):
                alive_by_proj[pid] = alive_ids

    return {
        eid: bool(pid and tid and tid not in alive_by_proj.get(pid, set()))
        for eid, pid, tid in pairs
    }


@router.get("/api/v1/eval-alive-status")
async def eval_alive_status(eids: str = ""):
    """按评测 ID 批量返回 task_deleted（列表页异步补全置灰状态用）。"""
    ids = [e.strip() for e in (eids or "").split(",") if e.strip()]
    deleted = await asyncio.to_thread(_eval_alive_status_sync, ids)
    return {"deleted": deleted}
