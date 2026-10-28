"""Web 展示路由（R6）— 静态 HTML dashboard + 评测列表。"""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from ...infrastructure.database import connect
from ...application.evaluation_service import get_progress

router = APIRouter()
STATIC = Path(__file__).parent.parent.parent / "static"

# 可覆盖的静态文件目录（k8s 下 /data/static 可写，便于热更新 HTML 而无需重建镜像）
# 与 v2/api/routes.py 的 debug.html 热更新机制共用同一环境变量
import os as _os
STATIC_OVERRIDE_DIR = Path(_os.environ.get("EVAL_STATIC_OVERRIDE", "/data/static"))


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


def _list_evaluations_sync(page: int, page_size: int, offset: int) -> dict:
    """同步逻辑：查 DB + 解析 config_json + 组装响应。"""
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
        for r in rows:
            kg_proj = kg_task = ""
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
                except (json.JSONDecodeError, TypeError):
                    pass
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
async def list_evaluations(page: int = 1, page_size: int = 20):
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size
    return await asyncio.to_thread(_list_evaluations_sync, page, page_size, offset)
