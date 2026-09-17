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


@router.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "dashboard.html").read_text(encoding="utf-8")


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
            kg_proj = kg_task = nogk_proj = nogk_task = ""
            bm_source = ""
            vb_proj_name = ""
            vc_proj_name = vc_task_name = ""
            if r[5]:
                try:
                    cfg = json.loads(r[5])
                    manifest = cfg.get("manifest", {})
                    bm_source = manifest.get("benchmark_source", "vbench_zip")
                    vb_proj_name = manifest.get("vbench_project_name") or ""
                    vc_proj_name = manifest.get("vc_source_project_name") or ""
                    vc_task_name = manifest.get("vc_source_task_name") or ""
                    for e in manifest.get("entries", []):
                        if e.get("condition") == "KG" and not kg_proj:
                            kg_proj = e.get("project_name") or e.get("project_id") or ""
                            kg_task = e.get("task_name") or e.get("task_id_actual") or ""
                        elif e.get("condition") == "NOGK" and not nogk_proj:
                            nogk_proj = e.get("project_name") or e.get("project_id") or ""
                            nogk_task = e.get("task_name") or e.get("task_id_actual") or ""
                except (json.JSONDecodeError, TypeError):
                    pass
            evals.append({"evaluation_id": r[0], "name": r[1], "status": r[2],
                          "benchmark_set_id": r[3],
                          "created_at": r[4].isoformat() if r[4] else "",
                          "kg_project": kg_proj, "kg_task": kg_task,
                          "nogk_project": nogk_proj, "nogk_task": nogk_task,
                          "benchmark_source": bm_source,
                          "vbench_project_name": vb_proj_name,
                          "vc_project_name": vc_proj_name,
                          "vc_task_name": vc_task_name,
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
