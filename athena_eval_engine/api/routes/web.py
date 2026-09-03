"""Web 展示路由（R6）— 静态 HTML dashboard + 评测列表。"""
from __future__ import annotations
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from ...infrastructure.database import connect

router = APIRouter()
STATIC = Path(__file__).parent.parent.parent / "static"


@router.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "dashboard.html").read_text(encoding="utf-8")


@router.get("/api/v1/evaluations")
def list_evaluations(page: int = 1, page_size: int = 20):
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM evaluation")
        total = cur.fetchone()[0]
        cur.execute("SELECT evaluation_id, evaluation_name, evaluation_status, benchmark_set_id, "
                    "created_at FROM evaluation ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (page_size, offset))
        rows = cur.fetchall()
        return {
            "evaluations": [
                {"evaluation_id": r[0], "name": r[1], "status": r[2],
                 "benchmark_set_id": r[3], "created_at": str(r[4])}
                for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }
    finally:
        conn.close()
