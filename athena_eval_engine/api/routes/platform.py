"""平台数据路由 — 项目/任务/trace 发现（新建评测向导用）。"""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, HTTPException
from ...application import platform_service as ps

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


@router.get("/projects")
def projects():
    try:
        return {"projects": ps.get_projects()}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/tasks")
def tasks(project_id: str | None = None):
    try:
        return {"tasks": ps.get_tasks(project_id)}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/tasks/{project_id}/{task_id}/traces")
async def traces(project_id: str, task_id: str):
    traces = await asyncio.to_thread(ps.find_traces, project_id, task_id)
    return {"traces": traces}
