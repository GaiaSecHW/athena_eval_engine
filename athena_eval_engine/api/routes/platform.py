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


@router.get("/tasks/{project_id}/{task_id}/trace-check")
async def trace_check(project_id: str, task_id: str):
    """选完项目+任务后自动检查 trace 是否存在，识别工具类型。

    返回: {mining: {trace_kind, source_uri} | null,
           verify: [{trace_kind, source_uri, agent_name}, ...],
           ready: bool}
    """
    mining = await asyncio.to_thread(ps.discover_mining_trace, project_id, task_id)
    verify = await asyncio.to_thread(ps.discover_verify_traces, project_id)
    return {
        "mining": {"trace_kind": mining[0], "source_uri": mining[1]} if mining else None,
        "verify": verify,
        "ready": mining is not None,
    }
