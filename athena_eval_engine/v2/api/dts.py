"""DTS 问题单 API 端点。

端点：
- GET    /api/v2/dts                  — 列出问题单（支持过滤）
- GET    /api/v2/dts/{dts_id}         — 获取单个问题单详情
- PUT    /api/v2/dts/{dts_id}         — 更新问题单（root_cause/solution/status）
- POST   /api/v2/dts/{dts_id}/close   — 关闭问题单（status→closing）
- POST   /api/v2/dts/{dts_id}/reject  — 驳回问题单（status→not_issue）
- GET    /api/v2/dts/stats             — 获取统计
- GET    /api/v2/dts/by-task/{task_id} — 按 task 列出问题单
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..persistence.dts_repo import (
    get_dts_issue,
    list_dts_issues,
    update_dts_issue,
    get_dts_stats,
    list_dts_by_task,
)

router = APIRouter(prefix="/api/v2/dts", tags=["dts"])


# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------

class DTSUpdate(BaseModel):
    """问题单更新模型。"""
    root_cause: str | None = None
    solution: str | None = None
    status: str | None = None
    replay_eval_id: str | None = None
    replay_result: str | None = None


class DTSReject(BaseModel):
    """驳回请求体。"""
    reason: str


# ---------------------------------------------------------------------------
# 端点
# ---------------------------------------------------------------------------

@router.get("")
def list_issues(
    evaluation_id: str | None = None,
    agent_type: str | None = None,
    status: str | None = None,
    cause_code: str | None = None,
    case_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    """列出 DTS 问题单（支持过滤、分页）。"""
    issues = list_dts_issues(
        evaluation_id=evaluation_id,
        agent_type=agent_type,
        status=status,
        cause_code=cause_code,
        case_type=case_type,
        limit=limit,
        offset=offset,
    )
    return {"issues": issues, "count": len(issues)}


@router.get("/stats")
def get_stats(evaluation_id: str | None = None):
    """获取 DTS 问题单统计。"""
    stats = get_dts_stats(evaluation_id)
    return stats


@router.get("/by-task/{task_id}")
def list_by_task(task_id: str):
    """按 task 列出 DTS 问题单。"""
    issues = list_dts_by_task(task_id)
    return {"issues": issues, "count": len(issues)}


@router.get("/{dts_id}")
def get_issue(dts_id: str):
    """获取单个 DTS 问题单详情。"""
    issue = get_dts_issue(dts_id)
    if issue is None:
        raise HTTPException(status_code=404, detail=f"DTS issue '{dts_id}' not found")
    return issue


@router.put("/{dts_id}")
def update_issue(dts_id: str, update: DTSUpdate):
    """更新 DTS 问题单（root_cause / solution / status 等）。"""
    existing = get_dts_issue(dts_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"DTS issue '{dts_id}' not found")

    updates = update.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    success = update_dts_issue(dts_id, updates)
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to update DTS issue '{dts_id}'")

    return get_dts_issue(dts_id)


@router.post("/{dts_id}/close")
def close_issue(dts_id: str):
    """关闭问题单（status→closing，设置 closed_at）。"""
    existing = get_dts_issue(dts_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"DTS issue '{dts_id}' not found")

    if existing["status"] in ("passed", "failed", "not_issue"):
        raise HTTPException(
            status_code=400,
            detail=f"DTS issue '{dts_id}' already in final state: {existing['status']}",
        )

    success = update_dts_issue(dts_id, {
        "status": "closing",
    })
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to close DTS issue '{dts_id}'")

    return {"dts_id": dts_id, "status": "closing"}


@router.post("/{dts_id}/reject")
def reject_issue(dts_id: str, body: DTSReject):
    """驳回问题单（status→not_issue，需要理由）。"""
    existing = get_dts_issue(dts_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"DTS issue '{dts_id}' not found")

    success = update_dts_issue(dts_id, {
        "status": "not_issue",
        "root_cause": f"[驳回] {body.reason}",
    })
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to reject DTS issue '{dts_id}'")

    return {"dts_id": dts_id, "status": "not_issue", "reason": body.reason}
