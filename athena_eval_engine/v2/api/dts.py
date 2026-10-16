"""问题单 API 端点。

端点：
- GET    /api/v2/dts                        — 列出问题单（支持过滤）
- GET    /api/v2/dts/{dts_id}               — 获取单个问题单详情
- PUT    /api/v2/dts/{dts_id}               — 更新问题单（root_cause/solution/status）
- POST   /api/v2/dts/{dts_id}/close         — 关闭问题单（status→closing）
- POST   /api/v2/dts/{dts_id}/reject        — 驳回问题单（status→not_issue）
- GET    /api/v2/dts/stats                   — 获取统计
- GET    /api/v2/dts/by-case/{case_id}       — 按 case 列出问题单
- GET    /api/v2/dts/by-task/{task_id}       — 按原始数据任务 ID 列出问题单
- POST   /api/v2/dts/regression-verify      — 回归验证：判断误报是否消除
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..persistence.dts_repo import (
    get_dts_issue,
    list_dts_issues,
    update_dts_issue,
    get_dts_stats,
    list_dts_by_case,
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


class RegressionVerifyRequest(BaseModel):
    """回归验证请求体。

    输入原始数据的任务 ID 和问题单 ID，以及对应漏洞的描述、标题和是否漏洞判定，
    判断该问题单对应的误报是否已消除。
    """
    task_id: str
    dts_id: str
    vuln_title: str = ""
    vuln_description: str = ""
    is_vulnerable: bool


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
    """列出问题单（支持过滤、分页）。表不存在时返回空结果。"""
    try:
        issues, total = list_dts_issues(
            evaluation_id=evaluation_id,
            agent_type=agent_type,
            status=status,
            cause_code=cause_code,
            case_type=case_type,
            limit=limit,
            offset=offset,
        )
        stats = get_dts_stats(evaluation_id)
    except Exception as e:
        from ...infrastructure.log_util import log
        log("DTS_API", f"list_issues 查询失败（表可能不存在）: {str(e)[:200]}")
        return {"issues": [], "count": 0, "total": 0, "stats": {"by_status": {}, "by_agent_type": {}, "by_cause_code": {}, "total": 0}}
    return {"issues": issues, "count": len(issues), "total": total, "stats": stats}


@router.get("/stats")
def get_stats(evaluation_id: str | None = None):
    """获取问题单统计。表不存在时返回空统计。"""
    try:
        stats = get_dts_stats(evaluation_id)
    except Exception as e:
        from ...infrastructure.log_util import log
        log("DTS_API", f"get_stats 查询失败（表可能不存在）: {str(e)[:200]}")
        return {"by_status": {}, "by_agent_type": {}, "by_cause_code": {}, "total": 0}
    return stats


@router.get("/by-case/{case_id}")
def list_by_case(case_id: str):
    """按 case 列出问题单。表不存在时返回空列表。"""
    try:
        issues = list_dts_by_case(case_id)
    except Exception as e:
        from ...infrastructure.log_util import log
        log("DTS_API", f"list_by_case 查询失败（表可能不存在）: {str(e)[:200]}")
        return {"issues": [], "count": 0}
    return {"issues": issues, "count": len(issues)}


@router.get("/by-task/{task_id}")
def list_by_task(task_id: str):
    """按原始数据任务 ID 列出问题单。

    用于回归验证流程的第一步：查询某个挖掘任务下产生了哪些问题单，
    获取问题单 ID 后提交回归验证。
    """
    try:
        issues = list_dts_by_task(task_id)
    except Exception as e:
        from ...infrastructure.log_util import log
        log("DTS_API", f"list_by_task 查询失败（表可能不存在）: {str(e)[:200]}")
        return {"issues": [], "count": 0}
    return {"issues": issues, "count": len(issues)}


@router.post("/regression-verify")
def regression_verify(req: RegressionVerifyRequest):
    """回归验证：判断误报是否消除。

    输入原始数据的任务 ID、问题单 ID，以及对应漏洞的标题、描述和是否漏洞判定。
    系统根据提交的 is_vulnerable 判断该问题单对应的误报是否已消除：
    - is_vulnerable=false：漏洞已被消除（误报已修复）→ 问题单状态设为 passed
    - is_vulnerable=true：漏洞仍然存在（误报未修复）→ 问题单状态设为 failed

    同时更新问题单的 replay_eval_id 和 replay_result 字段。
    """
    issue = get_dts_issue(req.dts_id)
    if issue is None:
        raise HTTPException(
            status_code=404,
            detail=f"问题单 '{req.dts_id}' 不存在",
        )

    # 校验 task_id 匹配
    if issue.get("task_id", "") != req.task_id:
        raise HTTPException(
            status_code=400,
            detail=f"task_id 不匹配：问题单的 task_id='{issue.get('task_id', '')}' "
                  f"≠ 请求的 task_id='{req.task_id}'",
        )

    # 判断误报是否消除
    if req.is_vulnerable:
        # 漏洞仍然存在 → 误报未消除
        new_status = "failed"
        replay_result = "still_vulnerable"
        message = "漏洞仍然存在，误报未消除"
    else:
        # 漏洞已被消除 → 误报已修复
        new_status = "passed"
        replay_result = "false_positive_resolved"
        message = "漏洞已消除，误报已修复"

    success = update_dts_issue(req.dts_id, {
        "status": new_status,
        "replay_eval_id": req.task_id,
        "replay_result": replay_result,
    })
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"更新问题单 '{req.dts_id}' 失败",
        )

    updated = get_dts_issue(req.dts_id)

    from ...infrastructure.log_util import log
    log("DTS_API",
        f"regression_verify: dts_id={req.dts_id}, task_id={req.task_id}, "
        f"is_vulnerable={req.is_vulnerable} → {new_status}")

    return {
        "dts_id": req.dts_id,
        "task_id": req.task_id,
        "vuln_title": req.vuln_title,
        "vuln_description": req.vuln_description,
        "is_vulnerable": req.is_vulnerable,
        "result": replay_result,
        "status": new_status,
        "message": message,
        "issue": updated,
    }


@router.get("/{dts_id}")
def get_issue(dts_id: str):
    """获取单个问题单详情。"""
    issue = get_dts_issue(dts_id)
    if issue is None:
        raise HTTPException(status_code=404, detail=f"问题单 '{dts_id}' 不存在")
    return issue


@router.put("/{dts_id}")
def update_issue(dts_id: str, update: DTSUpdate):
    """更新问题单（root_cause / solution / status 等）。"""
    existing = get_dts_issue(dts_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"问题单 '{dts_id}' 不存在")

    updates = update.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    success = update_dts_issue(dts_id, updates)
    if not success:
        raise HTTPException(status_code=500, detail=f"更新问题单 '{dts_id}' 失败")

    return get_dts_issue(dts_id)


@router.post("/{dts_id}/close")
def close_issue(dts_id: str):
    """关闭问题单（status→closing，设置 closed_at）。"""
    existing = get_dts_issue(dts_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"问题单 '{dts_id}' 不存在")

    if existing["status"] in ("passed", "failed", "not_issue"):
        raise HTTPException(
            status_code=400,
            detail=f"问题单 '{dts_id}' 已在终态: {existing['status']}",
        )

    success = update_dts_issue(dts_id, {
        "status": "closing",
    })
    if not success:
        raise HTTPException(status_code=500, detail=f"关闭问题单 '{dts_id}' 失败")

    return {"dts_id": dts_id, "status": "closing"}


@router.post("/{dts_id}/reject")
def reject_issue(dts_id: str, body: DTSReject):
    """驳回问题单（status→not_issue，需要理由）。"""
    existing = get_dts_issue(dts_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"问题单 '{dts_id}' 不存在")

    success = update_dts_issue(dts_id, {
        "status": "not_issue",
        "root_cause": f"[驳回] {body.reason}",
    })
    if not success:
        raise HTTPException(status_code=500, detail=f"驳回问题单 '{dts_id}' 失败")

    return {"dts_id": dts_id, "status": "not_issue", "reason": body.reason}
