"""问题单 API 端点。

端点：
- GET    /api/v2/dts                        — 列出问题单（支持过滤）
- GET    /api/v2/dts/{dts_id}               — 获取单个问题单详情
- PUT    /api/v2/dts/{dts_id}               — 更新问题单（root_cause/solution/status）
- GET    /api/v2/dts/stats                   — 获取统计
- GET    /api/v2/dts/post-regression-fpr/{evaluation_id} — 获取回归后误报率
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
    get_post_regression_fpr,
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


@router.get("/post-regression-fpr/{evaluation_id}")
def get_post_fpr(evaluation_id: str):
    """获取回归后误报率。

    根据问题单的回归验证状态计算：
    - passed：误报已消除（回归验证后漏洞不存在）
    - failed：误报未消除（回归验证后漏洞仍存在）
    - open：未参与回归验证

    回归后误报率 = failed / (passed + failed)。
    无回归验证数据时返回 None。
    """
    try:
        return get_post_regression_fpr(evaluation_id)
    except Exception as e:
        from ...infrastructure.log_util import log
        log("DTS_API", f"get_post_fpr 查询失败: {str(e)[:200]}")
        return {
            "post_regression_fpr": None,
            "passed_count": 0,
            "failed_count": 0,
            "verified_total": 0,
            "open_count": 0,
            "total": 0,
        }


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
    """按原始数据任务 ID 列出问题单（精简版）。

    用于回归验证流程的第一步：查询某个挖掘任务下产生了哪些问题单，
    获取问题单 ID 后提交回归验证。

    返回 dts_id、vuln_title（漏洞标题）、case_type（FP=误报单 / FN=漏报单）、
    raw_report（基线对应原始漏洞报告，Markdown 格式，从 analysis_data_path
    指向的 JSON 文件中的 description 字段读取）。
    """
    import os
    import json as _json
    from ...infrastructure.log_util import log

    try:
        issues = list_dts_by_task(task_id)
    except Exception as e:
        log("DTS_API", f"list_by_task 查询失败（表可能不存在）: {str(e)[:200]}")
        return {"issues": [], "count": 0}

    reports_dir = os.environ.get("EVAL_REPORTS_DIR", "reports")

    # 按 case_id 去重缓存，避免同 case 多条问题单重复读文件
    raw_report_cache: dict[str, str] = {}
    simplified = []
    for i in issues:
        case_id = i.get("case_id", "")
        if case_id not in raw_report_cache:
            raw_report = ""
            # 优先从 analysis_data_path 指向的 JSON 文件读 description 字段
            path = i.get("analysis_data_path") or ""
            if path:
                try:
                    file_path = os.path.join(reports_dir, path)
                    if os.path.exists(file_path):
                        with open(file_path, "r", encoding="utf-8") as f:
                            data = _json.loads(f.read())
                        raw_report = str(data.get("description") or "")
                except Exception as e:
                    log("DTS_API",
                        f"list_by_task 读取原始报告失败 case={case_id} "
                        f"path={path}: {str(e)[:200]}")
            raw_report_cache[case_id] = raw_report
        simplified.append({
            "dts_id": i.get("dts_id", ""),
            "vuln_title": i.get("vuln_title", ""),
            "case_type": i.get("case_type", ""),
            "raw_report": raw_report_cache.get(case_id, ""),
        })
    return {"issues": simplified, "count": len(simplified)}


@router.post("/regression-verify")
def regression_verify(req: RegressionVerifyRequest):
    """回归验证：判断误报是否消除。

    输入原始数据的任务 ID、问题单 ID，以及对应漏洞的标题、描述和是否漏洞判定。
    系统根据提交的 is_vulnerable 判断该问题单对应的误报是否已消除：
    - is_vulnerable=false：漏洞已被消除（误报已修复）→ 问题单状态设为 passed（关闭）
    - is_vulnerable=true：漏洞仍然存在（误报未修复）→ 问题单状态设为 failed（未关闭，可再次回归）

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

    # 回归验证提交的完整数据存入 replay_data
    import json as _json
    replay_data = _json.dumps({
        "task_id": req.task_id,
        "vuln_title": req.vuln_title,
        "vuln_description": req.vuln_description,
        "is_vulnerable": req.is_vulnerable,
        "result": replay_result,
        "message": message,
    }, ensure_ascii=False)

    success = update_dts_issue(req.dts_id, {
        "status": new_status,
        "replay_eval_id": req.task_id,
        "replay_result": replay_result,
        "replay_data": replay_data,
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
