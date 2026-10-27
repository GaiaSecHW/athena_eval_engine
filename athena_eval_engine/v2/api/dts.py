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

    输入原始数据的任务 ID，以及问题单 ID（dts_id）或 case_id 之一定位问题单，
    以及对应漏洞的描述、标题和是否漏洞判定，判断该问题单对应的误报是否已消除。
    dts_id 与 case_id 二选一即可，同时填写时优先 dts_id。
    """
    task_id: str
    dts_id: str = ""
    case_id: str = ""
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
    """获取回归后误报率/漏报率。

    根据问题单的回归验证状态计算，按 case_type 拆分：
    - passed：问题已消除（回归验证后漏洞不存在）
    - failed：问题未消除（回归验证后漏洞仍存在）
    - open：未参与回归验证

    回归后误报率（FP 单）= failed / (passed + failed)。
    回归后漏报率（FN 单）= failed / (passed + failed)。
    无对应回归数据时返回 None。
    """
    try:
        return get_post_regression_fpr(evaluation_id)
    except Exception as e:
        from ...infrastructure.log_util import log
        log("DTS_API", f"get_post_fpr 查询失败: {str(e)[:200]}")
        return {
            "post_regression_fpr": None,
            "post_regression_fnr": None,
            "passed_count": 0,
            "failed_count": 0,
            "verified_total": 0,
            "open_count": 0,
            "total": 0,
            "by_case_type": {
                "FP": {"passed": 0, "failed": 0, "verified_total": 0},
                "FN": {"passed": 0, "failed": 0, "verified_total": 0},
            },
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
            "case_id": i.get("case_id", ""),
            "vuln_title": i.get("vuln_title", ""),
            "case_type": i.get("case_type", ""),
            "raw_report": raw_report_cache.get(case_id, ""),
        })
    return {"issues": simplified, "count": len(simplified)}


def _match_issue_by_llm(task_id: str, vuln_title: str,
                        vuln_description: str) -> dict | None:
    """用 LLM 在 task_id 下全部问题单中匹配与提交漏洞对应的问题单。

    当调用方未提供 dts_id/case_id（或提供但匹配不上）时，从该任务下所有
    问题单中，用 LLM 语义比对选出一个与提交的漏洞描述最匹配的问题单。

    Args:
        task_id: 原始数据任务 ID。
        vuln_title: 提交的漏洞标题。
        vuln_description: 提交的漏洞描述。

    Returns:
        匹配到的问题单 dict；无候选或 LLM 失败时返回 None。
    """
    from ...infrastructure.log_util import log
    try:
        candidates = list_dts_by_task(task_id)
    except Exception as e:
        log("DTS_API", f"regression LLM 匹配: 查询问题单失败: {str(e)[:200]}")
        return None
    if not candidates:
        return None

    # 构建候选列表供 LLM 选择
    cand_lines = []
    for i, c in enumerate(candidates):
        cand_lines.append(
            f"{i}. dts_id={c.get('dts_id')} | case_id={c.get('case_id')} "
            f"| case_type={c.get('case_type')} | title={c.get('vuln_title')}"
        )
    cand_prompt = "\n".join(cand_lines)

    sys_prompt = (
        "你是漏洞回归验证助手。给定一个待回归的漏洞，以及同一任务下的一组"
        "候选问题单（每条含 dts_id/case_id/case_type/title）。请从候选中选出"
        "与该漏洞语义最匹配的问题单（漏洞点、接口、根因一致）。"
        "只输出一个 JSON 对象：{\"dts_id\": \"...\"}，不要输出其他内容。"
        "如果没有匹配项，输出 {\"dts_id\": \"\"}。"
    )
    user_prompt = (
        f"待回归漏洞标题: {vuln_title or '（空）'}\n"
        f"待回归漏洞描述: {vuln_description or '（空）'}\n\n"
        f"候选问题单:\n{cand_prompt}"
    )

    try:
        from ..infra import llm as llm_mod
        result = llm_mod.chat_json(
            [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        dts_id = str(result.get("dts_id", "") or "").strip()
        if not dts_id:
            return None
        matched = get_dts_issue(dts_id)
        return matched
    except Exception as e:
        log("DTS_API", f"regression LLM 匹配失败: {str(e)[:200]}")
        return None


def _is_same_vulnerability(vuln_title: str, vuln_description: str,
                           issue_vuln_title: str) -> bool:
    """用 LLM 判断提交的漏洞与问题单的漏洞是否为同一个。

    当调用方提供了 vuln_title/vuln_description 时，用 LLM 语义比对：
    - 是同一个漏洞 → 允许回归确认
    - 不是同一个漏洞 → 回归不通过（判定失败）

    Args:
        vuln_title: 提交的漏洞标题。
        vuln_description: 提交的漏洞描述。
        issue_vuln_title: 问题单记录的漏洞标题。

    Returns:
        True=同一漏洞，False=不同漏洞。LLM 失败时返回 True（保守放行）。
    """
    from ...infrastructure.log_util import log
    sys_prompt = (
        "你是漏洞一致性判断助手。给定两个漏洞描述（A=提交待回归的漏洞，"
        "B=问题单记录的漏洞），判断它们是否为同一个漏洞（漏洞点、接口、"
        "根因一致，即语义相同）。只输出一个 JSON 对象："
        "{\"same\": true 或 false}，不要输出其他内容。"
    )
    user_prompt = (
        f"漏洞A（提交待回归）标题: {vuln_title or '（空）'}\n"
        f"漏洞A描述: {vuln_description or '（空）'}\n\n"
        f"漏洞B（问题单记录）标题: {issue_vuln_title or '（空）'}"
    )
    try:
        from ..infra import llm as llm_mod
        result = llm_mod.chat_json(
            [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        same = result.get("same")
        return bool(same)
    except Exception as e:
        log("DTS_API", f"regression 漏洞一致性判断失败: {str(e)[:200]}")
        return True  # LLM 失败保守放行


@router.post("/regression-verify")
def regression_verify(req: RegressionVerifyRequest):
    """回归验证：判断误报是否消除。

    输入原始数据的任务 ID、问题单 ID（或 case_id），以及对应漏洞的标题、
    描述和是否漏洞判定。系统根据提交的 is_vulnerable 判断该问题单对应的
    误报是否已消除：
    - is_vulnerable=false：漏洞已被消除（误报已修复）→ 问题单状态设为 passed（关闭）
    - is_vulnerable=true：漏洞仍然存在（误报未修复）→ 问题单状态设为 failed（未关闭，可再次回归）

    定位问题单：dts_id 与 case_id 二选一，同时填写时优先 dts_id；
    两者都未填或都匹配不上时，用 LLM 在 task_id 下全部问题单中比对匹配。

    同时更新问题单的 replay_eval_id 和 replay_result 字段。
    """
    from ...infrastructure.log_util import log
    # 定位问题单：dts_id 与 case_id 二选一，同时填写时优先 dts_id
    issue = None
    match_failed = False
    used_llm_match = False
    if req.dts_id:
        issue = get_dts_issue(req.dts_id)
        if issue is None:
            match_failed = True
    elif req.case_id:
        issues = list_dts_by_case(req.case_id)
        if not issues:
            match_failed = True
        else:
            # 同 case 可能多条问题单，取最新一条（list_dts_by_case 按 created_at ASC）
            issue = issues[-1]
            req.dts_id = issue.get("dts_id", "")  # 回填 dts_id 供后续使用

    # dts_id/case_id 未提供或匹配不上 → 用 LLM 在 task_id 下全部问题单中匹配
    if issue is None:
        log("DTS_API",
            f"regression_verify: dts_id/case_id 未命中，LLM 匹配 "
            f"task_id={req.task_id} (dts_id={req.dts_id or ''}, case_id={req.case_id or ''})")
        issue = _match_issue_by_llm(
            req.task_id, req.vuln_title, req.vuln_description)
        if issue is None:
            if match_failed:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"问题单定位失败：dts_id='{req.dts_id or ''}' / "
                        f"case_id='{req.case_id or ''}' 均未命中，且 task_id "
                        f"'{req.task_id}' 下无匹配问题单"
                    ),
                )
            raise HTTPException(
                status_code=400,
                detail="dts_id 与 case_id 至少填一个（或提供可匹配的漏洞信息）",
            )
        used_llm_match = True
        req.dts_id = issue.get("dts_id", "")  # 回填 LLM 匹配到的 dts_id
        log("DTS_API",
            f"regression_verify: LLM 匹配到 dts_id={req.dts_id}")

    # 校验 task_id 匹配
    if issue.get("task_id", "") != req.task_id:
        raise HTTPException(
            status_code=400,
            detail=f"task_id 不匹配：问题单的 task_id='{issue.get('task_id', '')}' "
                  f"≠ 请求的 task_id='{req.task_id}'",
        )

    # 校验 case_id 匹配（请求传了 case_id 且用 dts_id 定位时；LLM 匹配场景跳过）
    if req.dts_id and req.case_id and issue.get("case_id", "") != req.case_id \
            and not used_llm_match:
        raise HTTPException(
            status_code=400,
            detail=f"case_id 不匹配：问题单的 case_id='{issue.get('case_id', '')}' "
                  f"≠ 请求的 case_id='{req.case_id}'",
        )

    # 漏洞一致性判断：提交的 vuln_title/vuln_description 非空时，
    # 用 LLM 判断与问题单的漏洞是否为同一个。
    # 是同一个 → 继续回归确认；不是同一个 → 回归不通过（failed）。
    if req.vuln_title or req.vuln_description:
        same = _is_same_vulnerability(
            req.vuln_title, req.vuln_description,
            issue.get("vuln_title", ""),
        )
        if not same:
            new_status = "failed"
            replay_result = "still_vulnerable"
            message = "提交的漏洞与问题单漏洞不一致，回归不通过"
            _json = __import__("json")
            replay_data = _json.dumps({
                "task_id": req.task_id,
                "case_id": req.case_id,
                "vuln_title": req.vuln_title,
                "vuln_description": req.vuln_description,
                "is_vulnerable": req.is_vulnerable,
                "result": replay_result,
                "message": message,
                "same_vulnerability": False,
            }, ensure_ascii=False)
            success = update_dts_issue(req.dts_id, {
                "status": new_status,
                "replay_eval_id": req.task_id,
                "replay_result": replay_result,
                "replay_data": replay_data,
            })
            updated = get_dts_issue(req.dts_id) if success else None
            from ...infrastructure.log_util import log as _log
            _log("DTS_API",
                 f"regression_verify: 漏洞不一致，回归不通过 dts_id={req.dts_id}")
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
        "case_id": req.case_id,
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


class HypothesisConfirmRequest(BaseModel):
    """假设根因确认请求体。"""
    hypothesis_key: str
    is_root: bool
    cause_code: str = ""
    agent_type: str = ""
    project_id: str = ""
    project_name: str = ""
    note: str = ""


@router.post("/{dts_id}/confirm-hypothesis")
def confirm_hypothesis(dts_id: str, req: HypothesisConfirmRequest):
    """确认某个假设是根因 / 非根因，结果存 DB 供看板统计。

    hypothesis_confirmations 结构：
    {
      "<hypothesis_key>": {
        "is_root": true/false,
        "cause_code": "A-K",
        "agent_type": "turing/webvuln_verify/...",
        "project_id": "...",
        "project_name": "...",
        "note": "...",
        "confirmed_at": "ISO 时间"
      },
      ...
    }
    """
    import json
    from datetime import datetime

    issue = get_dts_issue(dts_id)
    if issue is None:
        raise HTTPException(status_code=404, detail=f"问题单 '{dts_id}' 不存在")

    hc = issue.get("hypothesis_confirmations") or {}
    hc[req.hypothesis_key] = {
        "is_root": req.is_root,
        "cause_code": req.cause_code,
        "agent_type": req.agent_type,
        "project_id": req.project_id,
        "project_name": req.project_name,
        "note": req.note,
        "confirmed_at": datetime.now().isoformat(),
    }

    success = update_dts_issue(dts_id, {
        "hypothesis_confirmations": json.dumps(hc, ensure_ascii=False),
    })
    if not success:
        raise HTTPException(status_code=500, detail=f"确认假设 '{dts_id}' 失败")

    return get_dts_issue(dts_id)
