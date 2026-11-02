"""评测 API + 报告 API。

端点：
- GET /api/v2/evaluations/{eid}/report           — 基础报告段（指标 + 召回率/准确率 + 汇总）
- GET /api/v2/evaluations/{eid}/report/lifecycle  — 生命周期分析段
- GET /api/v2/evaluations/{eid}/report/status     — 各段报告就绪状态
- GET /api/v2/evaluations/{eid}                   — 评测详情（状态 + 元信息）
- GET /api/v2/evaluations/{eid}/debug/{step}      — 步骤中间数据明细（调试用）
- GET /api/v2/evaluations/{eid}/debug             — 调试页面（HTML）
"""
from __future__ import annotations

import json
import os
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from ..infra.progress import get_progress as _get_progress

router = APIRouter(prefix="/api/v2/evaluations", tags=["evaluations"])

# 报告目录（统一从 config_loader 读取）
from ...config_loader import get_reports_dir
REPORTS_DIR = get_reports_dir()

# evaluation_id 合法字符：字母、数字、下划线、连字符
_EVAL_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _validate_eval_id(evaluation_id: str) -> None:
    """校验 evaluation_id 防止路径遍历。

    evaluation_id 直接拼进文件路径，如果不校验，攻击者可传入
    ``../../etc/passwd`` 读取任意文件。
    """
    if not evaluation_id or not _EVAL_ID_RE.match(evaluation_id):
        raise HTTPException(
            status_code=400,
            detail=f"invalid evaluation_id: '{evaluation_id}'",
        )


def _report_path(evaluation_id: str, suffix: str) -> str:
    """构造报告文件路径。suffix 不含路径分隔符，如 'lifecycle'。"""
    return os.path.join(REPORTS_DIR, f"{evaluation_id}_{suffix}.json")


def _read_report_segment(evaluation_id: str, suffix: str) -> dict:
    """读取报告段 JSON 文件，不存在时返回 404。"""
    path = _report_path(evaluation_id, suffix)
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail=f"{suffix} report not found for evaluation '{evaluation_id}'",
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.loads(f.read())


# ---------------------------------------------------------------------------
# 评测详情端点
# ---------------------------------------------------------------------------

@router.get("/{evaluation_id}")
def get_evaluation(evaluation_id: str):
    """返回评测状态 + 元信息（从 DB 读取，兼容 v1/v2）。"""
    _validate_eval_id(evaluation_id)
    import json as _json
    from ..infra.database import connect

    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT e.evaluation_id, e.evaluation_name, e.evaluation_status, "
            "e.benchmark_set_id, e.created_at, e.started_at, e.finished_at, "
            "e.error_message, e.version, "
            "s.config_json, "
            "pts.task_created_at "
            "FROM evaluation e "
            "LEFT JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
            "LEFT JOIN project_task_summary pts "
            "  ON pts.project_id = e.benchmark_set_id "
            "  AND pts.task_id = e.task_id "
            "WHERE e.evaluation_id = %s",
            (evaluation_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"evaluation '{evaluation_id}' not found",
            )
        result = {
            "evaluation_id": row[0],
            "name": row[1] or row[0],
            "status": row[2],
            "benchmark_set_id": row[3],
            "created_at": row[4].isoformat() if row[4] else None,
            "started_at": row[5].isoformat() if row[5] else None,
            "finished_at": row[6].isoformat() if row[6] else None,
            "error_message": row[7],
            "version": row[8],
            "progress": _get_progress(evaluation_id),
            "task_created_at": row[10] or "",
        }
        # 从 config_json 提取 manifest 信息
        if row[9]:
            cfg = _json.loads(row[9]) if isinstance(row[9], str) else row[9]
            manifest = cfg.get("manifest", {})
            result["benchmark_source"] = manifest.get("benchmark_source", "vuln_center")
            result["eval_mode"] = manifest.get("eval_mode", "dev")
            result["vc_source_project_name"] = manifest.get("vc_source_project_name", "")
            result["vc_source_task_name"] = manifest.get("vc_source_task_name", "")
            entries = manifest.get("entries", [])
            result["entries_info"] = [
                {
                    "condition": e.get("condition"),
                    "project_name": e.get("project_name", ""),
                    "task_name": e.get("task_name", ""),
                    "category": e.get("category", ""),
                }
                for e in entries
            ]
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 报告端点
# ---------------------------------------------------------------------------

@router.get("/{evaluation_id}/report")
def get_base_report(evaluation_id: str):
    """返回 {eid}.json 基础报告段（指标 + 汇总）。"""
    _validate_eval_id(evaluation_id)
    path = os.path.join(REPORTS_DIR, f"{evaluation_id}.json")
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail=f"base report not found for evaluation '{evaluation_id}'",
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.loads(f.read())


@router.get("/{evaluation_id}/report/lifecycle")
def get_lifecycle_report(evaluation_id: str):
    """返回 {eid}_lifecycle.json 报告段。"""
    _validate_eval_id(evaluation_id)
    return _read_report_segment(evaluation_id, "lifecycle")


@router.get("/{evaluation_id}/report/status")
def get_report_status(evaluation_id: str):
    """返回各段报告就绪状态。

    检查以下段文件是否存在：
    - base: {eid}.json
    - lifecycle: {eid}_lifecycle.json
    """
    _validate_eval_id(evaluation_id)
    segments = {
        "base": f"{evaluation_id}.json",
        "lifecycle": f"{evaluation_id}_lifecycle.json",
    }
    return {
        name: os.path.isfile(os.path.join(REPORTS_DIR, filename))
        for name, filename in segments.items()
    }


# ---------------------------------------------------------------------------
# 调试端点 — 步骤中间数据明细
# ---------------------------------------------------------------------------

# 已知步骤列表（按 pipeline 顺序）
_DEBUG_STEPS = ["ingesting", "parsing", "case_matching", "root_cause",
                "resolving", "lifecycle", "causal_chain", "reporting"]

# debug.html 所在目录
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "static")
# 可覆盖的静态文件目录（k8s 下 /data 可写，便于热更新 HTML 而无需重建镜像）
from ...config_loader import get_static_override_dir as _get_static_override_dir
_STATIC_OVERRIDE_DIR = _get_static_override_dir()


@router.get("/{evaluation_id}/debug")
def get_debug_page(evaluation_id: str):
    """调试页面：展示各步骤中间数据。返回静态 HTML，前端通过 API 获取数据。"""
    _validate_eval_id(evaluation_id)
    # 优先从可覆盖目录读取（热更新），回退到打包目录
    override_path = os.path.join(_STATIC_OVERRIDE_DIR, "debug.html")
    if os.path.isfile(override_path):
        return FileResponse(override_path, media_type="text/html")
    path = os.path.join(_STATIC_DIR, "debug.html")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="debug.html not found")
    return FileResponse(path, media_type="text/html")


@router.get("/{evaluation_id}/debug/{step}")
def get_debug_step(evaluation_id: str, step: str):
    """返回某步骤的中间数据 JSON。"""
    _validate_eval_id(evaluation_id)
    # step 必须在已知步骤列表中，防止路径遍历
    if step not in _DEBUG_STEPS:
        raise HTTPException(
            status_code=400,
            detail=f"invalid debug step: '{step}'",
        )
    path = os.path.join(REPORTS_DIR, f"{evaluation_id}_debug_{step}.json")
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail=f"debug data for step '{step}' not found",
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.loads(f.read())
