"""评测 API + 报告 API（§4.6 新增 lifecycle/inventory 端点）。

端点：
- GET /api/v2/evaluations/{eid}/report           — 基础报告段（指标 + 汇总）
- GET /api/v2/evaluations/{eid}/report/lifecycle  — 生命周期分析段
- GET /api/v2/evaluations/{eid}/report/inventory  — 知识盘点段
- GET /api/v2/evaluations/{eid}/report/status     — 各段报告就绪状态
- GET /api/v2/evaluations/{eid}                   — 评测详情（状态 + 元信息）
"""
from __future__ import annotations

import json
import os

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v2/evaluations", tags=["evaluations"])

# 报告目录（与老代码一致，环境变量优先）
REPORTS_DIR = os.environ.get("EVAL_REPORTS_DIR", "reports")


def _report_path(evaluation_id: str, suffix: str) -> str:
    """构造报告文件路径。suffix 不含路径分隔符，如 'lifecycle' / 'inventory'。"""
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
    import json as _json
    from ...infrastructure.database import connect

    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT e.evaluation_id, e.evaluation_name, e.evaluation_status, "
            "e.benchmark_set_id, e.created_at, e.started_at, e.finished_at, "
            "e.error_message, e.version, "
            "s.config_json "
            "FROM evaluation e "
            "LEFT JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
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
    return _read_report_segment(evaluation_id, "lifecycle")


@router.get("/{evaluation_id}/report/inventory")
def get_inventory_report(evaluation_id: str):
    """返回 {eid}_inventory.json 报告段。"""
    return _read_report_segment(evaluation_id, "inventory")


@router.get("/{evaluation_id}/report/status")
def get_report_status(evaluation_id: str):
    """返回各段报告就绪状态。

    检查以下段文件是否存在：
    - base: {eid}.json
    - fpr: {eid}_fpr.json
    - kg: {eid}_kg.json
    - lifecycle: {eid}_lifecycle.json
    - inventory: {eid}_inventory.json
    """
    segments = {
        "base": f"{evaluation_id}.json",
        "fpr": f"{evaluation_id}_fpr.json",
        "kg": f"{evaluation_id}_kg.json",
        "lifecycle": f"{evaluation_id}_lifecycle.json",
        "inventory": f"{evaluation_id}_inventory.json",
    }
    return {
        name: os.path.isfile(os.path.join(REPORTS_DIR, filename))
        for name, filename in segments.items()
    }
