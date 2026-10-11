"""评测 API + 报告 API（§4.6 新增 lifecycle/inventory 端点）。

端点：
- GET /api/v2/evaluations/{eid}/report/lifecycle  — 生命周期分析段
- GET /api/v2/evaluations/{eid}/report/inventory  — 知识盘点段
- GET /api/v2/evaluations/{eid}/report/status     — 各段报告就绪状态
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
# 报告端点
# ---------------------------------------------------------------------------

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
