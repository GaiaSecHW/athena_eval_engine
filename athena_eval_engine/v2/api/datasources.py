"""Agent 数据源配置 CRUD + 测试连接 API (§3.4)。

端点：
- GET    /api/v2/datasources           — 列出全部 Agent 数据源配置（password 脱敏）
- GET    /api/v2/datasources/{agent_type} — 获取单个 Agent 数据源配置
- PUT    /api/v2/datasources/{agent_type} — 修改数据源配置，递增 _version
- POST   /api/v2/datasources/{agent_type}/test — 测试连接
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..infra.agent_db import AgentDBManager

router = APIRouter(prefix="/api/v2/datasources", tags=["datasources"])

_db = AgentDBManager()


# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------

class DatasourceConfig(BaseModel):
    """数据源配置（完整模型，用于响应）。"""
    agent_type: str
    display_name: str
    db_type: str
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None  # 写入时用，读取时脱敏
    database_name: str | None = None
    enabled: bool = True


class DatasourceUpdate(BaseModel):
    """数据源更新模型（部分字段，password 为 '***' 或空时不更新）。"""
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None  # '***' 或空时不更新密码
    database_name: str | None = None
    enabled: bool | None = None


# ---------------------------------------------------------------------------
# 端点
# ---------------------------------------------------------------------------

@router.get("")
def list_datasources():
    """列出全部 Agent 数据源配置（password 脱敏为 '***'）。"""
    configs = _db.list_configs()
    return {"datasources": configs}


@router.get("/{agent_type}")
def get_datasource(agent_type: str):
    """获取单个 Agent 数据源配置（password 脱敏）。"""
    config = _db.get_config(agent_type)
    if config is None:
        raise HTTPException(status_code=404, detail=f"Datasource '{agent_type}' not found")
    # 密码脱敏
    config["password"] = "***"
    return config


@router.put("/{agent_type}")
def update_datasource(agent_type: str, config: DatasourceUpdate):
    """修改数据源配置，递增 _version。

    password 为 '***' 或空时不更新密码。
    """
    # 先检查配置是否存在
    existing = _db.get_config(agent_type)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Datasource '{agent_type}' not found")

    # 转为 dict，仅包含非 None 字段
    updates = config.model_dump(exclude_none=True)

    success = _db.update_config(agent_type, updates)
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to update datasource '{agent_type}'")

    # 返回更新后的配置（脱敏）
    updated = _db.get_config(agent_type)
    if updated is not None:
        updated["password"] = "***"
    return updated


@router.post("/{agent_type}/test")
def test_connection(agent_type: str, project_id: str | None = None):
    """测试连接，返回 {success, error}，更新 last_connected_at / last_error。"""
    # 先检查配置是否存在
    existing = _db.get_config(agent_type)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Datasource '{agent_type}' not found")

    success, error = _db.test_connection(agent_type, project_id)
    return {"success": success, "error": error}
