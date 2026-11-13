"""结果通知配置 API（系统设置页用）。

- GET/PUT /api/v2/notify/owners          owner（agent/责任方）→ 负责人映射
- GET/PUT /api/v2/notify/env             环境标识（green/yellow）
- GET/PUT /api/v2/notify/xiaoluban-token 小鲁班发送 token

日报的构建与发送在 eval 服务端定时执行（v2/notify/scheduler.py），
不再提供离线脚本调用的 daily-report / ack 接口。
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...config_loader import EVAL_ENV_NAME
from ..core.agents import AGENT_DISPLAY_NAMES, ALL_AGENT_SET
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

router = APIRouter(prefix="/api/v2/notify", tags=["notify"])

_TARGET_TYPES = ("user", "group")
_RESPONSIBILITIES = ("knowledge", "external_data_source", "eval_process")


def _db_env_name() -> str:
    """环境标识：system_config.notify_env_name → EVAL_ENV_NAME → 空。"""
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='notify_env_name'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    value = _db_query(_do)
    return value or EVAL_ENV_NAME


def _db_xiaoluban_token() -> str:
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='xiaoluban_token'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    return _db_query(_do)


def _owner_display_name(owner_key: str) -> str:
    kind, _, key = owner_key.partition(":")
    if kind == "agent":
        return AGENT_DISPLAY_NAMES.get(key, key)
    labels = {"knowledge": "知识库", "external_data_source": "外部数据源",
              "eval_process": "评测流程"}
    return labels.get(key, key)


def _validate_owner_key(owner_key: str) -> tuple[str, str]:
    kind, _, key = owner_key.partition(":")
    if kind == "agent" and key in ALL_AGENT_SET:
        return kind, key
    if kind == "resp" and key in _RESPONSIBILITIES:
        return kind, key
    raise HTTPException(status_code=400, detail=f"unknown owner_key: {owner_key}")


class OwnerUpdate(BaseModel):
    owner_key: str
    owner_name: str = ""
    target_type: str = "user"
    target_id: str = ""
    enabled: bool = True


class EnvUpdate(BaseModel):
    env_name: str


class XiaolubanTokenUpdate(BaseModel):
    token: str


@router.get("/env")
def get_env():
    """返回环境标识（green / yellow），系统设置页展示用。"""
    return {"env_name": _db_env_name()}


@router.put("/env")
def set_env(update: EnvUpdate):
    value = (update.env_name or "").strip()

    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES ('notify_env_name', %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (value,))
    _db_query(_do)
    log("NOTIFY", f"更新环境标识: {value or '(空)'}")
    return {"status": "ok"}


@router.get("/xiaoluban-token")
def get_xiaoluban_token():
    """返回小鲁班 token（系统设置页展示/复制用）。"""
    return {"token": _db_xiaoluban_token()}


@router.put("/xiaoluban-token")
def set_xiaoluban_token(update: XiaolubanTokenUpdate):
    value = (update.token or "").strip()

    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES ('xiaoluban_token', %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (value,))
    _db_query(_do)
    log("NOTIFY", "更新小鲁班 token")
    return {"status": "ok"}


@router.get("/owners")
def list_owners():
    def _do(cur):
        cur.execute(
            "SELECT owner_key, owner_kind, display_name, owner_name, "
            "target_type, target_id, enabled, updated_at "
            "FROM notify_owner_config "
            "ORDER BY owner_kind, owner_key")
        cols = ["owner_key", "owner_kind", "display_name", "owner_name",
                "target_type", "target_id", "enabled", "updated_at"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    return {"owners": _db_query(_do)}


@router.put("/owners")
def update_owner(update: OwnerUpdate):
    kind, _ = _validate_owner_key(update.owner_key)
    if update.target_type not in _TARGET_TYPES:
        raise HTTPException(status_code=400, detail="target_type must be user or group")

    def _do(cur):
        cur.execute(
            "INSERT INTO notify_owner_config "
            "(owner_key, owner_kind, display_name, owner_name, target_type, "
            " target_id, enabled) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) "
            "ON DUPLICATE KEY UPDATE "
            "  owner_kind=VALUES(owner_kind), "
            "  owner_name=VALUES(owner_name), target_type=VALUES(target_type), "
            "  target_id=VALUES(target_id), enabled=VALUES(enabled), "
            "  _version=_version+1",
            (update.owner_key, kind, _owner_display_name(update.owner_key),
             update.owner_name, update.target_type, update.target_id,
             1 if update.enabled else 0))
        return cur.rowcount
    _db_query(_do)
    log("NOTIFY", f"更新日报负责人: {update.owner_key} -> {update.owner_name} "
                  f"({update.target_type}:{update.target_id})")
    return {"status": "ok", "owner_key": update.owner_key}
