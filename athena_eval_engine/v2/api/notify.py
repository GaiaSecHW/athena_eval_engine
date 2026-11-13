"""结果通知 API。

供离线 WeLink 脚本调用：
- GET  /api/v2/notify/daily-report      按 owner 拉取日报（含 Markdown 文本）
- POST /api/v2/notify/daily-report/ack  发送成功后回写窗口
- GET/PUT /api/v2/notify/owners         owner（agent/责任方）→ 负责人映射管理

owner_key 形式：
- ``agent:<agent_type>``
- ``resp:<responsibility>``（knowledge / external_data_source / eval_process）

手动触发不单独做按钮：脚本带 ``force=true`` 调 GET 即可。
日报数据接口用 token 保护：token 存在 system_config.notify_token，
在 /eval/system 页面查看/修改/随机生成；为空时不校验。
"""
from __future__ import annotations

import hmac
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ...config_loader import EVAL_ENV_NAME
from ..core.agents import AGENT_DISPLAY_NAMES, ALL_AGENT_SET
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log
from ..notify.daily_report import build_reports, render_text

router = APIRouter(prefix="/api/v2/notify", tags=["notify"])

_TARGET_TYPES = ("user", "group")
_ACK_STATUSES = ("sent", "failed")
_RESPONSIBILITIES = ("knowledge", "external_data_source", "eval_process")


def _db_token() -> str:
    """从 system_config 读取日报 token（空=不校验）。"""
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='notify_token'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    return _db_query(_do)


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


def _require_token(request: Request) -> None:
    expected = _db_token()
    if not expected:
        return
    supplied = request.headers.get("X-Notify-Token") or ""
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        supplied = auth[7:]
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="invalid notify token")


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


class AckRequest(BaseModel):
    owner_key: str
    window_start: str
    window_end: str
    recipient: str = ""
    content_hash: str = ""
    status: str = "sent"
    error: str | None = None


class TokenUpdate(BaseModel):
    token: str


class EnvUpdate(BaseModel):
    env_name: str


@router.get("/token")
def get_token():
    """返回当前日报 token（系统设置页展示/复制用）。"""
    return {"token": _db_token()}


@router.put("/token")
def set_token(update: TokenUpdate):
    token = (update.token or "").strip()

    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES ('notify_token', %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (token,))
    _db_query(_do)
    log("NOTIFY", "更新日报 API token")
    return {"status": "ok"}


@router.post("/token/generate")
def generate_token():
    """生成一个随机 token（不落库，由页面点保存后写入）。"""
    return {"token": secrets.token_urlsafe(32)}


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


@router.get("/daily-report", dependencies=[Depends(_require_token)])
def daily_report(owner_key: str | None = None,
                 since: str | None = None,
                 until: str | None = None,
                 force: bool = False):
    """按 owner 返回日报；每条附带渲染好的 Markdown 文本。"""
    try:
        result = build_reports(owner_key=owner_key, since=since,
                               until=until, force=force)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    env_name = _db_env_name()
    result["env_name"] = env_name
    for report in result.get("agents", []):
        report["env_name"] = env_name
        report["text"] = render_text(report)
    return result


@router.post("/daily-report/ack", dependencies=[Depends(_require_token)])
def ack_report(req: AckRequest):
    _validate_owner_key(req.owner_key)
    if req.status not in _ACK_STATUSES:
        raise HTTPException(status_code=400, detail="status must be sent or failed")

    def _do(cur):
        cur.execute(
            "INSERT INTO notification_log "
            "(owner_key, channel, recipient, window_start, window_end, "
            " content_hash, status, error) "
            "VALUES (%s,'welink',%s,%s,%s,%s,%s,%s)",
            (req.owner_key, req.recipient, req.window_start, req.window_end,
             req.content_hash, req.status, req.error))
        return cur.lastrowid
    log_id = _db_query(_do)
    log("NOTIFY", f"日报发送记录: owner={req.owner_key} status={req.status} "
                  f"window={req.window_start}~{req.window_end} id={log_id}")
    return {"status": "ok", "id": log_id}
