"""结果通知配置 API（系统设置页用）。

- GET/PUT /api/v2/notify/owners          owner（agent/责任方）→ 负责人映射
- GET/PUT /api/v2/notify/env             环境标识（green/yellow）
- GET/PUT /api/v2/notify/xiaoluban-token 小鲁班发送 token

日报的构建与发送在 eval 服务端定时执行（v2/notify/scheduler.py），
不再提供离线脚本调用的 daily-report / ack 接口。
"""
from __future__ import annotations

import re
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...config_loader import EVAL_ENV_NAME, EVAL_PUBLIC_URL
from ..core.agents import AGENT_DISPLAY_NAMES, ALL_AGENT_SET
from ..infra.database import connect as _connect
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log
from ..notify import scheduler

_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _normalize_dates(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values or []:
        text = str(value).strip()
        if not text:
            continue
        if not _DATE_RE.match(text):
            raise HTTPException(status_code=400, detail=f"invalid date: {text}")
        try:
            datetime.strptime(text, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail=f"invalid date: {text}")
        if text not in result:
            result.append(text)
    return sorted(result)

router = APIRouter(prefix="/api/v2/notify", tags=["notify"])

_TARGET_TYPES = ("user", "group")
# 知识库 / 外部数据源 / 评测流程合并为一个责任方
_RESPONSIBILITIES = ("other",)


def _db_env_name() -> str:
    """环境标识：system_config.notify_env_name → EVAL_ENV_NAME → 空。"""
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='notify_env_name'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    value = _db_query(_do) or EVAL_ENV_NAME
    if value:
        return value
    # 未显式配置时从公网地址推断，保证标题始终带环境名
    url = EVAL_PUBLIC_URL.lower()
    if "chimera-y" in url:
        return "yellow"
    if "chimera-g" in url:
        return "green"
    return ""


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
    labels = {"other": "其他责任（知识库/外部数据源/评测流程）"}
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


class DailyTimeUpdate(BaseModel):
    daily_time: str


class WorkdayUpdate(BaseModel):
    holidays: list[str] = []
    workdays: list[str] = []


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


def _mask_token(token: str) -> str:
    """只展示前 3 位和后 3 位，中间用 **** 代替。"""
    if not token:
        return ""
    if len(token) <= 6:
        return "****"
    return token[:3] + "****" + token[-3:]


@router.get("/xiaoluban-token")
def get_xiaoluban_token():
    """返回脱敏后的小鲁班 token；完整 token 不再对外返回。"""
    full = _db_xiaoluban_token()
    return {"configured": bool(full), "token": _mask_token(full)}


@router.put("/xiaoluban-token")
def set_xiaoluban_token(update: XiaolubanTokenUpdate):
    value = (update.token or "").strip()
    if not value:
        # 留空表示不修改，避免误把已保存的 token 清空
        return {"status": "unchanged",
                "configured": bool(_db_xiaoluban_token())}

    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES ('xiaoluban_token', %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (value,))
    _db_query(_do)
    log("NOTIFY", "更新小鲁班 token")
    return {"status": "ok", "configured": True,
            "token": _mask_token(value)}


@router.get("/daily-time")
def get_daily_time():
    return {"daily_time": scheduler.get_daily_time()}


@router.put("/daily-time")
def set_daily_time(update: DailyTimeUpdate):
    value = (update.daily_time or "").strip()
    if not _TIME_RE.match(value):
        raise HTTPException(status_code=400, detail="daily_time must be HH:MM")

    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES ('notify_daily_time', %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (value,))
    _db_query(_do)
    scheduler.invalidate_caches()
    log("NOTIFY", f"更新日报发送时间: {value}")
    return {"status": "ok", "daily_time": value}


def _calendar_range(holidays: list[str], workdays: list[str]) -> dict:
    all_dates = sorted(set(holidays) | set(workdays))
    return {
        "min_date": all_dates[0] if all_dates else "",
        "max_date": all_dates[-1] if all_dates else "",
    }


@router.get("/workdays")
def get_workdays():
    holidays, workdays = scheduler.get_workday_config()
    holidays = sorted(holidays)
    workdays = sorted(workdays)
    return {
        "holidays": holidays,
        "workdays": workdays,
        **_calendar_range(holidays, workdays),
    }


@router.put("/workdays")
def set_workdays(update: WorkdayUpdate):
    holidays = _normalize_dates(update.holidays)
    workdays = _normalize_dates(update.workdays)

    rows = ([(d, "holiday") for d in holidays]
            + [(d, "workday") for d in workdays])
    conn = _connect(autocommit=False)
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM notify_calendar")
        if rows:
            cur.executemany(
                "INSERT INTO notify_calendar (calendar_date, day_type) "
                "VALUES (%s,%s)", rows)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    scheduler.invalidate_caches()
    log("NOTIFY", f"更新工作日日历: holidays={len(holidays)} "
                  f"workdays={len(workdays)}")
    return {
        "status": "ok",
        "holidays": holidays,
        "workdays": workdays,
        **_calendar_range(holidays, workdays),
    }


@router.get("/status")
def get_status():
    """返回每个 owner 的最近一次发送状态 + 最近发送记录。"""
    def _do(cur):
        cur.execute(
            "SELECT owner_key, display_name, owner_name, target_type, "
            "       target_id, enabled "
            "FROM notify_owner_config ORDER BY owner_kind, owner_key")
        cols = ["owner_key", "display_name", "owner_name", "target_type",
                "target_id", "enabled"]
        owners = [dict(zip(cols, r)) for r in cur.fetchall()]
        for owner in owners:
            cur.execute(
                "SELECT status, sent_at, window_start, window_end, "
                "       recipient, error "
                "FROM notification_log WHERE owner_key=%s "
                "ORDER BY sent_at DESC LIMIT 1",
                (owner["owner_key"],))
            row = cur.fetchone()
            owner["last"] = (dict(zip(
                ["status", "sent_at", "window_start", "window_end",
                 "recipient", "error"], row)) if row else None)
        cur.execute(
            "SELECT owner_key, recipient, status, sent_at, window_start, "
            "       window_end, error "
            "FROM notification_log ORDER BY sent_at DESC LIMIT 20")
        recent_cols = ["owner_key", "recipient", "status", "sent_at",
                       "window_start", "window_end", "error"]
        recent = [dict(zip(recent_cols, r)) for r in cur.fetchall()]
        return owners, recent
    owners, recent = _db_query(_do)
    return {
        "daily_time": scheduler.get_daily_time(),
        "workday_today": scheduler.is_workday(),
        "running": scheduler.is_running(),
        "owners": owners,
        "recent": recent,
    }


@router.post("/run")
def run_now(owner_key: str | None = None):
    """手动触发一次发送（异步）。不传 owner_key 则发送全部。"""
    result = scheduler.trigger_run(owner_key)
    if result.get("status") == "running":
        raise HTTPException(status_code=409, detail="日报发送正在运行")
    return result


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
