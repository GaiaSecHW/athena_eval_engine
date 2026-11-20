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

from ..core.agents import AGENT_DISPLAY_NAMES, ALL_AGENT_SET
from ..infra.database import connect as _connect
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log
from ..notify import scheduler
from ..notify.daily_report import (
    build_reports,
    get_env_name,
    get_public_url,
    invalidate_public_url_cache,
    render_combined_text,
    render_text,
)

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


class PublicUrlUpdate(BaseModel):
    public_url: str


class XiaolubanTokenUpdate(BaseModel):
    token: str


class ReportConfigUpdate(BaseModel):
    """定期报告配置：周期（daily/weekly/monthly）+ 时间 + 触发日 + 接收群。

    - period=daily：每天；
    - period=weekly：weekday（ISO 1=周一…7=周日）触发；
    - period=monthly：mday（1-31，超过当月天数按当月最后一天）触发。
    - receivers：每种周期单独的接收群（群号/工号）——x 报为单消息模式，
      全 owner 汇总一条发到当前周期的接收群；未配置的周期不发送。
    """
    period: str
    time: str
    weekday: int = 1
    mday: int = 1
    receivers: dict[str, str] = {}


class WorkdayUpdate(BaseModel):
    holidays: list[str] = []
    workdays: list[str] = []


@router.get("/env")
def get_env():
    """返回环境标识和对外访问地址，系统设置页展示用。"""
    return {"env_name": get_env_name(), "public_url": get_public_url()}


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


@router.get("/public-url")
def get_public_url_endpoint():
    return {"public_url": get_public_url()}


@router.put("/public-url")
def set_public_url(update: PublicUrlUpdate):
    value = (update.public_url or "").strip().rstrip("/")
    if value and not (value.startswith("http://")
                      or value.startswith("https://")):
        raise HTTPException(
            status_code=400,
            detail="public_url must start with http:// or https://")

    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES ('notify_public_url', %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (value,))
    _db_query(_do)
    invalidate_public_url_cache()
    log("NOTIFY", f"更新对外访问地址: {value or '(空)'}")
    return {"status": "ok", "public_url": value}


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


@router.get("/report-config")
def get_report_config():
    return scheduler.get_report_config()


@router.put("/report-config")
def set_report_config(update: ReportConfigUpdate):
    period = (update.period or "").strip().lower()
    if period not in ("daily", "weekly", "monthly"):
        raise HTTPException(status_code=400,
                            detail="period must be daily/weekly/monthly")
    if not _TIME_RE.match((update.time or "").strip()):
        raise HTTPException(status_code=400, detail="time must be HH:MM")
    if not 1 <= int(update.weekday) <= 7:
        raise HTTPException(status_code=400,
                            detail="weekday must be 1-7 (ISO, 1=周一)")
    if not 1 <= int(update.mday) <= 31:
        raise HTTPException(status_code=400,
                            detail="mday must be 1-31")

    receivers = update.receivers or {}
    bad_keys = set(receivers) - {"daily", "weekly", "monthly"}
    if bad_keys:
        raise HTTPException(
            status_code=400,
            detail=f"receivers 仅支持 daily/weekly/monthly 键: {sorted(bad_keys)}")

    def _do(cur):
        rows = [
            ("notify_report_period", period),
            ("notify_report_time", update.time.strip()),
            ("notify_report_weekday", str(int(update.weekday))),
            ("notify_report_mday", str(int(update.mday))),
        ]
        for p in ("daily", "weekly", "monthly"):
            if p in receivers:
                rows.append((f"notify_report_receiver_{p}",
                             str(receivers.get(p) or "").strip()))
        for key, value in rows:
            cur.execute(
                "INSERT INTO system_config (config_key, config_value) "
                "VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
                (key, value))
    _db_query(_do)
    scheduler.invalidate_caches()
    log("NOTIFY", f"更新定期报告配置: {period} {update.time.strip()} "
                  f"(weekday={update.weekday}, mday={update.mday}, "
                  f"receivers={receivers})")
    return {"status": "ok",
            "period": period, "time": update.time.strip(),
            "weekday": int(update.weekday), "mday": int(update.mday),
            "receivers": {k: str(v or "").strip()
                          for k, v in receivers.items()}}


@router.post("/run-report")
def run_report_now(owner_key: str | None = None):
    """手动触发一次定期报告发送（异步）。不传 owner_key 则发送全部。"""
    result = scheduler.trigger_report(owner_key)
    if result.get("status") == "running":
        raise HTTPException(status_code=409, detail="发送正在运行")
    return result


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
        "report": scheduler.get_report_config(),
        "workday_today": scheduler.is_workday(),
        "running": scheduler.is_running(),
        "owners": owners,
        "recent": recent,
    }


@router.post("/run")
def run_now(owner_key: str | None = None):
    """手动触发一次定期报告发送（异步，单消息汇总模式）。"""
    result = scheduler.trigger_report(None)
    if result.get("status") == "running":
        raise HTTPException(status_code=409, detail="报告发送正在运行")
    return result


@router.get("/preview")
def preview(owner_key: str | None = None):
    """返回当前会发送的 WeLink 内容预览（只构建，不实际发送）。

    不传 owner_key：返回真实发送形态——全 owner（enabled）汇总的
    单条消息（render_combined_text，窗口=当前周期全量）。
    传 owner_key：返回该 owner 的分节形态。
    空报告也会返回，但标记 empty=True（不会发送）。
    """
    try:
        config = scheduler.get_report_config()
        period_start = scheduler._period_start_utc(config["period"])
        label = scheduler._period_label(config["period"])
        if not owner_key:
            reports = build_reports(
                force=True, since=period_start.isoformat(),
                channel="xiaoluban-report").get("agents", [])
            enabled = [r for r in reports if r.get("enabled")]
            empty = (not enabled
                     or all(scheduler._is_empty(r) for r in enabled))
            return {
                "mode": "combined",
                "period": config["period"],
                "receiver": (config.get("receivers") or {}).get(
                    config["period"], ""),
                "empty": empty,
                "window": (enabled[0].get("window") if enabled else None),
                "text": render_combined_text(enabled, period_label=label),
            }
        reports = build_reports(owner_key=owner_key, force=True).get("agents", [])
        previews = []
        for report in reports:
            previews.append({
                "owner_key": report.get("owner_key"),
                "owner_kind": report.get("owner_kind"),
                "display_name": report.get("display_name"),
                "owner_name": report.get("owner_name"),
                "target_id": report.get("target_id"),
                "enabled": bool(report.get("enabled")),
                "empty": scheduler._is_empty(report),
                "window": report.get("window"),
                "text": render_text(report, period_label=label),
            })
        return {"previews": previews}
    except Exception as e:
        log("NOTIFY", f"构建发送预览失败: {e}")
        raise HTTPException(status_code=500, detail=f"构建发送预览失败: {e}")


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
