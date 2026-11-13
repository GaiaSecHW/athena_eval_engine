"""日报定时发送（eval 服务端）。

每天按配置时间（默认 09:00，Asia/Shanghai）构建日报，通过小鲁班发送。
发送成功后写 notification_log；窗口从该 owner 上次成功发送时间开始。

单 worker 部署（Dockerfile --workers 1），进程内 _last_run_date 防重复；
run_daily 里再按 last_sent_at 做一次跨重启去重。
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import date, datetime, time as dt_time, timedelta, timezone

from . import xiaoluban
from .daily_report import (
    build_reports,
    content_hash,
    last_sent_at,
    record_send,
    render_text,
)
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

_DAILY_TIME_DEFAULT = "09:00"
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

_last_run_date: str | None = None
_lock = threading.Lock()
_running = False
_run_guard = threading.Lock()

_daily_time_cache: tuple[float, str] | None = None
_DAILY_TIME_CACHE_SECONDS = 60.0


def _now_local() -> datetime:
    return datetime.now(timezone(timedelta(hours=8)))


def get_daily_time() -> str:
    """读取 system_config.notify_daily_time（默认 09:00），60s 缓存。"""
    global _daily_time_cache
    now = time.monotonic()
    if (_daily_time_cache
            and now - _daily_time_cache[0] < _DAILY_TIME_CACHE_SECONDS):
        return _daily_time_cache[1]

    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='notify_daily_time'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    value = _db_query(_do) or _DAILY_TIME_DEFAULT
    if not _TIME_RE.match(value):
        value = _DAILY_TIME_DEFAULT
    _daily_time_cache = (now, value)
    return value


_workday_cache: tuple[float, set[str], set[str]] | None = None
_WORKDAY_CACHE_SECONDS = 60.0


def get_workday_config() -> tuple[set[str], set[str]]:
    """返回 (节假日集合, 调休上班集合)，日期格式 YYYY-MM-DD。"""
    global _workday_cache
    now = time.monotonic()
    if (_workday_cache
            and now - _workday_cache[0] < _WORKDAY_CACHE_SECONDS):
        return _workday_cache[1], _workday_cache[2]

    def _do(cur):
        cur.execute("SELECT calendar_date, day_type FROM notify_calendar")
        return cur.fetchall()

    holidays: set[str] = set()
    workdays: set[str] = set()
    for calendar_date, day_type in _db_query(_do):
        key = (calendar_date.strftime("%Y-%m-%d")
               if hasattr(calendar_date, "strftime") else str(calendar_date))
        if day_type == "workday":
            workdays.add(key)
        elif day_type == "holiday":
            holidays.add(key)
    holidays -= workdays
    _workday_cache = (now, holidays, workdays)
    return holidays, workdays


def invalidate_caches() -> None:
    """配置修改后立即失效，下一次循环生效。"""
    global _daily_time_cache, _workday_cache
    _daily_time_cache = None
    _workday_cache = None


def is_workday(d: date | None = None) -> bool:
    """默认周一到周五；节假日排除，调休上班的周末算工作日。"""
    d = d or _now_local().date()
    holidays, workdays = get_workday_config()
    key = d.strftime("%Y-%m-%d")
    if key in workdays:
        return True
    if key in holidays:
        return False
    return d.weekday() < 5


def _today_start_utc() -> datetime:
    """今天配置时间（北京时间）对应的 UTC naive 时间。"""
    hh, mm = get_daily_time().split(":")
    local = datetime.combine(_now_local().date(), dt_time(int(hh), int(mm)))
    return local - timedelta(hours=8)


def _is_empty(report: dict) -> bool:
    if report.get("owner_kind") == "agent":
        ev = report.get("evaluations") or {}
        open_total = (report.get("open_issues") or {}).get("total", 0)
        return (ev.get("total", 0) == 0
                and not (report.get("new_issues") or [])
                and open_total == 0)
    totals = report.get("totals") or {}
    return totals.get("new", 0) == 0 and totals.get("open", 0) == 0


def is_running() -> bool:
    return _running


def run_daily(force: bool = False, owner_key: str | None = None,
              scheduled: bool = True) -> dict:
    """构建并发送日报，返回统计。"""
    global _last_run_date
    with _lock:
        if scheduled and not is_workday():
            log("NOTIFY", "今天非工作日，跳过日报发送")
            return {"sent": 0, "skipped": 0, "failed": 0, "error": "holiday"}

        token = xiaoluban.get_token()
        if not token:
            log("NOTIFY", "小鲁班 token 未配置，跳过日报发送")
            return {"sent": 0, "skipped": 0, "failed": 0, "error": "no_token"}

        today_start = _today_start_utc()
        sent = skipped = failed = 0
        reports = build_reports(
            owner_key=owner_key, force=force).get("agents", [])
        for report in reports:
            owner = report.get("owner_key", "")
            receiver = report.get("target_id") or ""
            if not report.get("enabled") or not receiver:
                skipped += 1
                continue
            if not force:
                last = last_sent_at(owner)
                if last is not None and last >= today_start:
                    skipped += 1
                    continue
            if _is_empty(report):
                skipped += 1
                continue

            text = render_text(report)
            ok, detail = xiaoluban.send_message(receiver, text, token=token)
            window = report.get("window") or {}
            record_send(
                owner, receiver,
                window.get("start", ""), window.get("end", ""),
                content_hash(text),
                "sent" if ok else "failed",
                None if ok else detail,
            )
            if ok:
                sent += 1
                log("NOTIFY", f"日报发送成功: {owner} -> {receiver}")
            else:
                failed += 1
                log("NOTIFY", f"日报发送失败: {owner} -> {receiver}: {detail}")

        if scheduled:
            _last_run_date = _now_local().strftime("%Y-%m-%d")
        log("NOTIFY", f"日报发送完成: sent={sent} skipped={skipped} failed={failed}")
        return {"sent": sent, "skipped": skipped, "failed": failed}


def trigger_run(owner_key: str | None = None) -> dict:
    """手动触发一次发送（异步），返回启动状态。"""
    global _running
    with _run_guard:
        if _running or _lock.locked():
            return {"status": "running"}
        _running = True

    def _worker():
        global _running
        try:
            run_daily(force=True, owner_key=owner_key, scheduled=False)
        except Exception as e:
            log("NOTIFY", f"手动日报发送异常: {e}")
        finally:
            with _run_guard:
                _running = False

    threading.Thread(target=_worker, name="notify-manual", daemon=True).start()
    return {"status": "started", "owner_key": owner_key}


def schedule_loop(stop_event: threading.Event | None = None) -> None:
    """后台线程：每天配置时间触发 run_daily。"""
    log("NOTIFY", f"日报定时线程启动，每天 {get_daily_time()}（Asia/Shanghai）")
    while True:
        if stop_event is not None and stop_event.is_set():
            log("NOTIFY", "日报定时线程停止")
            return
        now = _now_local()
        today = now.strftime("%Y-%m-%d")
        daily_time = get_daily_time()
        if now.strftime("%H:%M") == daily_time and _last_run_date != today:
            if not is_workday(now.date()):
                log("NOTIFY", f"今天非工作日，跳过 {today} 日报发送")
                _last_run_date = today
                time.sleep(30)
                continue
            try:
                run_daily()
            except Exception as e:
                log("NOTIFY", f"日报发送异常: {e}")
                # 避免同一分钟反复重试刷日志；下一个自然日再试
                _last_run_date = today
        time.sleep(30)
