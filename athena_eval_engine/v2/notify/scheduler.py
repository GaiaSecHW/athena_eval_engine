"""定期报告定时发送（eval 服务端）。

x 报 = 日报/周报/月报（周期可配置，notify_report_period），按配置时间
（默认 09:00，Asia/Shanghai，回退旧 notify_daily_time）构建全 owner 汇总
的单条消息，通过小鲁班发到该周期单独配置的接收群。
发送成功后写 notification_log（通道 xiaoluban-report，owner=__combined__）。

单 worker 部署（Dockerfile --workers 1），进程内 _report_try_date 防重复
（每天只尝试一次）；周期级去重按 last_sent_at 跨重启兜底。
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import date, datetime, time as dt_time, timedelta, timezone

from . import xiaoluban
from .daily_report import (
    _CHANNEL_REPORT,
    _parse_dt,
    build_reports,
    content_hash,
    get_public_url,
    last_sent_at,
    record_send,
    render_leader_text,
)
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

_DAILY_TIME_DEFAULT = "09:00"
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

_last_run_date: str | None = None   # 兼容保留（旧日报机制已并入 x 报）
_report_try_date: str | None = None
_lock = threading.Lock()
_running = False
_run_guard = threading.Lock()

_DAILY_TIME_CACHE_SECONDS = 60.0


def _now_local() -> datetime:
    return datetime.now(timezone(timedelta(hours=8)))


# ── 定期报告配置（notify_report_period / time / weekday / mday / receiver_*）──
# 周期可配置：daily（每天）/ weekly（每周）/ monthly（每月）。
# weekday 用 ISO 星期（1=周一…7=周日）；mday 用月中日期（1-31，
# 超过当月天数按当月最后一天算）。
# 每种周期单独配置接收群（notify_report_receiver_daily/weekly/monthly）：
# x 报为单消息模式——全 owner 汇总一条，发到当前周期的接收群。
_REPORT_PERIODS = ("daily", "weekly", "monthly")
_REPORT_DEFAULTS = {"period": "weekly", "time": _DAILY_TIME_DEFAULT,
                    "weekday": 1, "mday": 1}
_REPORT_OWNER_KEY = "__combined__"
_report_config_cache: tuple[float, dict] | None = None


def get_report_config() -> dict:
    """读取定期报告配置，60s 缓存。

    返回 {"period": daily/weekly/monthly, "time": "HH:MM",
          "weekday": 1-7, "mday": 1-31,
          "receivers": {"daily": "", "weekly": "", "monthly": ""}}；
    默认每周一 09:00，接收群默认未配置（未配置则不发送）。
    """
    global _report_config_cache
    now = time.monotonic()
    if (_report_config_cache
            and now - _report_config_cache[0] < _DAILY_TIME_CACHE_SECONDS):
        return dict(_report_config_cache[1])

    def _do(cur):
        cur.execute(
            "SELECT config_key, config_value FROM system_config "
            "WHERE config_key IN ('notify_report_period', "
            "'notify_report_time', 'notify_daily_time', "
            "'notify_report_weekday', "
            "'notify_report_mday', 'notify_report_receiver_daily', "
            "'notify_report_receiver_weekly', "
            "'notify_report_receiver_monthly')")
        return {k: v for k, v in cur.fetchall()}

    cfg = _db_query(_do) or {}
    period = str(cfg.get("notify_report_period")
                 or _REPORT_DEFAULTS["period"]).strip().lower()
    if period not in _REPORT_PERIODS:
        period = _REPORT_DEFAULTS["period"]
    # 时间回退链：notify_report_time → notify_daily_time（旧日报配置兼容
    # 迁移——日报就是 period=daily 的 x 报，旧的发送时间继续生效）
    time_value = str(cfg.get("notify_report_time")
                     or cfg.get("notify_daily_time")
                     or _REPORT_DEFAULTS["time"]).strip()
    if not _TIME_RE.match(time_value):
        time_value = _REPORT_DEFAULTS["time"]

    def _int_or(key: str, default: int, lo: int, hi: int) -> int:
        try:
            v = int(cfg.get(key) or default)
        except (TypeError, ValueError):
            v = default
        return v if lo <= v <= hi else default

    weekday = _int_or("notify_report_weekday", 1, 1, 7)
    mday = _int_or("notify_report_mday", 1, 1, 31)
    receivers = {p: str(cfg.get(f"notify_report_receiver_{p}") or "").strip()
                 for p in _REPORT_PERIODS}
    result = {"period": period, "time": time_value,
              "weekday": weekday, "mday": mday, "receivers": receivers}
    _report_config_cache = (now, dict(result))
    return result


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
    global _workday_cache, _report_config_cache
    _workday_cache = None
    _report_config_cache = None
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


def _week_start_utc() -> datetime:
    """本周一 00:00（Asia/Shanghai）对应的 UTC naive 时间。"""
    local = _now_local()
    monday = local.date() - timedelta(days=local.date().weekday())
    week_start_local = datetime.combine(monday, dt_time(0, 0))
    return week_start_local - timedelta(hours=8)


def _period_start_utc(period: str) -> datetime:
    """当前周期起点（Asia/Shanghai → UTC）。

    定期报告的去重窗口与统计窗口：本周期已发送过则跳过。

    日报（daily）窗口=当天 00:00，**向前跨越连续非工作日**——周末/
    节假日不发日报，其数据在下一个工作日的日报中体现（周一窗口=
    周六 00:00 起，覆盖整个周末），不丢通知也不依赖增量窗口。
    """
    local = _now_local()
    if period == "daily":
        d = local.date()
        # 向前跨过连续非工作日（含周末/节假日），最多回看 60 天防死循环
        for _ in range(60):
            if is_workday(d - timedelta(days=1)):
                break
            d = d - timedelta(days=1)
        start_local = datetime.combine(d, dt_time(0, 0))
    elif period == "monthly":
        start_local = datetime.combine(local.date().replace(day=1), dt_time(0, 0))
    else:
        monday = local.date() - timedelta(days=local.date().weekday())
        start_local = datetime.combine(monday, dt_time(0, 0))
    return start_local - timedelta(hours=8)


def _period_label(period: str) -> str:
    return {"daily": "日报", "weekly": "周报", "monthly": "月报"}.get(
        period, "周报")


def _report_due_today(now: datetime, config: dict) -> bool:
    """今天是否到达定期报告的触发日（含）。

    - daily：每天；
    - weekly：ISO 星期 >= 配置 weekday；
    - monthly：日期 >= 配置 mday（mday 超过当月天数时按当月最后一天）。
    """
    period = config.get("period", "weekly")
    if period == "daily":
        return True
    if period == "weekly":
        return now.isoweekday() >= int(config.get("weekday", 1))
    # monthly
    mday = int(config.get("mday", 1))
    import calendar
    _, days_in_month = calendar.monthrange(now.year, now.month)
    effective = min(mday, days_in_month)
    return now.day >= effective


def _is_empty(report: dict) -> bool:
    """所有指标都是 0/NA 且没有新增问题单时，当天不发送。

    未关闭问题单只做附带展示，不作为是否发送的判定条件。
    """
    if report.get("owner_kind") == "agent":
        ev = report.get("evaluations") or {}
        if int(ev.get("failed") or 0) > 0:
            return False
        if report.get("new_issues"):
            return False
        for key in ("tp", "fp", "fn", "tn"):
            if int(ev.get(key) or 0) > 0:
                return False
        for key in ("fpr", "precision"):
            value = ev.get(key)
            if value is not None and float(value) != 0:
                return False
        return True
    totals = report.get("totals") or {}
    return int(totals.get("new") or 0) == 0


def is_running() -> bool:
    return _running


def run_report(force: bool = False, owner_key: str | None = None,
               period: str | None = None) -> dict:
    """构建并发送定期报告（日报/周报/月报），返回统计。

    单消息模式：全 owner（enabled）汇总成一条消息，发送到**当前周期
    单独配置的接收群**（notify_report_receiver_daily/weekly/monthly）——
    不是每个 owner 各发一条。

    - 周期可配置（notify_report_period：daily/weekly/monthly），
      标题按周期（日报/周报/月报）；传 ``period`` 可临时覆盖（手动触发某一期）；
    - 内容=该周期的全量汇总（日报=当天全部、周报=本周全部、
      月报=本月全部），显式窗口=周期起点 → 现在，不是增量；
    - 通道/窗口跟踪独立（xiaoluban-report），周期级去重
      （owner_key=__combined__）：本周期已发送过则跳过（force 可重发）；
    - 全部 owner 空报告时不发送；接收群未配置时不发送。
    """
    config = get_report_config()
    period = str(period or config["period"]).lower()
    if period not in ("daily", "weekly", "monthly"):
        period = config["period"]
    label = _period_label(period)
    token = xiaoluban.get_token()
    if not token:
        log("NOTIFY", "小鲁班 token 未配置，跳过定期报告发送")
        return {"sent": 0, "skipped": 0, "failed": 0, "error": "no_token"}

    receiver = (config.get("receivers") or {}).get(period, "")
    if not receiver:
        log("NOTIFY", f"{label}接收群未配置"
                      f"（notify_report_receiver_{period}），跳过发送")
        return {"sent": 0, "skipped": 0, "failed": 0, "error": "no_receiver"}

    period_start = _period_start_utc(period)
    if not force:
        last = last_sent_at(_REPORT_OWNER_KEY, _CHANNEL_REPORT)
        if last is not None and last >= period_start:
            log("NOTIFY", f"{label}本周期已发送过，跳过")
            return {"sent": 0, "skipped": 1, "failed": 0, "error": "dedup"}

    # 内容=该周期的全量汇总（日报=当天全部、周报=本周全部、月报=本月全部），
    # 不是「上次发送以来的增量」——显式 since 覆盖 build_reports 的
    # per-owner 增量窗口。
    reports = build_reports(
        owner_key=None, force=force,
        since=period_start.isoformat(),
        channel=_CHANNEL_REPORT).get("agents", [])
    enabled_reports = [r for r in reports if r.get("enabled")]
    # 没数据的 owner 不进汇总消息——判空口径：本周期无评测、无新增
    # 问题单、无指标，**且未关闭问题单为 0**（未关闭数也算数据：
    # 有存量待办就显示，只有彻底没有任何数据才整节省略）
    def _no_data_at_all(r: dict) -> bool:
        if not _is_empty(r):
            return False
        open_map = r.get("open_issues") or {}
        open_count = int(open_map.get("count",
                                      open_map.get("total", 0)) or 0)
        return open_count <= 0

    non_empty_reports = [r for r in enabled_reports
                         if not _no_data_at_all(r)]
    if not non_empty_reports:
        log("NOTIFY", f"{label}全部 owner 空报告，跳过发送")
        return {"sent": 0, "skipped": 1, "failed": 0, "error": "empty"}

    # x 报只发一条（领导视角：误报率趋势 → 根因分布 → 修复进展 → 欠账）。
    # 不再发责任明细：owner 看板自行处理，日报/周报/月报不打扰责任人。
    window = non_empty_reports[0].get("window") or {}
    until = (_parse_dt(window.get("end"))
             or datetime.now(timezone.utc).replace(tzinfo=None))
    text = render_leader_text(
        label, period_start, until, get_public_url())
    ok, detail = xiaoluban.send_message(receiver, text, token=token)
    record_send(
        _REPORT_OWNER_KEY, receiver,
        window.get("start", ""), window.get("end", ""),
        content_hash(text),
        "sent" if ok else "failed",
        None if ok else detail,
        channel=_CHANNEL_REPORT,
    )
    if ok:
        log("NOTIFY", f"{label}发送成功 -> {receiver}")
        return {"sent": 1, "skipped": 0, "failed": 0}
    log("NOTIFY", f"{label}发送失败 -> {receiver}: {detail}")
    return {"sent": 0, "skipped": 0, "failed": 1, "error": detail}


def trigger_report(owner_key: str | None = None,
                   period: str | None = None) -> dict:
    """手动触发一次定期报告发送（异步），返回启动状态。"""
    global _running
    with _run_guard:
        if _running or _lock.locked():
            return {"status": "running"}
        _running = True

    def _worker():
        global _running
        try:
            run_report(force=True, owner_key=owner_key, period=period)
        except Exception as e:
            log("NOTIFY", f"手动定期报告发送异常: {e}")
        finally:
            with _run_guard:
                _running = False

    threading.Thread(target=_worker, name="notify-report-manual",
                     daemon=True).start()
    return {"status": "started", "owner_key": owner_key}


def schedule_loop(stop_event: threading.Event | None = None) -> None:
    """后台线程：定期报告（x 报=日报/周报/月报，周期可配置）触发 run_report。

    注意：必须声明 global _report_try_date。函数体内有赋值，缺 global 时
    Python 会把它当局部变量，首次读取就抛 UnboundLocalError，定时线程
    直接退出。
    """
    global _report_try_date
    log("NOTIFY", "定期报告定时线程启动（x 报=日报/周报/月报，周期可配置）")
    while True:
        if stop_event is not None and stop_event.is_set():
            log("NOTIFY", "定期报告定时线程停止")
            return
        now = _now_local()
        today = now.strftime("%Y-%m-%d")
        # 到达配置周期触发日（含）之后的每个工作日、且本周期尚未发送过
        # （周期级去重兜底），在配置时间那一分钟触发一次；配置日遇节假日
        # 自然顺延到下一个工作日补发。_report_try_date 保证每天只尝试一次。
        report_config = get_report_config()
        if (now.strftime("%H:%M") == report_config["time"]
                and _report_due_today(now, report_config)
                and _report_try_date != today):
            _report_try_date = today
            if not is_workday(now.date()):
                log("NOTIFY", f"今天非工作日，跳过 {today} 定期报告发送（顺延）")
            else:
                try:
                    run_report()
                except Exception as e:
                    log("NOTIFY", f"定期报告发送异常: {e}")
        time.sleep(30)
