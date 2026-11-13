"""日报定时发送（eval 服务端）。

每天 09:00（Asia/Shanghai）按 owner 构建日报，通过小鲁班发送。
发送成功后写 notification_log；窗口从该 owner 上次成功发送时间开始。

单 worker 部署（Dockerfile --workers 1），进程内 _last_run_date 防重复；
run_daily 里再按 last_sent_at 做一次跨重启去重。
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, time as dt_time, timedelta, timezone

from . import xiaoluban
from .daily_report import (
    build_reports,
    content_hash,
    last_sent_at,
    record_send,
    render_text,
)
from ..infra.log_util import log

_DAILY_TIME = "09:00"
_last_run_date: str | None = None
_lock = threading.Lock()


def _now_local() -> datetime:
    return datetime.now(timezone(timedelta(hours=8)))


def _today_start_utc() -> datetime:
    """今天 09:00（北京时间）对应的 UTC naive 时间。"""
    local = datetime.combine(_now_local().date(), dt_time(9, 0))
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


def run_daily(force: bool = False) -> dict:
    """构建并发送所有 owner 的日报，返回统计。"""
    global _last_run_date
    with _lock:
        token = xiaoluban.get_token()
        if not token:
            log("NOTIFY", "小鲁班 token 未配置，跳过日报发送")
            return {"sent": 0, "skipped": 0, "failed": 0, "error": "no_token"}

        today_start = _today_start_utc()
        sent = skipped = failed = 0
        reports = build_reports(force=force).get("agents", [])
        for report in reports:
            owner_key = report.get("owner_key", "")
            receiver = report.get("target_id") or ""
            if not report.get("enabled") or not receiver:
                skipped += 1
                continue
            if not force:
                last = last_sent_at(owner_key)
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
                owner_key, receiver,
                window.get("start", ""), window.get("end", ""),
                content_hash(text),
                "sent" if ok else "failed",
                None if ok else detail,
            )
            if ok:
                sent += 1
                log("NOTIFY", f"日报发送成功: {owner_key} -> {receiver}")
            else:
                failed += 1
                log("NOTIFY", f"日报发送失败: {owner_key} -> {receiver}: {detail}")

        _last_run_date = _now_local().strftime("%Y-%m-%d")
        log("NOTIFY", f"日报发送完成: sent={sent} skipped={skipped} failed={failed}")
        return {"sent": sent, "skipped": skipped, "failed": failed}


def schedule_loop(stop_event: threading.Event | None = None) -> None:
    """后台线程：每天 09:00 触发 run_daily。"""
    log("NOTIFY", f"日报定时线程启动，每天 {_DAILY_TIME}（Asia/Shanghai）")
    while True:
        if stop_event is not None and stop_event.is_set():
            log("NOTIFY", "日报定时线程停止")
            return
        now = _now_local()
        today = now.strftime("%Y-%m-%d")
        if now.strftime("%H:%M") == _DAILY_TIME and _last_run_date != today:
            try:
                run_daily()
            except Exception as e:
                log("NOTIFY", f"日报发送异常: {e}")
                # 避免同一分钟反复重试刷日志；下一个自然日再试
                _last_run_date = today
        time.sleep(30)
