"""从 HR 工作日历同步节假日/调休到 eval（本机运行）。

HR 日历接口需要个人 SSO Cookie，只能在已登录 HR 的本机调用。
Cookie 只从本地文件/环境变量读取，不上传、不写库；eval 只接收日期列表。

用法：
    1. 浏览器打开 https://hr.huawei.com/ ，F12 -> Network
       找 queryHolidayCalendarDetails 请求，复制完整 Cookie 值
    2. 保存到 scripts/hr-cookie.txt（已在 .gitignore）
    3. 运行：
         python scripts\\sync_hr_calendar.py --dry-run
         python scripts\\sync_hr_calendar.py

两套环境：
    python scripts\\sync_hr_calendar.py --base-url http://chimera-g.icsl.huawei.com/eval
    python scripts\\sync_hr_calendar.py --base-url http://chimera-y.icsl.huawei.com/eval
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path

HR_API = ("https://kylin.huawei.com/eks-gw/"
          "com.huawei.hr.hcm.attendance:attendanceDocument/"
          "attendanceDocument/services/v1/attendance/homePage/"
          "queryHolidayCalendarDetails")

_DEFAULT_BASE = os.environ.get(
    "EVAL_PUBLIC_URL", "http://chimera-g.icsl.huawei.com/eval").rstrip("/")
_DEFAULT_COOKIE_FILE = Path(__file__).resolve().parent / "hr-cookie.txt"

# 不发送：周末休息日 + 法定假期
HOLIDAY_TYPES = {"休息日", "法定假期"}
# 发送：月末周六（华为工作日）+ 补班
WORKDAY_TYPES = {"月末周六", "补班"}


def _load_cookie(cli_value: str | None, cookie_file: str) -> str:
    if cli_value:
        return cli_value.strip()
    env = os.environ.get("HR_COOKIE", "").strip()
    if env:
        return env
    path = Path(cookie_file) if cookie_file else _DEFAULT_COOKIE_FILE
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return ""


def _fetch(cookie: str, begin: str, end: str, calendar_id: int) -> list[dict]:
    payload = {
        "holidayCalendarId": calendar_id,
        "holidayDateBegin": begin,
        "holidayDateEnd": end,
        "platform": "PC",
        "locale": "zh_CN",
    }
    req = urllib.request.Request(
        HR_API,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://hr.huawei.com",
            "Referer": "https://hr.huawei.com/",
            "Cookie": cookie,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"HR 接口 HTTP {exc.code}: {body}") from exc


def _parse(items: list[dict]) -> tuple[list[str], list[str]]:
    holidays: set[str] = set()
    workdays: set[str] = set()
    for item in items:
        day = str(item.get("holidayDate") or "").strip()
        kind = str(item.get("holidayType") or "").strip()
        if not day:
            continue
        if kind in WORKDAY_TYPES:
            workdays.add(day)
        elif kind in HOLIDAY_TYPES:
            holidays.add(day)
    # 同一天既在休息日又在月末周六时，以工作日为准
    holidays -= workdays
    return sorted(holidays), sorted(workdays)


def _push(base_url: str, holidays: list[str], workdays: list[str],
          token: str) -> dict:
    url = f"{base_url.rstrip('/')}/api/v2/notify/workdays"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Notify-Token"] = token
    req = urllib.request.Request(
        url,
        data=json.dumps({"holidays": holidays, "workdays": workdays}).encode("utf-8"),
        headers=headers,
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    today = date.today()
    parser = argparse.ArgumentParser(description="同步 HR 工作日历到 eval")
    parser.add_argument("--base-url", default=_DEFAULT_BASE)
    parser.add_argument("--cookie", default=None,
                        help="HR Cookie（默认读环境变量 HR_COOKIE 或 "
                             "scripts/hr-cookie.txt）")
    parser.add_argument("--cookie-file", default=str(_DEFAULT_COOKIE_FILE))
    parser.add_argument("--calendar-id", type=int, default=55)
    parser.add_argument("--begin", default=today.replace(day=1).isoformat())
    parser.add_argument("--end",
                        default=(today + timedelta(days=730)).isoformat())
    parser.add_argument("--token", default="",
                        help="eval API token（当前 /workdays 不鉴权，可留空）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只打印，不写入 eval")
    args = parser.parse_args()

    cookie = _load_cookie(args.cookie, args.cookie_file)
    if not cookie:
        print("HR Cookie 未配置：请保存到 scripts/hr-cookie.txt，"
              "或设置 HR_COOKIE，或传 --cookie", file=sys.stderr)
        return 2

    try:
        items = _fetch(cookie, args.begin, args.end, args.calendar_id)
    except Exception as exc:
        print(f"拉取 HR 日历失败: {exc}", file=sys.stderr)
        return 1

    holidays, workdays = _parse(items)
    print(f"HR 日历 {args.begin} ~ {args.end}: "
          f"不发送 {len(holidays)} 天, 上班 {len(workdays)} 天")
    print(f"  不发送示例: {holidays[:5]}")
    print(f"  上班示例: {workdays[:5]}")

    if args.dry_run:
        print(json.dumps({"holidays": holidays, "workdays": workdays},
                         ensure_ascii=False, indent=2))
        return 0

    try:
        result = _push(args.base_url, holidays, workdays, args.token)
    except Exception as exc:
        print(f"写入 eval 失败: {exc}", file=sys.stderr)
        return 1
    print(f"已写入 {args.base_url}: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
