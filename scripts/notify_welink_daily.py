"""按 owner 拉取评测日报，通过本机 WeLink CLI 发送给负责人。

Owner 两类：
- ``agent:<agent_type>``：agent 日报（评测指标 + agent 责任问题单）
- ``resp:<responsibility>``：知识库 / 外部数据源 / 评测流程日报（只列问题单）

架构（离线脚本）：
    Windows 任务计划程序每天 09:00 执行本脚本
      -> GET  {base_url}/api/v2/notify/daily-report
             （eval 侧按 owner 汇总，窗口=该 owner 上次成功发送至今）
      -> welink-cli im send-to-user / send-to-group
      -> POST {base_url}/api/v2/notify/daily-report/ack

前置条件：
    1. 本机已安装 WeLink CLI 并完成 `welink-cli auth login`
    2. eval 系统设置页已配置 owner 负责人/群号
    3. 在 eval 系统设置页生成并保存「日报 API Token」，
       脚本用 --token 或本机环境变量 EVAL_NOTIFY_TOKEN 传入同一个值

用法：
    python notify_welink_daily.py --dry-run
    python notify_welink_daily.py
    python notify_welink_daily.py --agent argo --force
    python notify_welink_daily.py --owner resp:knowledge
    python notify_welink_daily.py --since 2026-11-11T00:00:00Z

Windows 任务计划程序示例（每天 09:00）：
    程序：python.exe
    参数：D:\\athena_eval_engine\\scripts\\notify_welink_daily.py
    起始于：D:\\athena_eval_engine
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

_DEFAULT_BASE_URL = os.environ.get(
    "EVAL_PUBLIC_URL", "http://chimera-g.icsl.huawei.com/eval").rstrip("/")
_DEFAULT_CLI = os.environ.get("WELINK_CLI", "welink-cli")
_SEND_RETRIES = 3


def _log(message: str, log_file: str | None = None) -> None:
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(line, flush=True)
    if log_file:
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def _http_json(url: str, method: str = "GET", body: dict | None = None,
               token: str = "", timeout: int = 60, retries: int = 3) -> dict:
    data = None
    headers = {}
    if token:
        headers["X-Notify-Token"] = token
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=headers,
                                         method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError,
                json.JSONDecodeError) as exc:
            last_err = exc
            if attempt + 1 < retries:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"请求失败 {method} {url}: {last_err}")


def _check_welink_auth(cli: str) -> bool:
    try:
        result = subprocess.run([cli, "auth", "status"], capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _log(f"WeLink CLI 不可用: {exc}")
        return False
    output = (result.stdout or "") + (result.stderr or "")
    lowered = output.lower()
    not_logged = any(token in lowered for token in
                     ("not logged", "not login", "未登录", "not authenticated",
                      "login required"))
    if result.returncode != 0 or not_logged:
        _log(f"WeLink CLI 未登录或不可用（returncode={result.returncode}）："
             f"{output.strip()[:300]}")
        return False
    return True


def _send_once(cli: str, report: dict, text: str) -> tuple[bool, str]:
    target_type = report.get("target_type") or "user"
    target_id = report.get("target_id") or ""
    if not target_id:
        return False, "target_id 为空"
    # CLI 用 \n 转义表示换行；避免把真实换行直接塞进参数
    escaped = text.replace("\\", "\\\\").replace("\n", "\\n")
    if target_type == "group":
        cmd = [cli, "im", "send-to-group", "--group-id", target_id,
               "--text", escaped]
    else:
        cmd = [cli, "im", "send-to-user", "--receiver", target_id,
               "--text", escaped]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0:
        return False, output[:500] or f"exit={result.returncode}"
    return True, output[:500]


def _send_with_retry(cli: str, report: dict, text: str,
                     log_file: str | None) -> tuple[bool, str]:
    last_detail = ""
    for attempt in range(_SEND_RETRIES):
        ok, detail = _send_once(cli, report, text)
        if ok:
            return True, detail
        last_detail = detail
        _log(f"发送失败 {report.get('owner_key')} "
             f"({attempt + 1}/{_SEND_RETRIES}): {detail}", log_file)
        if attempt + 1 < _SEND_RETRIES:
            time.sleep(2 * (attempt + 1))
    return False, last_detail


def _is_empty(report: dict) -> bool:
    if report.get("owner_kind") == "agent":
        ev = report.get("evaluations") or {}
        open_total = (report.get("open_issues") or {}).get("total", 0)
        return (ev.get("total", 0) == 0
                and not (report.get("new_issues") or [])
                and open_total == 0)
    totals = report.get("totals") or {}
    return totals.get("new", 0) == 0 and totals.get("open", 0) == 0


def main() -> int:
    parser = argparse.ArgumentParser(description="按 owner 发送评测日报到 WeLink")
    parser.add_argument("--base-url", default=_DEFAULT_BASE_URL)
    parser.add_argument("--agent", action="append", default=[],
                        help="只发送指定 agent，可重复（等价 --owner agent:<name>）")
    parser.add_argument("--owner", action="append", default=[],
                        help="只发送指定 owner_key，可重复（如 resp:knowledge）")
    parser.add_argument("--since", default=None,
                        help="窗口开始（ISO，默认=该 owner 上次成功发送时间）")
    parser.add_argument("--until", default=None, help="窗口结束（ISO，默认=now）")
    parser.add_argument("--force", action="store_true",
                        help="忽略上次发送记录（手动触发）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只打印不发送、不回写")
    parser.add_argument("--include-empty", action="store_true",
                        help="没有评测/问题时也发送")
    parser.add_argument("--token", default=os.environ.get("EVAL_NOTIFY_TOKEN", ""))
    parser.add_argument("--welink-cli", default=_DEFAULT_CLI)
    parser.add_argument("--log-file", default=None)
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    log_file = args.log_file

    if not args.dry_run and not _check_welink_auth(args.welink_cli):
        _log("请先执行 `welink-cli auth login` 扫码登录", log_file)
        return 2

    owner_keys: list[str | None] = []
    owner_keys.extend(f"agent:{a}" for a in args.agent)
    owner_keys.extend(args.owner)
    if not owner_keys:
        owner_keys = [None]

    reports: list[dict] = []
    for owner_key in owner_keys:
        q = {}
        if owner_key:
            q["owner_key"] = owner_key
        if args.force:
            q["force"] = "true"
        if args.since:
            q["since"] = args.since
        if args.until:
            q["until"] = args.until
        url = f"{base}/api/v2/notify/daily-report"
        if q:
            url += "?" + urllib.parse.urlencode(q)
        try:
            data = _http_json(url, token=args.token)
        except Exception as exc:
            _log(f"拉取日报失败 owner={owner_key or 'all'}: {exc}", log_file)
            return 1
        reports.extend(data.get("agents") or [])

    sent = skipped = failed = 0
    for report in reports:
        owner_key = report.get("owner_key", "")
        text = report.get("text") or ""
        if not report.get("enabled") or not report.get("target_id"):
            _log(f"跳过 {owner_key}: 未配置负责人/目标或未启用", log_file)
            skipped += 1
            continue
        if not args.include_empty and _is_empty(report):
            _log(f"跳过 {owner_key}: 窗口内无评测/问题单", log_file)
            skipped += 1
            continue

        _log(f"发送 {owner_key} -> {report.get('target_type')}:"
             f"{report.get('target_id')} ({len(text)} 字符)", log_file)
        if args.dry_run:
            print("-" * 60)
            print(text)
            print("-" * 60)
            continue

        ok, detail = _send_with_retry(args.welink_cli, report, text, log_file)
        ack_body = {
            "owner_key": owner_key,
            "window_start": (report.get("window") or {}).get("start", ""),
            "window_end": (report.get("window") or {}).get("end", ""),
            "recipient": report.get("target_id", ""),
            "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest()[:32],
            "status": "sent" if ok else "failed",
            "error": None if ok else detail,
        }
        try:
            _http_json(f"{base}/api/v2/notify/daily-report/ack",
                       method="POST", body=ack_body, token=args.token)
        except Exception as exc:
            _log(f"回写发送状态失败 {owner_key}: {exc}", log_file)
        if ok:
            sent += 1
            _log(f"发送成功 {owner_key}", log_file)
        else:
            failed += 1
            _log(f"发送失败 {owner_key}: {detail}", log_file)

    _log(f"完成：sent={sent} skipped={skipped} failed={failed}", log_file)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
