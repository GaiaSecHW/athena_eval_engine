"""按 owner 拉取评测日报，通过小鲁班 API 发送到 WeLink。

发送方式：小鲁班 HTTP 接口（无需安装 WeLink CLI、无需扫码）
    POST http://xiaoluban.rnd.huawei.com:80/
    {"content": "...", "receiver": "工号或群号", "auth": "小鲁班 token"}

Owner 两类：
- ``agent:<agent_type>``：agent 日报（评测指标 + agent 责任问题单）
- ``resp:<responsibility>``：知识库 / 外部数据源 / 评测流程日报（只列问题单）

流程：
    Windows 任务计划程序每天 09:00 执行本脚本
      -> GET  {base_url}/api/v2/notify/daily-report
             （eval 侧按 owner 汇总，窗口=该 owner 上次成功发送至今）
      -> 小鲁班 API 发送（超过 4000 字符自动分条）
      -> POST {base_url}/api/v2/notify/daily-report/ack

前置条件：
    1. 在 WeLink 里找「小鲁班」，发送“获取发送token”，拿到 token
    2. token 放到脚本同目录的 xiaoluban-token.txt，或设置环境变量
       XIAOLUBAN_TOKEN，或用 --xiaoluban-token 传入
    3. eval 系统设置页已配置 owner 负责人/群号，并生成日报 API Token
    4. 脚本用 --token 或本机环境变量 EVAL_NOTIFY_TOKEN 传日报 API Token

用法：
    python notify_welink_daily.py --dry-run
    python notify_welink_daily.py
    python notify_welink_daily.py --agent argo --force
    python notify_welink_daily.py --owner resp:knowledge
    python notify_welink_daily.py --since 2026-11-12T00:00:00Z

两套环境（各跑一个任务，用各自的 base-url / token）：
    green : --base-url http://chimera-g.icsl.huawei.com/eval --token <green token>
    yellow: --base-url http://chimera-y.icsl.huawei.com:8888/eval --token <yellow token>
    环境标识在各自 /eval/system 页面配置（green / yellow），日报标题会自动带上。

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
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

_DEFAULT_BASE_URL = os.environ.get(
    "EVAL_PUBLIC_URL", "http://chimera-g.icsl.huawei.com/eval").rstrip("/")
_DEFAULT_XIAOLUBAN_URL = os.environ.get(
    "XIAOLUBAN_URL", "http://xiaoluban.rnd.huawei.com:80/")
_DEFAULT_TOKEN_FILE = Path(__file__).resolve().parent / "xiaoluban-token.txt"
_SEND_RETRIES = 3
_MAX_CHARS = 3800  # 小鲁班建议 4000 以内，留一点余量


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


def _load_xiaoluban_token(cli_token: str | None, token_file: str) -> str:
    if cli_token:
        return cli_token.strip()
    env = os.environ.get("XIAOLUBAN_TOKEN", "").strip()
    if env:
        return env
    path = Path(token_file) if token_file else _DEFAULT_TOKEN_FILE
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return ""


def _split_text(text: str, limit: int = _MAX_CHARS) -> list[str]:
    """按行切分，保证每段不超过 limit；单行超长时硬切。"""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in text.splitlines():
        # 单行本身超长：先收尾当前段，再硬切这一行
        if len(line) > limit:
            if current:
                chunks.append("\n".join(current))
                current, current_len = [], 0
            for i in range(0, len(line), limit):
                chunks.append(line[i:i + limit])
            continue
        add = len(line) + (1 if current else 0)
        if current and current_len + add > limit:
            chunks.append("\n".join(current))
            current, current_len = [line], len(line)
        else:
            current.append(line)
            current_len += add
    if current:
        chunks.append("\n".join(current))
    return chunks


def _send_xiaoluban_once(url: str, auth: str, receiver: str,
                         content: str) -> tuple[bool, str, bool]:
    """发送一条消息，返回 (成功, 详情, 是否鉴权失败)。"""
    payload = {"content": content, "receiver": receiver, "auth": auth}
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:300]}"
        return False, detail, exc.code in (401, 403)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, str(exc), False

    try:
        data = json.loads(body)
    except ValueError:
        return True, body[:300], False
    if isinstance(data, dict) and data.get("code") not in (None, 0, "0"):
        msg = str(data.get("msg") or data)
        auth_failed = "401" in msg or "auth" in msg.lower() or "token" in msg.lower()
        return False, msg[:300], auth_failed
    return True, body[:300], False


def _send_with_retry(url: str, auth: str, receiver: str, content: str,
                     log_file: str | None) -> tuple[bool, str]:
    last_detail = ""
    for attempt in range(_SEND_RETRIES):
        ok, detail, auth_failed = _send_xiaoluban_once(
            url, auth, receiver, content)
        if ok:
            return True, detail
        last_detail = detail
        _log(f"发送失败 ({attempt + 1}/{_SEND_RETRIES}): {detail}", log_file)
        if auth_failed:
            _log("小鲁班 token 可能已失效，请在 WeLink 找小鲁班重新发送"
                 "“获取发送token”", log_file)
            return False, detail
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
    parser = argparse.ArgumentParser(description="按 owner 发送评测日报到 WeLink（小鲁班）")
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
    parser.add_argument("--token", default=os.environ.get("EVAL_NOTIFY_TOKEN", ""),
                        help="eval 日报 API token")
    parser.add_argument("--xiaoluban-url", default=_DEFAULT_XIAOLUBAN_URL)
    parser.add_argument("--xiaoluban-token", default=None,
                        help="小鲁班 token（默认读环境变量 XIAOLUBAN_TOKEN "
                             "或脚本同目录 xiaoluban-token.txt）")
    parser.add_argument("--xiaoluban-token-file", default=str(_DEFAULT_TOKEN_FILE))
    parser.add_argument("--max-chars", type=int, default=_MAX_CHARS,
                        help="单条消息最大字符数（默认 3800）")
    parser.add_argument("--log-file", default=None)
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    log_file = args.log_file

    xl_token = _load_xiaoluban_token(args.xiaoluban_token,
                                     args.xiaoluban_token_file)
    if not xl_token and not args.dry_run:
        _log("小鲁班 token 未配置：请放到脚本同目录 xiaoluban-token.txt，"
             "或设置 XIAOLUBAN_TOKEN，或传 --xiaoluban-token", log_file)
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
        receiver = report.get("target_id") or ""
        if not report.get("enabled") or not receiver:
            _log(f"跳过 {owner_key}: 未配置负责人/目标或未启用", log_file)
            skipped += 1
            continue
        if not args.include_empty and _is_empty(report):
            _log(f"跳过 {owner_key}: 窗口内无评测/问题单", log_file)
            skipped += 1
            continue

        chunks = _split_text(text, max(500, args.max_chars))
        total = len(chunks)
        _log(f"发送 {owner_key} -> {receiver} "
             f"({len(text)} 字符, {total} 条)", log_file)
        if args.dry_run:
            for i, chunk in enumerate(chunks, 1):
                print("-" * 60)
                print(f"[{i}/{total}]")
                print(chunk)
            print("-" * 60)
            continue

        ok_all = True
        last_detail = ""
        for i, chunk in enumerate(chunks, 1):
            content = f"（{i}/{total}）\n{chunk}" if total > 1 else chunk
            ok, detail = _send_with_retry(
                args.xiaoluban_url, xl_token, receiver, content, log_file)
            if not ok:
                ok_all = False
                last_detail = detail
                break

        ack_body = {
            "owner_key": owner_key,
            "window_start": (report.get("window") or {}).get("start", ""),
            "window_end": (report.get("window") or {}).get("end", ""),
            "recipient": receiver,
            "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest()[:32],
            "status": "sent" if ok_all else "failed",
            "error": None if ok_all else last_detail,
        }
        try:
            _http_json(f"{base}/api/v2/notify/daily-report/ack",
                       method="POST", body=ack_body, token=args.token)
        except Exception as exc:
            _log(f"回写发送状态失败 {owner_key}: {exc}", log_file)
        if ok_all:
            sent += 1
            _log(f"发送成功 {owner_key}", log_file)
        else:
            failed += 1
            _log(f"发送失败 {owner_key}: {last_detail}", log_file)

    _log(f"完成：sent={sent} skipped={skipped} failed={failed}", log_file)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
