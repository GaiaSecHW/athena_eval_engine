#!/usr/bin/env python3
"""HTTP 级 smoke：创建 job → 轮询 → 拉 artifact → 校验基本契约。"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.request


def _request(method: str, url: str, *, token: str = "", body: dict | None = None,
             extra_headers: dict | None = None, timeout: float = 60) -> tuple:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw.decode()) if raw else None, raw
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"{method} {url} HTTP {exc.code}: {detail}") from exc


def _resolve(base: str, url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return f"{base.rstrip('/')}/{url.lstrip('/')}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--request-file", required=True)
    ap.add_argument("--token", default="")
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--poll-interval", type=float, default=0.5)
    ap.add_argument("--scenario", default="", help="mock 故障注入头 X-Mock-Scenario")
    args = ap.parse_args()

    with open(args.request_file, "r", encoding="utf-8") as f:
        payload = json.load(f)
    headers = {"Idempotency-Key": f"smoke:{payload.get('request_id', '')}"}
    if args.scenario:
        headers["X-Mock-Scenario"] = args.scenario

    base = args.base_url.rstrip("/")
    job, _ = _request(
        "POST", f"{base}/v1/case-analysis-jobs", token=args.token,
        body=payload, extra_headers=headers, timeout=60)
    if not isinstance(job, dict) or not job.get("job_id"):
        raise RuntimeError(f"创建 job 响应非法: {job}")
    deadline = time.time() + args.timeout
    while True:
        status = str(job.get("status", "")).lower()
        if status in ("succeeded", "completed", "success", "done"):
            break
        if status in ("failed", "error", "cancelled", "canceled"):
            raise RuntimeError(f"job 失败: {job}")
        if time.time() > deadline:
            raise RuntimeError(f"job 轮询超时: {job}")
        time.sleep(args.poll_interval)
        job, _ = _request(
            "GET", _resolve(base, job["poll_url"]), token=args.token,
            timeout=min(60, max(1, deadline - time.time())))

    result = job.get("result") or {}
    if result.get("case_id") != payload["case"]["case_id"]:
        raise RuntimeError("result.case_id 与请求不一致")
    ref = result.get("detail_ref") or {}
    if not ref.get("uri"):
        raise RuntimeError("result 缺少 detail_ref.uri")
    detail, raw = _request(
        "GET", _resolve(base, ref["uri"]), token=args.token, timeout=60)
    expected = ref.get("sha256", "")
    actual = hashlib.sha256(raw).hexdigest()
    if expected and expected != actual:
        raise RuntimeError(f"artifact sha256 不一致: {expected} != {actual}")
    if not isinstance(detail, dict):
        raise RuntimeError("artifact 不是 JSON object")

    def _cause(chain: dict) -> str:
        if chain.get("primary_cause"):
            return str(chain["primary_cause"])
        hyps = chain.get("hypotheses") or []
        return str((hyps[0] or {}).get("cause_code", "")) if hyps else ""

    summary = {
        "ok": True,
        "job_id": job["job_id"],
        "case_id": result["case_id"],
        "mining_cause": _cause(result.get("mining") or {}),
        "verification_cause": _cause(result.get("verification") or {}),
        "mining_hypotheses": len((result.get("mining") or {}).get("hypotheses") or []),
        "verification_hypotheses": len(
            (result.get("verification") or {}).get("hypotheses") or []),
        "detail_bytes": len(raw),
        "detail_sha256": actual,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
