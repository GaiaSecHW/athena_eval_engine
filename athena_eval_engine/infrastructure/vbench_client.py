"""V-Bench benchmark 数据读取 — 从本地 benchmark.zip 文件读取基线漏洞信息。

benchmark.zip 位于 /data/files/vbench/workspaces/{benchmark_set_id}/output/benchmark.zip
zip 内含：
  - benchmark_{id}/benchmark.json（case_id, vulnerability_type）
  - benchmark_{id}/ground_truths/{case_id}.json（finding_id, explanation）
  - benchmark_{id}/manifest.json
"""
from __future__ import annotations
import json
import os
import time
import zipfile
import io
import urllib.request
from urllib.error import URLError
from ..config_loader import DATA_ROOT, PLATFORM_TOKEN, VBENCH_API_URL
from .log_util import log


def _get(path: str, retries: int = 20, retry_delay: float = 5.0) -> dict | list:
    """通过 V-Bench API 读取（port-forward / k8s service）。内部 Service 短暂抖动时重试。"""
    url = f"{VBENCH_API_URL.rstrip('/')}{path}"
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {PLATFORM_TOKEN}"})
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read().decode("utf-8"))
        except (URLError, TimeoutError, OSError) as e:
            last_err = e
            if attempt + 1 < retries:
                time.sleep(retry_delay)
    raise last_err


def list_projects() -> list[dict]:
    d = _get("/projects")
    items = d.get("items", d) if isinstance(d, dict) else d
    return [{"id": p["id"], "name": p["name"], "status": p.get("status"),
             "package_type": p.get("package_type"),
             "tags": [t.get("tag_value") for t in (p.get("tags") or [])]}
            for p in items if p.get("status") in ("EXPORTED", "READY")]


def get_project(project_id: str) -> dict:
    return _get(f"/projects/{project_id}")


def get_cases(project_id: str) -> list[dict]:
    d = _get(f"/projects/{project_id}/cases")
    items = d if isinstance(d, list) else d.get("items", d if isinstance(d, dict) else [])
    return [{"id": c["id"], "cve_id": c.get("cve_id"),
             "description": c.get("description") or c.get("raw_description") or "",
             "external_id": c.get("external_id"), "status": c.get("status")}
            for c in items if c.get("status") == "INCLUDED"]


def get_tasks(project_id: str) -> list[dict]:
    try:
        d = _get(f"/projects/{project_id}/tasks")
        items = d if isinstance(d, list) else d.get("items", d if isinstance(d, dict) else [])
        return items
    except Exception:
        return []


def get_case_detail(project_id: str, case_id: str) -> dict:
    try:
        return _get(f"/projects/{project_id}/cases/{case_id}")
    except Exception:
        return {}


def get_case_delivery(case_id: str) -> dict:
    try:
        return _get(f"/cases/{case_id}/case-delivery")
    except Exception:
        return {}


def get_session_attempt(attempt_id: str) -> dict:
    try:
        return _get(f"/session-attempts/{attempt_id}")
    except Exception:
        return {}


def get_session_events(attempt_id: str) -> dict:
    try:
        return _get(f"/session-attempts/{attempt_id}/events")
    except Exception:
        return {}


def get_exported_projects() -> list[dict]:
    return [p for p in list_projects() if p.get("status") == "EXPORTED"]


def _extract_source_from_traces(cases: list) -> None:
    """从 ground_truths findings 的 traces 中提取 source_file/source_function，写入每个 case。

    traces[].steps[] 中 role=SINK 的 step 的 path/symbol 即漏洞所在文件和函数。
    """
    for c in cases:
        source_file = ""
        source_function = ""
        source_line = ""
        for f in (c.get("findings") or []):
            for trace in (f.get("traces") or []):
                for step in (trace.get("steps") or []):
                    if step.get("role") == "SINK":
                        source_file = step.get("path", "")
                        source_function = step.get("symbol", "")
                        source_line = str(step.get("line", "") or step.get("line_number", "") or step.get("line_no", ""))
                        break
                if source_file:
                    break
            if source_file:
                break
        c["source_file"] = source_file
        c["source_function"] = source_function
        c["source_line"] = source_line


def _read_false_positives(zf: zipfile.ZipFile, names: list[str]) -> list[dict]:
    """从 benchmark.zip 提取 false_positives.json，转为 NON_VULNERABLE 基线 case。

    支持两种格式：
    1. 漏洞中心全量格式 — case 含 id/title/subject 等字段，复用 _case_to_benchmark 归一
    2. 简版格式 — ``{"false_positives": [{"description": "...", "reason": "..."}]}``
    """
    from .log_util import log
    fp_files = [n for n in names if n.endswith("false_positives.json")]
    if not fp_files:
        log("VBENCH", "⚠ false_positives.json 未在 benchmark.zip 中找到 — 非漏洞基线将为 0")
        return []
    log("VBENCH", f"找到 false_positives.json: {fp_files[0]}")
    from .vuln_center_client import _case_to_benchmark
    data = json.loads(zf.read(fp_files[0]))
    fp_cases = data.get("false_positives", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    log("VBENCH", f"false_positives.json 解析出 {len(fp_cases)} 条非漏洞 case")
    result = []
    for i, c in enumerate(fp_cases):
        if isinstance(c, dict) and c.get("id"):
            # 漏洞中心全量格式
            result.append(_case_to_benchmark(c, "NON_VULNERABLE"))
        else:
            # 简版格式：description + reason（reason 是研判状态，不是漏洞类型）
            desc = c.get("description", "") if isinstance(c, dict) else str(c)
            reason = c.get("reason", "") if isinstance(c, dict) else ""
            cid = c.get("case_id") or c.get("id") or f"fp-{i:04d}"
            # title 取 description 第一行（Markdown 标题），去掉 # 前缀
            _title = desc.split("\n", 1)[0].lstrip("# ").strip() if desc else ""
            result.append({
                "case_id": cid,
                "vulnerability_type": _title or reason or "",
                "description": desc,
                "target_finding_id": "",
                "expected_label": "NON_VULNERABLE",
                "source_file": "",
                "source_function": "",
                "source_line": "",
            })
    return result


def _read_benchmark_zip(zip_path: str) -> dict:
    """从 benchmark.zip 提取 benchmark.json + ground_truths + false_positives.json。"""
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        bn = [n for n in names if n.endswith("benchmark.json")]
        if not bn:
            return {"benchmark_id": None, "name": None, "cases": []}
        benchmark = json.loads(zf.read(bn[0]))
        cases = benchmark.get("cases", [])
        for c in cases:
            gt = [n for n in names if n.endswith("ground_truths/" + c["case_id"] + ".json")]
            c["findings"] = json.loads(zf.read(gt[0])).get("findings", []) if gt else []
        _extract_source_from_traces(cases)
        _vuln_n = sum(1 for c in cases if (c.get("expected_label") or "VULNERABLE") == "VULNERABLE")
        log("VBENCH", f"benchmark.json: {len(cases)} 条漏洞 case")
        # 非漏洞基线（false_positives.json）— 与漏洞 case 同构，expected_label=NON_VULNERABLE
        fp_cases = _read_false_positives(zf, names)
        cases.extend(fp_cases)
        log("VBENCH", f"benchmark.zip 读取完成: 漏洞={_vuln_n} 非漏洞={len(fp_cases)} 总计={len(cases)}")
        return {"benchmark_id": benchmark.get("benchmark_id"), "name": benchmark.get("name"),
                "schema_version": benchmark.get("schema_version"), "cases": cases}


def get_benchmark(benchmark_set_id: str) -> dict:
    """从 benchmark.zip 读取基准漏洞信息。

    优先直接读本地文件（k8s 共享存储 / 本地 dev），路径不存在时 fallback 到 kubectl exec。
    """
    zip_path = f"{DATA_ROOT}/vbench/workspaces/{benchmark_set_id}/output/benchmark.zip"

    # ① 本地文件存在 → 直接读（毫秒级，k8s 共享存储 + 本地 dev 均走此路径）
    if os.path.isfile(zip_path):
        log("VBENCH", f"读取本地 benchmark.zip: {zip_path}")
        return _read_benchmark_zip(zip_path)

    # ② fallback: kubectl exec 进 schedule pod 读取（本地 dev 无共享存储时）
    log("VBENCH", f"本地路径不存在，fallback kubectl exec: {zip_path}")
    import subprocess
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    from ..application.platform_service import _get_sched_pod
    pod = _get_sched_pod()
    py_script = (
        "import zipfile,json\n"
        f"zf=zipfile.ZipFile('{zip_path}')\n"
        "names=zf.namelist()\n"
        "out={}\n"
        "bn=[n for n in names if n.endswith('benchmark.json')]\n"
        "out['benchmark']=json.loads(zf.read(bn[0])) if bn else {}\n"
        "cases=out['benchmark'].get('cases',[])\n"
        "for c in cases:\n"
        "  gt=[n for n in names if n.endswith('ground_truths/'+c['case_id']+'.json')]\n"
        "  c['findings']=json.loads(zf.read(gt[0])).get('findings',[]) if gt else []\n"
        "fp=[n for n in names if n.endswith('false_positives.json')]\n"
        "if fp:\n"
        "  out['false_positives']=json.loads(zf.read(fp[0])).get('false_positives',[])\n"
        "print(json.dumps(out,ensure_ascii=False))\n"
    )
    r = subprocess.run(
        ["kubectl", "-n", "secflow-ns", "exec", pod, "--", "python3", "-c", py_script],
        capture_output=True, timeout=120, env=env)
    if not r.stdout:
        log("VBENCH", "⚠ kubectl exec 无输出 — 返回空基线")
        return {"benchmark_id": None, "name": None, "cases": []}
    bm = json.loads(r.stdout.decode("utf-8").strip())
    benchmark = bm.get("benchmark", {})
    cases = benchmark.get("cases", [])
    _extract_source_from_traces(cases)
    # 非漏洞基线（false_positives.json）
    raw_fp = bm.get("false_positives") or []
    log("VBENCH", f"kubectl exec 读取: 漏洞={len(cases)} 非漏洞={len(raw_fp)} 总计={len(cases)+len(raw_fp)}")
    from .vuln_center_client import _case_to_benchmark
    for i, c in enumerate(raw_fp):
        if isinstance(c, dict) and c.get("id"):
            cases.append(_case_to_benchmark(c, "NON_VULNERABLE"))
        else:
            desc = c.get("description", "") if isinstance(c, dict) else str(c)
            reason = c.get("reason", "") if isinstance(c, dict) else ""
            cid = c.get("case_id") or c.get("id") or f"fp-{i:04d}"
            _title = desc.split("\n", 1)[0].lstrip("# ").strip() if desc else ""
            cases.append({
                "case_id": cid,
                "vulnerability_type": _title or reason or "",
                "description": desc,
                "target_finding_id": "",
                "expected_label": "NON_VULNERABLE",
                "source_file": "",
                "source_function": "",
                "source_line": "",
            })
    return {"benchmark_id": benchmark.get("benchmark_id"), "name": benchmark.get("name"),
            "schema_version": benchmark.get("schema_version"), "cases": cases}
