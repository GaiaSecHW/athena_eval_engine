"""平台对接 — 项目/任务/trace 发现。

配置来自 config_loader（dev: port-forward / k8s: ConfigMap）。
trace 文件：k8s 部署时 DATA_ROOT 直接挂载可读；dev 时 kubectl exec 到 schedule pod。
"""
from __future__ import annotations
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.request
from urllib.parse import urlencode
from ..config_loader import PROJECT_API, SCHEDULE_API, VULN_API_URL, PLATFORM_TOKEN, DATA_ROOT

# k8s 部署时 /data 直接挂载；dev 时 DATA_ROOT 不存在 → 走 kubectl exec
_K8S_MODE = os.path.isdir(DATA_ROOT)


def _find_kubectl() -> str:
    """查找 kubectl 可执行文件路径（WinGet / Program Files / PATH），带缓存。"""
    global _kubectl_cache
    if _kubectl_cache:
        return _kubectl_cache
    k = shutil.which("kubectl")
    if k:
        _kubectl_cache = k
        return k
    for p in (
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     "Microsoft", "WinGet", "Packages",
                     "Kubernetes.kubectl_Microsoft.Winget.Source_8wekyb3d8bbwe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Kubernetes", "bin"),
        r"C:\Program Files\Kubernetes\bin",
    ):
        exe = os.path.join(p, "kubectl.exe")
        if os.path.isfile(exe):
            _kubectl_cache = exe
            return exe
    _kubectl_cache = "kubectl"
    return _kubectl_cache  # fallback

_SCHED_LABEL = "app=chirmera-platform-schedule"  # schedule pod 标签选择器
_sched_pod_cache: str | None = None
_kubectl_cache: str | None = None
_vuln_case_cache: dict[str, tuple[float, dict]] = {}
_vuln_case_cache_lock = threading.Lock()
_VULN_CASE_CACHE_SECONDS = 60
_VULN_CASE_MAX_PAGES = 100
_CVULN_CASE_ID_RE = re.compile(r"漏洞\s*ID\s*[:：]\s*([^\s]+)")
_TASK_PATH_RE = re.compile(r"/tasks/([0-9a-f]{24})(?:/|$)")
_logger = logging.getLogger(__name__)


def _get_sched_pod() -> str:
    """dev 模式：按 label 动态获取 schedule pod 名称（缓存）。"""
    global _sched_pod_cache
    if _sched_pod_cache:
        return _sched_pod_cache
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    cmd = [_find_kubectl(), "-n", "secflow-ns", "get", "pod", "-l", _SCHED_LABEL,
           "-o", "jsonpath={.items[0].metadata.name}"]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=10, env=env)
    pod = r.stdout.strip()
    if not pod:
        raise RuntimeError(f"找不到 schedule pod（label={_SCHED_LABEL}）")
    _sched_pod_cache = pod
    return pod


def _get(url):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {PLATFORM_TOKEN}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def get_projects():
    d = _get(f"{PROJECT_API}/api/project")
    items = d.get("projects", []) if isinstance(d, dict) else d
    return [{"id": p["id"], "name": p.get("name"),
             "department_name": p.get("department_name"),
             "product_path": p.get("category_path") or p.get("category_node_name"),
             "category": p.get("category"),
             "k8s_namespace": p.get("k8s_namespace"),
             "owner_name": p.get("owner_name"),
             "description": p.get("description")} for p in items]


def get_tasks(project_id: str | None = None, page_size: int = 200, status_filter: str | None = None):
    """默认返回全部任务（含各状态）；status_filter 传状态字符串可过滤。"""
    if project_id:
        url = f"{SCHEDULE_API}/api/chirmera-platform-schedule/projects/{project_id}/user-tasks?page=1&page_size={page_size}&sort_by=created_at&sort_direction=desc"
    else:
        url = f"{SCHEDULE_API}/api/chirmera-platform-schedule/tasks?page=1&page_size={page_size}&sort_by=created_at&sort_direction=desc"
    d = _get(url)
    items = d.get("items") or d.get("data", {}).get("items", []) if isinstance(d, dict) else d
    out = []
    for t in items:
        st = (t.get("display_status") or t.get("status") or "").lower()
        if status_filter and st != status_filter:
            continue
        # 测试对象：取 inputs 的 display_name/input_label 汇总
        _inputs = t.get("inputs") or []
        _labels = [i.get("display_name") or i.get("input_label") or "" for i in _inputs]
        test_target = "，".join(filter(None, _labels)) or None
        out.append({"id": t.get("id"), "project_id": t.get("project_id"),
                     "name": t.get("name"), "status": t.get("display_status") or t.get("status"),
                     "task_type": t.get("task_type"),  # 工具（内置枚举或工具注册中心 id）
                     "test_target": test_target})  # 测试对象（inputs 汇总）
    return out


def _get_vuln_case_index(project_id: str) -> dict | None:
    """返回 case_id → case 元数据索引，供 CVuln trace 关联平台任务。

    漏洞平台是任务归属的正式来源；接口短暂不可用时返回 None，调用方再
    从 trace prompt 中的历史记忆路径回退推断任务 ID。
    """
    # 两侧的 KG/No-KG 选择会并发加载；在首个请求完成前持锁，避免重复拉取
    # 整个项目的 case 列表。
    with _vuln_case_cache_lock:
        cached = _vuln_case_cache.get(project_id)
        if cached and time.monotonic() - cached[0] < _VULN_CASE_CACHE_SECONDS:
            return cached[1]

        index = {}
        page = 1
        try:
            while page <= _VULN_CASE_MAX_PAGES:
                query = urlencode({"project_id": project_id, "page": page, "page_size": 200,
                                   "sort_field": "created_at", "sort_direction": "desc"})
                data = _get(f"{VULN_API_URL.rstrip('/')}/api/vuln/cases?{query}")
                batch = data.get("items", []) if isinstance(data, dict) else []
                total = data.get("total", len(index)) if isinstance(data, dict) else len(index)
                new_cases = 0
                for case in batch:
                    if not isinstance(case, dict) or not case.get("id") or case["id"] in index:
                        continue
                    source_task = case.get("source_task") or {}
                    metadata_source = (case.get("metadata") or {}).get("source") or {}
                    index[case["id"]] = {
                        "task_id": source_task.get("task_id") or metadata_source.get("task_id"),
                        "title": case.get("title") or (case.get("display_summary") or {}).get("title"),
                    }
                    new_cases += 1
                if not batch or len(index) >= total:
                    break
                if not new_cases:
                    _logger.warning("漏洞 case 接口分页无新增记录，停止读取：project_id=%s page=%s",
                                    project_id, page)
                    break
                page += 1
            else:
                _logger.warning("漏洞 case 接口超过最大分页数，停止读取：project_id=%s max_pages=%s",
                                project_id, _VULN_CASE_MAX_PAGES)
        except Exception:
            _logger.warning("读取漏洞 case 索引失败，将使用 trace prompt 回退关联：project_id=%s",
                            project_id, exc_info=True)
            return None

        _vuln_case_cache[project_id] = (time.monotonic(), index)
        return index


def _cvuln_trace_metadata(path: str) -> dict | None:
    """从 CVuln 单文件 trace 读取 case ID 和 prompt 中的兜底任务 ID。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("type") != "message":
                    continue
                message = event.get("message") or {}
                if message.get("role") != "user":
                    continue
                content = message.get("content") or []
                text = "\n".join(str(c.get("text", "")) for c in content if isinstance(c, dict))
                case_match = _CVULN_CASE_ID_RE.search(text)
                task_ids = _TASK_PATH_RE.findall(text)
                return {"case_id": case_match.group(1) if case_match else None,
                        "fallback_task_id": task_ids[-1] if task_ids else None}
    except (OSError, UnicodeDecodeError):
        return None
    return None


def _cvuln_trace_item(path: str, mtime: float | None, metadata: dict,
                      case_index: dict | None, task_id: str) -> dict | None:
    """按当前平台任务过滤一份 CVuln case 文件。"""
    case_id = metadata.get("case_id")
    case = case_index.get(case_id, {}) if case_index is not None and case_id else {}
    source_task_id = case.get("task_id") or metadata.get("fallback_task_id")
    if source_task_id != task_id:
        return None
    return {
        "path": path, "tool_task_id": "", "kind": "cvuln_verify_session",
        "trace_kind": "cvuln_verify", "file": case_id or os.path.basename(path),
        "case_id": case_id, "case_title": case.get("title"),
        "source_task_id": source_task_id, "mtime": mtime,
    }


def _cvuln_trace_group(root: str, task_id: str, files: list[dict]) -> dict | None:
    """把同一平台任务的多个 CVuln case 文件作为一条集合 trace 返回。"""
    if not files:
        return None
    mtimes = [item["mtime"] for item in files if item.get("mtime") is not None]
    case_ids = sorted({item["case_id"] for item in files if item.get("case_id")})
    return {
        "path": root, "tool_task_id": "", "kind": "cvuln_verify_session",
        "trace_kind": "cvuln_verify", "file": "CVulnVerify 验证集合",
        "file_count": len(files), "source_task_id": task_id,
        # 供创建评测时与 benchmark 求交集，确保解析、匹配、报告使用同一批 case。
        "case_ids": case_ids,
        "mtime": max(mtimes) if mtimes else None,
    }


def _scan_cvuln_dir(project_id: str, task_id: str, out: list) -> None:
    """挂载模式：按任务聚合项目共享目录中的 CVuln case 文件。"""
    root = os.path.join(DATA_ROOT, project_id, "tasks", "c_vuln_verify")
    if not os.path.isdir(root):
        return
    case_index = _get_vuln_case_index(project_id)
    matched = []
    for path in glob.glob(os.path.join(root, "*.jsonl")):
        metadata = _cvuln_trace_metadata(path)
        if not metadata:
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = None
        item = _cvuln_trace_item(path, mtime, metadata, case_index, task_id)
        if item:
            matched.append(item)
    group = _cvuln_trace_group(root, task_id, matched)
    if group:
        out.append(group)


def _classify_trace(p: str, mtime: float | None = None) -> dict:
    """分类单个 trace 文件。"""
    # Normalize path separators for consistent matching
    norm_path = p.replace("\\", "/")
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    tool_task_id = ""
    kind = "other"
    trace_kind = "other"
    if "opencode.db" in p:
        kind = "opencode_session"
        trace_kind = "turing"
        if "/tools/" in norm_path:
            seg = norm_path.split("/tools/")[1]
            tool_task_id = seg.split("/")[0] if seg else ""
    elif "findings.db" in p:
        kind = "findings"
        trace_kind = "turing"
    elif p.endswith(".jsonl"):
        if "/session/WebVerify/" in norm_path:
            kind = "webverify_session"
            trace_kind = "webvulnverify"
        else:
            kind = "turing_session"
            trace_kind = "argo"
    return {"path": p, "tool_task_id": tool_task_id, "kind": kind, "trace_kind": trace_kind,
            "file": os.path.basename(p), "file_count": 1, "mtime": mtime}


def _make_session_dir_trace(dir_path: str, mtime: float | None) -> dict:
    """构造 session 目录 trace（整个 session 目录作为一个 trace）。"""
    # Normalize path separators for consistent matching
    norm_path = dir_path.replace("\\", "/")
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    tool_task_id = ""
    trace_kind = "other"
    if norm_path.endswith("/session/secmate"):
        kind = "secmate_session"
        trace_kind = "secmate"
        tool_task_id = ""
    elif "/tools/" in norm_path:
        kind = "argo_session"
        trace_kind = "argo"
        seg = norm_path.split("/tools/")[1]
        tool_task_id = seg.split("/")[0] if seg else ""
    elif norm_path.endswith("/tasks/c_vuln_verify"):
        kind = "cvuln_verify_session"
        trace_kind = "cvuln_verify"
    elif norm_path.endswith("/session/dataflow_vuln_scan") or "/dataflow_vuln_scan/" in norm_path:
        kind = "dataflow_session"
        trace_kind = "dataflow"
    elif "/session/WebVerify" in norm_path:
        kind = "webverify_session"
        trace_kind = "webvulnverify"
    else:
        kind = "session"
        trace_kind = "argo"
    # 取上一级目录名（session 的父目录，如 argo-20260823_023850-03d75c31 或 task_id）
    parent = os.path.basename(os.path.dirname(dir_path.rstrip("/")))
    return {"path": dir_path, "tool_task_id": tool_task_id, "kind": kind, "trace_kind": trace_kind,
            "file": parent, "mtime": mtime}



def _scan_dir(base: str, out: list) -> None:
    """k8s 模式：只找 session 目录 + .db 文件。"""
    if not os.path.isdir(base):
        return
    # 1. 找所有名为 session 的目录
    for d in glob.glob(f"{base}/**/session", recursive=True):
        if not os.path.isdir(d):
            continue
        # 统计目录下的 .jsonl 文件数和最新 mtime（包括子目录如 argo/）
        jsonl_files = glob.glob(os.path.join(d, "**", "*.jsonl"), recursive=True)
        # dataflow_vuln_scan 子目录单独作为 dataflow trace（见下），此处排除避免重复计数
        jsonl_files = [f for f in jsonl_files if "dataflow_vuln_scan" not in f.replace("\\", "/")]
        # WebVerify .jsonl 由下方单独处理，此处排除避免重复
        jsonl_files = [f for f in jsonl_files if "/WebVerify/" not in f.replace("\\", "/")]
        if not jsonl_files:
            continue
        latest_mt = 0.0
        for f in jsonl_files:
            try:
                mt = os.path.getmtime(f)
                if mt > latest_mt:
                    latest_mt = mt
            except OSError:
                pass
        t = _make_session_dir_trace(d, latest_mt if latest_mt > 0 else None)
        t["file_count"] = len(jsonl_files)
        out.append(t)
    # 2. 找 WebVerify 目录（WebVulnVerify trace）
    for d in glob.glob(f"{base}/**/WebVerify", recursive=True):
        if not os.path.isdir(d):
            continue
        wv_files = glob.glob(os.path.join(d, "*.jsonl"))
        if not wv_files:
            continue
        latest_mt = 0.0
        for f in wv_files:
            try:
                mt = os.path.getmtime(f)
                if mt > latest_mt:
                    latest_mt = mt
            except OSError:
                pass
        t = _make_session_dir_trace(d, latest_mt if latest_mt > 0 else None)
        t["file_count"] = len(wv_files)
        out.append(t)
    # 2b. 找 dataflow_vuln_scan 目录（新工具：.../session/dataflow_vuln_scan/<dvs_run>/*.jsonl）
    for d in glob.glob(f"{base}/**/dataflow_vuln_scan", recursive=True):
        if not os.path.isdir(d):
            continue
        jsonl_files = [f for f in glob.glob(os.path.join(d, "**", "*.jsonl"), recursive=True)
                       if "system-prompt" not in os.path.basename(f)]
        if not jsonl_files:
            continue
        latest_mt = 0.0
        for f in jsonl_files:
            try:
                mt = os.path.getmtime(f)
                if mt > latest_mt:
                    latest_mt = mt
            except OSError:
                pass
        t = _make_session_dir_trace(d, latest_mt if latest_mt > 0 else None)
        t["file_count"] = len(jsonl_files)
        out.append(t)
    # 2c. 找 SecMate transcript 目录：{base}/**/session/secmate
    for d in glob.glob(f"{base}/**/session/secmate", recursive=True):
        if not os.path.isdir(d):
            continue
        jsonl_files = glob.glob(os.path.join(d, "*.jsonl"))  # 不读子目录
        if not jsonl_files:
            continue
        latest_mt = 0.0
        for f in jsonl_files:
            try:
                latest_mt = max(latest_mt, os.path.getmtime(f))
            except OSError:
                pass
        t = _make_session_dir_trace(d, latest_mt or None)
        t["file_count"] = len(jsonl_files)
        out.append(t)
    # 3. 找 .db 文件（opencode.db / findings.db）
    for p in glob.glob(f"{base}/**/*.db", recursive=True):
        try:
            mt = os.path.getmtime(p)
        except OSError:
            mt = None
        out.append(_classify_trace(p, mt))


def _kubectl_find_dirs(pod: str, base: str, dir_name: str, env: dict) -> list[dict]:
    """dev 模式：kubectl exec 找指定名称的目录，统计 .jsonl 文件。"""
    out = []
    cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
           "find", base, "-type", "d", "-name", dir_name,
           "-printf", "%T@ %p\n"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=60, env=env)
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            mt = None; p = line
            if len(parts) == 2 and parts[0].replace(".", "").isdigit():
                try: mt = float(parts[0])
                except ValueError: mt = None
                p = parts[1]
            cmd2 = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
                    "find", p, "-maxdepth", "1", "-name", "*.jsonl", "-printf", "%T@ %p\n"]
            r2 = subprocess.run(cmd2, capture_output=True, text=True, encoding="utf-8", timeout=30, env=env)
            jsonl_lines = [l for l in (r2.stdout or "").splitlines() if l.strip()]
            if not jsonl_lines:
                continue
            latest_mt = mt or 0.0
            for jl in jsonl_lines:
                jl_parts = jl.split(" ", 1)
                if len(jl_parts) == 2 and jl_parts[0].replace(".", "").isdigit():
                    try:
                        jmt = float(jl_parts[0])
                        if jmt > latest_mt:
                            latest_mt = jmt
                    except ValueError:
                        pass
            t = _make_session_dir_trace(p, latest_mt if latest_mt > 0 else None)
            t["file_count"] = len(jsonl_lines)
            out.append(t)
    except Exception:
        pass
    return out


def _kubectl_find(base: str) -> list[dict]:
    """dev 模式：kubectl exec 找 session 目录 + .db 文件。"""
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    pod = _get_sched_pod()
    out = []
    # 1+2. 找 session 目录和 WebVerify 目录（逻辑相同，dir_name 不同）
    out.extend(_kubectl_find_dirs(pod, base, "session", env))
    out.extend(_kubectl_find_dirs(pod, base, "WebVerify", env))
    # 2b. 找 dataflow_vuln_scan 目录（新工具：.../session/dataflow_vuln_scan/<dvs_run>/*.jsonl）
    cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
           "find", base, "-type", "d", "-name", "dataflow_vuln_scan",
           "-printf", "%T@ %p\n"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            mt = None; p = line
            if len(parts) == 2 and parts[0].replace(".", "").isdigit():
                try: mt = float(parts[0])
                except ValueError: mt = None
                p = parts[1]
            # 递归统计该目录下的 .jsonl 文件数（含 dvs_* 子目录，排除 system-prompt 旁路文件）
            cmd2 = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
                    "find", p, "-name", "*.jsonl", "-printf", "%T@ %p\n"]
            r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30, env=env)
            jsonl_lines = [l for l in (r2.stdout or "").splitlines()
                           if l.strip() and "system-prompt" not in l]
            if not jsonl_lines:
                continue
            latest_mt = mt or 0.0
            for jl in jsonl_lines:
                jl_parts = jl.split(" ", 1)
                if len(jl_parts) == 2 and jl_parts[0].replace(".", "").isdigit():
                    try:
                        jmt = float(jl_parts[0])
                        if jmt > latest_mt:
                            latest_mt = jmt
                    except ValueError:
                        pass
            t = _make_session_dir_trace(p, latest_mt if latest_mt > 0 else None)
            t["file_count"] = len(jsonl_lines)
            out.append(t)
    except Exception:
        pass
    # 2c. SecMate transcripts: {base}/**/session/secmate 目录，不读子目录
    cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
           "find", base, "-type", "d", "-path", "*/session/secmate",
           "-printf", "%T@ %p\n"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        for line in (r.stdout or "").splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) != 2:
                continue
            try:
                mt = float(parts[0])
            except ValueError:
                mt = None
            p = parts[1]
            # 只读 session/secmate/ 下的 .jsonl，不递归子目录
            cmd2 = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
                    "find", p, "-maxdepth", "1", "-name", "*.jsonl", "-printf", "%T@ %p\n"]
            r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30, env=env)
            lines = [value for value in (r2.stdout or "").splitlines() if value.strip()]
            if not lines:
                continue
            latest_mt = mt or 0.0
            for value in lines:
                parts = value.split(" ", 1)
                if len(parts) == 2:
                    try:
                        latest_mt = max(latest_mt, float(parts[0]))
                    except ValueError:
                        pass
            t = _make_session_dir_trace(p, latest_mt or None)
            t["file_count"] = len(lines)
            out.append(t)
    except Exception:
        pass
    # 3. 找 .db 文件
    cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
           "find", base, "-name", "*.db", "-printf", "%T@ %p\n"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=60, env=env)
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            mt = None; p = line
            if len(parts) == 2 and parts[0].replace(".", "").isdigit():
                try: mt = float(parts[0])
                except ValueError: mt = None
                p = parts[1]
            out.append(_classify_trace(p, mt))
    except Exception:
        pass
    return out


def _kubectl_scan_cvuln_dir(project_id: str, task_id: str) -> list[dict]:
    """开发模式：按任务聚合项目共享目录中的 CVuln case 文件。"""
    root = f"{DATA_ROOT}/{project_id}/tasks/c_vuln_verify"
    script = r'''
import glob, json, os, re, sys
case_re = re.compile(r"漏洞\s*ID\s*[:：]\s*([^\s]+)")
task_re = re.compile(r"/tasks/([0-9a-f]{24})(?:/|$)")
for path in glob.glob(os.path.join(sys.argv[1], "*.jsonl")):
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try: event = json.loads(line)
                except json.JSONDecodeError: continue
                message = event.get("message") or {}
                if event.get("type") != "message" or message.get("role") != "user": continue
                text = "\n".join(str(c.get("text", "")) for c in (message.get("content") or []) if isinstance(c, dict))
                cm = case_re.search(text); task_ids = task_re.findall(text)
                print(json.dumps({"path": path, "mtime": os.path.getmtime(path),
                                  "case_id": cm.group(1) if cm else None,
                                  "fallback_task_id": task_ids[-1] if task_ids else None}))
                break
    except (OSError, UnicodeDecodeError): pass
'''
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    try:
        cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", _get_sched_pod(), "--",
               "python3", "-c", script, root]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                timeout=90, env=env)
    except Exception:
        return []
    case_index = _get_vuln_case_index(project_id)
    matched = []
    for line in (result.stdout or "").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = _cvuln_trace_item(record.get("path", ""), record.get("mtime"), record,
                                 case_index, task_id)
        if item:
            matched.append(item)
    group = _cvuln_trace_group(root, task_id, matched)
    return [group] if group else []



def find_traces(project_id: str, task_id: str) -> list[dict]:
    """查找 trace 文件。

    k8s 部署：DATA_ROOT 直接挂载，os.path/glob 直读。
    dev 模式：kubectl exec 到 schedule pod 查找。

    除任务自身的 session/.db 外，还会从项目共享的
    tasks/c_vuln_verify/*.jsonl 中按漏洞 case 的 source_task.task_id 筛选。
    """
    task_base = os.path.join(DATA_ROOT, project_id, "tasks", task_id)
    out: list[dict] = []
    if _K8S_MODE:
        _scan_dir(task_base, out)
        _scan_cvuln_dir(project_id, task_id, out)
    else:
        remote_base = f"{DATA_ROOT}/{project_id}/tasks/{task_id}"
        out.extend(_kubectl_find(remote_base))
        out.extend(_kubectl_scan_cvuln_dir(project_id, task_id))
    return out


def fetch_trace_to_local(project_id: str, task_id: str, remote_path: str, local_dir: str) -> str:
    """trace 文件可直读时直接返回路径；dev 模式用 kubectl 拉到本地。

    目录（session/）→ kubectl tar 整个目录；单文件（.db/.jsonl）→ kubectl cat。
    """
    if os.path.exists(remote_path):
        return remote_path
    if _K8S_MODE:
        raise FileNotFoundError(f"trace 不可读：{remote_path}")
    # 判断是目录还是文件：有文件扩展名（.db/.jsonl）→ 文件，否则 → 目录
    import hashlib
    os.makedirs(local_dir, exist_ok=True)
    h = hashlib.md5(remote_path.encode()).hexdigest()[:8]
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    pod = _get_sched_pod()
    is_file = any(remote_path.endswith(ext) for ext in (".db", ".jsonl", ".sqlite", ".sqlite3"))
    if not is_file:
        # session 目录：kubectl gzip tar 整个目录 → 流式写临时文件 → extractall。
        # SecMate transcript 目录可能有数十 MiB；未压缩 tar 容易被 kubectl/proxy
        # 的长响应链路截断，而 JSONL 通常能被 gzip 大幅压缩。
        name = os.path.basename(remote_path.rstrip("/"))
        local = os.path.join(local_dir, f"{h}_{name}")
        if os.path.exists(local) and os.path.isdir(local):
            return local
        parent = os.path.dirname(remote_path.rstrip("/"))
        base = os.path.basename(remote_path.rstrip("/"))
        import tarfile, tempfile
        # --ignore-failed-read：跳过权限/符号链接等读不了的文件，避免 tar 流中断
        cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--",
               "tar", "czf", "-", "--ignore-failed-read", "-C", parent, base]
        env = dict(os.environ, MSYS_NO_PATHCONV="1")
        for attempt in range(2):
            tmp_tar = os.path.join(local_dir, f"{h}_tmp.tar")
            try:
                # stdout 直接写文件（不进内存），避免大目录 OOM / 截断
                with open(tmp_tar, "wb") as tmp:
                    r = subprocess.run(cmd, stdout=tmp, stderr=subprocess.PIPE,
                                       timeout=300, env=env)
                if r.returncode:
                    raise FileNotFoundError(
                        f"kubectl tar 失败（exit={r.returncode}）：{remote_path}; "
                        f"stderr={r.stderr.decode('utf-8', 'replace')[:300]}")
                if not os.path.getsize(tmp_tar):
                    raise FileNotFoundError(f"kubectl tar 失败（空输出）：{remote_path}; stderr={r.stderr.decode('utf-8','replace')[:300]}")
                with tarfile.open(tmp_tar) as tf:
                    # filter='data' 跳过符号链接等危险文件（session 目录含 .claude/skills 符号链接）
                    tf.extractall(local_dir, filter="data")
                break  # 成功
            except tarfile.ReadError as e:
                # tar 流截断 → 重试一次
                if attempt == 0:
                    print(f"[TRACE FETCH] tar 截断，重试：{remote_path}: {e}")
                    try: os.remove(tmp_tar)
                    except OSError: pass
                    continue
                raise FileNotFoundError(f"kubectl tar 截断（重试仍失败）：{remote_path}: {e}")
            finally:
                try: os.remove(tmp_tar)
                except OSError: pass
        # tar 解压后文件在 local_dir/base/，重命名为 local
        extracted = os.path.join(local_dir, base)
        if os.path.exists(extracted) and extracted != local:
            os.rename(extracted, local)
        return local
    # 单文件：kubectl exec cat（带重试，避免大文件截断）
    name = remote_path.split("/")[-1]
    local = os.path.join(local_dir, f"{h}_{name}")
    if os.path.exists(local):
        # 校验完整性：用 sqlite3 打开测试
        import sqlite3 as _sql
        _conn = None
        try:
            _conn = _sql.connect(local)
            _conn.execute("SELECT COUNT(*) FROM sqlite_master")
            _conn.close()
            return local
        except Exception:
            # 确保关闭 SQLite 连接，否则文件被锁 os.remove 会失败
            if _conn:
                try:
                    _conn.close()
                except Exception:
                    pass
            try:
                os.remove(local)  # 截断的缓存，删掉重新拉
            except OSError:
                # 文件仍被锁（前次进程残留），改用新文件名避免冲突
                import time as _time
                local = os.path.join(local_dir, f"{h}_{int(_time.time())}_{name}")
    cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--", "cat", remote_path]
    r = subprocess.run(cmd, capture_output=True, timeout=300, env=env)
    if not r.stdout:
        raise FileNotFoundError(f"kubectl cat 失败：{remote_path}")
    with open(local, "wb") as f:
        f.write(r.stdout)
    return local
