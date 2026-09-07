"""平台对接 — 项目/任务/trace 发现。

配置来自 config_loader（dev: port-forward / k8s: ConfigMap）。
trace 文件：k8s 部署时 DATA_ROOT 直接挂载可读；dev 时 kubectl exec 到 schedule pod。
"""
from __future__ import annotations
import glob
import json
import os
import shutil
import subprocess
import urllib.request
from ..config_loader import PROJECT_API, SCHEDULE_API, PLATFORM_TOKEN, DATA_ROOT

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


def get_tasks(project_id: str | None = None, page_size: int = 200, status_filter: str = "success"):
    """默认只返回已完成（success）的任务。"""
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
    return {"path": p, "tool_task_id": tool_task_id, "kind": kind, "trace_kind": trace_kind, "file": os.path.basename(p), "mtime": mtime}


def _make_session_dir_trace(dir_path: str, mtime: float | None) -> dict:
    """构造 session 目录 trace（整个 session 目录作为一个 trace）。"""
    # Normalize path separators for consistent matching
    norm_path = dir_path.replace("\\", "/")
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    tool_task_id = ""
    trace_kind = "other"
    if "/tools/" in norm_path:
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



def find_traces(project_id: str, task_id: str) -> list[dict]:
    """查找 trace 文件。

    k8s 部署：DATA_ROOT 直接挂载，os.path/glob 直读。
    dev 模式：kubectl exec 到 schedule pod 查找。

    只找 session 目录（tasks/{task_id}/session/ 或 tasks/{task_id}/tools/{tool_id}/session/）
    和 .db 文件（opencode.db / findings.db）。
    """
    task_base = os.path.join(DATA_ROOT, project_id, "tasks", task_id)
    out: list[dict] = []
    if _K8S_MODE:
        _scan_dir(task_base, out)
    else:
        remote_base = f"{DATA_ROOT}/{project_id}/tasks/{task_id}"
        out.extend(_kubectl_find(remote_base))
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
        # session 目录：kubectl tar 整个目录
        name = os.path.basename(remote_path.rstrip("/"))
        local = os.path.join(local_dir, f"{h}_{name}")
        if os.path.exists(local) and os.path.isdir(local):
            return local
        parent = os.path.dirname(remote_path.rstrip("/"))
        base = os.path.basename(remote_path.rstrip("/"))
        cmd = [_find_kubectl(), "-n", "secflow-ns", "exec", pod, "--", "tar", "cf", "-", "-C", parent, base]
        r = subprocess.run(cmd, capture_output=True, timeout=180, env=env)
        if not r.stdout:
            raise FileNotFoundError(f"kubectl tar 失败：{remote_path}")
        import tarfile, io
        with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tf:
            # filter='data' 跳过符号链接等危险文件（session 目录含 .claude/skills 符号链接）
            tf.extractall(local_dir, filter="data")
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
