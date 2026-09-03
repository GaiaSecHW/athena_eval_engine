"""平台对接 — 项目/任务/trace 发现。

配置来自 config_loader（dev: port-forward / k8s: ConfigMap）。
trace 文件：k8s 部署时 DATA_ROOT 直接挂载可读；dev 时 kubectl exec 到 schedule pod。
"""
from __future__ import annotations
import glob
import json
import os
import subprocess
import urllib.request
from ..config_loader import PROJECT_API, SCHEDULE_API, PLATFORM_TOKEN, DATA_ROOT

# k8s 部署时 /data 直接挂载；dev 时 DATA_ROOT 不存在 → 走 kubectl exec
_K8S_MODE = os.path.isdir(DATA_ROOT)
_SCHED_LABEL = "app=chirmera-platform-schedule"  # schedule pod 标签选择器
_sched_pod_cache: str | None = None


def _get_sched_pod() -> str:
    """dev 模式：按 label 动态获取 schedule pod 名称（缓存）。"""
    global _sched_pod_cache
    if _sched_pod_cache:
        return _sched_pod_cache
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    cmd = ["kubectl", "-n", "secflow-ns", "get", "pod", "-l", _SCHED_LABEL,
           "-o", "jsonpath={.items[0].metadata.name}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env)
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
    d = _get(f"{PROJECT_API}/api/project/list")
    items = d.get("data", []) if isinstance(d, dict) else d
    return [{"id": p["id"], "name": p["name"],
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
    p = p if p.startswith("/") else "/" + p
    tool_task_id = ""
    kind = "other"
    if "opencode.db" in p:
        kind = "opencode_session"
        if "/tools/" in p:
            seg = p.split("/tools/")[1]
            tool_task_id = seg.split("/")[0] if seg else ""
    elif "findings.db" in p:
        kind = "findings"
    elif p.endswith(".jsonl"):
        kind = "turing_session"
    return {"path": p, "tool_task_id": tool_task_id, "kind": kind, "file": p.split("/")[-1], "mtime": mtime}


def _make_session_dir_trace(dir_path: str, mtime: float | None) -> dict:
    """构造 session 目录 trace（整个 session 目录作为一个 trace）。"""
    dir_path = dir_path if dir_path.startswith("/") else "/" + dir_path
    tool_task_id = ""
    if "/tools/" in dir_path:
        kind = "argo_session"
        seg = dir_path.split("/tools/")[1]
        tool_task_id = seg.split("/")[0] if seg else ""
    else:
        kind = "session"  # tasks/{task_id}/session/ 下的 .jsonl，不标记为 turing
    # 取上一级目录名（session 的父目录，如 argo-20260823_023850-03d75c31 或 task_id）
    parent = os.path.basename(os.path.dirname(dir_path.rstrip("/")))
    return {"path": dir_path, "tool_task_id": tool_task_id, "kind": kind,
            "file": parent, "mtime": mtime}


def _group_traces(file_list: list[tuple[str, float | None]]) -> list[dict]:
    """把文件列表分组：.jsonl 按 session 目录合并；.db 单独返回。"""
    session_dirs: dict[str, float] = {}  # dir_path → latest mtime
    session_counts: dict[str, int] = {}
    out: list[dict] = []
    for p, mt in file_list:
        p_norm = p if p.startswith("/") else "/" + p
        if p.endswith(".jsonl"):
            # .jsonl：按 session 目录分组
            dir_path = os.path.dirname(p)
            if dir_path not in session_dirs:
                session_dirs[dir_path] = mt or 0.0
                session_counts[dir_path] = 1
            else:
                if mt and mt > session_dirs[dir_path]:
                    session_dirs[dir_path] = mt
                session_counts[dir_path] += 1
        else:
            # .db 等其他文件：单独返回
            out.append(_classify_trace(p, mt))
    for dir_path, mt in session_dirs.items():
        t = _make_session_dir_trace(dir_path, mt)
        t["file_count"] = session_counts[dir_path]
        out.append(t)
    return out


def _scan_dir(base: str, out: list) -> None:
    """k8s 模式：只找 session 目录 + .db 文件。"""
    if not os.path.isdir(base):
        return
    # 1. 找所有名为 session 的目录
    for d in glob.glob(f"{base}/**/session", recursive=True):
        if not os.path.isdir(d):
            continue
        # 统计目录下的 .jsonl 文件数和最新 mtime
        jsonl_files = glob.glob(os.path.join(d, "*.jsonl"))
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
    # 2. 找 .db 文件（opencode.db / findings.db）
    for p in glob.glob(f"{base}/**/*.db", recursive=True):
        try:
            mt = os.path.getmtime(p)
        except OSError:
            mt = None
        out.append(_classify_trace(p, mt))


def _kubectl_find(base: str) -> list[dict]:
    """dev 模式：kubectl exec 找 session 目录 + .db 文件。"""
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    pod = _get_sched_pod()
    out = []
    # 1. 找 session 目录
    cmd = ["kubectl", "-n", "secflow-ns", "exec", pod, "--",
           "find", base, "-type", "d", "-name", "session",
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
            # 统计该 session 目录下的 .jsonl 文件数
            cmd2 = ["kubectl", "-n", "secflow-ns", "exec", pod, "--",
                    "find", p, "-maxdepth", "1", "-name", "*.jsonl", "-printf", "%T@ %p\n"]
            r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30, env=env)
            jsonl_lines = [l for l in (r2.stdout or "").splitlines() if l.strip()]
            if not jsonl_lines:
                continue
            # 取最新 mtime
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
    # 2. 找 .db 文件
    cmd = ["kubectl", "-n", "secflow-ns", "exec", pod, "--",
           "find", base, "-name", "*.db", "-printf", "%T@ %p\n"]
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
            out.append(_classify_trace(p, mt))
    except Exception:
        pass
    return out


def _parse_find_lines(lines: list[str]) -> list[dict]:
    """解析 kubectl find 输出（每行 "%T@ %p"），分组后返回。"""
    files: list[tuple[str, float | None]] = []
    for line in lines:
        parts = line.split(" ", 1)
        mt = None; p = line
        if len(parts) == 2 and parts[0].replace(".", "").isdigit():
            try:
                mt = float(parts[0])
            except ValueError:
                mt = None
            p = parts[1]
        files.append((p, mt))
    return _group_traces(files)


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
        cmd = ["kubectl", "-n", "secflow-ns", "exec", pod, "--", "tar", "cf", "-", "-C", parent, base]
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
    # 单文件：kubectl cat
    name = remote_path.split("/")[-1]
    local = os.path.join(local_dir, f"{h}_{name}")
    if os.path.exists(local) and os.path.getsize(local) > 0:
        return local
    cmd = ["kubectl", "-n", "secflow-ns", "exec", pod, "--", "cat", remote_path]
    r = subprocess.run(cmd, capture_output=True, timeout=180, env=env)
    if not r.stdout:
        raise FileNotFoundError(f"kubectl cat 失败：{remote_path}")
    with open(local, "wb") as f:
        f.write(r.stdout)
    return local
