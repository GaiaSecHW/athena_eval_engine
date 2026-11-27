"""平台部门树同步——手动拉取（system 页输入账号密码，密码不保存）。

数据源：``secflow-platform-auth``
- ``POST /api/auth/login``（人机 token，24h 有效）
- ``GET /api/auth/org/departments``（需用户管理权限；返回扁平列表
  ``[{id, name, parent_id, description, ...}]``）

**凭据只存在于本次请求内存中**：由 system 页面输入用户名/密码，随
POST 请求传入；不写 system_config、不写文件、不写日志。每次拉取
重新登录，不缓存凭据、不做定时自动同步。

落库：``org_department``（id/parent_id/name/path/depth）**全量重建**；
path 为根→叶名称用 " / " 连接。页面用「项目 department_id」关联该表
展示层级路径（project_task_summary.department_id 由采集带出）。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

# auth 服务内部地址（可用环境变量覆盖）
_AUTH_BASE = __import__("os").environ.get(
    "EVAL_PLATFORM_AUTH_URL", "http://secflow-platform-auth")
_LOGIN_PATH = "/api/auth/login"
_DEPTS_PATH = "/api/auth/org/departments"


def _login(username: str, password: str) -> str:
    """登录换取人机 token（凭据仅本次调用内存使用）。"""
    body = json.dumps({"username": username, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        _AUTH_BASE + _LOGIN_PATH, data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 401 = 用户名或密码错误（不记录密码）
        raise RuntimeError(
            "平台账号登录失败（用户名或密码错误）" if e.code == 401
            else f"平台账号登录失败: HTTP {e.code}") from e
    token = str(data.get("access_token") or "")
    if not token:
        raise RuntimeError("登录响应缺少 access_token")
    return token


def _fetch_departments(token: str) -> list[dict]:
    req = urllib.request.Request(
        _AUTH_BASE + _DEPTS_PATH,
        headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "该账号无权读取部门（需用户管理权限）" if e.code in (401, 403)
            else f"拉取部门失败: HTTP {e.code}") from e
    return data if isinstance(data, list) else (data.get("departments") or [])


def _build_paths(items: list[dict]) -> list[tuple]:
    """扁平部门列表 → (id, parent_id, name, path, depth, description)。"""
    by_id = {int(i["id"]): i for i in items if i.get("id") is not None}
    paths: dict[int, str] = {}
    depths: dict[int, int] = {}

    def _resolve(nid: int, seen: frozenset) -> tuple[str, int]:
        if nid in paths:
            return paths[nid], depths[nid]
        node = by_id.get(nid) or {}
        name = str(node.get("name") or "")
        parent = node.get("parent_id")
        if parent is None or int(parent) not in by_id or int(parent) in seen:
            paths[nid] = name
            depths[nid] = 0
            return paths[nid], depths[nid]
        p_path, p_depth = _resolve(int(parent), seen | {nid})
        paths[nid] = f"{p_path} / {name}" if p_path else name
        depths[nid] = p_depth + 1
        return paths[nid], depths[nid]

    out = []
    for nid, node in by_id.items():
        path, depth = _resolve(nid, frozenset())
        out.append((nid, node.get("parent_id"),
                    str(node.get("name") or ""), path, depth,
                    str(node.get("description") or "")))
    return out


def sync_departments(username: str, password: str) -> dict:
    """登录 → 拉部门树 → 全量重建 org_department。

    凭据仅函数内使用，不落任何存储/日志。返回统计：
    {"departments": N, "roots": R, "max_depth": D}。
    """
    username = str(username or "").strip()
    password = str(password or "")
    if not username or not password:
        raise ValueError("用户名和密码不能为空")

    token = _login(username, password)
    items = _fetch_departments(token)
    rows = _build_paths(items)
    if not rows:
        return {"departments": 0, "roots": 0, "max_depth": 0}

    def _do(cur):
        cur.execute("DELETE FROM org_department")
        cur.executemany(
            "INSERT INTO org_department "
            "(id, parent_id, name, path, depth, description) "
            "VALUES (%s,%s,%s,%s,%s,%s)", rows)
        return len(rows)

    n = _db_query(_do)
    roots = sum(1 for r in rows if not r[1])
    max_depth = max(r[4] for r in rows)
    log("ORG_SYNC", f"部门树同步完成: {n} 个部门 / {roots} 个根 / "
                    f"深度 {max_depth}（手动拉取）")
    return {"departments": n, "roots": roots, "max_depth": max_depth}
