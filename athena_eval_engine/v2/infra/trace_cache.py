"""Trace 文件本地缓存管理 — k8s 下从 NFS 拷贝到 /tmp 加速 SQLite/JSONL 解析。

从 v1 evaluation_service.py 提取，消除 v2→v1 循环依赖。
"""
from __future__ import annotations

import os
import shutil
import hashlib

from ...infrastructure.log_util import log

# k8s 模式下 trace 文件在 NFS-backed PVC 上，SQLite 随机读极慢；
# 拷贝到 pod 本地 /tmp 加速解析，解析完删除，pod 重启自动清理
_K8S_TRACE_CACHE = "/tmp/eval_traces"


def _verify_sqlite(path: str) -> bool:
    """快速校验 SQLite 文件可读（不跑 integrity_check，太慢）。"""
    import sqlite3 as _sql
    _conn = None
    try:
        _conn = _sql.connect(f"file:{path}?immutable=1", uri=True)
        _conn.execute("SELECT COUNT(*) FROM sqlite_master")
        return True
    except Exception:
        return False
    finally:
        if _conn:
            try:
                _conn.close()
            except Exception:
                pass


def copy_trace_to_local(remote_path: str, evaluation_id: str = "") -> str:
    """k8s 模式下将 trace 文件从 NFS 拷贝到本地 /tmp，加速后续 SQLite/JSONL 解析。

    单文件（.db/.jsonl）→ 直接 copy；目录（session/）→ copytree。
    已存在且完整 → 直接返回（幂等，resume 场景复用）。
    拷贝后校验大小 + SQLite 可读性；校验失败回退到直接读 NFS 原始路径。

    evaluation_id 非空时，文件存到 {cache}/{evaluation_id}/ 子目录下，
    清理时只删该评测的文件，不影响并发评测。
    """
    h = hashlib.md5(remote_path.encode()).hexdigest()[:8]
    name = os.path.basename(remote_path.rstrip("/"))
    is_sqlite = name.endswith((".db", ".sqlite", ".sqlite3"))

    if evaluation_id:
        cache_dir = os.path.join(_K8S_TRACE_CACHE, evaluation_id)
    else:
        cache_dir = _K8S_TRACE_CACHE
    os.makedirs(cache_dir, exist_ok=True)
    local = os.path.join(cache_dir, f"{h}_{name}")

    def _verify_local():
        """校验本地文件：大小匹配 + SQLite 可读。"""
        if not os.path.exists(local):
            return False
        if os.path.isdir(local):
            return bool(os.listdir(local))
        if os.path.isfile(local):
            if os.path.getsize(local) == 0:
                return False
            if is_sqlite:
                return _verify_sqlite(local)
            return True
        return False

    # resume 场景：缓存文件已存在且校验通过 → 直接返回
    if _verify_local():
        return local
    # 缓存文件损坏 → 清理
    if os.path.exists(local):
        try:
            if os.path.isdir(local):
                shutil.rmtree(local, ignore_errors=True)
            else:
                os.remove(local)
        except OSError:
            pass

    # 执行拷贝
    try:
        if os.path.isdir(remote_path):
            shutil.copytree(remote_path, local)
        else:
            shutil.copy2(remote_path, local)
    except Exception as e:
        log("TRACE_CACHE", f"⚠ 拷贝失败: {remote_path} → {local}: {e}，回退到直接读 NFS")
        return remote_path

    # SecMate trace 目录拷贝后，findings.db 在上级 run/ 目录中，
    # 不会被 copytree 带过来。检查并额外拷贝。
    if "/.worker-config/" in remote_path:
        run_dir = remote_path.split("/.worker-config")[0]
        findings_db = os.path.join(run_dir, "findings.db")
        if os.path.isfile(findings_db):
            # findings.db 放在 local 的同级目录（对应原始 run/ 目录）
            local_run_dir = os.path.dirname(local)  # /tmp/eval_traces
            local_db = os.path.join(local_run_dir, f"{h}_findings.db")
            try:
                shutil.copy2(findings_db, local_db)
                log("TRACE_CACHE", f"额外拷贝 findings.db: {findings_db} → {local_db}")
            except Exception as e:
                log("TRACE_CACHE", f"⚠ findings.db 拷贝失败: {e}，回退到直接读 NFS")
                return remote_path

    remote_size = os.path.getsize(remote_path) if os.path.isfile(remote_path) else None
    local_size = os.path.getsize(local) if os.path.isfile(local) else None
    log("TRACE_CACHE", f"拷贝到本地: {remote_path} → {local} "
          f"(remote={remote_size}B local={local_size}B)")

    # 校验拷贝结果
    if remote_size is not None and local_size is not None and remote_size != local_size:
        log("TRACE_CACHE", f"⚠ 拷贝截断: remote={remote_size}B local={local_size}B "
              f"(差 {remote_size - local_size}B)，回退到直接读 NFS")
        try:
            os.remove(local)
        except OSError:
            pass
        return remote_path

    if is_sqlite and not _verify_sqlite(local):
        log("TRACE_CACHE", f"⚠ SQLite 校验失败: {local}，回退到直接读 NFS")
        try:
            os.remove(local)
        except OSError:
            pass
        return remote_path

    return local


def cleanup_trace_cache(evaluation_id: str = ""):
    """解析完成后清理本地 trace 缓存。

    evaluation_id 非空时只删该评测的子目录，不影响并发评测。
    为空时删整个缓存目录（向后兼容，不推荐在并发场景使用）。
    """
    target = (os.path.join(_K8S_TRACE_CACHE, evaluation_id)
              if evaluation_id else _K8S_TRACE_CACHE)
    try:
        if os.path.exists(target):
            shutil.rmtree(target, ignore_errors=True)
            log("TRACE_CACHE", f"已清理 {target}")
    except Exception:
        pass
