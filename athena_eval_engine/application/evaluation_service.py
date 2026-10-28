"""Evaluation Service — create() + 状态/报告查询 + trace 缓存管理。

create(request) → 冻结 snapshot + 建 evaluation。
get_status() / get_report() → 查询评测状态/报告。
set_cancel/clear_cancel → 协作取消信号（跨 worker，写 DB cancel_requested）。
_copy_trace_to_local / _cleanup_trace_cache → k8s 下 trace 文件本地缓存加速。

v2 Orchestrator (v2/pipeline/orchestrator.py) 已替代 v1 run() 函数。
"""
from __future__ import annotations
import json
import os
import threading
from dataclasses import dataclass
from ..infrastructure.database import connect
from ..infrastructure.log_util import log
from ..infrastructure.concurrency import get as _conc_get
from ..application import platform_service as ps


def _extract_source_task_id(entry: dict) -> str:
    """从 entry 的 source_uri 提取平台任务 UUID（漏洞中心 API 需要，非 benchmark task_id）。

    source_uri 格式: /data/files/{project_id}/tasks/{task_uuid}/session/...
    无法提取时返回空字符串。
    """
    import re
    src = entry.get("source_uri", "") or ""
    m = re.search(r'/tasks/([^/]+)', src)
    return m.group(1) if m else ""


def get_runtime_workers() -> dict:
    """返回 parse/kg_analysis 两个常用参数（兼容旧接口）。"""
    return {"parse": _conc_get("parse_workers"), "kg_analysis": _conc_get("kg_analysis_workers")}


# 进度文本：AI 匹配等慢阶段向前端报告进度（内存字典，pod 重启后重跑无需持久化）
# 两层：_progress_phase 存阶段级文本（解析/写入/配对等），_progress_tasks 存任务级文本（多 task_run 并行各自独立）
_progress_phase: dict[str, str] = {}
_progress_tasks: dict[str, dict[str, str]] = {}
_progress_lock = threading.Lock()


def set_progress(evaluation_id: str, text: str):
    """设置阶段级进度（覆盖任务级进度）。"""
    with _progress_lock:
        _progress_phase[evaluation_id] = text
        _progress_tasks.pop(evaluation_id, None)


def set_task_progress(evaluation_id: str, task_run_id: str, text: str):
    """设置任务级进度（多任务并行时各自独立，互不覆盖）。"""
    with _progress_lock:
        _progress_tasks.setdefault(evaluation_id, {})[task_run_id] = text


def get_progress(evaluation_id: str) -> str:
    with _progress_lock:
        tasks = _progress_tasks.get(evaluation_id, {})
        if tasks:
            return " | ".join(tasks.values())
        return _progress_phase.get(evaluation_id, "")


def clear_progress(evaluation_id: str):
    with _progress_lock:
        _progress_phase.pop(evaluation_id, None)
        _progress_tasks.pop(evaluation_id, None)


def set_cancel(evaluation_id: str):
    """标记一个评测任务为取消（force retry 时调用，通知旧线程退出）。
    跨 worker 生效：写 DB cancel_requested=1，独立于 status，不会被新线程覆盖。
    """
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("UPDATE evaluation SET cancel_requested=1 WHERE evaluation_id=%s",
                    (evaluation_id,))
        conn.commit()
    finally:
        conn.close()
    log("CANCEL", f"{evaluation_id} 收到取消信号")


def clear_cancel(evaluation_id: str):
    """清除取消标记（新线程启动时调用）。"""
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("UPDATE evaluation SET cancel_requested=0 WHERE evaluation_id=%s",
                    (evaluation_id,))
        conn.commit()
    finally:
        conn.close()


LOCAL_TRACE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tests", "fixtures", "fetched")
# k8s 模式下 trace 文件在 NFS-backed PVC 上，SQLite 随机读极慢；
# 拷贝到 pod 本地 /tmp 加速解析，解析完删除，pod 重启自动清理
_K8S_TRACE_CACHE = "/tmp/eval_traces"


def _is_webvulnverify_trace_module(path):
    """检测 JSONL 是否为 WebVulnVerify 格式（含 session_meta 行类型）。模块级版本。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                import json as _json
                d = _json.loads(line)
                return d.get("type") == "session_meta"
    except Exception:
        pass
    return False


def _get_parser_module(uri, trace_kind: str | None = None):
    """根据 trace_kind 或路径推断返回 parser 实例。模块级版本，供 rerun_kg 使用。"""
    import os as _os
    if trace_kind == "webvulnverify":
        from ..workers.webvulnverify_trace_parser import WebVulnVerifyTraceParser
        return WebVulnVerifyTraceParser()
    if trace_kind == "cvuln_verify":
        from ..workers.cvuln_verify_trace_parser import CVulnVerifyTraceParser
        return CVulnVerifyTraceParser()
    if trace_kind == "argo":
        from ..workers.argo_trace_parser import ArgoTraceParser
        from ..infrastructure import llm as _llm_mod
        return ArgoTraceParser(llm_module=_llm_mod)
    if trace_kind == "turing":
        from ..workers.turing_trace_parser import TuringTraceParser
        return TuringTraceParser()
    if trace_kind == "dataflow":
        from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
        return DataflowVulnScanTraceParser()
    if trace_kind == "secmate":
        from ..workers.secmate_trace_parser import SecMateTraceParser
        return SecMateTraceParser()
    # 兼容：无 trace_kind 时按路径推断
    p = _os.normpath(uri)
    cvuln_suffix = _os.path.join("tasks", "c_vuln_verify")
    argo_suffix = _os.path.join("session", "argo")
    dataflow_suffix = _os.path.join("session", "dataflow_vuln_scan")
    if p.replace("\\", "/").endswith("/session/secmate"):
        from ..workers.secmate_trace_parser import SecMateTraceParser
        return SecMateTraceParser()
    if _os.path.isdir(p) and p.endswith(cvuln_suffix):
        from ..workers.cvuln_verify_trace_parser import CVulnVerifyTraceParser
        return CVulnVerifyTraceParser()
    if _os.path.isdir(p) and p.endswith(argo_suffix):
        from ..workers.argo_trace_parser import ArgoTraceParser
        from ..infrastructure import llm as _llm_mod
        return ArgoTraceParser(llm_module=_llm_mod)
    if _os.path.isdir(p) and (p.endswith(dataflow_suffix) or "dataflow_vuln_scan" in p):
        from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
        return DataflowVulnScanTraceParser()
    if "dataflow_vuln_scan" in p and (p.endswith(".jsonl") or _os.path.isdir(p)):
        from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
        return DataflowVulnScanTraceParser()
    if p.endswith("opencode.db"):
        from ..workers.turing_trace_parser import TuringTraceParser
        return TuringTraceParser()
    if _os.path.isdir(p) or p.endswith(".jsonl"):
        from ..workers.secmate_trace_parser import is_secmate_trace
        if is_secmate_trace(p):
            from ..workers.secmate_trace_parser import SecMateTraceParser
            return SecMateTraceParser()
        _check_path = p
        if _os.path.isdir(p):
            import glob as _glob
            _jfiles = sorted(_glob.glob(_os.path.join(p, "*.jsonl")))
            _check_path = _jfiles[0] if _jfiles else ""
        if _check_path and _is_webvulnverify_trace_module(_check_path):
            from ..workers.webvulnverify_trace_parser import WebVulnVerifyTraceParser
            return WebVulnVerifyTraceParser()
        from ..workers.argo_trace_parser import ArgoTraceParser
        from ..infrastructure import llm as _llm_mod
        return ArgoTraceParser(llm_module=_llm_mod)
    from ..workers.turing_trace_parser import TuringTraceParser
    return TuringTraceParser()


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
            try: _conn.close()
            except: pass


def _copy_trace_to_local(remote_path: str, evaluation_id: str = "") -> str:
    """k8s 模式下将 trace 文件从 NFS 拷贝到本地 /tmp，加速后续 SQLite/JSONL 解析。

    单文件（.db/.jsonl）→ 直接 copy；目录（session/）→ copytree。
    已存在且完整 → 直接返回（幂等，resume 场景复用）。
    拷贝后校验大小 + SQLite 可读性；校验失败回退到直接读 NFS 原始路径。

    evaluation_id 非空时，文件存到 {cache}/{evaluation_id}/ 子目录下，
    清理时只删该评测的文件，不影响并发评测。
    """
    import hashlib, shutil
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
        try: os.remove(local)
        except OSError: pass
        return remote_path

    if is_sqlite and not _verify_sqlite(local):
        log("TRACE_CACHE", f"⚠ SQLite 校验失败: {local}，回退到直接读 NFS")
        try: os.remove(local)
        except OSError: pass
        return remote_path

    return local


def _cleanup_trace_cache(evaluation_id: str = ""):
    """解析完成后清理本地 trace 缓存。

    evaluation_id 非空时只删该评测的子目录，不影响并发评测。
    为空时删整个缓存目录（向后兼容，不推荐在并发场景使用）。
    """
    import shutil
    target = (os.path.join(_K8S_TRACE_CACHE, evaluation_id)
              if evaluation_id else _K8S_TRACE_CACHE)
    try:
        if os.path.exists(target):
            shutil.rmtree(target, ignore_errors=True)
            log("TRACE_CACHE", f"已清理 {target}")
    except Exception:
        pass


def _resolve_trace_path(source_uri: str, project_id: str = "", task_id: str = "",
                        evaluation_id: str = "") -> str:
    """source_uri 可能是 k8s pod 上的 /data/... 路径；本地开发时拉到本地。

    k8s 模式下 /data 在 NFS-backed PVC 上，SQLite 随机读极慢，
    拷贝到 pod 本地 /tmp 加速解析。
    """
    if os.path.exists(source_uri):
        # k8s 模式：/data 上的文件拷贝到本地 /tmp 加速
        if source_uri.startswith("/data/") and os.path.isdir(_K8S_TRACE_CACHE):
            return _copy_trace_to_local(source_uri, evaluation_id=evaluation_id)
        # 判断是否在 NFS 上（k8s 部署时 DATA_ROOT=/data/files 存在）
        from ..config_loader import DATA_ROOT
        if source_uri.startswith("/data/") and os.path.isdir(DATA_ROOT):
            return _copy_trace_to_local(source_uri)
        return source_uri
    if source_uri.startswith("/data/") or source_uri.startswith("data/"):
        return ps.fetch_trace_to_local(project_id, task_id, source_uri, LOCAL_TRACE_DIR)
    raise FileNotFoundError(f"trace 不可读且非 /data 路径：{source_uri}")


EVAL_CONFIG = {
    "access_rules": {
        "skill_names": [],
        "path_patterns": [],
        "command_patterns": [r"athena", r"athena\.py"],
        "text_patterns": [],
        "kg_tools": [],
    },
    "delivery_rules": {
        "path_patterns": [],
        "reject_patterns": [r"^404", r"404\s*Not Found", r"unreachable", r"Connection refused",
                           r"service.*not.*running", r"^$", r"^\[\]$", r'^{"result":""}',
                           "知识库暂无此类知识",
                           "Terminated", "timeout", "超时",
                           "command not found", "not found",
                           "unavailable",
                           # API 调用失败模式（athena_ask HTTP API 不可达 / 超时）
                           r"Execution error", r"Failed to poll", r"error sending request",
                           r"Failed to.*Athena"],
        "kg_success_patterns": ["knowledge persisted", "Success: knowledge", "知识已", r'"result":"Success"'],
    },
    "token_schema": {"reasoning_in_output": True, "cache_excluded": True},
}


@dataclass
class CreateRequest:
    """简化版创建请求 — 调用方只需传项目 ID + 任务 ID，trace 路径/kind/验证 trace 全部自动发现。

    必传：evaluation_id, kg_project_id, kg_task_id
    可选：benchmark_source，benchmark_set_id，vc_source_task_id，eval_mode
    """
    evaluation_id: str
    evaluation_name: str | None = None
    # 项目
    kg_project_id: str = ""
    kg_task_id: str = ""
    # 基线来源
    benchmark_source: str = "vuln_center"  # "vbench_zip" | "vuln_center"
    benchmark_set_id: str | None = None  # vuln_center: 漏洞中心项目ID; vbench_zip: V-Bench set ID; 默认=kg_project_id
    vc_source_task_id: str | None = None  # 漏洞中心 source_task_id（可选）
    # 评测模式
    eval_mode: str = "dev"  # "dev"（开发态） | "runtime"（运行态）


def _build_entries(req: CreateRequest) -> list[dict]:
    """从项目 ID + 任务 ID 自动发现 trace，构建 entries。

    每个 entry 包含：task_id, condition, source_uri, trace_kind, category,
    project_id, project_name, task_id_actual, task_name, benchmark_item_ids（空，INGESTING 阶段填充）, expected_label。
    """
    entries: list[dict] = []

    # 预收集项目名/任务名（best-effort，平台不可用时不阻断）
    _proj_names: dict[str, str] = {}
    _task_names: dict[str, dict[str, str]] = {}  # project_id -> {task_id -> task_name}
    _pids = {req.kg_project_id} - {""}
    if _pids:
        try:
            for p in ps.get_projects():
                if p["id"] in _pids:
                    _proj_names[p["id"]] = p.get("name") or p["id"]
        except Exception:
            pass
        for pid in _pids:
            try:
                _task_names[pid] = {t["id"]: t.get("name") or t["id"] for t in ps.get_tasks(pid)}
            except Exception:
                _task_names[pid] = {}

    # 1. 挖掘 trace
    pid = req.kg_project_id
    tid = req.kg_task_id
    if pid and tid:
        try:
            result = ps.discover_mining_trace(pid, tid)
            if result:
                kind, uri = result
                entries.append({
                    "task_id": "T001",
                    "condition": "KG",
                    "source_uri": uri,
                    "trace_kind": kind,
                    "category": "mining",
                    "project_id": pid,
                    "project_name": _proj_names.get(pid, pid),
                    "task_id_actual": tid,
                    "task_name": _task_names.get(pid, {}).get(tid, tid),
                    "benchmark_item_ids": [],
                    "expected_label": "VULNERABLE",
                })
                log("CREATE", f"自动发现挖掘 trace: kind={kind} project={pid} task={tid}")
            else:
                log("CREATE", f"⚠ 未找到挖掘 trace: project={pid} task={tid}")
        except Exception as err:
            log("CREATE", f"⚠ 自动发现挖掘 trace 失败: project={pid} task={tid} err={err}")

    # 2. 验证 trace
    if pid:
        try:
            verify_traces = ps.discover_verify_traces(pid, tid)
            for vt in verify_traces:
                # 多个同类型验证 trace 用 source_task_id 区分，避免 task_run_id 冲突
                tid = vt.get("source_task_id", "")
                suffix = f"-{tid[:8]}" if tid else ""
                entries.append({
                    "task_id": f"verify-{vt['agent_name']}{suffix}",
                    "condition": "KG",
                    "source_uri": vt["source_uri"],
                    "trace_kind": vt["trace_kind"],
                    "category": "verify",
                    "project_id": pid,
                    "project_name": _proj_names.get(pid, pid),
                    "benchmark_item_ids": [],
                })
                log("CREATE", f"自动发现验证 trace: kind={vt['trace_kind']} agent={vt['agent_name']}")
        except Exception as err:
            log("CREATE", f"⚠ 自动发现验证 trace 失败: project={pid} err={err}")

    return entries


def create(req: CreateRequest):
    """Stage 0：建 evaluation + snapshot（冻结）。

    调用方只需传项目 ID + 任务 ID，trace 路径/kind/验证 trace 全部自动发现。
    基线 case 数据在 run() 的 INGESTING 阶段从漏洞中心/V-Bench 获取。
    """
    # 1. 默认 benchmark_set_id
    if not req.benchmark_set_id:
        req.benchmark_set_id = req.kg_project_id

    # 2. 自动发现 trace，构建 entries
    entries = _build_entries(req)
    if not entries:
        raise ValueError(
            f"未发现任何 trace：kg_project={req.kg_project_id} kg_task={req.kg_task_id}")

    # 3. 查基线名称（best-effort）
    vbench_project_name = ""
    vc_source_project_name = ""
    vc_source_task_name = ""
    if req.benchmark_source == "vuln_center":
        # 漏洞中心：benchmark_set_id=项目ID, vc_source_task_id=任务ID
        try:
            for p in ps.get_projects():
                if p["id"] == req.benchmark_set_id:
                    vc_source_project_name = p.get("name") or ""
                    break
        except Exception:
            pass
        if req.vc_source_task_id:
            try:
                for t in ps.get_tasks(req.benchmark_set_id):
                    if t["id"] == req.vc_source_task_id:
                        vc_source_task_name = t.get("name") or ""
                        break
            except Exception:
                pass
    elif req.benchmark_source == "vbench_zip":
        # V-Bench：benchmark_set_id=V-Bench set ID
        try:
            from ..infrastructure.vbench_client import get_project
            vp = get_project(req.benchmark_set_id)
            vbench_project_name = vp.get("name") or "" if vp else ""
        except Exception:
            pass

    # 4. benchmark_set + evaluation + snapshot
    eval_name = req.evaluation_name or f"eval-{req.evaluation_id}"
    manifest = {"entries": entries,
                "kg_project_id": req.kg_project_id,
                "kg_task_id": req.kg_task_id,
                "benchmark_source": req.benchmark_source,
                "benchmark_set_id": req.benchmark_set_id,
                "vc_source_task_id": req.vc_source_task_id,
                "vbench_project_name": vbench_project_name,
                "vc_source_project_name": vc_source_project_name,
                "vc_source_task_name": vc_source_task_name,
                "eval_mode": req.eval_mode}

    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT IGNORE INTO benchmark_set (benchmark_set_id, name, version, manifest_hash) "
            "VALUES (%s,%s,'1.0','hash-bs001')",
            (req.benchmark_set_id, f"name-{req.benchmark_set_id}"))
        cur.execute(
            "INSERT INTO evaluation (evaluation_id, evaluation_name, benchmark_set_id, "
            "task_id, agent_name) "
            "VALUES (%s,%s,%s,%s,'Turing')",
            (req.evaluation_id, eval_name, req.benchmark_set_id, req.kg_task_id))
        cur.execute(
            "INSERT INTO evaluation_snapshot (snapshot_id, evaluation_id, parser_version, resolver_version, "
            "metric_profile_version, statistical_profile, canonical_action_schema, knowledge_rule_version, "
            "token_schema_version, experiment_fingerprint_json, code_hashes_json, config_json) "
            "VALUES (%s,%s,'1.0','1.0','1.0','1.0','1.0','1.0','1.0',%s,%s,%s)",
            (f"snap-{req.evaluation_id}", req.evaluation_id,
             json.dumps({"agent_hash": "a"}), json.dumps({}),
             json.dumps({"manifest": manifest, **EVAL_CONFIG})))
    finally:
        conn.close()

    return req.evaluation_id


def _db_query(fn, _retries=8):
    """短连接 + 重试包装器。

    2006/2013（连接丢失）时指数退避重试，其他错误直接抛出。
    """
    import pymysql
    from ..infrastructure.log_util import log_to_file
    last_err = None
    for attempt in range(_retries):
        conn = None
        try:
            conn = connect(autocommit=True)
            return fn(conn.cursor())
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
            last_err = e
            # 强制关闭底层 pymysql 连接，防止池复用坏连接
            if conn:
                try:
                    inner = getattr(conn, '_con', None)
                    if inner is not None and not getattr(inner, '_closed', True):
                        inner.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            if e.args and e.args[0] in (2013, 2006) and attempt < _retries - 1:
                _wait = min(2 * (attempt + 1), 30)
                log("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]}, retry in {_wait}s...")
                log_to_file("DB RETRY", f"{attempt+1}/{_retries}: {e.args[0]} {e}, retry in {_wait}s...")
                import time; time.sleep(_wait)
                continue
            raise
        finally:
            if conn:
                try: conn.close()
                except: pass
    raise last_err  # type: ignore[misc]


def get_status(evaluation_id: str) -> dict:
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT evaluation_status, evaluation_name, error_message, started_at "
                    "FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        r = cur.fetchone()
        if not r:
            return {"error": "not found"}
        cur.execute("SELECT COUNT(*) FROM metric_result WHERE evaluation_id=%s", (evaluation_id,))
        n_metrics = cur.fetchone()[0]
        # MySQL NOW(3) 返回 UTC，前端统一转北京时间
        return {"evaluation_id": evaluation_id, "status": r[0], "name": r[1], "metrics": n_metrics,
                "error_message": r[2],
                "started_at": r[3].isoformat() if r[3] else None,
                "progress": get_progress(evaluation_id)}
    finally:
        conn.close()


def get_report(evaluation_id: str) -> dict:
    # 优先从文件读取（新方式），回退到 DB report_config_json（旧数据兼容）
    import os as _os
    _reports_dir = _os.environ.get("EVAL_REPORTS_DIR") or "/app/reports"
    _json_path = _os.path.join(_reports_dir, f"{evaluation_id}.json")
    if _os.path.isfile(_json_path):
        with open(_json_path, "r", encoding="utf-8") as _f:
            return {"evaluation_id": evaluation_id, "status": "READY",
                    "report": json.loads(_f.read())}
    # 回退：从 DB 读旧数据
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT report_config_json, status FROM evaluation_report WHERE evaluation_id=%s", (evaluation_id,))
        r = cur.fetchone()
        if not r:
            return {"error": "report not found"}
        return {"evaluation_id": evaluation_id, "status": r[1],
                "report": json.loads(r[0]) if r[0] else None}
    finally:
        conn.close()
