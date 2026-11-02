"""Evaluation Service — create() + 状态/报告查询 + trace 缓存管理。

create(request) → 冻结 snapshot + 建 evaluation。
get_status() / get_report() → 查询评测状态/报告。
set_cancel/clear_cancel → 协作取消信号（跨 worker，写 DB cancel_requested）。

v2 Orchestrator (v2/pipeline/orchestrator.py) 已替代 v1 run() 函数。
进度追踪和 trace 缓存已提取到 v2/infra/progress.py 和 v2/infra/trace_cache.py，
此处 re-export 保持向后兼容（es.xxx 调用不受影响）。
"""
from __future__ import annotations
import json
import os
import threading
from dataclasses import dataclass
from ..infrastructure.database import connect
from ..infrastructure.log_util import log
from ..application import platform_service as ps

# ── re-export: 进度追踪（已提取到 v2/infra/progress.py）──
from ..v2.infra.progress import (
    set_progress as _set_progress_impl,
    set_task_progress as _set_task_progress_impl,
    get_progress,
    clear_progress,
)

def set_progress(evaluation_id: str, text: str):
    _set_progress_impl(evaluation_id, text)

def set_task_progress(evaluation_id: str, task_run_id: str, text: str):
    _set_task_progress_impl(evaluation_id, task_run_id, text)

# ── re-export: trace 缓存（已提取到 v2/infra/trace_cache.py）──
from ..v2.infra.trace_cache import (
    cleanup_trace_cache as _cleanup_trace_cache_impl,
    copy_trace_to_local as _copy_trace_to_local_impl,
    _verify_sqlite,
    _K8S_TRACE_CACHE,
)

def _cleanup_trace_cache(evaluation_id: str = ""):
    _cleanup_trace_cache_impl(evaluation_id)

def _copy_trace_to_local(remote_path: str, evaluation_id: str = "") -> str:
    return _copy_trace_to_local_impl(remote_path, evaluation_id=evaluation_id)


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


from ..v2.infra.db_utils import db_query as _db_query


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
    from ..config_loader import get_reports_dir
    _reports_dir = get_reports_dir()
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
