"""System + V-Bench 路由。系统参数管理 + V-Bench 只读。"""
from __future__ import annotations
import asyncio
import threading
import time
from fastapi import APIRouter
from pydantic import BaseModel, Field
from ...infrastructure.database import connect
from ...infrastructure.log_util import log
from ...infrastructure.concurrency import get_keys as _conc_keys, get as _conc_get, set_val as _conc_set

sys_r = APIRouter(prefix="/api/v1/system", tags=["system"])
vb = APIRouter(prefix="/api/v1/vbench", tags=["vbench"])

# 可持久化的配置 key 集合 — 所有并发参数
_CONFIG_KEYS = _conc_keys()

# 配置时间戳（DB 更新时写 NOW(3)，worker 定期检查，变化则重载）
_config_version = None
_config_version_lock = threading.Lock()


class SystemConfigUpdate(BaseModel):
    llm_max_concurrency: int | None = Field(default=None, ge=1, le=1000)
    max_concurrent_evals: int | None = Field(default=None, ge=1, le=10)
    eval_pool_max: int | None = Field(default=None, ge=1, le=50)
    parse_workers: int | None = Field(default=None, ge=1, le=50)
    source_fill_workers: int | None = Field(default=None, ge=1, le=1000)
    ac_fetch_workers: int | None = Field(default=None, ge=1, le=50)
    resolver_workers: int | None = Field(default=None, ge=1, le=1000)
    ai_match_workers: int | None = Field(default=None, ge=1, le=1000)
    ac_llm_workers: int | None = Field(default=None, ge=1, le=1000)
    fpr_cond_workers: int | None = Field(default=None, ge=1, le=10)
    fpr_baseline_workers: int | None = Field(default=None, ge=1, le=1000)
    fpr_baseline_batch: int | None = Field(default=None, ge=1, le=1000)
    kg_analysis_workers: int | None = Field(default=None, ge=1, le=1000)
    bootstrap_workers: int | None = Field(default=None, ge=1, le=20)
    reasoning_effort: str | None = Field(default=None, pattern="^(none|low|high|max)$")


def _apply_config(key: str, value: str):
    """把 DB 里的 config_value 应用到运行时。"""
    from ...infrastructure import llm
    from .evaluations import set_max_concurrent_evals
    if key == "llm_max_concurrency":
        llm.set_max_concurrency(int(value))
        _conc_set("llm_max_concurrency", int(value))
    elif key == "max_concurrent_evals":
        set_max_concurrent_evals(int(value))
    elif key == "reasoning_effort":
        llm.set_runtime_config(reasoning_effort=value)
    elif key in _CONFIG_KEYS:
        _conc_set(key, int(value))


def load_system_config():
    """启动时从 DB 加载系统参数（表由 migrations 创建，此处只读取）。"""
    global _config_version
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT config_key, config_value FROM system_config")
            rows = cur.fetchall()
            for key, value in rows:
                if key in _CONFIG_KEYS or key == "reasoning_effort":
                    _apply_config(key, value)
                    log("SYS_CFG", f"loaded {key}={value}")
            if rows:
                log("SYS_CFG", f"从 DB 加载 {len(rows)} 项系统参数")
        finally:
            conn.close()
    except Exception as e:
        log("SYS_CFG", f"加载系统参数失败（用默认值）: {e}")
    # 启动定期重载线程（解决多 worker 内存隔离问题）
    _start_config_watcher()


def _start_config_watcher():
    """后台线程：每 10 秒同步配置时间戳 + 检测僵死评测任务。

    1. 配置同步：比较 DB 中 _version 时间戳，变化则重载所有配置。
    2. 僵死检测：查询非终态但超时的评测，不在本 worker 运行则标记 FAILED。
       - 首次 tick：标记 worker 启动前已存在的运行中评测（pod 重启后的僵死）
       - 后续 tick：标记超过 2 小时的僵死评测
    """
    _RUNNING_STATES = (
        'RUNNING', 'VALIDATING', 'INGESTING', 'PARSING', 'AI_MATCHING',
        'RESOLVING', 'PAIRING', 'CALCULATING', 'STATISTICAL_ANALYSIS',
        'DIAGNOSING', 'REPORTING', 'FINALIZING',
    )
    _TERMINAL = ('COMPLETED', 'COMPLETED_WITH_WARNINGS', 'FAILED', 'CANCELLED')

    def _watcher():
        global _config_version
        from .evaluations import _running_futures, _running_lock
        _first_tick = True
        while True:
            time.sleep(10)
            try:
                conn = connect(autocommit=True)
                try:
                    cur = conn.cursor()

                    # ── 1. 配置同步（时间戳比较）──
                    cur.execute("SELECT config_value FROM system_config WHERE config_key='_version'")
                    row = cur.fetchone()
                    db_ts = str(row[0]) if row else None
                    if db_ts is not None and db_ts != _config_version:
                        with _config_version_lock:
                            _config_version = db_ts
                        _reload_keys = tuple(_CONFIG_KEYS) + ("reasoning_effort",)
                        cur.execute(
                            "SELECT config_key, config_value FROM system_config "
                            "WHERE config_key IN (%s)" % ",".join(["%s"] * len(_reload_keys)),
                            _reload_keys)
                        for key, value in cur.fetchall():
                            _apply_config(key, value)
                        log("SYS_CFG", f"配置已重载 (timestamp={db_ts})")

                    # ── 2. 僵死评测检测 ──
                    placeholders = ",".join(["%s"] * len(_RUNNING_STATES))
                    if _first_tick:
                        # 首次：标记 worker 启动前已存在的运行中评测
                        # 注意：不检查 finished_at IS NULL，因为续跑的评测可能有上一轮的 stale finished_at
                        cur.execute(
                            f"SELECT evaluation_id, evaluation_status FROM evaluation "
                            f"WHERE evaluation_status IN ({placeholders}) "
                            f"AND started_at < DATE_SUB(NOW(3), INTERVAL 2 MINUTE)",
                            _RUNNING_STATES)
                    else:
                        # 后续：标记超过 2 小时的僵死评测
                        cur.execute(
                            f"SELECT evaluation_id, evaluation_status FROM evaluation "
                            f"WHERE evaluation_status IN ({placeholders}) "
                            f"AND started_at < DATE_SUB(NOW(3), INTERVAL 120 MINUTE)",
                            _RUNNING_STATES)
                    zombies = cur.fetchall()
                    if zombies:
                        with _running_lock:
                            active_ids = set(_running_futures.keys())
                        for eid, status in zombies:
                            if eid in active_ids:
                                continue  # 仍在运行
                            cur.execute(
                                "UPDATE evaluation SET evaluation_status='FAILED', "
                                "error_message=%s, finished_at=NOW(3) "
                                "WHERE evaluation_id=%s AND evaluation_status NOT IN "
                                "('COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCELLED')",
                                (f"线程异常退出（{status} 状态超时）", eid))
                            if cur.rowcount > 0:
                                log("WATCHDOG", f"僵死评测 {eid} (status={status}) → FAILED")

                    # ── 3. CREATED + 有 snapshot 但不在线程池中的评测 → 续跑 ──
                    cur.execute(
                        "SELECT e.evaluation_id FROM evaluation e "
                        "INNER JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
                        "WHERE e.evaluation_status='CREATED'")
                    created_rows = cur.fetchall()
                    if created_rows:
                        from .evaluations import _running_futures, _running_lock, _pending_evals, _paused_evals
                        with _running_lock:
                            active_ids = set(_running_futures.keys())
                            pending_ids = set(eid for eid, _ in _pending_evals)
                            paused_ids = set(_paused_evals)
                        known_ids = active_ids | pending_ids | paused_ids
                        from .evaluations import _submit_eval, _run_bg_resume
                        for (eid,) in created_rows:
                            if eid in known_ids:
                                continue  # 已在线程池或队列中
                            log("WATCHDOG", f"{eid} (CREATED, has snapshot) 不在线程池 → 续跑")
                            _submit_eval(eid, lambda eid=eid: _run_bg_resume(eid))

                    # ── 4. QUEUED 但不在线程池中的评测 → 加入暂停队列（pod 重启后恢复）──
                    cur.execute("SELECT evaluation_id FROM evaluation WHERE evaluation_status='QUEUED'")
                    queued_rows = cur.fetchall()
                    if queued_rows:
                        with _running_lock:
                            active_ids = set(_running_futures.keys())
                        from .evaluations import _submit_paused_eval
                        for (eid,) in queued_rows:
                            if eid in active_ids:
                                continue  # 已在线程池
                            log("WATCHDOG", f"{eid} (QUEUED) 不在线程池 → 加入暂停队列")
                            _submit_paused_eval(eid)

                    _first_tick = False
                finally:
                    conn.close()

                # ── 5. LLM 线程 dict watchdog ──
                # 清理已完成/卡死的线程，释放 dict 空间
                try:
                    from ...infrastructure import llm as _llm_mod
                    _llm_mod.watchdog_cleanup()
                except Exception as _e:
                    log("WATCHDOG", f"LLM 线程清理异常: {_e}")
            except Exception as e:
                log("WATCHDOG", f"watcher 异常: {e}")

    t = threading.Thread(target=_watcher, daemon=True, name="config-watcher")
    t.start()


def _save_config(key: str, value: str):
    """写入 DB（upsert），并更新 _version 时间戳触发其他 worker 重载。"""
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (key, value))
        # 写入当前时间戳，触发其他 worker 的 watcher 重载
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) VALUES ('_version', NOW(3)) "
            "ON DUPLICATE KEY UPDATE config_value=NOW(3)")
        conn.commit()
    finally:
        conn.close()


@sys_r.get("/health")
def health():
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='athena_eval'")
        tables = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM information_schema.referential_constraints WHERE constraint_schema='athena_eval'")
        fks = cur.fetchone()[0]
        return {"db": "ok", "tables": tables, "fks": fks, "database": "athena_eval"}
    except Exception as e:
        return {"db": "error", "detail": str(e)}
    finally:
        conn.close()


@sys_r.get("/schema")
def schema_info():
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT table_name, table_rows FROM information_schema.tables WHERE table_schema='athena_eval' ORDER BY table_name")
        return {"tables": [dict(zip(["table", "rows"], r)) for r in cur.fetchall()]}
    finally:
        conn.close()


def _load_config_from_db() -> dict:
    """从 DB 读取持久化的系统参数（不受多 worker 内存隔离影响）。"""
    result = {}
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT config_key, config_value FROM system_config")
            for key, value in cur.fetchall():
                if key in _CONFIG_KEYS:
                    result[key] = value
        finally:
            conn.close()
    except Exception as e:
        log("SYS_CFG", f"从 DB 读取配置失败: {e}")
    return result


@sys_r.get("/config")
async def get_system_config():
    """获取系统参数（从 DB 读取，确保多 worker 一致）。
    async + to_thread 避免 sync 端点在 GIL 竞争时阻塞事件循环。
    """
    from ...infrastructure import llm
    db_cfg = await asyncio.to_thread(_load_config_from_db)
    # _running_lock 是 threading.Lock，持有时间极短（几个 len() 调用）
    # 但在 GIL 竞争下仍可能阻塞，用 to_thread 避免占用事件循环
    def _get_counts():
        from .evaluations import _running_futures, _pending_evals, _paused_evals, _pausing_eids, _running_lock
        with _running_lock:
            running = len(_running_futures) - len(_pausing_eids)
            pending = len(_pending_evals)
            paused = len(_paused_evals)
        return running, pending, paused
    running, pending, paused = await asyncio.to_thread(_get_counts)
    # 所有并发参数：DB 有值用 DB 值，否则用内存默认值
    result = {}
    for key in _CONFIG_KEYS:
        result[key] = int(db_cfg.get(key, _conc_get(key)))
    # llm_max_concurrency 单独走 llm 模块（dict 管理线程）
    result["llm_max_concurrency"] = int(db_cfg.get("llm_max_concurrency", llm.get_max_concurrency()))
    result["reasoning_effort"] = db_cfg.get("reasoning_effort", llm.get_runtime_config().get("reasoning_effort", "none"))
    result["running_tasks"] = running
    result["queued_tasks"] = pending + paused
    result["paused_tasks"] = paused
    result["llm_active"] = llm.get_active_concurrency()
    result["llm_thread_count"] = llm.get_thread_count()
    result["thread_count"] = threading.active_count()
    return result


@sys_r.put("/config")
def update_system_config(params: SystemConfigUpdate):
    """更新运行时系统参数，同时写入 DB 持久化。"""
    global _config_version
    from ...infrastructure import llm
    from .evaluations import set_max_concurrent_evals
    updated = []
    # 遍历所有参数字段，非 None 的更新
    for field_name in params.model_fields:
        value = getattr(params, field_name)
        if value is None:
            continue
        if field_name == "llm_max_concurrency":
            llm.set_max_concurrency(value)
            _conc_set("llm_max_concurrency", value)
        elif field_name == "max_concurrent_evals":
            set_max_concurrent_evals(value)
        elif field_name == "reasoning_effort":
            llm.set_runtime_config(reasoning_effort=value)
        else:
            _conc_set(field_name, value)
        _save_config(field_name, str(value))
        updated.append(f"{field_name}={value}")
    # 同步本地时间戳，避免 watcher 重复重载
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT config_value FROM system_config WHERE config_key='_version'")
            row = cur.fetchone()
            if row:
                with _config_version_lock:
                    _config_version = str(row[0])
        finally:
            conn.close()
    except Exception:
        pass
    return {"updated": updated}


@vb.get("/projects")
def vbench_projects():
    """V-Bench 项目列表（只读）。"""
    from ...infrastructure.vbench_client import list_projects
    return {"projects": list_projects()}


@vb.get("/projects/{project_id}/cases")
def vbench_cases(project_id: str):
    """V-Bench 项目 benchmark 漏洞 case（真值，只读）。"""
    from ...infrastructure.vbench_client import get_cases
    return {"cases": get_cases(project_id)}


@vb.get("/projects/{project_id}/benchmark")
def vbench_benchmark(project_id: str):
    """V-Bench 项目 benchmark 包：benchmark.json + ground truth 详情。"""
    from ...infrastructure.vbench_client import get_benchmark
    return get_benchmark(project_id)


@vb.get("/vuln-center/{project_id}/{task_id}")
def vuln_center_benchmark(project_id: str, task_id: str):
    """漏洞中心基线：按项目+任务拉取人工确认漏洞（VULNERABLE）。"""
    from ...infrastructure.vuln_center_client import get_vuln_center_benchmark
    return get_vuln_center_benchmark(project_id, task_id)
