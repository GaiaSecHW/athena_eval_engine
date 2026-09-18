"""System + V-Bench 路由。系统参数管理 + V-Bench 只读。"""
from __future__ import annotations
import threading
import time
from fastapi import APIRouter
from pydantic import BaseModel, Field
from ...infrastructure.database import connect
from ...infrastructure.log_util import log

sys_r = APIRouter(prefix="/api/v1/system", tags=["system"])
vb = APIRouter(prefix="/api/v1/vbench", tags=["vbench"])

# 可持久化的配置 key 集合（用于 load 时过滤）
_CONFIG_KEYS = {
    "llm_max_concurrency", "max_concurrent_evals",
    "parse_workers", "kg_analysis_workers",
}

# 配置版本号（DB 更新时 +1，worker 定期检查，变化则重载）
_config_version = 0
_config_version_lock = threading.Lock()


class SystemConfigUpdate(BaseModel):
    llm_max_concurrency: int | None = Field(default=None, ge=1, le=200)
    max_concurrent_evals: int | None = Field(default=None, ge=1, le=10)
    parse_workers: int | None = Field(default=None, ge=1, le=50)
    kg_analysis_workers: int | None = Field(default=None, ge=1, le=50)


def _apply_config(key: str, value: str):
    """把 DB 里的 config_value 应用到运行时。"""
    from ...infrastructure import llm
    from .evaluations import set_max_concurrent_evals
    from ...application.evaluation_service import set_runtime_workers
    if key == "llm_max_concurrency":
        llm.set_max_concurrency(int(value))
    elif key == "max_concurrent_evals":
        set_max_concurrent_evals(int(value))
    elif key == "parse_workers":
        set_runtime_workers(parse=int(value))
    elif key == "kg_analysis_workers":
        set_runtime_workers(kg_analysis=int(value))


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
                if key in _CONFIG_KEYS:
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
    """后台线程：每 10 秒检查 DB config_version，变化则重载配置。"""
    def _watcher():
        global _config_version
        while True:
            time.sleep(10)
            try:
                conn = connect(autocommit=True)
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT config_value FROM system_config WHERE config_key='_version'")
                    row = cur.fetchone()
                    db_ver = int(row[0]) if row else 0
                finally:
                    conn.close()
                with _config_version_lock:
                    if db_ver != _config_version:
                        _config_version = db_ver
                if db_ver > 0:
                    # 重新加载所有配置
                    conn = connect(autocommit=True)
                    try:
                        cur = conn.cursor()
                        cur.execute("SELECT config_key, config_value FROM system_config WHERE config_key IN (%s)" % ",".join(["%s"]*len(_CONFIG_KEYS)), tuple(_CONFIG_KEYS))
                        for key, value in cur.fetchall():
                            _apply_config(key, value)
                        log("SYS_CFG", f"配置已重载 (version={db_ver})")
                    finally:
                        conn.close()
            except Exception:
                pass

    t = threading.Thread(target=_watcher, daemon=True, name="config-watcher")
    t.start()


def _save_config(key: str, value: str):
    """写入 DB（upsert），并递增 _version 触发其他 worker 重载。"""
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (key, value))
        # 递增版本号，触发其他 worker 的 watcher 重载
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) VALUES ('_version', '1') "
            "ON DUPLICATE KEY UPDATE config_value=config_value+1")
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
def get_system_config():
    """获取系统参数（从 DB 读取，确保多 worker 一致）。"""
    from ...infrastructure import llm
    from .evaluations import get_max_concurrent_evals
    from ...application.evaluation_service import get_runtime_workers
    db_cfg = _load_config_from_db()
    return {
        "llm_max_concurrency": int(db_cfg.get("llm_max_concurrency", llm.get_max_concurrency())),
        "max_concurrent_evals": int(db_cfg.get("max_concurrent_evals", get_max_concurrent_evals())),
        "parse_workers": int(db_cfg.get("parse_workers", get_runtime_workers().get("parse", 4))),
        "kg_analysis_workers": int(db_cfg.get("kg_analysis_workers", get_runtime_workers().get("kg_analysis", 8))),
    }


@sys_r.put("/config")
def update_system_config(params: SystemConfigUpdate):
    """更新运行时系统参数，同时写入 DB 持久化。"""
    global _config_version
    from ...infrastructure import llm
    from .evaluations import set_max_concurrent_evals
    from ...application.evaluation_service import set_runtime_workers
    updated = []
    if params.llm_max_concurrency is not None:
        llm.set_max_concurrency(params.llm_max_concurrency)
        _save_config("llm_max_concurrency", str(params.llm_max_concurrency))
        updated.append(f"llm_max_concurrency={params.llm_max_concurrency}")
    if params.max_concurrent_evals is not None:
        set_max_concurrent_evals(params.max_concurrent_evals)
        _save_config("max_concurrent_evals", str(params.max_concurrent_evals))
        updated.append(f"max_concurrent_evals={params.max_concurrent_evals}")
    if params.parse_workers is not None:
        set_runtime_workers(parse=params.parse_workers)
        _save_config("parse_workers", str(params.parse_workers))
        updated.append(f"parse_workers={params.parse_workers}")
    if params.kg_analysis_workers is not None:
        set_runtime_workers(kg_analysis=params.kg_analysis_workers)
        _save_config("kg_analysis_workers", str(params.kg_analysis_workers))
        updated.append(f"kg_analysis_workers={params.kg_analysis_workers}")
    # 同步本地版本号，避免 watcher 重复重载
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT config_value FROM system_config WHERE config_key='_version'")
            row = cur.fetchone()
            if row:
                with _config_version_lock:
                    _config_version = int(row[0])
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
