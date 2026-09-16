"""System + V-Bench 路由。系统参数管理 + V-Bench 只读。"""
from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel
from ...infrastructure.database import connect
from ...infrastructure.log_util import log

sys_r = APIRouter(prefix="/api/v1/system", tags=["system"])
vb = APIRouter(prefix="/api/v1/vbench", tags=["vbench"])

# config_key → (apply_fn, serialize_fn) 映射
# apply_fn: 把 DB 值应用到运行时
# serialize_fn: 把 API 传入值序列化为 DB 字符串
_CONFIG_KEYS = {
    "llm_max_concurrency":  ("int", 1, 200),
    "max_concurrent_evals": ("int", 1, 10),
    "parse_workers":        ("int", 1, 50),
    "kg_analysis_workers":  ("int", 1, 50),
    "llm_base_url":         ("str",),
    "llm_enabled":          ("bool",),
}


class SystemConfigUpdate(BaseModel):
    llm_max_concurrency: int | None = None
    max_concurrent_evals: int | None = None
    llm_base_url: str | None = None
    llm_enabled: bool | None = None
    parse_workers: int | None = None
    kg_analysis_workers: int | None = None


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
    elif key == "llm_base_url":
        llm.set_runtime_config(llm_base_url=value)
    elif key == "llm_enabled":
        llm.set_runtime_config(llm_enabled=(value.lower() == "true"))


def load_system_config():
    """启动时从 DB 加载系统参数。表不存在则自动建表，无数据时用默认值。"""
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            # 自动建表（IF NOT EXISTS）
            cur.execute(
                "CREATE TABLE IF NOT EXISTS system_config ("
                "  config_key VARCHAR(64) PRIMARY KEY,"
                "  config_value VARCHAR(512) NOT NULL,"
                "  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
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


def _save_config(key: str, value: str):
    """写入 DB（upsert）。"""
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (key, value))
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


@sys_r.get("/config")
def get_system_config():
    """获取运行时系统参数。"""
    from ...infrastructure import llm
    from .evaluations import get_max_concurrent_evals
    from ...application.evaluation_service import get_runtime_workers
    cfg = llm.get_runtime_config()
    return {
        "llm_max_concurrency": llm.get_max_concurrency(),
        "max_concurrent_evals": get_max_concurrent_evals(),
        "llm_base_url": cfg.get("llm_base_url", ""),
        "llm_enabled": cfg.get("llm_enabled", True),
        "parse_workers": get_runtime_workers().get("parse", 4),
        "kg_analysis_workers": get_runtime_workers().get("kg_analysis", 8),
    }


@sys_r.put("/config")
def update_system_config(params: SystemConfigUpdate):
    """更新运行时系统参数，同时写入 DB 持久化。"""
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
    if params.llm_base_url is not None:
        llm.set_runtime_config(llm_base_url=params.llm_base_url)
        _save_config("llm_base_url", params.llm_base_url)
        updated.append("llm_base_url")
    if params.llm_enabled is not None:
        llm.set_runtime_config(llm_enabled=params.llm_enabled)
        _save_config("llm_enabled", str(params.llm_enabled))
        updated.append(f"llm_enabled={params.llm_enabled}")
    if params.parse_workers is not None:
        set_runtime_workers(parse=params.parse_workers)
        _save_config("parse_workers", str(params.parse_workers))
        updated.append(f"parse_workers={params.parse_workers}")
    if params.kg_analysis_workers is not None:
        set_runtime_workers(kg_analysis=params.kg_analysis_workers)
        _save_config("kg_analysis_workers", str(params.kg_analysis_workers))
        updated.append(f"kg_analysis_workers={params.kg_analysis_workers}")
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
