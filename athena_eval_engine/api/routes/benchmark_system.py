"""System + V-Bench 只读路由。Benchmark 管理由 V-Bench 系统负责。"""
from __future__ import annotations
from fastapi import APIRouter
from ...infrastructure.database import connect

sys_r = APIRouter(prefix="/api/v1/system", tags=["system"])
vb = APIRouter(prefix="/api/v1/vbench", tags=["vbench"])


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
    """漏洞中心基线：按项目+任务拉取人工确认的漏洞（含漏洞与非漏洞两类）。"""
    from ...infrastructure.vuln_center_client import get_vuln_center_benchmark
    return get_vuln_center_benchmark(project_id, task_id)
