"""FastAPI app + 路由。

POST /api/v1/evaluations              → 创建 + 后台异步跑（最多 N 并发，超出排队）
GET  /api/v1/evaluations              → 列表（web.py）
GET  /api/v1/evaluations/{id}         → 状态
DELETE /api/v1/evaluations/{id}       → 删除
POST /api/v1/evaluations/{id}/retry   → 重试
POST /api/v1/evaluations/{id}/cancel  → 取消
GET  /api/v1/evaluations/running      → 运行中列表

v2 报告端点在 v2/api/routes.py（/api/v2/evaluations/{id}/report 等）。
"""
from __future__ import annotations
import asyncio
import os
import sys
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, Future
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from ...application import evaluation_service as es
from ...infrastructure.log_util import log, set_eval_ctx, clear_eval_ctx, log_error
from ...infrastructure.concurrency import get as _conc_get, set_val as _conc_set

# 调大 GIL 切换间隔：600 线程下减少切换开销，让 HTTP 处理器能及时拿到 GIL
sys.setswitchinterval(0.015)
from .web import router as web_router
from .platform import router as platform_router
from .benchmark_system import vb as vbench_router, sys_r as sys_router

# 报告目录（删除旧 HTML 时用）
REPORTS_DIR = os.environ.get("EVAL_REPORTS_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "reports",
)

# 最多 N 个评测同时运行，其余排队等待
# 线程池固定大小（上界由 eval_pool_max 控制），通过队列 + 协作取消动态控制实际并发数
#   - 增大并发：_try_dispatch() 从队列调度（暂停的优先于新任务）
#   - 减小并发：_pause_excess() 对最晚创建的任务设 cancel_requested，
#     任务在下一个 _check_cancel 阶段边界退出，状态设为 QUEUED
_executor = ThreadPoolExecutor(max_workers=_conc_get("eval_pool_max"), thread_name_prefix="eval")
_running_futures: dict[str, Future] = {}  # 已提交到池（运行中 + 暂停中）
_pausing_eids: set[str] = set()  # 已发取消信号但尚未退出的任务
_paused_evals: deque[str] = deque()  # 暂停的任务（优先级高于新任务）
_pending_evals: deque[tuple[str, object]] = deque()  # 新任务等待队列
_running_lock = threading.Lock()
_TERMINAL_EVALUATION_STATUSES = {"COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED"}


def get_max_concurrent_evals() -> int:
    return _conc_get("max_concurrent_evals")


def _running_count() -> int:
    """实际运行中（已提交但未在暂停中）。须在 _running_lock 内调用。"""
    return len(_running_futures) - len(_pausing_eids)


def set_max_concurrent_evals(n: int):
    """设置最大并发评测数。立即生效，无需重建线程池。

    增大时从队列调度等待任务（暂停的优先于新任务），并清除暂停中的取消标记；
    减小时暂停最晚创建的任务（协作取消，在下一个阶段边界退出）。
    """
    old = _conc_get("max_concurrent_evals")
    _conc_set("max_concurrent_evals", n)
    n = _conc_get("max_concurrent_evals")  # 范围限制后的值
    if n > old:
        # 增大：清除暂停中任务的取消标记（让它们继续运行）
        with _running_lock:
            to_clear = list(_pausing_eids)
            _pausing_eids.clear()
        for eid in to_clear:
            es.clear_cancel(eid)
            log("THREAD", f"{eid} 暂停取消（并发数增大）")
        _try_dispatch()  # 调度等待中的任务
    elif n < old:
        _pause_excess(n)  # 减小：暂停多余的任务
    log("THREAD", f"max_concurrent_evals: {old} → {n}")


def _try_dispatch():
    """从队列调度任务到线程池。暂停的任务优先于新任务。"""
    while True:
        with _running_lock:
            if _running_count() >= _conc_get("max_concurrent_evals"):
                return
            if _paused_evals:
                eid = _paused_evals.popleft()
                es.clear_cancel(eid)  # 清除取消标记
                fn = lambda e=eid: _run_bg_resume(e)
            elif _pending_evals:
                eid, fn = _pending_evals.popleft()
            else:
                return
            fut = _executor.submit(fn)
            _running_futures[eid] = fut
            log("THREAD", f"_try_dispatch: 调度 {eid} (running={len(_running_futures)}, pausing={len(_pausing_eids)}, "
                  f"pending={len(_pending_evals)}, paused={len(_paused_evals)})")
        # done callback 在锁外注册
        def _done_cb(f, eid=eid):
            with _running_lock:
                cur = _running_futures.get(eid)
                if cur is not None and cur is f:
                    _running_futures.pop(eid, None)
                else:
                    log("THREAD", f"_done_cb: {eid} cur is f={cur is f} (cur={'set' if cur else 'None'}, "
                          f"running={len(_running_futures)}, pausing={len(_pausing_eids)})")
                was_pausing = eid in _pausing_eids
                _pausing_eids.discard(eid)
                if was_pausing:
                    # 任务被暂停后退出：设状态为 QUEUED，加入暂停队列
                    _set_queued_status(eid)
                    _paused_evals.append(eid)
            try:
                _try_dispatch()
            except RuntimeError:
                pass  # executor 已关闭（pod 关闭中）
        fut.add_done_callback(_done_cb)


def _pause_excess(target: int):
    """暂停最晚创建的任务，使运行数降至 target。

    对最晚创建的任务设 cancel_requested，任务在下一个 _check_cancel
    阶段边界退出（TaskCancelledError）。done callback 将状态设为 QUEUED，
    并加入 _paused_evals 队列（优先于新任务调度）。
    """
    to_pause = []
    with _running_lock:
        # 非暂停中的任务，最晚创建的在最后
        candidates = [eid for eid in _running_futures if eid not in _pausing_eids]
        while len(candidates) > target:
            eid = candidates.pop()
            _pausing_eids.add(eid)
            to_pause.append(eid)
    for eid in to_pause:
        es.set_cancel(eid)  # 通知任务在下一个阶段边界退出
        log("THREAD", f"{eid} 已暂停（并发数减少）")


def _set_queued_status(eid: str):
    """任务被暂停后，将 DB 状态设为 QUEUED。"""
    try:
        from ...infrastructure.database import connect
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (eid,))
            row = cur.fetchone()
            status = row[0] if row else "UNKNOWN"
            if status not in _TERMINAL_EVALUATION_STATUSES:
                cur.execute("UPDATE evaluation SET evaluation_status='QUEUED' WHERE evaluation_id=%s", (eid,))
                conn.commit()
                log("THREAD", f"{eid} 已暂停，状态 {status} → QUEUED")
            else:
                log("THREAD", f"{eid} 暂停时已终态 {status}，不覆盖")
        finally:
            conn.close()
    except Exception as e:
        log("THREAD", f"{eid} 设置 QUEUED 失败: {e}")


def _submit_eval(evaluation_id: str, fn) -> None:
    """提交评测任务到队列。保证一个 evaluation_id 只有一个在运行的线程。

    新任务加入 _pending_evals 队列，由 _try_dispatch() 调度。
    如果该 evaluation_id 已在暂停队列中，移至新任务队列（force retry 场景）。
    """
    with _running_lock:
        # 从暂停队列移除（force retry 暂停中的任务）
        try:
            _paused_evals.remove(evaluation_id)
        except ValueError:
            pass
        # 从待调度队列移除
        for item in list(_pending_evals):
            if item[0] == evaluation_id:
                _pending_evals.remove(item)
                break
        # 取消旧线程
        old = _running_futures.pop(evaluation_id, None)
        if old is not None:
            old.cancel()
            _pausing_eids.discard(evaluation_id)
            log("THREAD", f"{evaluation_id} 旧线程被替换（force retry）")
        _pending_evals.append((evaluation_id, fn))
        log("THREAD", f"_submit_eval: {evaluation_id} 加入队列 "
              f"(running={len(_running_futures)}, pausing={len(_pausing_eids)}, "
              f"pending={len(_pending_evals)}, paused={len(_paused_evals)}, max={_conc_get('max_concurrent_evals')})")
    _try_dispatch()


def _submit_paused_eval(evaluation_id: str):
    """将暂停的评测加入暂停队列（pod 重启后恢复）。"""
    with _running_lock:
        if evaluation_id in _running_futures:
            return  # 已在线程池
        if evaluation_id in _paused_evals:
            return  # 已在暂停队列
        _paused_evals.append(evaluation_id)
    _try_dispatch()


def _record_background_failure(evaluation_id: str, error: Exception, source: str) -> None:
    """Mark an in-progress evaluation failed without clobbering a final report.

    A late exception can occur after ``run()`` has persisted its report and
    transitioned the evaluation to a terminal state.  In that case the report
    is usable; overwriting the state with FAILED makes reopening it impossible.
    """
    # 写异常日志文件（独立文件，只写异常）
    log_error(evaluation_id, source, error)

    from ...infrastructure.database import connect
    err_msg = str(error)[:500]

    def _mark_failed_db(cur):
        cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        row = cur.fetchone()
        phase = row[0] if row else "UNKNOWN"
        if phase in _TERMINAL_EVALUATION_STATUSES:
            log(source, f"忽略终态后的异常: {evaluation_id} status={phase}: {err_msg}")
            return
        log(source, f"{evaluation_id} at {phase}: {err_msg}")
        cur.execute("UPDATE evaluation SET evaluation_status='FAILED', "
                    "error_message=%s, finished_at=NOW(3) "
                    "WHERE evaluation_id=%s", (f"[{phase}] {err_msg}", evaluation_id))

    try:
        es._db_query(_mark_failed_db)
    except Exception as db_error:
        log(source, f"记录失败状态失败: {db_error}")


class CreateRequest(BaseModel):
    """简化版创建请求 — 只传项目 ID + 任务 ID，trace 自动发现。"""
    evaluation_id: str
    evaluation_name: str | None = None
    kg_project_id: str = ""
    kg_task_id: str = ""
    benchmark_source: str = "vuln_center"  # "vbench_zip" | "vuln_center"
    benchmark_set_id: str | None = None  # 默认=kg_project_id
    vc_source_task_id: str | None = None
    eval_mode: str = "dev"  # "dev"（开发态） | "runtime"（运行态）


app = FastAPI(title="Athena Eval Engine", version="0.1.0")
app.include_router(web_router)
app.include_router(platform_router)
app.include_router(vbench_router)
app.include_router(sys_router)

# 挂载 v2 路由（数据源配置 + 报告端点 + 问题单端点）
from ...v2.api import create_v2_app
create_v2_app(app)

# v2 pipeline：替代 v1 es.run()，启用 v2 编排器
from ...v2.pipeline.orchestrator import Orchestrator as _V2Orchestrator
from ...v2.pipeline.orchestrator import TaskCancelledError as _V2TaskCancelledError


@app.on_event("startup")
def _on_startup():
    # 先启动独立健康检查端口（8091），让 probe 尽快通过
    from ...infrastructure.health_server import start as _start_health
    _start_health(8091)
    # resume_stuck_evaluations 在后台线程跑，不阻塞 startup
    # 它会做 schema migration + DB 查询 + 续跑评测，可能耗时数秒
    _resume_thread = threading.Thread(target=resume_stuck_evaluations, name="resume-stuck", daemon=True)
    _resume_thread.start()


@app.on_event("shutdown")
def _on_shutdown():
    from ...infrastructure.health_server import stop as _stop_health
    _stop_health()


def resume_stuck_evaluations():
    """Pod 重启后自动续跑卡住的评测。

    状态在 RUNNING_STATES 里的评测 = 后台线程已死（pod 重启），但 DB 里还显示运行中。
    重新提交到线程池，run() 会检查 facts 是否已存在自动跳过已完成的阶段。
    CREATED 状态 + 有 snapshot = create() 已完成但未被线程池捡到，续跑。
    CREATED 状态 + 无 snapshot = create() 半途失败，标记 FAILED 清理。
    """
    # 执行 schema 迁移 + 加载系统参数 + 续跑卡住的评测
    try:
        from ...v2.infra.migrations import run_migrations
        run_migrations()
        from .benchmark_system import load_system_config
        load_system_config()
        from ...infrastructure.database import connect
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            # CREATED + 有 snapshot = create() 完成但未被线程池捡到（如 pod 重启），续跑
            cur.execute(
                "SELECT e.evaluation_id FROM evaluation e "
                "INNER JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
                "WHERE e.evaluation_status='CREATED'")
            created_with_snapshot = cur.fetchall()
            for (eid,) in created_with_snapshot:
                log("STARTUP", f"{eid} (was CREATED, has snapshot) → 续跑")
                _submit_eval(eid, lambda eid=eid: _run_bg_resume(eid))
            # CREATED + 无 snapshot = create() 半途失败，标记 FAILED
            cur.execute(
                "SELECT e.evaluation_id FROM evaluation e "
                "LEFT JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
                "WHERE e.evaluation_status='CREATED' AND s.evaluation_id IS NULL")
            created_rows = cur.fetchall()
            for (eid,) in created_rows:
                log("STARTUP", f"{eid} (was CREATED, no snapshot) → 标记 FAILED（create 未完成）")
                cur.execute("UPDATE evaluation SET evaluation_status='FAILED', "
                            "error_message=%s, finished_at=NOW(3) WHERE evaluation_id=%s",
                            ("create() 未完成（无 snapshot），评测创建失败", eid))
            # QUEUED = 暂停的评测，加入暂停队列（优先于新任务调度）
            cur.execute("SELECT evaluation_id FROM evaluation WHERE evaluation_status='QUEUED'")
            queued_rows = cur.fetchall()
            for (eid,) in queued_rows:
                log("STARTUP", f"{eid} (was QUEUED) → 加入暂停队列")
                _submit_paused_eval(eid)
            # RUNNING_STATES = 线程已死但 DB 还显示运行中，续跑
            stuck_states = ('RUNNING', 'VALIDATING', 'INGESTING', 'PARSING',
                            'CASE_MATCHING', 'ROOT_CAUSE_ANALYSIS', 'RESOLVING',
                            'REPORTING', 'FINALIZING')
            placeholders = ','.join(['%s'] * len(stuck_states))
            cur.execute(f"SELECT evaluation_id, evaluation_status FROM evaluation "
                        f"WHERE evaluation_status IN ({placeholders})", stuck_states)
            stuck = cur.fetchall()
            if stuck:
                log("STARTUP", f"发现 {len(stuck)} 个卡住的评测，准备续跑:")
                for eid, status in stuck:
                    log("STARTUP", f"{eid} (was {status}) → 续跑")
                    _submit_eval(eid, lambda eid=eid: _run_bg_resume(eid))
            else:
                log("STARTUP", f"无卡住的评测")
        finally:
            conn.close()
    except Exception as e:
        log("STARTUP", f"扫描卡住评测失败（DB 可能未就绪）: {e}")


def _run_bg_resume(evaluation_id: str):
    """续跑单个评测。原子获取状态锁，跨 worker 只有一个能跑。"""
    set_eval_ctx(evaluation_id)
    log("THREAD", f"_run_bg_resume: {evaluation_id} 开始执行")
    from ...infrastructure.database import connect
    stuck_states = ('CREATED', 'QUEUED', 'RUNNING', 'VALIDATING', 'INGESTING', 'PARSING',
                    'CASE_MATCHING', 'ROOT_CAUSE_ANALYSIS', 'RESOLVING',
                    'REPORTING', 'FINALIZING')
    placeholders = ','.join(['%s'] * len(stuck_states))
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE evaluation SET evaluation_status='RUNNING', started_at=NOW(3), finished_at=NULL, error_message=NULL, cancel_requested=0 "
                f"WHERE evaluation_id=%s AND evaluation_status IN ({placeholders})",
                (evaluation_id, *stuck_states))
            if cur.rowcount == 0:
                log("EVAL", f"{evaluation_id} 续跑已被其他 worker 接管，退出")
                return
        finally:
            conn.close()
    except Exception:
        pass
    try:
        _V2Orchestrator().run(evaluation_id)
    except _V2TaskCancelledError:
        log("EVAL", f"{evaluation_id} 续跑被取消（被 force retry 替换）")
        _mark_cancelled_if_running(evaluation_id)
    except Exception as e:
        if isinstance(e, RuntimeError) and "cannot schedule new futures" in str(e):
            log("EVAL", f"{evaluation_id} 续跑失败：解释器正在关闭（pod 终止），标记 FAILED 等待重启后续跑")
            _record_background_failure(evaluation_id, e, "EVAL RESUME FAILED")
        else:
            import traceback
            traceback.print_exc()
            _record_background_failure(evaluation_id, e, "EVAL RESUME FAILED")
    finally:
        clear_eval_ctx()
        es.clear_progress(evaluation_id)
        es._cleanup_trace_cache(evaluation_id)


@app.get("/health")
async def health():
    # liveness probe 端点：不加锁、不做 I/O，避免 GIL 竞争时事件循环被阻塞
    # 详细运行状态请用 /api/v1/evaluations/running
    return {"status": "ok"}


@app.get("/api/v1/evaluations/running")
async def get_running():
    """查看当前正在运行的评测任务（DB-based，跨 worker 一致）。"""
    from ...infrastructure.database import connect
    conn = await asyncio.to_thread(connect, autocommit=True)
    try:
        cur = conn.cursor()
        await asyncio.to_thread(cur.execute,
            "SELECT evaluation_id FROM evaluation WHERE evaluation_status NOT IN "
            "('CREATED','COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCELLED','CANCEL_REQUESTED','QUEUED')")
        rows = cur.fetchall()
    finally:
        conn.close()
    ids = [r[0] for r in rows]
    return {"running_count": len(ids), "evaluation_ids": ids}


@app.post("/api/v1/evaluations")
def create_evaluation(req: CreateRequest):
    try:
        es.create(es.CreateRequest(evaluation_id=req.evaluation_id,
                                   evaluation_name=req.evaluation_name,
                                   kg_project_id=req.kg_project_id,
                                   kg_task_id=req.kg_task_id,
                                   benchmark_source=req.benchmark_source,
                                   benchmark_set_id=req.benchmark_set_id,
                                   vc_source_task_id=req.vc_source_task_id,
                                   eval_mode=req.eval_mode))
        # 不再同步设 RUNNING——由 _run_bg 的原子 UPDATE 处理（跨 worker 同步）
        # 提交到线程池排队运行（最多 3 并发，超出自动排队）
        def _run_bg():
            from ...infrastructure.database import connect
            set_eval_ctx(req.evaluation_id)
            # 原子获取状态锁：只有 CREATED/CANCEL_REQUESTED/FAILED/CANCELLED 才能跳转 RUNNING
            # 跨 worker 同步：两个 worker 同时调用，只有一个 rowcount=1
            conn = connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE evaluation SET evaluation_status='RUNNING', started_at=NOW(3), finished_at=NULL, error_message=NULL, cancel_requested=0 "
                    "WHERE evaluation_id=%s AND evaluation_status IN ('CREATED','CANCEL_REQUESTED','FAILED','CANCELLED')",
                    (req.evaluation_id,))
                if cur.rowcount == 0:
                    log("EVAL", f"{req.evaluation_id} 已被其他 worker 接管，退出")
                    return
            finally:
                conn.close()
            try:
                _V2Orchestrator().run(req.evaluation_id)
            except _V2TaskCancelledError:
                log("EVAL", f"{req.evaluation_id} 被取消（force retry 替换）")
                _mark_cancelled_if_running(req.evaluation_id)
            except Exception as e:
                if isinstance(e, RuntimeError) and "cannot schedule new futures" in str(e):
                    log("EVAL", f"{req.evaluation_id} 续跑失败：解释器正在关闭（pod 终止），标记 FAILED 等待重启后续跑")
                    _record_background_failure(req.evaluation_id, e, "EVAL FAILED")
                else:
                    import traceback
                    traceback.print_exc()
                    _record_background_failure(req.evaluation_id, e, "EVAL FAILED")
            finally:
                clear_eval_ctx()
                es.clear_progress(req.evaluation_id)
                es._cleanup_trace_cache(req.evaluation_id)
        _submit_eval(req.evaluation_id, _run_bg)
        return {"evaluation_id": req.evaluation_id, "status": "QUEUED"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/evaluations/{evaluation_id}")
def delete_evaluation(evaluation_id: str):
    """删除评测：清除该评测的全部数据（不可恢复）。"""
    from ...infrastructure.database import connect
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        # 用 evaluation_id 的表
        eid_tables = [
            "finding_benchmark_match", "outcome_fact", "knowledge_interaction_fact",
            "tool_action_fact", "resource_fact", "task_run", "trace_source",
            "evaluation_report",
        ]
        for t in eid_tables:
            cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (evaluation_id,))
        # 用 calculation_run_id 的表
        cr_tables = ["evaluation_population_snapshot", "evaluation_calculation_run"]
        for t in cr_tables:
            try:
                cur.execute(f"DELETE FROM {t} WHERE calculation_run_id LIKE %s", (f"CR-{evaluation_id}%",))
            except Exception:
                pass
        # 最后删 snapshot + evaluation
        cur.execute("DELETE FROM evaluation_snapshot WHERE evaluation_id=%s", (evaluation_id,))
        cur.execute("DELETE FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
        log("DELETE", f"评测 {evaluation_id} 已删除")
    finally:
        conn.close()
    # 删除报告文件（旧 HTML + JSON）
    try:
        import glob as _glob
        for _f in _glob.glob(os.path.join(REPORTS_DIR, f"{evaluation_id}*")):
            os.remove(_f)
    except Exception:
        pass
    return {"status": "ok", "evaluation_id": evaluation_id}


@app.post("/api/v1/evaluations/{evaluation_id}/retry")
def retry_evaluation(evaluation_id: str, force: bool = False):
    """重试失败的评测：删除全部数据，重新解析+计算+报告。

    force=true: 跳过状态检查，强制重跑（用于任务挂了但状态卡在运行中的情况）。
    """
    try:
        from ...infrastructure.database import connect

        # Step 0: 检查当前状态 — 运行中禁止重跑，避免并发写冲突
        _RUNNING_STATES = ('RUNNING', 'VALIDATING', 'INGESTING', 'PARSING',
                           'CASE_MATCHING', 'ROOT_CAUSE_ANALYSIS', 'RESOLVING',
                           'REPORTING', 'FINALIZING')
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"evaluation {evaluation_id} not found")
            if row[0] in _RUNNING_STATES and not force:
                raise HTTPException(status_code=409,
                                   detail=f"evaluation {evaluation_id} is running (status={row[0]}), "
                                         f"retry not allowed. Wait for completion, delete first, "
                                         f"or retry with ?force=true to force.")
        finally:
            conn.close()

        # Step 1: 获取 benchmark_set_id（用于清理 benchmark_item）
        bsid = None
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
            row = cur.fetchone()
            if row:
                bsid = row[0]
        finally:
            conn.close()

        # Step 2: 清理全部数据（单连接 + FK off）
        # 基线数据、告警中心数据、benchmark_items 在 run() INGESTING 阶段重新获取/插入
        tables = [
            # 核心计算结果
            "outcome_fact", "knowledge_interaction_fact", "tool_action_fact", "resource_fact",
            # trace 与 finding
            "task_run", "trace_source", "extracted_finding", "finding_benchmark_match",
            "session_graph",
            # 报告
            "evaluation_report",
            # 计算运行记录
            "evaluation_population_snapshot", "evaluation_calculation_run",
            # 排除记录与覆盖率
            "exclusion_record", "evaluation_coverage",
            # 阶段运行记录
            "evaluation_stage_run", "evaluation_job",
            # 状态转换记录
            "evaluation_state_transition",
        ]
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            if bsid:
                cur.execute("DELETE FROM benchmark_item WHERE benchmark_set_id=%s", (bsid,))
            for t in tables:
                if t in ("evaluation_population_snapshot", "evaluation_calculation_run"):
                    cur.execute(f"DELETE FROM {t} WHERE calculation_run_id LIKE %s", (f"CR-{evaluation_id}%",))
                elif t == "evaluation_job":
                    # evaluation_job 通过 stage_run_id 关联，先查 job_id 再清 job_lease
                    cur.execute("SELECT job_id FROM evaluation_job WHERE evaluation_id=%s", (evaluation_id,))
                    job_ids = [r[0] for r in cur.fetchall()]
                    if job_ids:
                        placeholders = ",".join(["%s"] * len(job_ids))
                        cur.execute(f"DELETE FROM job_lease WHERE job_id IN ({placeholders})", job_ids)
                    cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (evaluation_id,))
                else:
                    cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (evaluation_id,))
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        except Exception as e:
            log("RETRY", f"清理数据异常: {e}")
        finally:
            conn.close()

        # Step 2b: 归档旧报告文件（不删除，改名保留）
        from datetime import datetime as _dt_r, timezone as _tz_r, timedelta as _td_r
        _tz_r = _tz_r(_td_r(hours=8))
        _archive_ts = _dt_r.now(_tz_r).strftime("%Y%m%d_%H%M%S")
        try:
            for _suffix in (".html", ".json", "_fpr.json", "_kg.json", "_fpr_match.json",
                            "_lifecycle.json", "_debug_*.json"):
                if "*" in _suffix:
                    import glob as _glob
                    for _f in _glob.glob(os.path.join(REPORTS_DIR, f"{evaluation_id}{_suffix}")):
                        _arc = os.path.join(REPORTS_DIR, f"{evaluation_id}_archive_{_archive_ts}"
                                            + _f.replace(evaluation_id, ""))
                        os.rename(_f, _arc)
                else:
                    _old = os.path.join(REPORTS_DIR, f"{evaluation_id}{_suffix}")
                    if os.path.isfile(_old):
                        _arc = os.path.join(REPORTS_DIR, f"{evaluation_id}_archive_{_archive_ts}{_suffix}")
                        os.rename(_old, _arc)
                        log("RETRY", f"归档旧报告: {_old} → {_arc}")
        except Exception:
            pass

        # Step 3: 重置状态
        conn = connect(autocommit=True)
        try:
            # 清理旧代码残留的 " | FAILED at ..." 名称后缀
            conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s, "
                                "evaluation_name=SUBSTRING_INDEX(IFNULL(evaluation_name,''),' |',1), "
                                "finished_at=NULL, cancel_requested=0, error_message=NULL "
                                "WHERE evaluation_id=%s",
                                ("CREATED", evaluation_id))
        finally:
            conn.close()

        # Step 4: 通知旧线程取消（协作取消），提交新线程到线程池
        es.set_cancel(evaluation_id)  # 通知旧线程在下一个阶段边界退出
        # 不再同步设 RUNNING——由 _run_bg 的原子 UPDATE 处理（跨 worker 同步）
        def _run_bg():
            from ...infrastructure.database import connect as _connect
            set_eval_ctx(evaluation_id)
            log("THREAD", f"_run_bg: {evaluation_id} 开始执行")
            # 原子获取状态锁：只有 CREATED/CANCEL_REQUESTED/FAILED/CANCELLED 才能跳转 RUNNING
            conn = _connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE evaluation SET evaluation_status='RUNNING', started_at=NOW(3), finished_at=NULL, error_message=NULL, cancel_requested=0 "
                    "WHERE evaluation_id=%s AND evaluation_status IN ('CREATED','CANCEL_REQUESTED','FAILED','CANCELLED')",
                    (evaluation_id,))
                if cur.rowcount == 0:
                    log("EVAL", f"{evaluation_id} retry 已被其他 worker 接管，退出")
                    return
            finally:
                conn.close()
            try:
                _V2Orchestrator().run(evaluation_id)
            except _V2TaskCancelledError:
                log("EVAL", f"{evaluation_id} retry 被取消（又被 force retry 替换）")
                _mark_cancelled_if_running(evaluation_id)
            except Exception as e:
                if isinstance(e, RuntimeError) and "cannot schedule new futures" in str(e):
                    log("EVAL", f"{evaluation_id} retry 续跑失败：解释器正在关闭（pod 终止），标记 FAILED 等待重启后续跑")
                    _record_background_failure(evaluation_id, e, "EVAL RETRY FAILED")
                else:
                    import traceback
                    traceback.print_exc()
                    _record_background_failure(evaluation_id, e, "EVAL RETRY FAILED")
            finally:
                clear_eval_ctx()
                es.clear_progress(evaluation_id)
                es._cleanup_trace_cache(evaluation_id)
        _submit_eval(evaluation_id, _run_bg)
        return {"evaluation_id": evaluation_id, "status": "QUEUED"}
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        raise HTTPException(status_code=400, detail=str(e))


def _mark_cancelled_if_running(evaluation_id: str):
    """TaskCancelledError 后，如果状态仍是运行中阶段（被线程覆盖），设为 CANCELLED。

    条件 UPDATE：只覆盖运行中阶段状态，不触碰 CREATED/RUNNING（force retry 设的）
    或已终态（CANCELLED/COMPLETED/FAILED）。
    """
    from ...infrastructure.database import connect
    _RUNNING_PHASES = ('VALIDATING', 'INGESTING', 'PARSING',
                       'CASE_MATCHING', 'ROOT_CAUSE_ANALYSIS', 'RESOLVING',
                       'REPORTING', 'FINALIZING')
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            placeholders = ','.join(['%s'] * len(_RUNNING_PHASES))
            cur.execute(
                f"UPDATE evaluation SET evaluation_status='CANCELLED', finished_at=NOW(3) "
                f"WHERE evaluation_id=%s AND evaluation_status IN ({placeholders})",
                (evaluation_id, *_RUNNING_PHASES))
            if cur.rowcount > 0:
                log("CANCEL", f"{evaluation_id} 线程退出后状态恢复为 CANCELLED")
        finally:
            conn.close()
    except Exception as e:
        log("CANCEL", f"{evaluation_id} 设 CANCELLED 失败: {e}")


@app.post("/api/v1/evaluations/{evaluation_id}/cancel")
def cancel_evaluation(evaluation_id: str):
    """取消运行中的评测任务。

    协作式取消：设置 cancel_requested=1（线程在下一个阶段边界退出），
    同时立即将状态设为 CANCELLED（API/前端立即可见）。

    如果线程正在长 LLM 调用中，需等调用返回后到下一个 _check_cancel 才真正退出。
    线程退出后 _mark_cancelled_if_running 会修复可能被覆盖的状态。
    """
    from ...infrastructure.database import connect
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"evaluation {evaluation_id} not found")
        status = row[0]
        if status in _TERMINAL_EVALUATION_STATUSES:
            raise HTTPException(status_code=409,
                               detail=f"evaluation {evaluation_id} already terminal (status={status})")
        # 1. 设 cancel_requested=1（协作取消信号，线程在下一个 _check_cancel 退出）
        es.set_cancel(evaluation_id)
        # 2. 立即设状态为 CANCELLED（API/前端可见，防止 watcher 误判僵死）
        cur.execute(
            "UPDATE evaluation SET evaluation_status='CANCELLED', finished_at=NOW(3), "
            "error_message='用户取消' WHERE evaluation_id=%s",
            (evaluation_id,))
        log("CANCEL", f"{evaluation_id} 已取消 (was {status})")
    finally:
        conn.close()

    # 3. 清理内存中的任务跟踪
    with _running_lock:
        _running_futures.pop(evaluation_id, None)
        _pausing_eids.discard(evaluation_id)
        try:
            _paused_evals.remove(evaluation_id)
        except ValueError:
            pass
        for i in range(len(_pending_evals)):
            if _pending_evals[i][0] == evaluation_id:
                del _pending_evals[i]
                break
    _try_dispatch()

    return {"evaluation_id": evaluation_id, "status": "CANCELLED"}


@app.get("/api/v1/evaluations/{evaluation_id}")
async def get_status(evaluation_id: str):
    # DB-based：不再依赖 _running_futures（多 worker 下各进程内存不共享）
    r = await asyncio.to_thread(es.get_status, evaluation_id)
    if "error" in r:
        raise HTTPException(status_code=404, detail=r["error"])
    return r


# ===== SPA catch-all：必须最后注册，确保不拦截已有路由 =====
@app.get("/{path:path}")
def serve_spa(path: str):
    if path.startswith("api/") or path.startswith("reports/") or path == "health":
        raise HTTPException(404)
    html_path = os.path.join(os.path.dirname(__file__), "..", "..", "static", "dashboard.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())
