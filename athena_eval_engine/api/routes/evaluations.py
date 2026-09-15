"""FastAPI app + 路由（§11.1）。

POST /api/v1/evaluations → 创建 + 后台异步跑（最多 3 个并发，超出排队）
GET  /api/v1/evaluations/{id} → 状态
GET  /api/v1/evaluations/{id}/metrics → 指标
GET  /api/v1/evaluations/{id}/report → 报告
"""
from __future__ import annotations
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from ...application import evaluation_service as es
from ...infrastructure.log_util import log, set_eval_ctx, clear_eval_ctx, log_error
from ...persistence.repositories import fact_repo
from .web import router as web_router
from .platform import router as platform_router
from .benchmark_system import vb as vbench_router, sys_r as sys_router

# 最多 3 个评测同时运行，其余排队等待
_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="eval")
_TERMINAL_EVALUATION_STATUSES = {"COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED"}

# 任务 ↔ 线程映射：一个任务只能存在一个在运行的线程
_running_futures: dict[str, Future] = {}
_running_lock = threading.Lock()


def _submit_eval(evaluation_id: str, fn) -> Future:
    """提交评测任务到线程池，保证一个 evaluation_id 只有一个在运行的线程。

    - 如果该 evaluation_id 已有线程在跑（force retry 场景），先从映射中移除旧线程
    - 旧线程物理上可能仍在运行，但不再被追踪；新线程的 DB 写入会覆盖旧线程的结果
    - 线程结束（正常或异常）时自动从映射中移除
    """
    with _running_lock:
        old = _running_futures.pop(evaluation_id, None)
        if old is not None:
            old.cancel()  # 如果还在排队未执行，取消；已运行的无法取消但不再追踪
            log("THREAD", f"{evaluation_id} 旧线程被替换（force retry）")
        fut = _executor.submit(fn)
        _running_futures[evaluation_id] = fut
        def _done_cb(f, eid=evaluation_id):
            """只移除自己——旧线程的回调不能误删新线程的 future。"""
            with _running_lock:
                if _running_futures.get(eid) is f:
                    _running_futures.pop(eid, None)
        fut.add_done_callback(_done_cb)
        return fut


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
    conn = None
    try:
        conn = connect(autocommit=True)
        cur = conn.cursor()
        cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        row = cur.fetchone()
        phase = row[0] if row else "UNKNOWN"
        if phase in _TERMINAL_EVALUATION_STATUSES:
            log(source, f"忽略终态后的异常: {evaluation_id} status={phase}: {err_msg}")
            return
        log(source, f"{evaluation_id} at {phase}: {err_msg}")
        cur.execute("UPDATE evaluation SET evaluation_status='FAILED', "
                    "evaluation_name=CONCAT(IFNULL(evaluation_name,''),' | FAILED at ',%s,': ',%s), "
                    "error_message=%s, finished_at=NOW(3) "
                    "WHERE evaluation_id=%s", (phase, err_msg, err_msg, evaluation_id))
    except Exception as db_error:
        log(source, f"记录失败状态失败: {db_error}")
    finally:
        if conn:
            conn.close()


class CreateRequest(BaseModel):
    evaluation_id: str
    evaluation_name: str | None = None
    benchmark_set_id: str = "BS001"
    vbench_project_name: str | None = None
    benchmark_source: str = "vbench_zip"  # "vbench_zip" | "vuln_center"
    vc_source_task_id: str | None = None  # 漏洞中心模式下的 source_task_id
    vc_source_project_name: str | None = None  # 漏洞中心项目名
    vc_source_task_name: str | None = None  # 漏洞中心任务名
    entries: list[dict]


app = FastAPI(title="Athena Eval Engine", version="0.1.0")
app.include_router(web_router)
app.include_router(platform_router)
app.include_router(vbench_router)
app.include_router(sys_router)


@app.on_event("startup")
def resume_stuck_evaluations():
    """Pod 重启后自动续跑卡住的评测。

    状态在 RUNNING_STATES 里的评测 = 后台线程已死（pod 重启），但 DB 里还显示运行中。
    重新提交到线程池，run() 会检查 facts 是否已存在自动跳过已完成的阶段。
    CREATED 状态 = create() 未完成的半成品（无 snapshot），标记 FAILED 清理。
    """
    try:
        from ...infrastructure.database import connect
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            # CREATED = create() 半途失败（有 evaluation 行但无 snapshot），标记 FAILED
            cur.execute("SELECT evaluation_id FROM evaluation WHERE evaluation_status='CREATED'")
            created_rows = cur.fetchall()
            for (eid,) in created_rows:
                log("STARTUP", f"{eid} (was CREATED) → 标记 FAILED（create 未完成）")
                cur.execute("UPDATE evaluation SET evaluation_status='FAILED', "
                            "error_message=%s, finished_at=NOW(3) WHERE evaluation_id=%s",
                            ("create() 未完成（无 snapshot），评测创建失败", eid))
            # RUNNING_STATES = 线程已死但 DB 还显示运行中，续跑
            stuck_states = ('RUNNING', 'VALIDATING', 'INGESTING', 'PARSING', 'AI_MATCHING',
                            'RESOLVING', 'PAIRING', 'CALCULATING', 'STATISTICAL_ANALYSIS',
                            'DIAGNOSING', 'REPORTING', 'FINALIZING')
            placeholders = ','.join(['%s'] * len(stuck_states))
            cur.execute(f"SELECT evaluation_id, evaluation_status FROM evaluation "
                        f"WHERE evaluation_status IN ({placeholders})", stuck_states)
            stuck = cur.fetchall()
            if stuck:
                log("STARTUP", f"发现 {len(stuck)} 个卡住的评测，准备续跑:")
                for eid, status in stuck:
                    log("STARTUP", f"{eid} (was {status}) → 续跑")
                    # 同步设 RUNNING，确保即使线程池满排队中，DB 也反映"正在运行"
                    cur.execute("UPDATE evaluation SET evaluation_status='RUNNING', error_message=NULL WHERE evaluation_id=%s",
                                (eid,))
                    _submit_eval(eid, lambda eid=eid: _run_bg_resume(eid))
            else:
                log("STARTUP", f"无卡住的评测")
        finally:
            conn.close()
    except Exception as e:
        log("STARTUP", f"扫描卡住评测失败（DB 可能未就绪）: {e}")


def _run_bg_resume(evaluation_id: str):
    """续跑单个评测。设 RUNNING 状态，确保 DB 反映实际运行状态。"""
    set_eval_ctx(evaluation_id)
    from ...infrastructure.database import connect
    try:
        conn = connect(autocommit=True)
        try:
            conn.cursor().execute("UPDATE evaluation SET evaluation_status='RUNNING', error_message=NULL, started_at=NOW(3) WHERE evaluation_id=%s",
                                  (evaluation_id,))
        finally:
            conn.close()
    except Exception:
        pass
    try:
        es.run(evaluation_id)
    except es.TaskCancelledError:
        log("EVAL", f"{evaluation_id} 续跑被取消（被 force retry 替换）")
    except Exception as e:
        import traceback
        traceback.print_exc()
        _record_background_failure(evaluation_id, e, "EVAL RESUME FAILED")
    finally:
        clear_eval_ctx()
        es.clear_progress(evaluation_id)


@app.get("/health")
def health():
    with _running_lock:
        running = len(_running_futures)
    return {"status": "ok", "running_tasks": running}


@app.get("/api/v1/evaluations/running")
def get_running():
    """查看当前正在运行的评测任务（线程数 = 任务数）。"""
    with _running_lock:
        ids = list(_running_futures.keys())
    return {"running_count": len(ids), "evaluation_ids": ids}


@app.post("/api/v1/evaluations")
def create_evaluation(req: CreateRequest):
    try:
        es.create(es.CreateRequest(evaluation_id=req.evaluation_id,
                                   evaluation_name=req.evaluation_name,
                                   benchmark_set_id=req.benchmark_set_id,
                                   vbench_project_name=req.vbench_project_name,
                                   benchmark_source=req.benchmark_source,
                                   vc_source_task_id=req.vc_source_task_id,
                                   vc_source_project_name=req.vc_source_project_name,
                                   vc_source_task_name=req.vc_source_task_name,
                                   entries=req.entries))
        # 同步设 RUNNING，确保即使线程池满排队中，DB 也反映"正在运行"
        from ...infrastructure.database import connect as _connect_create
        _conn = _connect_create(autocommit=True)
        try:
            _conn.cursor().execute("UPDATE evaluation SET evaluation_status='RUNNING', started_at=NOW(3) WHERE evaluation_id=%s",
                                   (req.evaluation_id,))
        finally:
            _conn.close()
        # 提交到线程池排队运行（最多 3 并发，超出自动排队）
        def _run_bg():
            from ...infrastructure.database import connect
            set_eval_ctx(req.evaluation_id)
            # 标记 RUNNING
            conn = connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute("UPDATE evaluation SET evaluation_status='RUNNING', started_at=NOW(3) WHERE evaluation_id=%s",
                            (req.evaluation_id,))
            finally:
                conn.close()
            try:
                es.run(req.evaluation_id)
            except es.TaskCancelledError:
                log("EVAL", f"{req.evaluation_id} 被取消（force retry 替换）")
            except Exception as e:
                import traceback
                traceback.print_exc()
                _record_background_failure(req.evaluation_id, e, "EVAL FAILED")
            finally:
                clear_eval_ctx()
                es.clear_progress(req.evaluation_id)
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
            "statistical_result", "metric_result",
            "pair_derived_fact", "task_pair",
            "finding_benchmark_match", "outcome_fact", "knowledge_interaction_fact",
            "tool_action_fact", "resource_fact", "task_run", "trace_source",
            "evaluation_report",
        ]
        for t in eid_tables:
            try:
                cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (evaluation_id,))
            except Exception as e:
                # statistical_result / metric_result 用 calculation_run_id
                if "Unknown column" in str(e):
                    cur.execute(f"DELETE FROM {t} WHERE calculation_run_id LIKE %s", (f"CR-{evaluation_id}%",))
                else:
                    raise
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
    # 删除固化 HTML
    try:
        p = _static_report_path(evaluation_id)
        if os.path.isfile(p):
            os.remove(p)
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
        _RUNNING_STATES = ('RUNNING', 'VALIDATING', 'INGESTING', 'PARSING', 'AI_MATCHING',
                           'RESOLVING', 'PAIRING', 'CALCULATING', 'STATISTICAL_ANALYSIS',
                           'DIAGNOSING', 'REPORTING', 'FINALIZING')
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

        # Step 1: 获取 benchmark_set_id + config_json（一个连接）
        bsid = None
        entries = []
        bm_source = "vbench_zip"
        vc_source_task_id = None
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
            row = cur.fetchone()
            if row:
                bsid = row[0]
                cur.execute("SELECT config_json FROM evaluation_snapshot WHERE evaluation_id=%s", (evaluation_id,))
                srow = cur.fetchone()
                if srow and srow[0]:
                    import json as _j
                    cfg = _j.loads(srow[0]) if isinstance(srow[0], str) else srow[0]
                    entries = cfg.get("manifest", {}).get("entries", [])
                    bm_source = cfg.get("manifest", {}).get("benchmark_source", "vbench_zip")
                    vc_source_task_id = cfg.get("manifest", {}).get("vc_source_task_id")
        finally:
            conn.close()

        # Step 2: 获取 case 描述（按数据源分别处理）
        case_details = {}
        # 漏洞中心模式下，如果未指定 vc_source_task_id，用 entries 的 task_id_actual 补取
        effective_vc_task = vc_source_task_id
        if bm_source == "vuln_center" and not effective_vc_task:
            for e in entries:
                effective_vc_task = e.get("task_id_actual") or e.get("task_id")
                if effective_vc_task:
                    break
        if bsid:
            try:
                if bm_source == "vuln_center":
                    from ...infrastructure.vuln_center_client import get_vuln_center_benchmark
                    log("RETRY", f"漏洞中心取基线: project={bsid} task={effective_vc_task}")
                    bm = get_vuln_center_benchmark(bsid, effective_vc_task)
                    _n = len(bm.get("cases") or [])
                    if _n == 0 and effective_vc_task:
                        log("RETRY", f"task={effective_vc_task} 不是漏洞中心 source_task，不带 task 过滤重试")
                        bm = get_vuln_center_benchmark(bsid, None)
                        log("RETRY", f"不带 task 过滤返回 {len(bm.get('cases') or [])} 条 case")
                    for c in (bm.get("cases") or []):
                        cid = c.get("case_id") or c.get("id") or ""
                        if cid:
                            case_details[cid] = {
                                "description": c.get("description") or "",
                                "vulnerability_type": c.get("vulnerability_type") or "",
                                "target_finding_id": c.get("target_finding_id") or "",
                                "expected_label": c.get("expected_label") or "VULNERABLE",
                                "source_file": c.get("source_file") or "",
                                "source_function": c.get("source_function") or "",
                            }
                            es._fill_missing_source(case_details[cid])
                else:
                    from ...infrastructure.vbench_client import get_benchmark
                    bm = get_benchmark(bsid)
                    for c in (bm.get("cases") or []):
                        cid = c.get("case_id") or c.get("id") or ""
                        if cid:
                            fnd = c.get("findings") or []
                            desc = " ".join(f.get("explanation", "") for f in fnd if f.get("explanation")) or c.get("vulnerability_type", "") or c.get("description") or ""
                            case_details[cid] = {"description": desc,
                                                "vulnerability_type": c.get("vulnerability_type") or c.get("category") or "",
                                                "target_finding_id": c.get("target_finding_id") or "",
                                                "source_file": c.get("source_file") or "",
                                                "source_function": c.get("source_function") or ""}
                            es._fill_missing_source(case_details[cid])
            except Exception:
                pass

        # Step 3: 清理全部数据（单连接 + FK off）
        tables = ["statistical_result", "metric_result", "pair_derived_fact", "task_pair",
                  "outcome_fact", "knowledge_interaction_fact", "tool_action_fact", "resource_fact",
                  "task_run", "trace_source", "evaluation_report",
                  "evaluation_population_snapshot", "evaluation_calculation_run"]
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            if bsid:
                cur.execute("DELETE FROM benchmark_item WHERE benchmark_set_id=%s", (bsid,))
            for t in tables:
                if t in ("evaluation_population_snapshot", "evaluation_calculation_run"):
                    cur.execute(f"DELETE FROM {t} WHERE calculation_run_id LIKE %s", (f"CR-{evaluation_id}",))
                else:
                    cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (evaluation_id,))
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        except: pass
        finally:
            conn.close()

        # Step 3b: 删除固化 HTML 报告文件
        try:
            p = _static_report_path(evaluation_id)
            if os.path.isfile(p):
                os.remove(p)
                log("RETRY", f"删除旧报告: {p}")
        except Exception:
            pass

        # Step 4: 重置状态
        conn = connect(autocommit=True)
        try:
            conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s, evaluation_name=SUBSTRING_INDEX(IFNULL(evaluation_name,''),' |',1) WHERE evaluation_id=%s",
                                ("CREATED", evaluation_id))
        finally:
            conn.close()

        # Step 5: 重新插入 benchmark items（含 case 描述）— 单连接批量插入
        # 漏洞中心模式下，只插入 case_details 里有的 case（过滤掉不属于当前任务的 case）
        _filter_by_case_details = bm_source == "vuln_center" and case_details
        if bsid and entries:
            conn = connect(autocommit=True)
            try:
                cur = conn.cursor()
                for e in entries:
                    item_ids = e.get("benchmark_item_ids") or ([e["benchmark_item_id"]] if e.get("benchmark_item_id") else [])
                    if _filter_by_case_details:
                        item_ids = [bid for bid in item_ids if bid in case_details]
                    for bid in item_ids:
                        cd = case_details.get(bid) or {}
                        fact_repo.insert_benchmark_item(cur, bid, bsid,
                                                       e["task_id"], cd.get("expected_label") or e.get("expected_label", "VULNERABLE"),
                                                       cd.get("target_finding_id") or e.get("target_finding_id"),
                                                       cd if cd else None)
            finally:
                conn.close()

        # Step 5b: 重新获取告警中心数据并更新 snapshot
        _ac_pairs = []
        _seen = set()
        for e in entries:
            _pid = e.get("project_id") or ""
            _tid = e.get("task_id_actual") or effective_vc_task or ""
            if _pid and _tid and (_pid, _tid) not in _seen:
                _ac_pairs.append((_pid, _tid))
                _seen.add((_pid, _tid))
        if _ac_pairs:
            try:
                from ...infrastructure.vuln_center_client import get_alert_center_summary
                _all_cases = []
                _merged_counts = {"vulnerable": 0, "not_vulnerable": 0, "inconclusive": 0, "pending": 0}
                for _ac_proj, _ac_task in _ac_pairs:
                    log("RETRY", f"告警中心取数据: project={_ac_proj} task={_ac_task}")
                    ac_sum = get_alert_center_summary(_ac_proj, _ac_task)
                    for k in _merged_counts:
                        _merged_counts[k] += ac_sum.get("counts", {}).get(k, 0)
                    _all_cases.extend({
                        "case_id": c.get("id") or c.get("case_id") or "",
                        "title": c.get("title") or "",
                        "summary": c.get("summary") or "",
                        "validation_result": c.get("validation_result"),
                        "current_stage": c.get("current_stage"),
                        "current_status": c.get("current_status"),
                        "project_id": _ac_proj,
                    } for c in ac_sum.get("cases", []))
                _new_ac = {
                    "source_task_ids": [t for _, t in _ac_pairs],
                    "project_ids": [p for p, _ in _ac_pairs],
                    "total": len(_all_cases),
                    "counts": _merged_counts,
                    "cases": _all_cases,
                }
                # 更新 snapshot 的 config_json
                conn = connect(autocommit=True)
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT config_json FROM evaluation_snapshot WHERE evaluation_id=%s", (evaluation_id,))
                    srow = cur.fetchone()
                    if srow and srow[0]:
                        import json as _j2
                        cfg = _j2.loads(srow[0]) if isinstance(srow[0], str) else srow[0]
                        cfg.setdefault("manifest", {})["alert_center_data"] = _new_ac
                        cur.execute("UPDATE evaluation_snapshot SET config_json=%s WHERE evaluation_id=%s",
                                    (_j2.dumps(cfg, ensure_ascii=False), evaluation_id))
                        log("RETRY", f"告警中心数据已更新 snapshot: total={len(_all_cases)}")
                finally:
                    conn.close()
            except Exception as e:
                import traceback as _tb
                log("RETRY", f"告警中心数据获取失败: {e}")
                _tb.print_exc()

        # Step 6: 通知旧线程取消（协作取消），提交新线程到线程池
        es.set_cancel(evaluation_id)  # 通知旧线程在下一个阶段边界退出
        # 同步设 RUNNING，确保即使线程池满排队中，DB 也反映"正在运行"
        conn = connect(autocommit=True)
        try:
            conn.cursor().execute("UPDATE evaluation SET evaluation_status='RUNNING', error_message=NULL, started_at=NOW(3) WHERE evaluation_id=%s",
                                  (evaluation_id,))
        finally:
            conn.close()
        def _run_bg():
            from ...infrastructure.database import connect as _connect
            set_eval_ctx(evaluation_id)
            conn = _connect(autocommit=True)
            try:
                conn.cursor().execute("UPDATE evaluation SET evaluation_status='RUNNING', error_message=NULL, started_at=NOW(3) WHERE evaluation_id=%s", (evaluation_id,))
            finally:
                conn.close()
            try:
                es.run(evaluation_id)
            except es.TaskCancelledError:
                log("EVAL", f"{evaluation_id} retry 被取消（又被 force retry 替换）")
            except Exception as e:
                import traceback
                traceback.print_exc()
                _record_background_failure(evaluation_id, e, "EVAL RETRY FAILED")
            finally:
                clear_eval_ctx()
                es.clear_progress(evaluation_id)
        _submit_eval(evaluation_id, _run_bg)
        return {"evaluation_id": evaluation_id, "status": "QUEUED"}
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/evaluations/{evaluation_id}")
def get_status(evaluation_id: str):
    # 死线程检测：状态是运行中但线程已不在 _running_futures → 线程静默死亡
    _RUNNING = ('RUNNING', 'VALIDATING', 'INGESTING', 'PARSING', 'AI_MATCHING',
                'RESOLVING', 'PAIRING', 'CALCULATING', 'STATISTICAL_ANALYSIS',
                'DIAGNOSING', 'REPORTING', 'FINALIZING')
    with _running_lock:
        is_alive = evaluation_id in _running_futures
    if not is_alive:
        from ...infrastructure.database import connect
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
            row = cur.fetchone()
            if row and row[0] in _RUNNING:
                cur.execute("UPDATE evaluation SET evaluation_status='FAILED', "
                            "evaluation_name=CONCAT(IFNULL(evaluation_name,''),' | FAILED at ',%s,': thread died'), "
                            "error_message=%s, finished_at=NOW(3) WHERE evaluation_id=%s",
                            (row[0], f"评测线程静默死亡（状态卡在 {row[0]}，线程已不在运行池中）", evaluation_id))
                log("WATCHDOG", f"{evaluation_id} 状态={row[0]} 但线程已死，标记 FAILED")
        finally:
            conn.close()
    r = es.get_status(evaluation_id)
    if "error" in r:
        raise HTTPException(status_code=404, detail=r["error"])
    return r


@app.get("/api/v1/evaluations/{evaluation_id}/metrics")
def get_metrics(evaluation_id: str):
    from ...infrastructure.database import connect
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT metric_id, estimate, unit, n, calculation_status, reason_code, median, iqr "
                    "FROM metric_result WHERE evaluation_id=%s", (evaluation_id,))
        return {"evaluation_id": evaluation_id, "metrics": [dict(zip(["metric_id", "estimate", "unit", "n",
                            "calculation_status", "reason_code", "median", "iqr"], row)) for row in cur.fetchall()]}
    finally:
        conn.close()


@app.get("/api/v1/evaluations/{evaluation_id}/report")
def get_report(evaluation_id: str):
    return _build_report(evaluation_id)


def _build_report(evaluation_id: str):
    """构建完整报告 JSON（含知识介入、case 结果、元信息）。固化 HTML 和动态接口共用。"""
    r = es.get_report(evaluation_id)
    if "error" in r:
        raise HTTPException(status_code=404, detail=r["error"])
    # 附加知识介入原始事件 + 评测元信息
    import json as _json
    from ...infrastructure.database import connect
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        # 评测元信息：名称、基线项目
        cur.execute("SELECT evaluation_name, benchmark_set_id, started_at, finished_at FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        erow = cur.fetchone()
        if erow:
            r["evaluation_name"] = erow[0]
            r["started_at"] = erow[2].isoformat() if erow[2] else None
            r["finished_at"] = erow[3].isoformat() if erow[3] else None
        # 从 snapshot 的 config_json 提取 manifest 信息
        cur.execute("SELECT config_json FROM evaluation_snapshot WHERE evaluation_id=%s", (evaluation_id,))
        srow = cur.fetchone()
        if srow:
            cfg = _json.loads(srow[0]) if isinstance(srow[0], str) else srow[0]
            manifest = cfg.get("manifest", {})
            entries = manifest.get("entries", [])
            r["vbench_project_name"] = manifest.get("vbench_project_name", "")
            r["benchmark_source"] = manifest.get("benchmark_source", "vbench_zip")
            r["entries_info"] = [{"condition": e.get("condition"), "project_name": e.get("project_name", ""),
                                  "task_name": e.get("task_name", ""),
                                  "task_id": e.get("task_id", ""),
                                  "category": e.get("category", "")} for e in entries]
        # 知识介入
        cur.execute("SELECT task_run_id, access, delivery, access_event_count, "
                    "read_event_count, evidence_json FROM knowledge_interaction_fact "
                    "WHERE evaluation_id=%s AND task_run_id LIKE %s AND task_run_id NOT LIKE %s",
                    (evaluation_id, '%-KG', '%NOGK%'))
        kgs = []
        for row in cur.fetchall():
            ev = _json.loads(row[5]) if row[5] and isinstance(row[5], str) else (row[5] or {})
            kgs.append({"task_run_id": row[0], "access": bool(row[1]), "delivery": bool(row[2]),
                        "access_count": row[3], "read_count": row[4],
                        "interactions": ev.get("interactions", []) if isinstance(ev, dict) else [],
                        "memory": ev.get("memory", {}) if isinstance(ev, dict) else {}})
        r["knowledge_interactions"] = kgs
        # 诊断信息：outcome resolver_status + tool finding counts
        cur.execute("SELECT task_run_id, outcome, prediction, resolver_status, validation_result "
                    "FROM outcome_fact WHERE evaluation_id=%s", (evaluation_id,))
        r["outcome_details"] = [{"task_run_id": row[0], "outcome": row[1], "prediction": row[2],
                                 "resolver_status": row[3], "validation": row[4]} for row in cur.fetchall()]
        # 工具统计（confirmed_finding_count 从 action_distribution JSON 提取）
        cur.execute("SELECT task_run_id, kg_count, finding_count, total_tool_calls, action_distribution FROM tool_action_fact WHERE evaluation_id=%s", (evaluation_id,))
        r["tool_stats"] = [{"task_run_id": row[0], "kg_count": row[1],
                            "finding_count": (json.loads(row[4]).get("confirmed_finding_count", 0) if row[4] else 0),
                            "false_positive_count": (json.loads(row[4]).get("false_positive_finding_count", 0) if row[4] else 0),
                            "analyze_received_count": (json.loads(row[4]).get("analyze_received_count", 0) if row[4] else 0),
                            "total_tools": row[3]} for row in cur.fetchall()]
        # 资源统计（token/steps/duration 原始值）
        cur.execute("SELECT task_run_id, effective_tokens, steps, duration_ms, time_valid FROM resource_fact WHERE evaluation_id=%s", (evaluation_id,))
        r["resource_stats"] = [{"task_run_id": row[0], "tokens": row[1], "steps": row[2], "duration": row[3], "time_valid": bool(row[4])} for row in cur.fetchall()]
        # 基准 case 数 + per-case 匹配结果
        cur.execute("SELECT benchmark_item_id, expected_label, metadata_json FROM benchmark_item "
                    "WHERE benchmark_set_id=(SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s)", (evaluation_id,))
        import json as _j
        raw_rows = cur.fetchall()
        # 关联 outcome 的 case_results（从 evidence_json 里取，KG 和 No-KG 分别取）
        def _load_case_results_from_outcome(suffix):
            """从 outcome_fact.evidence_json 读取 per-case 匹配结果。suffix: '-KG' 或 '-NOGK'"""
            cur.execute("SELECT evidence_json FROM outcome_fact WHERE evaluation_id=%s AND task_run_id LIKE %s",
                        (evaluation_id, f"%{suffix}"))
            row = cur.fetchone()
            if row and row[0]:
                ev = _j.loads(row[0]) if isinstance(row[0], str) else row[0]
                if not isinstance(ev, dict):
                    return []
                return ev.get("case_results") or []
            return []

        kg_oc_cases = _load_case_results_from_outcome("-KG")
        nogk_oc_cases = _load_case_results_from_outcome("-NOGK")

        # 漏洞中心模式：只保留人工确认 case（含漏洞与非漏洞）作为基线。
        # task_id_actual 不是有效的 source_task_id 时会返回 0 条，不带 task 过滤重试。
        _vc_fallback = {}
        _vc_valid_case_ids = None
        _bm_source = manifest.get("benchmark_source", "vbench_zip")
        _vc_task = manifest.get("vc_source_task_id")
        if _bm_source == "vuln_center" and not _vc_task:
            for e in manifest.get("entries", []):
                _vc_task = e.get("task_id_actual") or e.get("task_id")
                if _vc_task:
                    break
        if _bm_source == "vuln_center" and _vc_task:
            try:
                from ...infrastructure.vuln_center_client import get_vuln_center_benchmark
                _vc_proj = erow[1] if erow else None
                log("REPORT", f"漏洞中心校验基线: project={_vc_proj} task={_vc_task}")
                _vc_bm = get_vuln_center_benchmark(_vc_proj, _vc_task)
                _vc_cases = _vc_bm.get("cases") or []
                if not _vc_cases:
                    # task_id_actual 不是有效的 source_task_id，不带 task 过滤重试
                    log("REPORT", f"漏洞中心 task={_vc_task} 返回 0 条，不带 task 过滤重试")
                    _vc_bm = get_vuln_center_benchmark(_vc_proj, None)
                    _vc_cases = _vc_bm.get("cases") or []
                    log("REPORT", f"不带 task 过滤返回 {len(_vc_cases)} 条 case")
                if _vc_cases:
                    _vc_valid_case_ids = {c.get("case_id") or c.get("id") or "" for c in _vc_cases}
                    for c in _vc_cases:
                        cid = c.get("case_id") or c.get("id") or ""
                        if cid:
                            _vc_fallback[cid] = c
                    log("REPORT", f"漏洞中心返回 {len(_vc_valid_case_ids)} 条 case，"
                          f"benchmark_item 表有 {len(raw_rows)} 条")
            except Exception as e:
                log("REPORT", f"漏洞中心校验失败: {e}")

        # 用漏洞中心返回的 case 集合过滤 benchmark_item
        if _vc_valid_case_ids is not None:
            _before = len(raw_rows)
            raw_rows = [r for r in raw_rows if r[0] in _vc_valid_case_ids]
            log("REPORT", f"过滤 benchmark_item: {_before} → {len(raw_rows)} 条")

        has_null_meta = any(r[2] is None for r in raw_rows)
        if has_null_meta and not _vc_fallback:
            try:
                from ...infrastructure.vuln_center_client import get_vuln_center_benchmark
                vc_proj = erow[1] if erow else None
                if not _vc_task:
                    _vc_task = manifest.get("vc_source_task_id")
                log("REPORT", f"metadata 缺失，从漏洞中心补取: project={vc_proj} task={_vc_task}")
                vc_bm = get_vuln_center_benchmark(vc_proj, _vc_task)
                _vc_fb_count = len(vc_bm.get("cases") or [])
                if _vc_fb_count == 0 and _vc_task:
                    # task_id_actual 不是有效的 source_task_id，不带 task 过滤重试
                    log("REPORT", f"漏洞中心返回 0 条，不带 task 过滤重试")
                    vc_bm = get_vuln_center_benchmark(vc_proj, None)
                for c in (vc_bm.get("cases") or []):
                    _vc_fallback[c.get("case_id") or c.get("id") or ""] = c
            except Exception as e:
                log("REPORT", f"漏洞中心补取失败: {e}")

        case_results = []
        for bid, label, meta in raw_rows:
            md = _j.loads(meta) if isinstance(meta, str) else (meta or {})
            if not md and bid in _vc_fallback:
                vc_c = _vc_fallback[bid]
                md = {"description": vc_c.get("description", ""),
                      "vulnerability_type": vc_c.get("vulnerability_type", ""),
                      "source_file": vc_c.get("source_file", ""),
                      "source_function": vc_c.get("source_function", "")}
                if not label or label == "VULNERABLE":
                    label = vc_c.get("expected_label", label)
            case_results.append({"case_id": bid, "expected_label": label or "NA",
                                "description": md.get("description", ""),
                                "vulnerability_type": md.get("vulnerability_type", ""),
                                "source_file": md.get("source_file", ""),
                                "source_function": md.get("source_function", "")})

        # 用 outcome 的 per-case 结果覆盖（含 matched/confusion）
        for c in case_results:
            # KG
            for oc_c in kg_oc_cases:
                if c["case_id"] == oc_c.get("case_id"):
                    c["matched"] = oc_c.get("matched", False)
                    c["confusion"] = oc_c.get("confusion", "NA")
                    c["matched_finding_id"] = oc_c.get("matched_finding_id")
                    break
            if "confusion" not in c:
                c["matched"] = False
                c["confusion"] = "NA"
            # No-KG
            for oc_c in nogk_oc_cases:
                if c["case_id"] == oc_c.get("case_id"):
                    c["nogk_matched"] = oc_c.get("matched", False)
                    c["nogk_confusion"] = oc_c.get("confusion", "NA")
                    break
            if "nogk_confusion" not in c:
                c["nogk_matched"] = False
                c["nogk_confusion"] = "NA"
        r["case_results"] = case_results
        r["baseline_count"] = len(case_results)
        # 同步过滤 metric_groups 中的 case_results 和 per_case_kg_analysis
        if _vc_valid_case_ids is not None:
            _rep = r.get("report") or {}
            for _grp in (_rep.get("metric_groups") or []):
                _gc = _grp.get("case_results") or []
                _grp["case_results"] = [c for c in _gc if c.get("case_id") in _vc_valid_case_ids]
                if len(_gc) != len(_grp["case_results"]):
                    log("REPORT", f"metric_groups[{_grp.get('task_id','')}] case_results: "
                          f"{len(_gc)} → {len(_grp['case_results'])} 条")
                _pcka = _grp.get("per_case_kg_analysis") or []
                _grp["per_case_kg_analysis"] = [p for p in _pcka if p.get("case_id") in _vc_valid_case_ids]
    finally:
        conn.close()
    return r


REPORTS_DIR = os.environ.get("EVAL_REPORTS_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "reports",
)
try:
    os.makedirs(REPORTS_DIR, exist_ok=True)
except OSError:
    pass  # 只读文件系统下跳过，首次写入时再创建


def _compute_interaction_stats(interactions, is_mem=False):
    """从原始交互列表预计算统计量（与渲染器 _stats 函数逻辑一致）。

    is_mem=True 时用本地文件读取的失败关键词（permission denied / no such file 等），
    is_mem=False 时用远程 API 的失败关键词（404 / timeout / connection refused 等）。
    """
    call_count = sum(1 for iv in interactions if isinstance(iv, dict) and iv.get("type") == "CALL")
    result_count = sum(1 for iv in interactions if isinstance(iv, dict) and iv.get("type") == "RESULT")
    no_response = max(0, call_count - result_count)
    fail = no_response
    blind = 0
    success = 0
    if is_mem:
        fail_kw = ("permission denied", "cannot access", "i/o error", "is a directory", "no space left")
        blind_kw = ("no such file", "not found", "does not exist", "no data available")
    else:
        fail_kw = ("terminated", "timeout", "error", "404", "failed",
                    "exception", "unreachable", "connection refused")
        blind_kw = ("知识库暂无此类知识", "no memory", "not found", "empty")
    for iv in interactions:
        if not isinstance(iv, dict) or iv.get("type") != "RESULT" or not iv.get("output"):
            continue
        out = str(iv.get("output", "")).lower()
        if any(kw in out for kw in fail_kw):
            fail += 1
        elif any(kw in out for kw in blind_kw):
            blind += 1
        else:
            success += 1
    return {"call_count": call_count, "result_count": result_count,
            "no_response": no_response, "fail": fail, "blind": blind, "success": success}


def _strip_report_for_html(r):
    """剥离报告中的大块原始交互数据，用预计算统计量替代，减小 HTML 体积。"""
    # knowledge_interactions: 预计算统计量，清空原始 interactions
    for ki in r.get("knowledge_interactions", []):
        interactions = ki.get("interactions", [])
        memory = ki.get("memory") or {}
        mem_interactions = memory.get("interactions", []) if isinstance(memory, dict) else []
        ki["kg_stats"] = _compute_interaction_stats(interactions, is_mem=False)
        ki["mem_stats"] = _compute_interaction_stats(mem_interactions, is_mem=True)
        ki["interactions"] = []
        ki["memory"] = {"interactions": []}

    # per_case_kg_analysis: 剥离 interactions 和 memory_interactions（原始事件太大）
    report_obj = r.get("report") or r
    for group in (report_obj.get("metric_groups") or []):
        for pcKa in (group.get("per_case_kg_analysis") or []):
            pcKa.pop("interactions", None)
            pcKa.pop("memory_interactions", None)
    for pcKa in (r.get("per_case_kg_analysis") or []):
        pcKa.pop("interactions", None)
        pcKa.pop("memory_interactions", None)

    return r


def render_static_report(evaluation_id: str) -> str:
    """固化报告为静态 HTML 文件。FINALIZE 阶段调用；返回文件路径。

    报告完全自包含：CSS + 渲染器 JS + 数据全部内联，无外部依赖，
    避免 Vite 产物文件名变化导致报告打不开的问题。
    """
    import json as _json
    r = _build_report(evaluation_id)
    r = _strip_report_for_html(r)
    # 读取渲染器 JS（内联到 HTML，使报告自包含）
    renderer_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "static", "report-renderer.js",
    )
    with open(renderer_path, "r", encoding="utf-8") as _f:
        renderer_js = _f.read()
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__EVAL_ID__ 报告</title>
<style>
:root{--bg:#f5f6f8;--panel:#ffffff;--p2:#f0f2f5;--p3:#e8eaed;--bd:#e1e4e8;--border:#e1e4e8;--txt:#1a1d23;--sub:#6b7280;--acc:#2563eb;--green:#16a34a;--red:#dc2626;--amber:#d97706;--gray:#9ca3af}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--txt);font-size:18px;line-height:1.6}
.bdg{font-size:14px;padding:2px 8px;border-radius:12px;font-weight:600}
.b-COMPLETED{background:rgba(74,222,128,.18);color:var(--green)}
.b-COMPLETEDWITHWARNINGS,.b-COMPLETED_WITH_WARNINGS{background:rgba(251,191,36,.18);color:var(--amber)}
.b-FAILED,.b-CANCEL,.b-CANCELLED,.b-CANCELLING{background:rgba(248,113,113,.18);color:var(--red)}
.b-CREATED,.b-QUEUED{background:rgba(107,114,128,.18);color:var(--gray)}
.b-RUNNING,.b-VALIDATING,.b-PARSING,.b-AI_MATCHING,.b-RESOLVING,.b-CALCULATING{background:rgba(96,165,250,.18);color:var(--acc)}
.rep{flex:1;overflow-y:auto}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.card{background:var(--panel);border:1px solid var(--bd);border-radius:14px;padding:22px}
.card.f{grid-column:1/-1}
.card h3{font-size:15px;color:var(--sub);text-transform:uppercase;letter-spacing:.6px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.tier{font-size:14px;padding:3px 8px;border-radius:12px;font-weight:600}
.t-p0{background:rgba(91,156,246,.18);color:var(--acc)}
.t-p1{background:rgba(251,191,36,.18);color:var(--amber)}
.t-p2{background:rgba(107,114,128,.18);color:var(--gray)}
table{width:100%;border-collapse:collapse;font-size:17px}
th{color:var(--sub);font-weight:500;text-align:left;padding:10px 8px;border-bottom:1px solid var(--bd);font-size:14px;text-transform:uppercase;letter-spacing:.4px}
td{padding:12px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
td.num{font-family:"SF Mono",Consolas,monospace;color:var(--acc)}
.ci{color:var(--sub);font-size:14px;font-family:"SF Mono",Consolas,monospace}
.na{color:var(--red);font-style:italic;font-size:16px}
.dp{color:var(--green)}.dn{color:var(--red)}
.diag{background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.2);border-radius:10px;padding:12px 14px;margin:8px 0}
.diag .rid{color:var(--amber);font-weight:600;font-size:14px;font-family:monospace}
.diag .ob{font-weight:500;font-size:17px}.diag .ip{color:var(--sub);font-size:15px;margin-top:4px}
.narr{font-size:17px;line-height:1.8}.narr b{color:var(--sub);font-weight:500}
.note{font-size:14px;color:var(--sub);margin-top:14px;padding-top:14px;border-top:1px solid var(--bd)}
svg{display:block;margin:0 auto;max-width:100%}
.lg{display:flex;gap:18px;justify-content:center;margin-top:10px}.lg span{font-size:14px;color:var(--sub);display:flex;align-items:center;gap:6px}.lg i{width:12px;height:12px;border-radius:3px;display:inline-block}
.mcard{background:var(--panel);border:1px solid var(--bd);border-radius:14px;padding:18px 16px;text-align:center;transition:transform .15s}
.mcard:hover{transform:translateY(-2px);border-color:var(--acc)}
.mc-icon{font-size:24px;margin-bottom:6px}
.mc-label{font-size:14px;color:var(--sub);margin-bottom:6px}
.mc-val{font-size:24px;font-weight:700;font-family:"SF Mono",Consolas,monospace}
.mc-ci{font-size:14px;color:var(--sub);margin-top:6px;font-family:"SF Mono",Consolas,monospace}
.mc-n{font-size:14px;color:var(--gray)}
.barr{display:flex;align-items:center;gap:10px;margin:10px 0}
.bar-l{font-size:16px;width:140px;flex-shrink:0}
.bar-track{flex:1;height:28px;background:var(--p2);border-radius:14px;overflow:hidden;border:1px solid var(--bd)}
.bar-fill{height:100%;border-radius:14px;transition:width .5s}
.bar-v{font-size:18px;font-weight:600;width:60px;text-align:right;font-family:"SF Mono",Consolas,monospace}
.ps{display:flex;gap:14px;padding:0;position:relative}
.ps:not(:last-child)::after{content:"";position:absolute;left:15px;top:36px;bottom:0;width:2px;background:var(--bd)}
.ps-n{width:32px;height:32px;border-radius:50%;background:var(--green);color:#fff;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;flex-shrink:0;z-index:1}
.ps-body{flex:1;padding-bottom:20px;font-size:16px;line-height:1.8}
.ps-det{font-size:14px;color:var(--sub);font-family:"SF Mono",Consolas,monospace}
.ps-body b{font-size:17px}
.ef-btn{background:var(--p2);border:1px solid var(--bd);color:var(--sub);padding:5px 10px;border-radius:8px;cursor:pointer;font-size:14px;flex:1}
.ef-btn.active{background:var(--acc);color:#fff;border-color:var(--acc)}
.ef-btn:hover{border-color:var(--acc)}
.knd{font-size:14px;padding:2px 7px;border-radius:8px;background:var(--p2);color:var(--sub)}
.knd.k-opencode{background:rgba(74,222,128,.18);color:var(--green)}
.knd.k-argo{background:rgba(96,165,250,.18);color:var(--acc)}
.knd.k-turing{background:rgba(217,119,6,.18);color:var(--amber)}
.btn{background:var(--acc);color:#fff;border:none;padding:11px 20px;border-radius:10px;cursor:pointer;font-size:16px;font-weight:500}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn.g{background:var(--p2);border:1px solid var(--bd);color:var(--txt)}
#rep{padding:28px}
</style>
</head>
<body>
<div style="background:#1a1d23;color:#9ca3af;font-size:13px;padding:5px 28px;text-align:right;font-family:'SF Mono',Consolas,monospace">报告生成时间：__GEN_TIME__ · 运行时长：__RUN_DUR__</div>
<div id="rep"></div>
<script>
__RENDERER_JS__
</script>
<script>
window.__REPORT_DATA__ = __REPORT_JSON__;
renderReport(window.__REPORT_DATA__);
</script>
</body>
</html>"""
    # 转义 </script> 防止 JSON 里含脚本闭合标签
    data_str = _json.dumps(r, ensure_ascii=False).replace("</", "<\\/")
    from datetime import datetime, timezone, timedelta
    _tz = timezone(timedelta(hours=8))
    _gen_time = datetime.now(_tz).strftime("%Y-%m-%d %H:%M:%S")
    # 计算总运行时长
    _run_dur = "-"
    if r.get("started_at") and r.get("finished_at"):
        from datetime import datetime as _dt
        _s = _dt.fromisoformat(r["started_at"])
        _f = _dt.fromisoformat(r["finished_at"])
        _dur_s = int((_f - _s).total_seconds())
        if _dur_s >= 3600:
            _run_dur = f"{_dur_s//3600}时 {(_dur_s%3600)//60}分"
        elif _dur_s >= 60:
            _run_dur = f"{_dur_s//60}分 {_dur_s%60}秒"
        else:
            _run_dur = f"{_dur_s}秒"
    html = (
        html
        .replace("__EVAL_ID__", evaluation_id)
        .replace("__GEN_TIME__", _gen_time)
        .replace("__RUN_DUR__", _run_dur)
        .replace("__RENDERER_JS__", renderer_js)
        .replace("__REPORT_JSON__", data_str)
    )
    out_path = os.path.join(REPORTS_DIR, f"{evaluation_id}.html")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    log("REPORT", f"固化报告 HTML: {out_path} ({len(html)} chars)")
    return out_path


def _static_report_path(evaluation_id: str) -> str:
    return os.path.join(REPORTS_DIR, f"{evaluation_id}.html")


from fastapi.responses import FileResponse


@app.api_route("/reports/{evaluation_id}.html", methods=["GET", "HEAD"])
def get_static_report(request: Request, evaluation_id: str):
    """直接返回固化 HTML（无计算，毫秒级）。不存在时回退动态接口。"""
    p = _static_report_path(evaluation_id)
    if os.path.isfile(p):
        return FileResponse(p, media_type="text/html")
    # HEAD 请求不触发渲染，直接返回 404
    if request.method == "HEAD":
        raise HTTPException(status_code=404, detail="report not found")
    # 回退：现场固化一次并返回
    try:
        render_static_report(evaluation_id)
        return FileResponse(p, media_type="text/html")
    except Exception:
        raise HTTPException(status_code=404, detail="report not found")


@app.get("/api/v1/evaluations/{evaluation_id}/pipeline")
def get_pipeline(evaluation_id: str):
    """分析过程日志：管线各阶段数据（parse→resolve→pair→metric）。"""
    from ...infrastructure.database import connect
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        # task_run
        cur.execute("SELECT task_run_id,task_id,`condition`,trace_valid,runtime_valid,kg_runtime_state FROM task_run WHERE evaluation_id=%s", (evaluation_id,))
        runs = [dict(zip(["task_run_id","task_id","condition","trace_valid","runtime_valid","kg_runtime_state"], r)) for r in cur.fetchall()]
        # facts
        cur.execute("SELECT 'outcome' AS t, task_run_id, outcome, prediction, resolver_status, validation_result FROM outcome_fact WHERE evaluation_id=%s", (evaluation_id,))
        outcomes = [dict(zip(["type","task_run_id","outcome","prediction","resolver_status","validation_result"], r)) for r in cur.fetchall()]
        cur.execute("SELECT task_run_id, access, delivery, mount_status FROM knowledge_interaction_fact WHERE evaluation_id=%s", (evaluation_id,))
        knowledge = [dict(zip(["task_run_id","access","delivery","mount_status"], r)) for r in cur.fetchall()]
        cur.execute("SELECT task_run_id, kg_count, finding_count, code_count, shell_count, other_count, total_tool_calls FROM tool_action_fact WHERE evaluation_id=%s", (evaluation_id,))
        tools = [dict(zip(["task_run_id","kg","finding","code","shell","other","total"], r)) for r in cur.fetchall()]
        cur.execute("SELECT task_run_id, effective_tokens, steps, duration_ms, time_valid FROM resource_fact WHERE evaluation_id=%s", (evaluation_id,))
        resources = [dict(zip(["task_run_id","tokens","steps","duration","time_valid"], r)) for r in cur.fetchall()]
        # pair
        cur.execute("SELECT pair_match_status, pair_experiment_valid, outcome_valid, pair_transition FROM task_pair WHERE evaluation_id=%s", (evaluation_id,))
        pairs = [dict(zip(["match_status","exp_valid","outcome_valid","transition"], r)) for r in cur.fetchall()]
        cur.execute("SELECT derived_fact_type, value_numeric, value_string, status, reason_code FROM pair_derived_fact WHERE evaluation_id=%s", (evaluation_id,))
        derived = [dict(zip(["type","value_num","value_str","status","reason"], r)) for r in cur.fetchall()]
        # metrics
        cur.execute("SELECT metric_id, calculation_status, reason_code, n FROM metric_result WHERE evaluation_id=%s", (evaluation_id,))
        metrics = [dict(zip(["metric_id","status","reason","n"], r)) for r in cur.fetchall()]
        return {"evaluation_id": evaluation_id, "task_runs": runs, "outcomes": outcomes,
                "knowledge": knowledge, "tools": tools, "resources": resources,
                "pairs": pairs, "derived": derived, "metrics": metrics}
    finally:
        conn.close()
