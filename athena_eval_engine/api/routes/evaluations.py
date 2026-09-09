"""FastAPI app + 路由（§11.1）。

POST /api/v1/evaluations → 创建 + 后台异步跑（最多 3 个并发，超出排队）
GET  /api/v1/evaluations/{id} → 状态
GET  /api/v1/evaluations/{id}/metrics → 指标
GET  /api/v1/evaluations/{id}/report → 报告
"""
from __future__ import annotations
import os
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from ...application import evaluation_service as es
from ...persistence.repositories import fact_repo
from .web import router as web_router
from .platform import router as platform_router
from .benchmark_system import vb as vbench_router, sys_r as sys_router

# 最多 3 个评测同时运行，其余排队等待
_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="eval")
_TERMINAL_EVALUATION_STATUSES = {"COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED"}


def _record_background_failure(evaluation_id: str, error: Exception, source: str) -> None:
    """Mark an in-progress evaluation failed without clobbering a final report.

    A late exception can occur after ``run()`` has persisted its report and
    transitioned the evaluation to a terminal state.  In that case the report
    is usable; overwriting the state with FAILED makes reopening it impossible.
    """
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
            print(f"[{source}] 忽略终态后的异常: {evaluation_id} status={phase}: {err_msg}", flush=True)
            return
        print(f"[{source}] {evaluation_id} at {phase}: {err_msg}", flush=True)
        cur.execute("UPDATE evaluation SET evaluation_status='FAILED', "
                    "evaluation_name=CONCAT(IFNULL(evaluation_name,''),' | FAILED at ',%s,': ',%s) "
                    "WHERE evaluation_id=%s", (phase, err_msg, evaluation_id))
    except Exception as db_error:
        print(f"[{source}] 记录失败状态失败: {db_error}", flush=True)
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
    """
    try:
        from ...infrastructure.database import connect
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            stuck_states = ('RUNNING', 'VALIDATING', 'INGESTING', 'PARSING', 'AI_MATCHING',
                            'RESOLVING', 'PAIRING', 'CALCULATING', 'STATISTICAL_ANALYSIS',
                            'DIAGNOSING', 'REPORTING', 'FINALIZING')
            placeholders = ','.join(['%s'] * len(stuck_states))
            cur.execute(f"SELECT evaluation_id, evaluation_status FROM evaluation "
                        f"WHERE evaluation_status IN ({placeholders})", stuck_states)
            stuck = cur.fetchall()
            if stuck:
                print(f"[STARTUP] 发现 {len(stuck)} 个卡住的评测，准备续跑:", flush=True)
                for eid, status in stuck:
                    print(f"[STARTUP]   {eid} (was {status}) → 续跑", flush=True)
                    _executor.submit(_run_bg_resume, eid)
            else:
                print(f"[STARTUP] 无卡住的评测", flush=True)
        finally:
            conn.close()
    except Exception as e:
        print(f"[STARTUP] 扫描卡住评测失败（DB 可能未就绪）: {e}", flush=True)


def _run_bg_resume(evaluation_id: str):
    """续跑单个评测（与 _run_bg 相同，但不设 RUNNING——保留原状态给 run() 覆盖）。"""
    try:
        es.run(evaluation_id)
    except Exception as e:
        import traceback
        traceback.print_exc()
        _record_background_failure(evaluation_id, e, "EVAL RESUME FAILED")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/evaluations")
def create_evaluation(req: CreateRequest):
    try:
        es.create(es.CreateRequest(evaluation_id=req.evaluation_id,
                                   evaluation_name=req.evaluation_name,
                                   benchmark_set_id=req.benchmark_set_id,
                                   vbench_project_name=req.vbench_project_name,
                                   benchmark_source=req.benchmark_source,
                                   vc_source_task_id=req.vc_source_task_id,
                                   entries=req.entries))
        # 提交到线程池排队运行（最多 3 并发，超出自动排队）
        def _run_bg():
            from ...infrastructure.database import connect
            # 标记 RUNNING
            conn = connect(autocommit=True)
            try:
                cur = conn.cursor()
                cur.execute("UPDATE evaluation SET evaluation_status='RUNNING' WHERE evaluation_id=%s",
                            (req.evaluation_id,))
            finally:
                conn.close()
            try:
                es.run(req.evaluation_id)
            except Exception as e:
                import traceback
                traceback.print_exc()
                _record_background_failure(req.evaluation_id, e, "EVAL FAILED")
        _executor.submit(_run_bg)
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
        print(f"[DELETE] 评测 {evaluation_id} 已删除", flush=True)
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
def retry_evaluation(evaluation_id: str):
    """重试失败的评测：删除全部数据，重新解析+计算+报告。"""
    try:
        from ...infrastructure.database import connect

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
                    print(f"[RETRY] 漏洞中心取基线: project={bsid} task={effective_vc_task}", flush=True)
                    bm = get_vuln_center_benchmark(bsid, effective_vc_task)
                    _n = len(bm.get("cases") or [])
                    if _n == 0 and effective_vc_task:
                        print(f"[RETRY] task={effective_vc_task} 不是漏洞中心 source_task，不带 task 过滤重试", flush=True)
                        bm = get_vuln_center_benchmark(bsid, None)
                        print(f"[RETRY] 不带 task 过滤返回 {len(bm.get('cases') or [])} 条 VULNERABLE case", flush=True)
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
                print(f"[RETRY] 删除旧报告: {p}", flush=True)
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

        # Step 6: 提交到线程池
        def _run_bg():
            from ...infrastructure.database import connect as _connect
            conn = _connect(autocommit=True)
            try:
                conn.cursor().execute("UPDATE evaluation SET evaluation_status='RUNNING' WHERE evaluation_id=%s", (evaluation_id,))
            finally:
                conn.close()
        # 重新提交到线程池
        def _run_bg():
            from ...infrastructure.database import connect as _connect
            conn = _connect(autocommit=True)
            try:
                conn.cursor().execute("UPDATE evaluation SET evaluation_status='RUNNING' WHERE evaluation_id=%s", (evaluation_id,))
            finally:
                conn.close()
            try:
                es.run(evaluation_id)
            except Exception as e:
                import traceback
                traceback.print_exc()
                _record_background_failure(evaluation_id, e, "EVAL RETRY FAILED")
        _executor.submit(_run_bg)
        return {"evaluation_id": evaluation_id, "status": "QUEUED"}
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/evaluations/{evaluation_id}")
def get_status(evaluation_id: str):
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
        cur.execute("SELECT evaluation_name, benchmark_set_id FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        erow = cur.fetchone()
        if erow:
            r["evaluation_name"] = erow[0]
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
        # 工具统计（finding 提交数等）
        cur.execute("SELECT task_run_id, kg_count, finding_count, total_tool_calls FROM tool_action_fact WHERE evaluation_id=%s", (evaluation_id,))
        r["tool_stats"] = [{"task_run_id": row[0], "kg_count": row[1], "finding_count": row[2], "total_tools": row[3]} for row in cur.fetchall()]
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

        # 漏洞中心模式：只保留人工确认漏洞（VULNERABLE）的 case 作为基线。
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
                print(f"[REPORT] 漏洞中心校验基线: project={_vc_proj} task={_vc_task}", flush=True)
                _vc_bm = get_vuln_center_benchmark(_vc_proj, _vc_task)
                _vc_cases = _vc_bm.get("cases") or []
                if not _vc_cases:
                    # task_id_actual 不是有效的 source_task_id，不带 task 过滤重试
                    print(f"[REPORT] 漏洞中心 task={_vc_task} 返回 0 条，不带 task 过滤重试", flush=True)
                    _vc_bm = get_vuln_center_benchmark(_vc_proj, None)
                    _vc_cases = _vc_bm.get("cases") or []
                    print(f"[REPORT] 不带 task 过滤返回 {len(_vc_cases)} 条 VULNERABLE case", flush=True)
                if _vc_cases:
                    _vc_valid_case_ids = {c.get("case_id") or c.get("id") or "" for c in _vc_cases}
                    for c in _vc_cases:
                        cid = c.get("case_id") or c.get("id") or ""
                        if cid:
                            _vc_fallback[cid] = c
                    print(f"[REPORT] 漏洞中心返回 {len(_vc_valid_case_ids)} 条 VULNERABLE case，"
                          f"benchmark_item 表有 {len(raw_rows)} 条", flush=True)
            except Exception as e:
                print(f"[REPORT] 漏洞中心校验失败: {e}", flush=True)

        # 用漏洞中心返回的 VULNERABLE case 集合过滤 benchmark_item
        if _vc_valid_case_ids is not None:
            _before = len(raw_rows)
            raw_rows = [r for r in raw_rows if r[0] in _vc_valid_case_ids]
            print(f"[REPORT] 过滤 benchmark_item: {_before} → {len(raw_rows)} 条（只保留 VULNERABLE）", flush=True)

        has_null_meta = any(r[2] is None for r in raw_rows)
        if has_null_meta and not _vc_fallback:
            try:
                from ...infrastructure.vuln_center_client import get_vuln_center_benchmark
                vc_proj = erow[1] if erow else None
                if not _vc_task:
                    _vc_task = manifest.get("vc_source_task_id")
                print(f"[REPORT] metadata 缺失，从漏洞中心补取: project={vc_proj} task={_vc_task}", flush=True)
                vc_bm = get_vuln_center_benchmark(vc_proj, _vc_task)
                _vc_fb_count = len(vc_bm.get("cases") or [])
                if _vc_fb_count == 0 and _vc_task:
                    # task_id_actual 不是有效的 source_task_id，不带 task 过滤重试
                    print(f"[REPORT] 漏洞中心返回 0 条，不带 task 过滤重试", flush=True)
                    vc_bm = get_vuln_center_benchmark(vc_proj, None)
                for c in (vc_bm.get("cases") or []):
                    _vc_fallback[c.get("case_id") or c.get("id") or ""] = c
            except Exception as e:
                print(f"[REPORT] 漏洞中心补取失败: {e}", flush=True)

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
                    print(f"[REPORT] metric_groups[{_grp.get('task_id','')}] case_results: "
                          f"{len(_gc)} → {len(_grp['case_results'])} 条", flush=True)
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


def render_static_report(evaluation_id: str) -> str:
    """固化报告为静态 HTML 文件。FINALIZE 阶段调用；返回文件路径。

    报告完全自包含：CSS + 渲染器 JS + 数据全部内联，无外部依赖，
    避免 Vite 产物文件名变化导致报告打不开的问题。
    """
    import json as _json
    r = _build_report(evaluation_id)
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
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;max-width:1100px}
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
#rep{padding:28px;max-width:1200px;margin:0 auto}
</style>
</head>
<body>
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
    html = (
        html
        .replace("__EVAL_ID__", evaluation_id)
        .replace("__RENDERER_JS__", renderer_js)
        .replace("__REPORT_JSON__", data_str)
    )
    out_path = os.path.join(REPORTS_DIR, f"{evaluation_id}.html")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[REPORT] 固化报告 HTML: {out_path} ({len(html)} chars)", flush=True)
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
