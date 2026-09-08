"""FastAPI app + 路由（§11.1）。

POST /api/v1/evaluations → 创建 + 后台异步跑（最多 3 个并发，超出排队）
GET  /api/v1/evaluations/{id} → 状态
GET  /api/v1/evaluations/{id}/metrics → 指标
GET  /api/v1/evaluations/{id}/report → 报告
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ...application import evaluation_service as es
from ...persistence.repositories import fact_repo
from .web import router as web_router
from .platform import router as platform_router
from .benchmark_system import vb as vbench_router, sys_r as sys_router

# 最多 3 个评测同时运行，其余排队等待
_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="eval")


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
    from ...infrastructure.database import connect
    try:
        es.run(evaluation_id)
    except Exception as e:
        import traceback
        traceback.print_exc()
        err_msg = str(e)[:500]
        print(f"[EVAL RESUME FAILED] {evaluation_id}: {err_msg}", flush=True)
        try:
            conn = connect(autocommit=True)
            cur = conn.cursor()
            cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
            row = cur.fetchone()
            phase = row[0] if row else "UNKNOWN"
            cur.execute("UPDATE evaluation SET evaluation_status='FAILED', "
                        "evaluation_name=CONCAT(IFNULL(evaluation_name,''),' | FAILED at ',%s,': ',%s) "
                        "WHERE evaluation_id=%s", (phase, err_msg, evaluation_id))
            conn.close()
        except Exception:
            pass


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
                # 后台失败 → 记录当前阶段 + 错误 + 标记 FAILED
                import traceback
                err_msg = str(e)
                traceback.print_exc()
                # 查当前在哪个阶段
                conn = connect(autocommit=True)
                phase = "UNKNOWN"
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (req.evaluation_id,))
                    row = cur.fetchone()
                    if row: phase = row[0]
                except: pass
                print(f"[EVAL FAILED] {req.evaluation_id} at {phase}: {err_msg}")
                try:
                    cur = conn.cursor()
                    cur.execute("UPDATE evaluation SET evaluation_status='FAILED', evaluation_name=CONCAT(IFNULL(evaluation_name,''),' | FAILED at ',%s,': ',%s) WHERE evaluation_id=%s",
                                (phase, err_msg[:500], req.evaluation_id))
                finally:
                    conn.close()
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
        tables = [
            "statistical_result", "metric_result", "pair_derived_fact", "task_pair",
            "finding_benchmark_match", "outcome_fact", "knowledge_interaction_fact",
            "tool_action_fact", "resource_fact", "task_run", "trace_source",
            "evaluation_report", "evaluation_population_snapshot", "evaluation_calculation_run",
            "evaluation_snapshot", "evaluation",
        ]
        for t in tables:
            cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (evaluation_id,))
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
        print(f"[DELETE] 评测 {evaluation_id} 已删除", flush=True)
    finally:
        conn.close()
    return {"status": "ok", "evaluation_id": evaluation_id}


@app.post("/api/v1/evaluations/{evaluation_id}/retry")
def retry_evaluation(evaluation_id: str):
    """重试失败的评测：删除全部数据，重新解析+计算+报告。"""
    try:
        from ...infrastructure.database import connect
        from ...infrastructure.vbench_client import get_benchmark

        # Step 1: 获取 benchmark_set_id + config_json（一个连接）
        bsid = None
        entries = []
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
        finally:
            conn.close()

        # Step 2: 从 V-Bench API 获取 case 描述（HTTP，不用 MySQL）
        case_details = {}
        if bsid:
            try:
                bm = get_benchmark(bsid)
                for c in (bm.get("cases") or []):
                    cid = c.get("case_id") or c.get("id") or ""
                    if cid:
                        fnd = c.get("findings") or []
                        desc = " ".join(f.get("explanation", "") for f in fnd if f.get("explanation")) or c.get("vulnerability_type", "") or c.get("description") or ""
                        case_details[cid] = {"description": desc,
                                            "vulnerability_type": c.get("vulnerability_type") or c.get("category") or "",
                                            "target_finding_id": c.get("target_finding_id") or ""}
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

        # Step 4: 重置状态
        conn = connect(autocommit=True)
        try:
            conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s, evaluation_name=SUBSTRING_INDEX(IFNULL(evaluation_name,''),' |',1) WHERE evaluation_id=%s",
                                ("CREATED", evaluation_id))
        finally:
            conn.close()

        # Step 5: 重新插入 benchmark items（含 case 描述）— 单连接批量插入
        if bsid and entries:
            conn = connect(autocommit=True)
            try:
                cur = conn.cursor()
                for e in entries:
                    item_ids = e.get("benchmark_item_ids") or ([e["benchmark_item_id"]] if e.get("benchmark_item_id") else [])
                    for bid in item_ids:
                        fact_repo.insert_benchmark_item(cur, bid, bsid,
                                                       e["task_id"], e.get("expected_label", "VULNERABLE"),
                                                       e.get("target_finding_id"), case_details.get(bid))
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
                err_msg = str(e)
                traceback.print_exc()
                conn = _connect(autocommit=True)
                phase = "UNKNOWN"
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT evaluation_status FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
                    row = cur.fetchone()
                    if row: phase = row[0]
                except: pass
                print(f"[EVAL RETRY FAILED] {evaluation_id} at {phase}: {err_msg}")
                try:
                    cur = conn.cursor()
                    cur.execute("UPDATE evaluation SET evaluation_status='FAILED', evaluation_name=CONCAT(IFNULL(evaluation_name,''),' | FAILED at ',%s,': ',%s) WHERE evaluation_id=%s",
                                (phase, err_msg[:500], evaluation_id))
                finally:
                    conn.close()
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
                        "interactions": ev.get("interactions", []) if isinstance(ev, dict) else []})
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
        case_results = []
        raw_rows = cur.fetchall()
        # 如果 metadata_json 全是 NULL（旧评测/取基线失败），从漏洞中心补取
        _vc_fallback = {}
        has_null_meta = any(r[2] is None for r in raw_rows)
        if has_null_meta:
            try:
                from ...infrastructure.vuln_center_client import get_vuln_center_benchmark
                vc_proj = erow[1] if erow else None  # benchmark_set_id = project_id
                vc_task = manifest.get("vc_source_task_id")
                print(f"[REPORT] metadata 缺失，从漏洞中心补取: project={vc_proj} task={vc_task}", flush=True)
                vc_bm = get_vuln_center_benchmark(vc_proj, vc_task)
                for c in (vc_bm.get("cases") or []):
                    _vc_fallback[c.get("case_id") or c.get("id") or ""] = c
            except Exception as e:
                print(f"[REPORT] 漏洞中心补取失败: {e}", flush=True)
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
    finally:
        conn.close()
    return r


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
