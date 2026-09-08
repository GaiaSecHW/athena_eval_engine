"""Evaluation Service（§10 Orchestrator + §6 stages）— v1 同步串行单跑。

create(request) → 冻结 snapshot + 建 evaluation。
run(evaluation_id) → VALIDATE→...→FINALIZE 同步执行，落库。
run() 使用短连接：慢操作（trace 解析、LLM 调用）期间不持有 MySQL 连接。
"""
from __future__ import annotations
import json
import os
import sys
from dataclasses import dataclass, field
from ..infrastructure.database import connect
from ..persistence.repositories import fact_repo
from ..workers.turing_trace_parser import TuringTraceParser
from ..workers.resolvers import (
    OutcomeResolverImpl, KnowledgeResolverImpl, ToolActionResolverImpl, ResourceResolverImpl,
)
from ..workers.ai_matcher import ai_match_outcome
from ..workers.pairing import TaskPairMatcherImpl, PairDerivedFactComputer
from ..domain.metrics import PairView, run_all_metrics
from ..domain.diagnostics import diagnose
from .report_assembler import assemble, render_json, ai_narrative, ai_vuln_analysis, ai_per_case_kg_analysis
from ..domain.task_run import TaskRun, BenchmarkItem
from ..domain.enums import Condition, ConditionSource, ExpectedLabel
from ..orchestration.state_machine import PIPELINE, assert_transition
from ..application import platform_service as ps

LOCAL_TRACE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tests", "fixtures", "fetched")


def _resolve_trace_path(source_uri: str, project_id: str = "", task_id: str = "") -> str:
    """source_uri 可能是 k8s pod 上的 /data/... 路径；本地开发时拉到本地。"""
    if os.path.exists(source_uri):
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
                           "unavailable"],
        "kg_success_patterns": ["knowledge persisted", "Success: knowledge", "知识已", r'"result":"Success"'],
    },
    "token_schema": {"reasoning_in_output": True, "cache_excluded": True},
}


@dataclass
class CreateRequest:
    evaluation_id: str
    evaluation_name: str | None = None
    benchmark_set_id: str = "BS001"
    vbench_project_name: str | None = None
    entries: list = field(default_factory=list)  # [{task_id, condition, source_uri, benchmark_item_id}]


def _set_status(cur, evaluation_id, status):
    cur.execute("UPDATE evaluation SET evaluation_status=%s WHERE evaluation_id=%s", (status, evaluation_id))


def _set_status_short(evaluation_id, status):
    """短连接设状态，用于 run() 各阶段更新进度。"""
    conn = connect(autocommit=True)
    try:
        conn.cursor().execute("UPDATE evaluation SET evaluation_status=%s WHERE evaluation_id=%s", (status, evaluation_id))
    finally:
        conn.close()


def create(req: CreateRequest):
    """Stage 0：建 evaluation + snapshot（冻结）。每步用独立连接避免远程防火墙重置。"""
    # 获取 V-Bench 基线 case 详情（含漏洞描述）
    case_details = {}
    try:
        from ..infrastructure.vbench_client import get_benchmark
        bm = get_benchmark(req.benchmark_set_id)
        for c in (bm.get("cases") or []):
            cid = c.get("case_id") or c.get("id") or ""
            if cid:
                findings = c.get("findings") or []
                desc = " ".join(f.get("explanation", "") for f in findings if f.get("explanation")) or c.get("vulnerability_type", "") or c.get("description") or ""
                case_details[cid] = {
                    "description": desc,
                    "vulnerability_type": c.get("vulnerability_type") or c.get("category") or "",
                    "target_finding_id": c.get("target_finding_id") or "",
                }
    except Exception:
        pass

    # Step 1: benchmark_set
    conn = connect(autocommit=True)
    try:
        fact_repo.insert_benchmark_set(conn.cursor(), req.benchmark_set_id)
    finally:
        conn.close()

    # Step 2: benchmark_items（含 case 描述存入 metadata_json）
    for e in req.entries:
        item_ids = e.get("benchmark_item_ids") or ([e["benchmark_item_id"]] if e.get("benchmark_item_id") else [])
        for bid in item_ids:
            conn = connect(autocommit=True)
            try:
                fact_repo.insert_benchmark_item(conn.cursor(), bid, req.benchmark_set_id,
                                                e["task_id"], e.get("expected_label", "VULNERABLE"),
                                                e.get("target_finding_id"),
                                                case_details.get(bid))
            finally:
                conn.close()

    # Step 3: evaluation
    eval_name = req.evaluation_name or f"eval-{req.evaluation_id}"
    conn = connect(autocommit=True)
    try:
        conn.cursor().execute(
            "INSERT INTO evaluation (evaluation_id, evaluation_name, benchmark_set_id, agent_name) "
            "VALUES (%s,%s,%s,'Turing')",
            (req.evaluation_id, eval_name, req.benchmark_set_id))
    finally:
        conn.close()

    # Step 4: evaluation_snapshot（独立连接）
    manifest = {"entries": req.entries, "manifest_hash": "mh",
                "vbench_project_name": req.vbench_project_name}
    conn = connect(autocommit=True)
    try:
        conn.cursor().execute(
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


def _db_query(fn, _retries=5):
    """短连接执行 DB 操作。连接断开时重连重试。"""
    import pymysql
    last_err = None
    for attempt in range(_retries):
        conn = None
        try:
            conn = connect(autocommit=True)
            return fn(conn.cursor())
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
            last_err = e
            if e.args and e.args[0] in (2013, 2006) and attempt < _retries - 1:
                print(f"[DB RETRY] {attempt+1}/{_retries}: {e.args[0]}, retry...")
                import time; time.sleep(2 * (attempt + 1))  # 指数退避
                continue
            raise
        finally:
            if conn:
                try: conn.close()
                except: pass


def run(evaluation_id: str) -> dict:
    """跑完整管线。使用短连接：慢操作（trace 解析、LLM）期间不持有 MySQL 连接。"""

    # ===== Phase 1: 读配置（短连接）=====
    def _load_config(cur):
        cur.execute("SELECT config_json FROM evaluation_snapshot WHERE evaluation_id=%s", (evaluation_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"evaluation {evaluation_id} not found")
        cfg = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        entries = cfg.get("manifest", {}).get("entries", [])
        cur.execute("SELECT benchmark_item_id, task_id, expected_label, target_finding_id, metadata_json FROM benchmark_item "
                    "WHERE benchmark_set_id=(SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s)",
                    (evaluation_id,))
        bench_by_task = {}
        for bi_id, tid, label, tfid, meta in cur.fetchall():
            md = json.loads(meta) if isinstance(meta, str) else (meta or None)
            bench_by_task.setdefault(tid, []).append(
                BenchmarkItem(bi_id, "BS001", tid, ExpectedLabel(label) if label else None, tfid, md))
        return cfg, entries, bench_by_task
    cfg, entries, bench_by_task = _db_query(_load_config)

    # ===== Phase 2: 解析 trace + 提取 facts（无 DB 连接 — 慢操作）=====
    # 检查 facts 是否已存在（重试时跳过慢操作）
    def _facts_exist(cur):
        cur.execute("SELECT COUNT(*) FROM outcome_fact WHERE evaluation_id=%s", (evaluation_id,))
        return cur.fetchone()[0] > 0
    facts_already_exist = _db_query(_facts_exist)

    def _is_webvulnverify_trace(path):
        """检测 JSONL 是否为 WebVulnVerify 格式（含 session_meta 行类型）。"""
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

    def _get_parser(uri, trace_kind: str | None = None):
        import os as _os
        if trace_kind == "webvulnverify":
            from ..workers.webvulnverify_trace_parser import WebVulnVerifyTraceParser
            return WebVulnVerifyTraceParser()
        if trace_kind == "cvuln_verify":
            from ..workers.cvuln_verify_trace_parser import CVulnVerifyTraceParser
            return CVulnVerifyTraceParser()
        if trace_kind == "argo":
            from ..workers.argo_trace_parser import ArgoTraceParser
            return ArgoTraceParser()
        if trace_kind == "turing":
            from ..workers.turing_trace_parser import TuringTraceParser
            return TuringTraceParser()
        if trace_kind == "dataflow":
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        # 兼容：无 trace_kind 时按路径推断
        p = _os.path.normpath(uri)
        cvuln_suffix = _os.path.join("tasks", "c_vuln_verify")
        argo_suffix = _os.path.join("session", "argo")
        dataflow_suffix = _os.path.join("session", "dataflow_vuln_scan")
        if _os.path.isdir(p) and p.endswith(cvuln_suffix):
            from ..workers.cvuln_verify_trace_parser import CVulnVerifyTraceParser
            return CVulnVerifyTraceParser()
        if _os.path.isdir(p) and p.endswith(argo_suffix):
            from ..workers.argo_trace_parser import ArgoTraceParser
            return ArgoTraceParser()
        if _os.path.isdir(p) and (p.endswith(dataflow_suffix) or "dataflow_vuln_scan" in p):
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        # 单个 dataflow jsonl 文件（路径含 dataflow_vuln_scan）也用 dataflow 解析器
        if "dataflow_vuln_scan" in p and (p.endswith(".jsonl") or _os.path.isdir(p)):
            from ..workers.dataflow_trace_parser import DataflowVulnScanTraceParser
            return DataflowVulnScanTraceParser()
        if p.endswith("opencode.db") or p.endswith("findings.db"):
            from ..workers.turing_trace_parser import TuringTraceParser
            return TuringTraceParser()
        if _os.path.isdir(p) or p.endswith(".jsonl"):
            # Check WebVulnVerify format (has session_meta line type)
            _check_path = p
            if _os.path.isdir(p):
                import glob as _glob
                _jfiles = sorted(_glob.glob(_os.path.join(p, "*.jsonl")))
                _check_path = _jfiles[0] if _jfiles else ""
            if _check_path and _is_webvulnverify_trace(_check_path):
                from ..workers.webvulnverify_trace_parser import WebVulnVerifyTraceParser
                return WebVulnVerifyTraceParser()
            from ..workers.argo_trace_parser import ArgoTraceParser
            return ArgoTraceParser()
        from ..workers.turing_trace_parser import TuringTraceParser
        return TuringTraceParser()

    task_runs: list[TaskRun] = []
    facts: dict[str, dict] = {}
    if facts_already_exist:
        # 重试：从 DB 加载已有 facts，跳过解析
        _set_status_short(evaluation_id, "CALCULATING")
        def _load_facts(cur):
            cur.execute("SELECT task_run_id, task_id, `condition`, benchmark_item_id, trace_valid, runtime_valid FROM task_run WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                tr = TaskRun(task_run_id=r[0], evaluation_id=evaluation_id, task_id=r[1],
                            trace_id=r[0].replace("tr-", "ts-"),
                            condition=Condition[r[2]], condition_source=ConditionSource.MANIFEST,
                            trace_valid=bool(r[4]), runtime_valid=bool(r[5]), benchmark_item_id=r[3])
                task_runs.append(tr)
        _db_query(_load_facts)
        # 加载 outcomes + tool + resource facts
        def _load_facts_from_db(cur):
            for tr_id in [t.task_run_id for t in task_runs]:
                facts[tr_id] = {}
            # outcomes
            cur.execute("SELECT task_run_id, outcome, prediction, resolver_status, validation_result FROM outcome_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                from ..domain.enums import Outcome, Prediction
                facts[r[0]] = {"outcome": type('OC', (), {
                    'task_run_id': r[0], 'outcome_fact_id': f"ocf-{r[0]}",
                    'outcome': Outcome(r[1]) if r[1] else Outcome.UNDETERMINED,
                    'prediction': Prediction(r[2]) if r[2] else Prediction.UNDETERMINED,
                    'resolver_status': r[3], 'validation_result': r[4],
                })()}
            # tool action facts
            cur.execute("SELECT task_run_id, kg_count, finding_count, code_count, shell_count, other_count, total_tool_calls FROM tool_action_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                if r[0] in facts:
                    facts[r[0]]["tool"] = type('TA', (), {
                        'kg_count': r[1], 'finding_count': r[2], 'code_count': r[3],
                        'shell_count': r[4], 'other_count': r[5], 'total_tool_calls': r[6],
                        'tool_action_fact_id': r[0],
                    })()
            # resource facts
            cur.execute("SELECT task_run_id, effective_tokens, steps, duration_ms, time_valid FROM resource_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                if r[0] in facts:
                    facts[r[0]]["resource"] = type('RS', (), {
                        'resource_fact_id': f"rsf-{r[0]}",
                        'effective_tokens': r[1], 'tokens': r[1], 'steps': r[2],
                        'duration': r[3], 'duration_ms': r[3], 'time_valid': bool(r[4]),
                    })()
            # knowledge facts
            cur.execute("SELECT task_run_id, access, delivery, mount_status, evidence_json FROM knowledge_interaction_fact WHERE evaluation_id=%s", (evaluation_id,))
            for r in cur.fetchall():
                if r[0] in facts:
                    # 从 evidence_json 恢复 interactions（retry/重载路径必须取回，否则 AI 分析无输入）
                    ev = json.loads(r[4]) if r[4] and isinstance(r[4], str) else (r[4] or {})
                    _interactions = ev.get("interactions", []) if isinstance(ev, dict) else []
                    facts[r[0]]["knowledge"] = type('KN', (), {
                        'access': bool(r[1]), 'delivery': bool(r[2]), 'mount_status': r[3],
                        'interactions': _interactions,
                    })()
        _db_query(_load_facts_from_db)
    else:
        _set_status_short(evaluation_id, "PARSING")
        from concurrent.futures import ThreadPoolExecutor

        def _parse_one(e):
            """解析单个 trace + resolve，返回 (tr, facts_dict, bench)。"""
            from concurrent.futures import ThreadPoolExecutor
            cond = Condition.KG if e["condition"] == "KG" else Condition.NOGK
            biid = e.get("benchmark_item_id") or None
            tr = TaskRun(
                task_run_id=f"tr-{evaluation_id}-{e['task_id']}-{cond.value}",
                evaluation_id=evaluation_id, task_id=e["task_id"],
                trace_id=f"ts-{evaluation_id}-{e['task_id']}-{cond.value}",
                condition=cond, condition_source=ConditionSource.MANIFEST,
                trace_valid=True, runtime_valid=True, benchmark_item_id=biid,
            )
            local_path = _local_paths.get(e["source_uri"]) or _resolve_trace_path(e["source_uri"], e.get("project_id", ""), e["task_id"])
            parser = _get_parser(local_path, e.get("trace_kind"))
            trace_source = {"trace_id": tr.trace_id, "source_uri": local_path,
                            "turing_session_id": "sess"}
            # CVulnVerify 的目录由多个平台任务共享，解析时必须只保留本次选择
            # 的原始平台任务所关联的 case 文件。
            if e.get("trace_kind") == "cvuln_verify":
                trace_source["source_task_id"] = e.get("task_id_actual", "")
            events = list(parser.parse(trace_source))
            # 跨 JSONL 文件时按时间戳排序，确保事件顺序正确
            events.sort(key=lambda e: (e.timestamp_ms or 0, e.event_id))
            session = parser.load_session(trace_source)
            session["_events_ts"] = [ev.timestamp_ms for ev in events]
            bench = bench_by_task.get(e["task_id"]) or []
            if not bench:
                bench = [BenchmarkItem(None, "BS001", e["task_id"], None, e.get("target_finding_id"))]
            # ai_match_outcome（LLM）和 3 个 resolver 互相独立，并行执行
            with ThreadPoolExecutor(max_workers=4) as inner_pool:
                fut_outcome = inner_pool.submit(ai_match_outcome, tr, bench, events)
                fut_kn = inner_pool.submit(KnowledgeResolverImpl(EVAL_CONFIG).resolve, tr, events)
                fut_ta = inner_pool.submit(ToolActionResolverImpl(EVAL_CONFIG).resolve, tr, events, "1.0")
                fut_rs = inner_pool.submit(ResourceResolverImpl(EVAL_CONFIG).resolve, tr, session)
                oc, case_results = fut_outcome.result()
                kn = fut_kn.result()
                ta = fut_ta.result()
                rs = fut_rs.result()
            oc.case_results = case_results
            # 构建 session 关系图（跨 session 关联漏洞挖掘链）
            import re as _re
            from collections import defaultdict as _dd
            # 排除公共文件（所有 session 都可能读的）
            _EXCLUDE_FILES = {'athena.py', 'davinci_intf_init.c', 'urd_acc_ctrl.c', 'urd_feature.c',
                              'urd_init.c', 'pbl_urd_common.h', 'pbl_task_ctx.h', 'svm_addr_desc.h'}
            session_graph = {
                'sessions': {},      # session_id → {files, facts, athena_qs}
                'file_to_sessions': _dd(set),  # file → session_ids
                'fact_to_sessions': _dd(set),  # fact_id → session_ids
                'edges': _dd(set),  # session_id → related session_ids
            }
            for ev in events:
                sid = ev.session_id
                if sid not in session_graph['sessions']:
                    session_graph['sessions'][sid] = {'files': set(), 'facts': set(), 'athena_qs': []}
                sg = session_graph['sessions'][sid]
                # 1. SYSTEM_EVENT（queue-operation enqueue）里的 fact 引用
                if ev.event_type == "SYSTEM_EVENT" and ev.output_json:
                    refs = _re.findall(r'(f\d{3,5})\s+(?:found|concluded|reported|discovered|noted|observed|identified)', str(ev.output_json))
                    for fid in refs:
                        if fid != 'f001':
                            sg['facts'].add(fid)
                            session_graph['fact_to_sessions'][fid].add(sid)
                # 2. argo.memory get fXXX 命令
                if ev.is_tool_call() and ev.tool_name == "bash":
                    cmd = str((ev.input_json or {}).get("command", ""))
                    if "argo.memory" in cmd and " get" in cmd:
                        fids = _re.findall(r'f\d{3,5}', cmd)
                        for fid in fids:
                            if fid != 'f001':
                                sg['facts'].add(fid)
                                session_graph['fact_to_sessions'][fid].add(sid)
                    if 'athena' in cmd.lower() and 'ask' in cmd:
                        m = _re.search(r'ask\s+"([^"]{0,50})', cmd)
                        if m:
                            sg['athena_qs'].append(m.group(1))
                    # 收集源文件
                    for fm in _re.findall(r'(\w+\.(?:c|h|py|java))', cmd):
                        if fm not in _EXCLUDE_FILES:
                            sg['files'].add(fm)
                            session_graph['file_to_sessions'][fm].add(sid)
                if ev.is_tool_call() and ev.tool_name == "read":
                    fp = str((ev.input_json or {}).get("file_path", ""))
                    for fm in _re.findall(r'(\w+\.(?:c|h|py|java))', fp):
                        if fm not in _EXCLUDE_FILES:
                            sg['files'].add(fm)
                            session_graph['file_to_sessions'][fm].add(sid)
            # 3. 构建边：共享文件或 fact ID 的 session 互相关联
            for fid, sids in session_graph['fact_to_sessions'].items():
                for s1 in sids:
                    for s2 in sids:
                        if s1 != s2:
                            session_graph['edges'][s1].add(s2)
            for fm, sids in session_graph['file_to_sessions'].items():
                if len(sids) > 1:
                    for s1 in sids:
                        for s2 in sids:
                            if s1 != s2:
                                session_graph['edges'][s1].add(s2)
            return tr, {"outcome": oc, "knowledge": kn, "tool": ta, "resource": rs, "case_results": case_results, "session_graph": session_graph}, e["source_uri"]

        # 预取所有 trace 到本地（串行，避免并发写同一文件 WinError 32）
        _local_paths = {}
        for e in entries:
            key = e["source_uri"]
            if key not in _local_paths:
                _local_paths[key] = _resolve_trace_path(key, e.get("project_id", ""), e["task_id"])
        # 并行解析所有 trace（KG + No-KG 独立，无共享状态）
        with ThreadPoolExecutor(max_workers=max(1, min(len(entries), 4))) as pool:
            results = list(pool.map(_parse_one, entries))
        for tr, f, src in results:
            task_runs.append(tr)
            facts[tr.task_run_id] = f
            facts[tr.task_run_id]["_source_uri"] = src

        # Phase 3: 写入 facts（单连接批量，重试整体幂等）
        def _insert_facts(cur):
            cur.execute("UPDATE evaluation SET evaluation_status=%s WHERE evaluation_id=%s", ("RESOLVING", evaluation_id))
            for tr in task_runs:
                f = facts[tr.task_run_id]
                cur.execute("SET FOREIGN_KEY_CHECKS=0")
                fact_repo.insert_trace_source(cur, tr.trace_id, evaluation_id, f.get("_source_uri", ""))
                fact_repo.insert_task_run(cur, tr)
                fact_repo.insert_outcome_fact(cur, f["outcome"])
                fact_repo.insert_knowledge_fact(cur, f["knowledge"])
                fact_repo.insert_tool_action_fact(cur, f["tool"])
                fact_repo.insert_resource_fact(cur, f["resource"])
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        _db_query(_insert_facts)

    # ===== Phase 4: 配对 + 计算指标（纯内存，无 DB）=====
    _set_status_short(evaluation_id, "PAIRING")
    pairs = TaskPairMatcherImpl().match(task_runs)
    pair_views: list[PairView] = []
    kg_access = kg_valid = kg_delivery = access = 0
    kg_access_events = kg_successful_reads = 0  # 交互级计数（M6 KDR 用）
    kg_tool_calls = total_tool_calls = 0  # 交互级计数（M5 KAR 用）
    for pair in pairs:
        kg_f = facts[pair.kg_task_run_id]; nogk_f = facts[pair.nogk_task_run_id]
        derived = PairDerivedFactComputer().compute(
            pair, kg_f["outcome"], nogk_f["outcome"], kg_f["tool"], nogk_f["tool"],
            kg_f["resource"], nogk_f["resource"])
        kg_f_run = next(t for t in task_runs if t.task_run_id == pair.kg_task_run_id)
        if kg_f_run and kg_f_run.condition == Condition.KG and kg_f_run.trace_valid and kg_f_run.runtime_valid:
            kg_valid += 1
            kn = kg_f["knowledge"]
            if kn.access: access += 1
            if kn.access and kn.delivery: kg_delivery += 1
            # 交互级累加：M6 KDR = 有效回复次数 / 总查询次数
            kg_access_events += kn.access_event_count
            kg_successful_reads += kn.successful_read_count
            # 交互级累加：M5 KAR = 知识查询次数 / 总工具调用次数
            ta = kg_f["tool"]
            kg_tool_calls += ta.kg_count
            total_tool_calls += ta.total_tool_calls
        j = next((d.value_numeric for d in derived if d.derived_fact_type == "JSD"), None)
        dt = next((d.value_numeric for d in derived if d.derived_fact_type == "DELTA_TOKEN"), None)
        ds = next((d.value_numeric for d in derived if d.derived_fact_type == "DELTA_STEPS"), None)
        dtm = next((d.value_numeric for d in derived if d.derived_fact_type == "DELTA_TIME"), None)
        bench = bench_by_task.get(pair.task_id) or [BenchmarkItem(pair.benchmark_item_id, "BS001", pair.task_id, None)]
        bench_item = bench[0] if bench else BenchmarkItem(pair.benchmark_item_id, "BS001", pair.task_id, None)
        pair_views.append(PairView(
            kg_success=kg_f["outcome"].outcome.value == "SUCCESS",
            nogk_success=nogk_f["outcome"].outcome.value == "SUCCESS",
            gt=bench_item.expected_label.value if bench_item and bench_item.expected_label else "NA",
            kg_outcome=kg_f["outcome"].outcome.value, nogk_outcome=nogk_f["outcome"].outcome.value,
            jsd=j, delta_token=dt, delta_steps=ds, delta_time=dtm))
    # 存配对数据（短连接）
    pair_derived = []
    for pair in pairs:
        kg_f = facts[pair.kg_task_run_id]; nogk_f = facts[pair.nogk_task_run_id]
        derived = PairDerivedFactComputer().compute(
            pair, kg_f["outcome"], nogk_f["outcome"], kg_f["tool"], nogk_f["tool"],
            kg_f["resource"], nogk_f["resource"])
        pair_derived.append((pair, derived))
    def _insert_pairs(cur):
        for pair, derived in pair_derived:
            fact_repo.insert_task_pair(cur, pair)
            for d in derived:
                fact_repo.insert_pair_derived_fact(cur, d)
    _db_query(_insert_pairs)

    _set_status_short(evaluation_id, "CALCULATING")
    out = run_all_metrics(pair_views, kg_access=access, kg_valid=kg_valid,
                          kg_delivery=kg_delivery, access=access,
                          kg_access_events=kg_access_events, kg_successful_reads=kg_successful_reads,
                          kg_tool_calls=kg_tool_calls, total_tool_calls=total_tool_calls,
                          seed=42)

    # ===== Phase 4b: 分组计算指标（挖掘/验证各自独立）=====
    # 按 task_id 分组 pair_views，每组独立算指标
    from collections import defaultdict as _dd2
    # 建立 pair_view → task_id 的映射（pair_views 与 pairs 顺序一致）
    _pv_task_ids: list[str] = []
    for pair in pairs:
        _pv_task_ids.append(pair.task_id)
    _groups_pv: dict[str, list[PairView]] = _dd2(list)
    for i, pv in enumerate(pair_views):
        tid = _pv_task_ids[i] if i < len(_pv_task_ids) else "T001"
        _groups_pv[tid].append(pv)
    # 为每组计算指标
    _metric_groups: list[dict] = []
    for tid, gvs in _groups_pv.items():
        if not gvs:
            continue
        # 计算 group 级别的 kg_access 等
        _g_kg_valid = _g_access = _g_kg_delivery = 0
        _g_kg_access_events = _g_kg_successful_reads = 0
        _g_kg_tool_calls = _g_total_tool_calls = 0
        for pair in pairs:
            if pair.task_id != tid:
                continue
            kg_f = facts[pair.kg_task_run_id]
            kg_f_run = next(t for t in task_runs if t.task_run_id == pair.kg_task_run_id)
            if kg_f_run and kg_f_run.condition == Condition.KG and kg_f_run.trace_valid and kg_f_run.runtime_valid:
                _g_kg_valid += 1
                kn = kg_f["knowledge"]
                if kn.access: _g_access += 1
                if kn.access and kn.delivery: _g_kg_delivery += 1
                _g_kg_access_events += kn.access_event_count
                _g_kg_successful_reads += kn.successful_read_count
                ta = kg_f["tool"]
                _g_kg_tool_calls += ta.kg_count
                _g_total_tool_calls += ta.total_tool_calls
        g_out = run_all_metrics(gvs, kg_access=_g_access, kg_valid=_g_kg_valid,
                                  kg_delivery=_g_kg_delivery, access=_g_access,
                                  kg_access_events=_g_kg_access_events, kg_successful_reads=_g_kg_successful_reads,
                                  kg_tool_calls=_g_kg_tool_calls, total_tool_calls=_g_total_tool_calls,
                                  seed=42)
        g_hits = diagnose(g_out["metric_results"], g_out["statistical_results"])
        g_report = assemble(evaluation_id, g_out["metric_results"], g_out["statistical_results"], g_hits,
                            pair_views=gvs)
        # 找到这个 task_id 对应的 category
        _g_category = ""
        for e in entries:
            if e.get("task_id") == tid:
                _g_category = e.get("category", "")
                break
        _metric_groups.append({
            "task_id": tid,
            "category": _g_category,
            "label": "漏洞验证" if _g_category == "verify" else "漏洞挖掘",
            "p0": g_report.p0, "p1": g_report.p1, "p2": g_report.p2,
            "pair_count": len(gvs),
        })

    # ===== Phase 5: 写入指标（短连接）=====
    cr_id = f"CR-{evaluation_id}"; pop_id = f"PS-{evaluation_id}"
    def _insert_metrics(cur):
        cur.execute("INSERT IGNORE INTO evaluation_calculation_run (calculation_run_id, evaluation_id, run_type, config_snapshot_id) "
                    "VALUES (%s,%s,'INITIAL',%s)", (cr_id, evaluation_id, f"snap-{evaluation_id}"))
        cur.execute("INSERT IGNORE INTO evaluation_population_snapshot (population_snapshot_id, calculation_run_id, "
                    "population_type, population_entity_type, task_count, estimator_version, population_ids_uri, population_ids_hash) "
                    "VALUES (%s,%s,'primary_analysis','TASK_PAIR',%s,'1.0','uri','hash')", (pop_id, cr_id, len(pair_views)))
        for m in out["metric_results"]:
            fact_repo.insert_metric_result(cur, cr_id, pop_id, m, evaluation_id)
        for s in out["statistical_results"]:
            fact_repo.insert_statistical_result(cur, cr_id, pop_id, s, evaluation_id)
    _db_query(_insert_metrics)

    # ===== Phase 6: 生成报告 + AI 分析（慢操作，无 DB 连接）=====
    _set_status_short(evaluation_id, "REPORTING")
    hits = diagnose(out["metric_results"], out["statistical_results"])
    report = assemble(evaluation_id, out["metric_results"], out["statistical_results"], hits,
                      pair_views=pair_views)
    report.metric_groups = _metric_groups
    report.narrative = ai_narrative(out["metric_results"], out["statistical_results"], hits)
    # 取 KG 任务的 outcome（用于 AI 分析）
    kg_outcome_for_analysis = None
    for tr in task_runs:
        if tr.condition == Condition.KG:
            oc = facts.get(tr.task_run_id, {}).get("outcome")
            if oc:
                kg_outcome_for_analysis = {"outcome": oc.outcome.value, "prediction": oc.prediction.value if oc.prediction else None,
                                         "resolver_status": oc.resolver_status, "validation": oc.validation_result,
                                         "case_results": facts.get(tr.task_run_id, {}).get("case_results", [])}
            break
    kg_interactions = []
    for tr in task_runs:
        # 只统计 KG 任务的介入，不统计 No-KG
        if tr.condition != Condition.KG:
            continue
        kf = facts.get(tr.task_run_id, {})
        kn = kf.get("knowledge")
        if kn and kn.interactions:
            kg_interactions.extend(kn.interactions)
    baseline_cnt = sum(len(v) for v in bench_by_task.values())
    # ai_knowledge_analysis 已删除（与 narrative/vuln_analysis 重复），省一次 LLM 调用
    # AI 逐漏洞知识介入分析
    kg_case_results = []
    kg_session_graph = None
    for tr in task_runs:
        if tr.condition == Condition.KG:
            kf = facts.get(tr.task_run_id, {})
            kg_case_results = kf.get("case_results", [])
            kg_session_graph = kf.get("session_graph")
            break
    report.per_case_kg_analysis = ai_per_case_kg_analysis(kg_case_results, kg_interactions, bench_by_task, session_graph=kg_session_graph)
    # AI 漏洞对比分析：Agent 提交的漏洞 vs 基线 case
    report.vuln_analysis = ai_vuln_analysis(facts, bench_by_task)
    # AI 评测摘要
    outcomes_list = [{"task_run_id": tr.task_run_id,
                      "outcome": facts[tr.task_run_id]["outcome"].outcome.value,
                      "prediction": facts[tr.task_run_id]["outcome"].prediction.value if facts[tr.task_run_id]["outcome"].prediction else None,
                      "resolver_status": facts[tr.task_run_id]["outcome"].resolver_status,
                      "validation": facts[tr.task_run_id]["outcome"].validation_result}
                     for tr in task_runs]
    tool_stats_list = [{"task_run_id": tr.task_run_id,
                        "finding_count": facts[tr.task_run_id]["tool"].finding_count,
                        "total_tools": facts[tr.task_run_id]["tool"].total_tool_calls}
                       for tr in task_runs]
    # ai_summary 已合并进 narrative，不再单独调用（省一次 LLM）
    rj = render_json(report)

    # ===== Phase 7: 写入报告 + 标记完成（短连接）=====
    def _finalize(cur):
        cur.execute("INSERT IGNORE INTO evaluation_report (report_id, evaluation_id, calculation_run_id, snapshot_id, "
                    "report_version, report_config_json, status) VALUES (%s,%s,%s,%s,'1.0',%s,'READY')",
                    (f"rp-{evaluation_id}", evaluation_id, cr_id, f"snap-{evaluation_id}", rj))
        _set_status(cur, evaluation_id, "COMPLETED")
    _db_query(_finalize)

    return {"status": "COMPLETED", "metrics": len(out["metric_results"]),
            "statistical_results": len(out["statistical_results"]),
            "report_uri": f"report/{evaluation_id}", "pair_count": len(pair_views)}


def get_status(evaluation_id: str) -> dict:
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT evaluation_status, evaluation_name FROM evaluation WHERE evaluation_id=%s", (evaluation_id,))
        r = cur.fetchone()
        if not r:
            return {"error": "not found"}
        cur.execute("SELECT COUNT(*) FROM metric_result WHERE evaluation_id=%s", (evaluation_id,))
        n_metrics = cur.fetchone()[0]
        return {"evaluation_id": evaluation_id, "status": r[0], "name": r[1], "metrics": n_metrics}
    finally:
        conn.close()


def get_report(evaluation_id: str) -> dict:
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
