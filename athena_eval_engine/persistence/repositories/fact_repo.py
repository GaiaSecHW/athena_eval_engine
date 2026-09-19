"""Fact / Metric / PairDerivedFact 持久化（§7.9-7.26）。

Insert-If-Absent：相同 Key+Content → IDEMPOTENT_REPLAY；不同 Content → FACT_CONFLICT（§7.0）。
Fact 不可变；重新解析须新建 Evaluation。复合 FK 由 DB 强制（§7.27）。
"""
from __future__ import annotations
import json
import math
from ...infrastructure.database import connect
from ...domain.facts import (
    OutcomeFact, KnowledgeInteractionFact, ToolActionFact, ResourceFact, PairDerivedFact,
)
from ...domain.metrics import MetricResult, StatisticalResult


def _clean(v):
    """NaN/inf → None（MySQL 不接受）。"""
    if v is None:
        return None
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return None
    return v


def _evid(evs) -> str | None:
    return json.dumps([e.model_dump() for e in evs], ensure_ascii=False) if evs else None



def _upsert(cur, sql, args, conflict_label: str) -> str:
    """Insert-If-Absent：主键冲突 → 返回 IDEMPOTENT_REPLAY（不 UPDATE）。"""
    try:
        cur.execute(sql, args)
        return "INSERTED"
    except Exception as e:
        if "Duplicate" in str(e) or "1062" in str(e):
            return conflict_label
        raise


def insert_evaluation(cur, evaluation_id: str, benchmark_set_id: str, agent_name: str = "Turing"):
    cur.execute(
        "INSERT INTO evaluation (evaluation_id, evaluation_name, benchmark_set_id, agent_name) "
        "VALUES (%s,%s,%s,%s)",
        (evaluation_id, f"eval-{evaluation_id}", benchmark_set_id, agent_name),
    )


def insert_benchmark_item(cur, bi_id: str, set_id: str, task_id: str, label: str, target_finding_id=None, metadata_json=None):
    import json as _json
    sql = ("INSERT INTO benchmark_item (benchmark_item_id, benchmark_set_id, task_id, expected_label, "
           "target_finding_id, metadata_json) VALUES (%s,%s,%s,%s,%s,%s) "
           "ON DUPLICATE KEY UPDATE expected_label=VALUES(expected_label), "
           "target_finding_id=VALUES(target_finding_id), metadata_json=VALUES(metadata_json)")
    cur.execute(sql, (bi_id, set_id, task_id, label, target_finding_id,
                     _json.dumps(metadata_json, ensure_ascii=False) if metadata_json else None))


def insert_benchmark_set(cur, set_id: str = "BS001", manifest_hash: str = "hash-bs001"):
    cur.execute(
        "INSERT IGNORE INTO benchmark_set (benchmark_set_id, name, version, manifest_hash) VALUES (%s,%s,%s,%s)",
        (set_id, f"name-{set_id}", "1.0", manifest_hash),
    )


def insert_trace_source(cur, trace_id: str, evaluation_id: str, source_uri: str,
                        content_hash: str = "hash", sidecar_hash: str | None = None,
                        condition_hint: str = "UNKNOWN"):
    cur.execute(
        "INSERT IGNORE INTO trace_source (trace_id, evaluation_id, source_type, source_uri, content_hash, "
        "sidecar_hash, condition_evidence_hash, condition_hint) "
        "VALUES (%s,%s,'SQLITE',%s,%s,%s,%s,%s)",
        (trace_id, evaluation_id, source_uri, content_hash, sidecar_hash,
         content_hash, condition_hint),
    )


def insert_task_run(cur, tr) -> str:
    sql = """INSERT INTO task_run
        (task_run_id, evaluation_id, task_id, benchmark_item_id, trace_id, turing_session_id,
         `condition`, condition_source, condition_conflict, agent_name, trace_valid, runtime_valid,
         runtime_invalid_reason, kg_runtime_state, parser_version)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        tr.task_run_id, tr.evaluation_id, tr.task_id, tr.benchmark_item_id, tr.trace_id,
        tr.turing_session_id, tr.condition.value, tr.condition_source.value, tr.condition_conflict,
        tr.agent_name if hasattr(tr, "agent_name") else "Turing", tr.trace_valid, tr.runtime_valid,
        tr.runtime_invalid_reason, tr.kg_runtime_state, tr.parser_version,
    ), "IDEMPOTENT_REPLAY")


def insert_outcome_fact(cur, f: OutcomeFact) -> str:
    import json as _json
    import os as _os
    # case_results 全部存文件，DB 只存 URI
    case_results = getattr(f, "case_results", None) or []
    ev_json = _json.dumps({"case_results": case_results}, ensure_ascii=False)
    _reports_dir = _os.environ.get("EVAL_REPORTS_DIR") or "/app/reports"
    _os.makedirs(_reports_dir, exist_ok=True)
    _cr_path = _os.path.join(_reports_dir, f"{f.evaluation_id}_{f.task_run_id}_cr.json")
    with open(_cr_path, "w", encoding="utf-8") as _f:
        _f.write(ev_json)
    ev_data = {"case_results_uri": _cr_path}
    sql = """INSERT INTO outcome_fact
        (outcome_fact_id, task_run_id, evaluation_id, `condition`, condition_source, condition_conflict,
         benchmark_item_id, gt_label, prediction, outcome, target_finding_id,
         validation_result, resolver_status, resolver_version, evidence_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        f.outcome_fact_id, f.task_run_id, f.evaluation_id, f.condition.value,
        f.condition_source.value, f.condition_conflict, f.benchmark_item_id,
        f.gt_label.value if f.gt_label else None, f.prediction.value if f.prediction else None,
        f.outcome.value,
        f.target_finding_id, f.validation_result, f.resolver_status, f.resolver_version,
        _json.dumps(ev_data, ensure_ascii=False),
    ), "IDEMPOTENT_REPLAY")


def insert_knowledge_fact(cur, f: KnowledgeInteractionFact) -> str:
    import json as _json
    # evidence_json 存 interactions + memory_interactions（报告生成时从 DB 读取）；evidence 列表不回读，不存入
    ev_data = {"interactions": f.interactions,
               "memory": {
                   "access": f.memory_access,
                   "access_event_count": f.memory_access_event_count,
                   "successful_read_count": f.memory_successful_read_count,
                   "interactions": f.memory_interactions,
               }}
    sql = """INSERT INTO knowledge_interaction_fact
        (knowledge_fact_id, task_run_id, evaluation_id, access, delivery, mount_status,
         access_event_count, read_event_count, successful_read_count, evidence_json, resolver_version)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        f.knowledge_fact_id, f.task_run_id, f.evaluation_id, f.access, f.delivery, f.mount_status,
        f.access_event_count, f.read_event_count, f.successful_read_count, _json.dumps(ev_data, ensure_ascii=False), f.resolver_version,
    ), "IDEMPOTENT_REPLAY")


def insert_tool_action_fact(cur, f: ToolActionFact) -> str:
    sql = """INSERT INTO tool_action_fact
        (tool_action_fact_id, task_run_id, evaluation_id, action_schema_version,
         kg_count, finding_count, code_count, shell_count, other_count, total_tool_calls,
         action_distribution, evidence_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        f.tool_action_fact_id, f.task_run_id, f.evaluation_id, f.action_schema_version,
        f.kg_count, f.finding_count, f.code_count, f.shell_count, f.other_count, f.total_tool_calls,
        json.dumps(f.action_distribution, ensure_ascii=False), None,  # evidence 不回读，不存入
    ), "IDEMPOTENT_REPLAY")


def insert_resource_fact(cur, f: ResourceFact) -> str:
    sql = """INSERT INTO resource_fact
        (resource_fact_id, task_run_id, evaluation_id, input_tokens, output_tokens, reasoning_tokens,
         cache_read_tokens, effective_tokens, token_schema_valid, token_schema_version, steps, step_source,
         step_integrity_warning, duration_ms, time_valid, validity_status, evidence_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        f.resource_fact_id, f.task_run_id, f.evaluation_id, f.input_tokens, f.output_tokens,
        f.reasoning_tokens, f.cache_read_tokens, f.effective_tokens, f.token_schema_valid,
        f.token_schema_version, f.steps, f.step_source, f.step_integrity_warning, f.duration_ms,
        f.time_valid, f.validity_status, None,  # evidence 不回读，不存入
    ), "IDEMPOTENT_REPLAY")


def insert_extracted_findings(cur, task_run_id: str, evaluation_id: str, findings: list[dict]) -> None:
    """持久化 parser.extract_findings 返回的 finding 列表。

    每条 finding 一行，主键 (task_run_id, finding_id)。
    断点续跑时可直接从 DB 读取，无需重新解析 trace。
    """
    for f in findings:
        sql = """INSERT INTO extracted_finding
            (finding_id, task_run_id, evaluation_id, platform, session_id, verify_session_id,
             vuln_type, file, severity, validation_result, title, description, source, sink,
             event_idx, finding_json)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
        _upsert(cur, sql, (
            str(f.get("finding_id", "")),
            task_run_id,
            evaluation_id,
            str(f.get("platform", "")),
            str(f.get("session_id", "")) or None,
            str(f.get("_verify_session_id", "")) or None,
            str(f.get("vuln_type", "")) or None,
            str(f.get("file", f.get("source", ""))) or None,  # file 从 finding dict 取
            str(f.get("severity", "")) or None,
            str(f.get("validation_result") or "") or None,
            str(f.get("title", ""))[:200000] or None,
            str(f.get("description", ""))[:200000] or None,
            str(f.get("source", "")) or None,
            str(f.get("sink", "")) or None,
            f.get("_event_idx"),
            json.dumps(f, ensure_ascii=False, default=str),
        ), "IDEMPOTENT_REPLAY")


def insert_session_graph(cur, task_run_id: str, evaluation_id: str, graph: dict) -> str:
    """持久化 parser.build_session_graph 返回的 session 关系图。

    每个 task_run 一行，graph_json 存完整图结构。
    断点续跑时可直接从 DB 读取，无需重新解析 trace。
    """
    # 序列化前把 set 转成 list（JSON 不支持 set）
    def _serialize(obj):
        if isinstance(obj, set):
            return sorted(obj)
        if isinstance(obj, dict):
            return {k: _serialize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_serialize(x) for x in obj]
        return obj
    sql = """INSERT INTO session_graph
        (task_run_id, evaluation_id, graph_json)
        VALUES (%s,%s,%s)"""
    return _upsert(cur, sql, (
        task_run_id,
        evaluation_id,
        json.dumps(_serialize(graph), ensure_ascii=False, default=str),
    ), "IDEMPOTENT_REPLAY")


def insert_task_pair(cur, pair) -> str:
    sql = """INSERT INTO task_pair
        (task_pair_id, evaluation_id, task_id, benchmark_item_id, nogk_task_run_id, kg_task_run_id,
         pair_experiment_valid, pair_fingerprint_status, pair_match_status, outcome_valid, pair_transition)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        pair.task_pair_id, pair.evaluation_id, pair.task_id, pair.benchmark_item_id,
        pair.nogk_task_run_id, pair.kg_task_run_id, pair.pair_experiment_valid,
        pair.pair_fingerprint_status, pair.pair_match_status.value, pair.outcome_valid,
        pair.pair_transition.value,
    ), "IDEMPOTENT_REPLAY")


def insert_pair_derived_fact(cur, f: PairDerivedFact) -> str:
    sql = """INSERT INTO pair_derived_fact
        (derived_fact_id, evaluation_id, task_pair_id, derived_fact_type, value_numeric, value_string,
         status, reason_code, resolver_version, evidence_json, source_fact_refs_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        f.derived_fact_id, f.evaluation_id, f.task_pair_id, f.derived_fact_type,
        f.value_numeric, f.value_string, f.status, f.reason_code, f.resolver_version,
        _evid(f.evidence), json.dumps(f.source_fact_refs, ensure_ascii=False) if f.source_fact_refs else None,
    ), "IDEMPOTENT_REPLAY")


def insert_metric_result(cur, cr_id: str, pop_snap_id: str, m: MetricResult, eval_id: str) -> str:
    sql = """INSERT INTO metric_result
        (metric_result_id, evaluation_id, calculation_run_id, population_snapshot_id, metric_id,
         metric_name, metric_version, estimate, unit, n, n_population, median, q1, q3, iqr,
         reason_code, calculation_status, calculation_method, details_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        f"mr-{cr_id}-{m.metric_id}", eval_id, cr_id, pop_snap_id, m.metric_id,
        m.metric_id, "1.0", _clean(m.estimate), m.unit, m.n, m.n_population, _clean(m.median),
        _clean(m.q1), _clean(m.q3), _clean(m.iqr),
        m.reason_code, m.calculation_status, json.dumps(m.method, ensure_ascii=False), None,
    ), "IDEMPOTENT_REPLAY")


def insert_statistical_result(cur, cr_id: str, pop_snap_id: str, s: StatisticalResult, eval_id: str) -> str:
    sql = """INSERT INTO statistical_result
        (statistical_result_id, evaluation_id, calculation_run_id, population_snapshot_id, metric_id,
         metric_version, test_name, statistic, p_value, alternative, effect_size, effect_type,
         ci_lower, ci_upper, testing_tier, scope_type, joint_analysis_id, related_metric_ids,
         method_version, status, reason_code, details_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    return _upsert(cur, sql, (
        f"sr-{cr_id}-{s.metric_id or s.joint_analysis_id}-{s.test_name}", eval_id, cr_id, pop_snap_id,
        s.metric_id, "1.0", s.test_name, _clean(s.statistic), _clean(s.p_value), None, None, None,
        _clean(s.ci_lower), _clean(s.ci_upper), s.testing_tier, s.scope_type, s.joint_analysis_id,
        json.dumps(s.related_metric_ids, ensure_ascii=False) if s.related_metric_ids else None,
        "1.0", s.status, s.reason_code, json.dumps(s.details, ensure_ascii=False) if s.details else None,
    ), "IDEMPOTENT_REPLAY")
