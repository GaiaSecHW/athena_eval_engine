"""端到端持久化测试 — Trace→Fact→Metric→落 MySQL→Report（§4 / §13.16）。

用 16_recovered_pair fixture（NoKG FAIL + KG SUCCESS → RECOVERED）跑全链，
Fact + PairDerivedFact + Metric + StatisticalResult 落 athena_eval 库，读回校验。
"""
from __future__ import annotations
import json
from pathlib import Path

import pytest

from athena_eval_engine.workers.turing_trace_parser import TuringTraceParser
from athena_eval_engine.workers.resolvers import (
    OutcomeResolverImpl, KnowledgeResolverImpl, ToolActionResolverImpl, ResourceResolverImpl,
)
from athena_eval_engine.workers.pairing import TaskPairMatcherImpl, PairDerivedFactComputer
from athena_eval_engine.domain.metrics import PairView, run_all_metrics
from athena_eval_engine.domain.diagnostics import diagnose
from athena_eval_engine.application.report_assembler import assemble, render_json
from athena_eval_engine.domain.task_run import TaskRun, BenchmarkItem
from athena_eval_engine.domain.enums import Condition, ConditionSource, ExpectedLabel
from athena_eval_engine.infrastructure import database as db
from athena_eval_engine.persistence.repositories import fact_repo

FIXTURE_DIR = Path(__file__).parent / "fixtures"
EVAL_ID = "EVTEST001"


EVAL_CONFIG = {
    "access_rules": {"skill_names": ["wiki-mount", "general-pre", "secocto-context-init"],
                     "path_patterns": ["wiki", "compiled_knowledge"],
                     "command_patterns": [r"source secocto.*wiki", "compiled_knowledge"]},
    "delivery_rules": {"path_patterns": ["/wiki/", "/compiled_knowledge/"],
                       "reject_patterns": [r"^not found$", r"^No wiki mount",
                                           r"^Error: .*permission denied", r"^Permission denied"]},
    "token_schema": {"reasoning_in_output": True, "cache_excluded": True},
}


def _trace_source(name, fname):
    return {"trace_id": f"ts-{name}-{fname}", "source_uri": str(FIXTURE_DIR / name / fname),
            "turing_session_id": "sess-1"}


def _make_task_run(name, cond, side):
    return TaskRun(
        task_run_id=f"tr-{EVAL_ID}-{name}-{side}", evaluation_id=EVAL_ID, task_id="T001",
        trace_id=f"ts-{name}-{side}", condition=cond, condition_source=ConditionSource.MANIFEST,
        trace_valid=True, runtime_valid=True, benchmark_item_id="BI-T001",
    )


@pytest.fixture(scope="module")
def conn():
    db.ensure_schema()
    c = db.connect(autocommit=True)
    yield c
    cur = c.cursor()
    cur.execute("DELETE FROM pair_derived_fact WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM statistical_result WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM metric_result WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation_population_snapshot WHERE calculation_run_id IN (SELECT calculation_run_id FROM evaluation_calculation_run WHERE evaluation_id=%s)", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation_calculation_run WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation_snapshot WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM task_pair WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM outcome_fact WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM knowledge_interaction_fact WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM tool_action_fact WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM resource_fact WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM task_run WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM trace_source WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation WHERE evaluation_id=%s", (EVAL_ID,))
    c.close()


def test_end_to_end_persist(conn):
    """16_recovered_pair 全链落库 + 读回。"""
    from tests import fixture_builder
    fixture_builder.fixture_recovered_pair()  # 确保 fixture 存在
    name = "16_recovered_pair"
    bench = BenchmarkItem("BI-T001", "BS001", "T001", ExpectedLabel.VULNERABLE, "F-T001")
    parser = TuringTraceParser()

    # KG + NoKG TaskRun
    tr_kg = _make_task_run(name, Condition.KG, "kg")
    tr_nogk = _make_task_run(name, Condition.NOGK, "nogk")
    ev_kg = list(parser.parse(_trace_source(name, "kg.db")))
    sess_kg = parser.load_session(_trace_source(name, "kg.db"))
    ev_nogk = list(parser.parse(_trace_source(name, "nogk.db")))
    sess_nogk = parser.load_session(_trace_source(name, "nogk.db"))

    # Resolve Facts
    kg_out = OutcomeResolverImpl().resolve(tr_kg, bench, ev_kg)
    nogk_out = OutcomeResolverImpl().resolve(tr_nogk, bench, ev_nogk)
    kg_know = KnowledgeResolverImpl(EVAL_CONFIG).resolve(tr_kg, ev_kg)
    nogk_know = KnowledgeResolverImpl(EVAL_CONFIG).resolve(tr_nogk, ev_nogk)
    kg_tool = ToolActionResolverImpl(EVAL_CONFIG).resolve(tr_kg, ev_kg, "1.0")
    nogk_tool = ToolActionResolverImpl(EVAL_CONFIG).resolve(tr_nogk, ev_nogk, "1.0")
    kg_res = ResourceResolverImpl(EVAL_CONFIG).resolve(tr_kg, sess_kg)
    nogk_res = ResourceResolverImpl(EVAL_CONFIG).resolve(tr_nogk, sess_nogk)

    # Pairing + PairDerivedFacts
    pairs = TaskPairMatcherImpl().match([tr_kg, tr_nogk],
                                        fingerprints={tr_kg.task_run_id: "fp", tr_nogk.task_run_id: "fp"})
    pair = pairs[0]
    derived = PairDerivedFactComputer().compute(pair, kg_out, nogk_out, kg_tool, nogk_tool, kg_res, nogk_res)

    # 落库
    cur = conn.cursor()
    fact_repo.insert_benchmark_set(cur)
    fact_repo.insert_benchmark_item(cur, "BI-T001", "BS001", "T001", "VULNERABLE", "F-T001")
    fact_repo.insert_evaluation(cur, EVAL_ID, "BS001")
    for tr in (tr_kg, tr_nogk):
        fact_repo.insert_trace_source(cur, tr.trace_id, EVAL_ID, str(FIXTURE_DIR / name / ("kg.db" if tr.condition.value=="KG" else "nogk.db")))
        fact_repo.insert_task_run(cur, tr)
    fact_repo.insert_outcome_fact(cur, kg_out)
    fact_repo.insert_outcome_fact(cur, nogk_out)
    fact_repo.insert_knowledge_fact(cur, kg_know)
    fact_repo.insert_knowledge_fact(cur, nogk_know)
    fact_repo.insert_tool_action_fact(cur, kg_tool)
    fact_repo.insert_tool_action_fact(cur, nogk_tool)
    fact_repo.insert_resource_fact(cur, kg_res)
    fact_repo.insert_resource_fact(cur, nogk_res)
    fact_repo.insert_task_pair(cur, pair)
    for d in derived:
        fact_repo.insert_pair_derived_fact(cur, d)

    # 读回校验（复合 FK 保证 evaluation_id 一致）
    cur.execute("SELECT pair_transition, outcome_valid, pair_match_status FROM task_pair WHERE evaluation_id=%s",
                (EVAL_ID,))
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "RECOVERED", f"transition={row[0]}"
    assert row[1] == 1, "outcome_valid 应为 TRUE"
    assert row[2] == "VALID_PAIR"

    cur.execute("SELECT COUNT(*) FROM pair_derived_fact WHERE evaluation_id=%s", (EVAL_ID,))
    assert cur.fetchone()[0] == 5  # PAIR_TRANSITION + JSD + DELTA_TOKEN + DELTA_STEPS + DELTA_TIME

    # Idempotency：重写同 Fact → IDEMPOTENT_REPLAY（不报错）
    r = fact_repo.insert_outcome_fact(cur, kg_out)
    assert r == "IDEMPOTENT_REPLAY"

    # Metric + StatisticalResult 落库（用 single pair 构造 PairView）
    pv = PairView(
        kg_success=(kg_out.outcome.value == "SUCCESS"),
        nogk_success=(nogk_out.outcome.value == "SUCCESS"),
        gt="VULNERABLE",
        kg_outcome=kg_out.outcome.value, nogk_outcome=nogk_out.outcome.value,
        jsd=next(d.value_numeric for d in derived if d.derived_fact_type == "JSD"),
        delta_token=next(d.value_numeric for d in derived if d.derived_fact_type == "DELTA_TOKEN"),
        delta_steps=next(d.value_numeric for d in derived if d.derived_fact_type == "DELTA_STEPS"),
        delta_time=next(d.value_numeric for d in derived if d.derived_fact_type == "DELTA_TIME"),
    )
    # 复制为 20 对满足 bootstrap 最小样本（合成同构样本，仅为打通落库链）
    pairs_view = [pv] * 20
    out = run_all_metrics(pairs_view, kg_access=1, kg_valid=1, kg_delivery=0, access=1, seed=5)
    cr_id = "CR001"; pop_id = "PS001"
    cur.execute("INSERT IGNORE INTO evaluation_snapshot (snapshot_id, evaluation_id, parser_version, "
                "resolver_version, metric_profile_version, statistical_profile, canonical_action_schema, "
                "knowledge_rule_version, token_schema_version, experiment_fingerprint_json, code_hashes_json, config_json) "
                "VALUES (%s,%s,'1.0','1.0','1.0','1.0','1.0','1.0','1.0','{}','{}','{}')", (f"snap-{EVAL_ID}", EVAL_ID))
    cur.execute("INSERT INTO evaluation_calculation_run (calculation_run_id, evaluation_id, run_type, config_snapshot_id) "
                "VALUES (%s,%s,'INITIAL',%s)", (cr_id, EVAL_ID, f"snap-{EVAL_ID}"))
    cur.execute("INSERT INTO evaluation_population_snapshot (population_snapshot_id, calculation_run_id, "
                "population_type, population_entity_type, task_count, estimator_version, population_ids_uri, population_ids_hash) "
                "VALUES (%s,%s,'primary_analysis','TASK_PAIR',%s,'1.0','uri','hash')", (pop_id, cr_id, 20))
    for m in out["metric_results"]:
        fact_repo.insert_metric_result(cur, cr_id, pop_id, m, EVAL_ID)
    for s in out["statistical_results"]:
        fact_repo.insert_statistical_result(cur, cr_id, pop_id, s, EVAL_ID)

    cur.execute("SELECT COUNT(*) FROM metric_result WHERE evaluation_id=%s", (EVAL_ID,))
    assert cur.fetchone()[0] == 10
    cur.execute("SELECT COUNT(*) FROM statistical_result WHERE evaluation_id=%s", (EVAL_ID,))
    assert cur.fetchone()[0] >= 10  # 10 单指标 + 1 JOINT
    cur.execute("SELECT scope_type, joint_analysis_id FROM statistical_result WHERE scope_type='JOINT' AND evaluation_id=%s", (EVAL_ID,))
    jrow = cur.fetchone()
    assert jrow is not None and jrow[1] == "J001"

    # Report
    hits = diagnose(out["metric_results"], out["statistical_results"])
    report = assemble(EVAL_ID, out["metric_results"], out["statistical_results"], hits)
    rj = render_json(report)
    rdict = json.loads(rj)
    assert "p0" in rdict and "M1" in rdict["p0"]
    assert rdict["p0"]["m2_m3_mcnemar"]["joint_analysis_id"] == "J001"
    assert "不输出总分" in rdict["notes"]
    assert rdict["narrative"]["evidence_refs"][0]["source"] in ("metric_result", "statistical_result")
