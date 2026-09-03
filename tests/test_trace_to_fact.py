"""Golden Trace Fixtures harness — Trace → Fact → (Pair Derived Fact) 链（§4）。

- 单 trace fixture（01-12）：parser+resolvers → Fact，与 expected.json 对比
- pair fixture（13-16）：KG+NoKG → TaskPairMatcher → PairDerivedFact，与 expected.json 对比
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
from athena_eval_engine.domain.task_run import TaskRun, BenchmarkItem
from athena_eval_engine.domain.enums import (
    Condition, ConditionSource, ExpectedLabel, Outcome,
)
from tests import fixture_builder

FIXTURE_DIR = Path(__file__).parent / "fixtures"

EVAL_CONFIG = {
    "access_rules": {
        "skill_names": ["wiki-mount", "general-pre", "secocto-context-init"],
        "path_patterns": ["wiki", "compiled_knowledge"],
        "command_patterns": [r"source secocto.*wiki", "compiled_knowledge"],
    },
    "delivery_rules": {
        "path_patterns": ["/wiki/", "/compiled_knowledge/"],
        "reject_patterns": [r"^not found$", r"^No wiki mount", r"^Error: .*permission denied", r"^Permission denied"],
    },
    "token_schema": {"reasoning_in_output": True, "cache_excluded": True},
}

SINGLE_TRACE = [f for f in fixture_builder.build_all_fixtures() if f < "13"]
PAIR_TRACE = [f for f in fixture_builder.build_all_fixtures() if f >= "13"]


def _trace_source(name: str, fname: str = "trace.db") -> dict:
    return {"trace_id": f"ts-{name}", "source_uri": str(FIXTURE_DIR / name / fname),
            "turing_session_id": "sess-1"}


def _make_task_run(name: str, condition: Condition) -> TaskRun:
    return TaskRun(
        task_run_id=f"tr-{name}-{condition.value}", evaluation_id="EV001", task_id="T001",
        trace_id=f"ts-{name}-{condition.value}", condition=condition,
        condition_source=ConditionSource.MANIFEST, trace_valid=True, runtime_valid=True,
        benchmark_item_id="BI-T001",
    )


def _benchmark(expected_label: ExpectedLabel = ExpectedLabel.VULNERABLE) -> BenchmarkItem:
    return BenchmarkItem(
        benchmark_item_id="BI-T001", benchmark_set_id="BS001", task_id="T001",
        expected_label=expected_label, target_finding_id="F-T001",
    )


def _fingerprints(name: str, tr_kg: TaskRun, tr_nogk: TaskRun) -> dict | None:
    """#15 注入 KG/NoKG fingerprint 不一致 → MISMATCH。其余 pair 默认 SAME（None → 不校验）。"""
    if "fingerprint_mismatch" in name:
        return {tr_kg.task_run_id: "fp-kg-A", tr_nogk.task_run_id: "fp-nogk-B"}
    return {tr_kg.task_run_id: "fp-same", tr_nogk.task_run_id: "fp-same"}


def _run_resolvers(name, cond, bench, token_schema_override=None):
    parser = TuringTraceParser()
    ts = _trace_source(name)
    events = list(parser.parse(ts)); session = parser.load_session(ts)
    tr = _make_task_run(name, cond)
    cfg = dict(EVAL_CONFIG)
    if token_schema_override:
        cfg["token_schema"] = token_schema_override
    outcome = OutcomeResolverImpl().resolve(tr, bench, events)
    knowledge = KnowledgeResolverImpl(cfg).resolve(tr, events)
    behavior = ToolActionResolverImpl(cfg).resolve(tr, events, schema="1.0")
    resource = ResourceResolverImpl(cfg).resolve(tr, session)
    return tr, outcome, knowledge, behavior, resource


@pytest.mark.parametrize("name", SINGLE_TRACE)
def test_trace_to_fact_single(name):
    """R1：单 trace Trace→Fact，与 expected.json 一致。"""
    expected = json.loads((FIXTURE_DIR / name / "expected.json").read_text(encoding="utf-8"))
    token_schema = expected.get("_token_schema")
    cond = Condition.KG if "nogk" not in name else Condition.NOGK
    # GT 从 confusion 推断：FP/TN → NON_VULNERABLE，TP/FN → VULNERABLE
    conf = expected["outcome"].get("confusion")
    label = ExpectedLabel.NON_VULNERABLE if conf in ("FP", "TN") else ExpectedLabel.VULNERABLE
    tr, outcome, knowledge, behavior, resource = _run_resolvers(name, cond, _benchmark(label), token_schema)

    assert outcome.outcome.value == expected["outcome"]["outcome"], f"{name} outcome"
    assert outcome.prediction.value == expected["outcome"]["prediction"]
    assert outcome.resolver_status == expected["outcome"]["resolver_status"]
    if "confusion" in expected["outcome"]:
        assert outcome.confusion_label.value == expected["outcome"]["confusion"]
    assert (outcome.validation_result or "NA") == expected["outcome"]["validation_result"]

    assert knowledge.access == expected["knowledge"]["access"]
    assert knowledge.delivery == expected["knowledge"]["delivery"]
    assert knowledge.mount_status == expected["knowledge"]["mount_status"]

    b = expected["behavior"]
    assert (behavior.kg_count, behavior.finding_count, behavior.code_count,
            behavior.shell_count, behavior.other_count) == (b["kg_count"], b["finding_count"], b["code_count"], b["shell_count"], b["other_count"])

    r = expected["resource"]
    assert resource.effective_tokens == r["effective_tokens"]
    assert resource.steps == r["steps"]
    assert resource.duration_ms == r["duration_ms"]
    assert resource.time_valid == r["time_valid"]
    if "step_integrity_warning" in r:
        assert resource.step_integrity_warning == r["step_integrity_warning"]


def _run_pair(name):
    """跑 KG+NoKG 两 trace → Facts → Matcher → PairDerivedFacts。返回 (pair, derived_list, kg_out, nogk_out)。"""
    parser = TuringTraceParser()
    bench = _benchmark()
    # KG
    tr_kg = _make_task_run(name + "_kg", Condition.KG)
    ev_kg = list(parser.parse(_trace_source(name, "kg.db"))); sess_kg = parser.load_session(_trace_source(name, "kg.db"))
    # NoKG
    tr_nogk = _make_task_run(name + "_nogk", Condition.NOGK)
    ev_nogk = list(parser.parse(_trace_source(name, "nogk.db"))); sess_nogk = parser.load_session(_trace_source(name, "nogk.db"))

    kg_out = OutcomeResolverImpl().resolve(tr_kg, bench, ev_kg)
    nogk_out = OutcomeResolverImpl().resolve(tr_nogk, bench, ev_nogk)
    kg_tool = ToolActionResolverImpl(EVAL_CONFIG).resolve(tr_kg, ev_kg, "1.0")
    nogk_tool = ToolActionResolverImpl(EVAL_CONFIG).resolve(tr_nogk, ev_nogk, "1.0")
    kg_res = ResourceResolverImpl(EVAL_CONFIG).resolve(tr_kg, sess_kg)
    nogk_res = ResourceResolverImpl(EVAL_CONFIG).resolve(tr_nogk, sess_nogk)

    pairs = TaskPairMatcherImpl().match([tr_kg, tr_nogk],
                                        fingerprints=_fingerprints(name, tr_kg, tr_nogk))
    assert pairs, f"{name}: no pair produced"
    pair = pairs[0]
    derived = PairDerivedFactComputer().compute(pair, kg_out, nogk_out, kg_tool, nogk_tool, kg_res, nogk_res)
    return pair, derived, kg_out, nogk_out


@pytest.mark.parametrize("name", PAIR_TRACE)
def test_pair_derived_facts(name):
    """R1 Phase 2：Pair Derived Facts（JSD / Δ / PairTransition / pair_match_status）。"""
    expected = json.loads((FIXTURE_DIR / name / "expected.json").read_text(encoding="utf-8"))
    pair, derived, kg_out, nogk_out = _run_pair(name)
    pe = expected["pair"]

    assert pair.pair_match_status.value == pe["pair_match_status"], f"{name} match_status"
    if "pair_experiment_valid" in pe:
        assert pair.pair_experiment_valid == pe["pair_experiment_valid"]
    if "pair_fingerprint_status" in pe:
        assert pair.pair_fingerprint_status == pe["pair_fingerprint_status"]

    dmap = {d.derived_fact_type: d for d in derived}
    if "pair_transition" in pe:
        assert dmap["PAIR_TRANSITION"].value_string == pe["pair_transition"]
        assert pair.pair_transition.value == pe["pair_transition"]
        assert pair.outcome_valid == pe["outcome_valid"]
    if "jsd" in pe:
        assert dmap["JSD"].status == pe["jsd_status"]
        assert abs(dmap["JSD"].value_numeric - pe["jsd"]) < 1e-9
    if "jsd_gt_zero" in pe:
        assert dmap["JSD"].status == pe["jsd_status"]
        assert dmap["JSD"].value_numeric > 0
    if "nogk_outcome" in pe:
        assert nogk_out.outcome.value == pe["nogk_outcome"]
        assert kg_out.outcome.value == pe["kg_outcome"]


def test_parser_schema_gate_block():
    """§8.3 — part/session 表缺失 → BLOCK。"""
    import sqlite3, tempfile
    p = Path(tempfile.mkdtemp()) / "bad.db"
    conn = sqlite3.connect(p); conn.execute("CREATE TABLE foo (id INT)"); conn.commit(); conn.close()
    parser = TuringTraceParser()
    with pytest.raises(RuntimeError, match="Schema Gate BLOCK"):
        list(parser.parse({"trace_id": "x", "source_uri": str(p)}))
