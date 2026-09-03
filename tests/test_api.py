"""Phase 6 测试 — API + Orchestrator（§10/§11）。

POST /api/v1/evaluations → 创建 + 同步跑 → COMPLETED
GET status / metrics / report
"""
from __future__ import annotations
from pathlib import Path

from fastapi.testclient import TestClient

from athena_eval_engine.api.routes.evaluations import app
from athena_eval_engine.infrastructure import database as db
from athena_eval_engine.persistence.repositories import fact_repo
from tests import fixture_builder

FIXTURE_DIR = Path(__file__).parent / "fixtures"
EVAL_ID = "EVAPI001"


def _cleanup(conn):
    cur = conn.cursor()
    for t in ("pair_derived_fact", "statistical_result", "metric_result"):
        cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation_report WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation_population_snapshot WHERE calculation_run_id IN (SELECT calculation_run_id FROM evaluation_calculation_run WHERE evaluation_id=%s)", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation_calculation_run WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation_snapshot WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM task_pair WHERE evaluation_id=%s", (EVAL_ID,))
    for t in ("outcome_fact", "knowledge_interaction_fact", "tool_action_fact", "resource_fact"):
        cur.execute(f"DELETE FROM {t} WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM task_run WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM trace_source WHERE evaluation_id=%s", (EVAL_ID,))
    cur.execute("DELETE FROM evaluation WHERE evaluation_id=%s", (EVAL_ID,))


def test_api_create_run_status_metrics_report():
    db.ensure_schema()
    fixture_builder.fixture_recovered_pair()
    name = "16_recovered_pair"
    entries = [
        {"task_id": "T001", "condition": "KG", "source_uri": str(FIXTURE_DIR / name / "kg.db"),
         "benchmark_item_id": "BI-T001", "expected_label": "VULNERABLE", "target_finding_id": "F-T001"},
        {"task_id": "T001", "condition": "NOGK", "source_uri": str(FIXTURE_DIR / name / "nogk.db"),
         "benchmark_item_id": "BI-T001", "expected_label": "VULNERABLE", "target_finding_id": "F-T001"},
    ]
    client = TestClient(app)
    # 预清理（上次残留）
    conn = db.connect(autocommit=True)
    _cleanup(conn); conn.close()

    # POST create → 同步跑
    resp = client.post("/api/v1/evaluations", json={
        "evaluation_id": EVAL_ID, "benchmark_set_id": "BS001", "entries": entries})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["metrics"] == 10
    assert body["pair_count"] == 1

    # GET status
    r = client.get(f"/api/v1/evaluations/{EVAL_ID}")
    assert r.status_code == 200
    assert r.json()["status"] == "COMPLETED"

    # GET metrics
    r = client.get(f"/api/v1/evaluations/{EVAL_ID}/metrics")
    assert r.status_code == 200
    mets = r.json()["metrics"]
    assert len(mets) == 10
    ids = {m["metric_id"] for m in mets}
    assert ids == {f"M{i}" for i in range(1, 11)}

    # GET report
    r = client.get(f"/api/v1/evaluations/{EVAL_ID}/report")
    assert r.status_code == 200
    rep = r.json()
    assert rep["status"] == "READY"
    assert "p0" in rep["report"]
    assert rep["report"]["p0"]["m2_m3_mcnemar"]["joint_analysis_id"] == "J001"

    # 清理
    conn = db.connect(autocommit=True)
    _cleanup(conn); conn.close()


def test_state_machine_whitelist():
    from athena_eval_engine.orchestration.state_machine import can_transition, assert_transition
    assert can_transition("CREATED", "VALIDATING")
    assert can_transition("FINALIZING", "COMPLETED")
    assert can_transition("REPORTING", "CANCELLING")
    assert not can_transition("COMPLETED", "VALIDATING")  # 终态不可 resume
    import pytest
    with pytest.raises(ValueError, match="INVALID_TRANSITION"):
        assert_transition("COMPLETED", "PARSING")
