"""Phase R6 测试 — Web 展示（dashboard + 评测列表 + Sankey 渲染）。"""
from __future__ import annotations
from pathlib import Path
from fastapi.testclient import TestClient
from athena_eval_engine.api.routes.evaluations import app
from athena_eval_engine.infrastructure import database as db
from tests import fixture_builder

FIXTURE_DIR = Path(__file__).parent / "fixtures"
EVAL_ID = "EVWEB001"


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


def test_dashboard_and_list_and_report():
    db.ensure_schema()
    fixture_builder.fixture_recovered_pair()
    name = "16_recovered_pair"
    conn = db.connect(autocommit=True); _cleanup(conn); conn.close()

    entries = [
        {"task_id": "T001", "condition": "KG", "source_uri": str(FIXTURE_DIR / name / "kg.db"),
         "benchmark_item_id": "BI-T001", "expected_label": "VULNERABLE", "target_finding_id": "F-T001"},
        {"task_id": "T001", "condition": "NOGK", "source_uri": str(FIXTURE_DIR / name / "nogk.db"),
         "benchmark_item_id": "BI-T001", "expected_label": "VULNERABLE", "target_finding_id": "F-T001"},
    ]
    client = TestClient(app)
    # 跑一次评测
    r = client.post("/api/v1/evaluations", json={"evaluation_id": EVAL_ID, "benchmark_set_id": "BS001", "entries": entries})
    assert r.status_code == 200, r.text

    # 1. dashboard HTML
    r = client.get("/")
    assert r.status_code == 200
    assert "Athena" in r.text and "桑基图" in r.text

    # 2. 评测列表
    r = client.get("/api/v1/evaluations")
    assert r.status_code == 200
    evs = r.json()["evaluations"]
    assert any(e["evaluation_id"] == EVAL_ID for e in evs)
    assert any(e["status"] == "COMPLETED" for e in evs)

    # 3. report 含 Sankey A/B/C/D（C=1 recovered）
    r = client.get(f"/api/v1/evaluations/{EVAL_ID}/report")
    assert r.status_code == 200
    rep = r.json()["report"]
    assert rep["sankey"]
    # recovered: NoKG FAIL → KG SUCCESS = C=1
    c_edge = [e for e in rep["sankey"] if e["nogk"] == "FAIL" and e["kg"] == "SUCCESS"][0]
    assert c_edge["count"] == 1
    assert c_edge["color"] == "#2e7d32"  # 绿
    assert rep["raw_stats"]["net_gain"] == 1  # C-B = 1-0

    # 清理
    conn = db.connect(autocommit=True); _cleanup(conn); conn.close()
