"""vuln_center_client 单元测试 — 不依赖网络，只测纯函数。"""
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from athena_eval_engine.infrastructure.vuln_center_client import (
    _normalize_case_description,
    _case_to_benchmark,
    _join_present,
    _render_description_value,
)


def _sample_case(**overrides) -> dict:
    """构造一个典型的漏洞中心 case dict。"""
    base = {
        "id": "case-001",
        "title": "SQL Injection in login form",
        "summary": "User input is concatenated directly into SQL query.",
        "human_confirmation": {
            "result": "vulnerable",
            "summary": "Confirmed via black-box replay",
            "operator": "analyst1",
            "confirmed_at": "2026-08-01T10:00:00Z",
        },
        "latest_human_decision": {
            "result": "vulnerable",
            "reason": "Reproduced with POC payload",
            "created_at": "2026-08-01T12:00:00Z",
        },
        "subject": {"type": "web_app", "name": "login_service", "version": "1.2"},
        "raw_report_summary": {"scanner": "sast", "severity": "high"},
        "display_summary": "POC: ' OR 1=1 --",
        "has_static_poc": True,
        "has_dynamic_poc": False,
        "decision_status": "vulnerable",
        "source_task": {"task_id": "task-99", "finding_id": "finding-ABC"},
    }
    base.update(overrides)
    return base


# ── _case_to_benchmark ─────────────────────────────────────────────────────


def test_case_to_benchmark_vulnerable():
    c = _case_to_benchmark(_sample_case(), "VULNERABLE")
    assert c["case_id"] == "case-001"
    assert c["expected_label"] == "VULNERABLE"
    assert c["vulnerability_type"] == "SQL Injection in login form"
    assert c["target_finding_id"] == "finding-ABC"
    assert "SQL Injection" in c["description"]


def test_case_to_benchmark_not_vulnerable():
    c = _case_to_benchmark(_sample_case(), "NOT_VULNERABLE")
    assert c["expected_label"] == "NOT_VULNERABLE"


def test_case_to_benchmark_missing_fields():
    c = _case_to_benchmark({"id": "bare"}, "VULNERABLE")
    assert c["case_id"] == "bare"
    assert c["vulnerability_type"] == ""
    assert c["target_finding_id"] is None
    assert c["expected_label"] == "VULNERABLE"


# ── _normalize_case_description ────────────────────────────────────────────


def test_normalize_six_sections_present():
    desc = _normalize_case_description(_sample_case())
    for heading in (
        "## Vulnerability title",
        "## Human-confirmed black-box vulnerability",
        "## Upstream summary",
        "## Human confirmation notes",
        "## Report claims requiring code verification",
        "## POC or trigger-input evidence",
    ):
        assert heading in desc, f"missing section: {heading}"


def test_normalize_uses_title():
    desc = _normalize_case_description(_sample_case())
    assert "SQL Injection in login form" in desc


def test_normalize_includes_human_notes():
    desc = _normalize_case_description(_sample_case())
    assert "Confirmed via black-box replay" in desc
    assert "Reproduced with POC payload" in desc


def test_normalize_includes_report_claims_as_json():
    desc = _normalize_case_description(_sample_case())
    assert "scanner" in desc and "sast" in desc


def test_normalize_includes_poc_detail():
    desc = _normalize_case_description(_sample_case())
    assert "POC is evidence only and must not be executed" in desc
    assert "Static POC material is referenced." in desc
    assert "Dynamic POC material is referenced." not in desc


def test_normalize_handles_missing_fields():
    """所有可选字段缺失时不应抛异常，用 (not provided upstream) 兜底。"""
    c = {"id": "bare-case", "title": None, "summary": None}
    desc = _normalize_case_description(c)
    assert "## Vulnerability title" in desc
    assert "bare-case" in desc  # title 为 None → 用 id
    assert "(not provided upstream)" in desc


# ── _render_description_value / _join_present ──────────────────────────────


def test_render_none():
    assert _render_description_value(None) == "(not provided upstream)"


def test_render_empty_string():
    assert _render_description_value("") == "(not provided upstream)"


def test_render_dict_sorted_json():
    import json
    out = _render_description_value({"b": 2, "a": 1})
    assert json.loads(out) == {"a": 1, "b": 2}  # sort_keys=True


def test_join_present_skips_empty():
    assert _join_present("x", None, "", "y") == "x\ny"


def test_join_present_all_empty():
    assert _join_present(None, "", None) is None
