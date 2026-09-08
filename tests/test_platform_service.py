"""平台 trace 发现测试。"""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from athena_eval_engine.application import platform_service as ps


def _write_cvuln_trace(path, case_id: str, task_id: str):
    path.write_text("\n".join([
        json.dumps({"type": "session", "id": "session-1"}),
        json.dumps({"type": "message", "message": {"role": "user", "content": [{
            "type": "text",
            "text": f"漏洞 ID: {case_id}\n当前历史记忆目录/data/files/p/tasks/{task_id}/tools/x/seeddir/historical-vulns",
        }]}}),
    ]), encoding="utf-8")


def test_find_traces_filters_cvuln_files_by_case_source_task(tmp_path, monkeypatch):
    project_id = "project-1"
    task_a = "aaaaaaaaaaaaaaaaaaaaaaaa"
    task_b = "bbbbbbbbbbbbbbbbbbbbbbbb"
    cvuln_dir = tmp_path / project_id / "tasks" / "c_vuln_verify"
    cvuln_dir.mkdir(parents=True)
    trace_a = cvuln_dir / "trace-a.jsonl"
    trace_b = cvuln_dir / "trace-b.jsonl"
    _write_cvuln_trace(trace_a, "case-a", task_a)
    _write_cvuln_trace(trace_b, "case-b", task_b)

    monkeypatch.setattr(ps, "DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(ps, "_K8S_MODE", True)
    monkeypatch.setattr(ps, "_get_vuln_case_index", lambda _project: {
        "case-a": {"task_id": task_a, "title": "A"},
        "case-b": {"task_id": task_b, "title": "B"},
    })

    traces = ps.find_traces(project_id, task_a)

    assert len(traces) == 1
    assert traces[0]["path"] == str(cvuln_dir)
    assert traces[0]["kind"] == "cvuln_verify_session"
    assert traces[0]["trace_kind"] == "cvuln_verify"
    assert traces[0]["file_count"] == 1
    assert traces[0]["source_task_id"] == task_a


def test_cvuln_prompt_task_id_is_fallback_when_case_api_unavailable(tmp_path, monkeypatch):
    project_id = "project-1"
    task_id = "aaaaaaaaaaaaaaaaaaaaaaaa"
    cvuln_dir = tmp_path / project_id / "tasks" / "c_vuln_verify"
    cvuln_dir.mkdir(parents=True)
    trace = cvuln_dir / "trace.jsonl"
    _write_cvuln_trace(trace, "case-a", task_id)

    monkeypatch.setattr(ps, "DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(ps, "_K8S_MODE", True)
    monkeypatch.setattr(ps, "_get_vuln_case_index", lambda _project: None)

    traces = ps.find_traces(project_id, task_id)

    assert [t["path"] for t in traces] == [str(cvuln_dir)]
    assert traces[0]["file_count"] == 1


def test_vuln_case_index_uses_source_task_and_caches_paginated_results(monkeypatch):
    project_id = "project-1"
    calls = []

    def fake_get(url):
        page = int(parse_qs(urlparse(url).query)["page"][0])
        calls.append(page)
        if page == 1:
            return {"total": 2, "items": [{"id": "case-a", "source_task": {"task_id": "task-a"}}]}
        return {"total": 2, "items": [{"id": "case-b", "metadata": {"source": {"task_id": "task-b"}}}]}

    ps._vuln_case_cache.clear()
    monkeypatch.setattr(ps, "_get", fake_get)

    index = ps._get_vuln_case_index(project_id)

    assert index == {"case-a": {"task_id": "task-a", "title": None},
                     "case-b": {"task_id": "task-b", "title": None}}
    assert calls == [1, 2]
    assert ps._get_vuln_case_index(project_id) == index
    assert calls == [1, 2]


def test_vuln_case_index_stops_when_api_repeats_a_page(monkeypatch):
    calls = []

    def fake_get(_url):
        calls.append(1)
        return {"total": 999, "items": [{"id": "case-a", "source_task": {"task_id": "task-a"}}]}

    ps._vuln_case_cache.clear()
    monkeypatch.setattr(ps, "_get", fake_get)

    index = ps._get_vuln_case_index("project-repeat")

    assert index == {"case-a": {"task_id": "task-a", "title": None}}
    assert len(calls) == 2
