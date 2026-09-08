"""CVulnVerify parser 的任务级文件聚合测试。"""
from __future__ import annotations

import json

from athena_eval_engine.workers.cvuln_verify_trace_parser import CVulnVerifyTraceParser


def _write_trace(path, task_id: str, input_tokens: int):
    path.write_text("\n".join([
        json.dumps({"type": "message", "message": {"role": "user", "content": [{
            "type": "text", "text": f"历史记忆目录/data/files/p/tasks/{task_id}/tools/x/historical-vulns",
        }]}}),
        json.dumps({"type": "message", "message": {"role": "assistant", "content": [], "usage": {
            "input_tokens": input_tokens, "output_tokens": 2,
        }}}),
    ]), encoding="utf-8")


def test_directory_trace_is_filtered_to_selected_source_task(tmp_path):
    task_a = "aaaaaaaaaaaaaaaaaaaaaaaa"
    task_b = "bbbbbbbbbbbbbbbbbbbbbbbb"
    _write_trace(tmp_path / "case-a.jsonl", task_a, 10)
    _write_trace(tmp_path / "case-b.jsonl", task_b, 20)
    source = {"source_uri": str(tmp_path), "source_task_id": task_a}

    parser = CVulnVerifyTraceParser()
    events = list(parser.parse(source))
    session = parser.load_session(source)

    assert {event.session_id for event in events} == {"case-a"}
    assert session["tokens_input"] == 10
    assert session["tokens_output"] == 2
