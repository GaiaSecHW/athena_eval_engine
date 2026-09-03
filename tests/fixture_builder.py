"""Golden Trace Fixture 构造器 — 合成 Turing SQLite trace.db（§4 16 例的子集先行落地 2 例）。

每个 fixture：trace.db + expected.json（期望 Fact）。test_trace_to_fact 跑 Trace→Fact→Metric 链。
"""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _make_part(pid: int, ptype: str, data: dict, message_id: int = 1) -> dict:
    return {"id": pid, "type": ptype, "data": json.dumps(data), "message_id": message_id}


def _tool(pid: int, tool: str, inp: dict, output: str | None = None, msg: int = 1, ts: int | None = None) -> dict:
    """单个 tool part（opencode 真实格式：data.state 含 input+output，§8.9 一个 tool event）。"""
    d = {"type": "tool", "tool": tool, "callID": f"call_{pid}",
         "state": {"status": "completed", "input": inp}}
    if output is not None:
        d["state"]["output"] = output
    if ts is not None:
        d["time"] = {"start": ts}
    return _make_part(pid, "tool", d, msg)


def _build_session_row(tokens_input=1000, tokens_output=500, tokens_reasoning=200,
                       time_created=1700000000000, time_updated=1700000093000,
                       model="gpt-4", agent="Turing") -> dict:
    return dict(tokens_input=tokens_input, tokens_output=tokens_output,
                tokens_reasoning=tokens_reasoning, cache_read_tokens=10,
                time_created=time_created, time_updated=time_updated,
                model=model, agent=agent)


def write_trace_db(path: Path, session_row: dict, parts: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path); conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS session (
            id INTEGER PRIMARY KEY, tokens_input INT, tokens_output INT,
            tokens_reasoning INT, cache_read_tokens INT,
            time_created INT, time_updated INT, model TEXT, agent TEXT
        );
        CREATE TABLE IF NOT EXISTS message (id INTEGER PRIMARY KEY, session_id INT);
        CREATE TABLE IF NOT EXISTS part (
            id INTEGER PRIMARY KEY, type TEXT, data TEXT, message_id INT
        );
    """)
    conn.execute("DELETE FROM session"); conn.execute("DELETE FROM part")
    conn.execute("INSERT INTO session VALUES (1,?,?,?,?,?,?,?,?)", (
        session_row["tokens_input"], session_row["tokens_output"],
        session_row["tokens_reasoning"], session_row.get("cache_read_tokens", 0),
        session_row["time_created"], session_row["time_updated"],
        session_row.get("model"), session_row.get("agent"),
    ))
    for p in parts:
        conn.execute("INSERT INTO part (id,type,data,message_id) VALUES (?,?,?,?)",
                     (p["id"], p["type"], p["data"], p.get("message_id", 1)))
    conn.commit(); conn.close()


def fixture_normal_tp():
    """Fixture 1：正常 TP — GT=VULNERABLE, update CONFIRMED → POSITIVE → TP→SUCCESS。KG 侧 Access+Delivery=True。"""
    name = "01_normal_tp_kg"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "skill", {"name": "wiki-mount"}, "NFS symlink set"),
        _tool(3, "read", {"file_path": "/wiki/vuln.md"}, "wiki content here"),
        _tool(4, "vuln_hunt_insert_finding", {"finding_id": "F-T001", "title": "x"}),
        _tool(5, "vuln_hunt_update_finding", {"finding_id": "F-T001", "validation_result": "CONFIRMED"}, ts=1700000050000),
        _tool(6, "bash", {"command": "ls"}),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"prediction": "POSITIVE", "outcome": "SUCCESS", "confusion": "TP",
                    "validation_result": "CONFIRMED", "resolver_status": "RESOLVED"},
        "knowledge": {"access": True, "delivery": True, "mount_status": "SUCCESS"},
        "behavior": {"kg_count": 2, "finding_count": 2, "code_count": 0, "shell_count": 1, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_insert_no_update():
    """Fixture 2：insert 无 update → UNDETERMINED（不默认 POSITIVE，§8.6）。"""
    name = "02_insert_no_update_nogk"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "vuln_hunt_insert_finding", {"finding_id": "F-T001"}),
        _tool(3, "bash", {"command": "cat /a"}),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db",
                    _build_session_row(tokens_input=800, tokens_output=300, time_updated=1700000080000), parts)
    expected = {
        "outcome": {"outcome": "UNDETERMINED", "prediction": "UNDETERMINED",
                    "resolver_status": "NO_UPDATE", "validation_result": "NA"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 1, "code_count": 0, "shell_count": 1, "other_count": 0},
        "resource": {"effective_tokens": 1100, "steps": 1, "duration_ms": 80000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_normal_fn():
    """Fixture 3：GT=VULNERABLE, update FALSE_POSITIVE → NEGATIVE → FN → FAIL。"""
    name = "03_normal_fn"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "vuln_hunt_insert_finding", {"finding_id": "F-T001"}),
        _tool(3, "vuln_hunt_update_finding", {"finding_id": "F-T001", "validation_result": "FALSE_POSITIVE"}, ts=1700000050000),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"prediction": "NEGATIVE", "outcome": "FAIL", "confusion": "FN",
                    "validation_result": "FALSE_POSITIVE", "resolver_status": "RESOLVED"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 2, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_normal_fp():
    """Fixture 4：GT=NON_VULNERABLE, CONFIRMED → POSITIVE → FP → FAIL。"""
    name = "04_normal_fp"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "vuln_hunt_update_finding", {"finding_id": "F-T001", "validation_result": "CONFIRMED"}, ts=1700000050000),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"prediction": "POSITIVE", "outcome": "FAIL", "confusion": "FP",
                    "validation_result": "CONFIRMED", "resolver_status": "RESOLVED"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 1, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_normal_tn():
    """Fixture 5：GT=NON_VULNERABLE, FALSE_POSITIVE → NEGATIVE → TN → SUCCESS。"""
    name = "05_normal_tn"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "vuln_hunt_update_finding", {"finding_id": "F-T001", "validation_result": "FALSE_POSITIVE"}, ts=1700000050000),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"prediction": "NEGATIVE", "outcome": "SUCCESS", "confusion": "TN",
                    "validation_result": "FALSE_POSITIVE", "resolver_status": "RESOLVED"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 1, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_multi_finding():
    """Fixture 6：多 finding，只评 target F-T001（其他 F-OTHER 不影响 Outcome）。"""
    name = "06_multi_finding"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "vuln_hunt_insert_finding", {"finding_id": "F-OTHER"}),
        _tool(3, "vuln_hunt_update_finding", {"finding_id": "F-OTHER", "validation_result": "CONFIRMED"}, ts=1700000040000),
        _tool(4, "vuln_hunt_insert_finding", {"finding_id": "F-T001"}),
        _tool(5, "vuln_hunt_update_finding", {"finding_id": "F-T001", "validation_result": "CONFIRMED"}, ts=1700000060000),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"prediction": "POSITIVE", "outcome": "SUCCESS", "confusion": "TP",
                    "validation_result": "CONFIRMED", "resolver_status": "RESOLVED"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 4, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_wiki_mount_failed():
    """Fixture 7：mount FAILED，但 Agent 通过其他路径读知识 → Delivery=True, mount_status=FAILED（§5 异常处理）。"""
    name = "07_wiki_mount_failed"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "skill", {"name": "wiki-mount"}, "No wiki mount"),
        _tool(3, "read", {"file_path": "/compiled_knowledge/vuln.md"}, "compiled content"),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"outcome": "UNDETERMINED", "prediction": "UNDETERMINED",
                    "resolver_status": "NO_FINDING", "validation_result": "NA"},
        "knowledge": {"access": True, "delivery": True, "mount_status": "FAILED"},
        "behavior": {"kg_count": 2, "finding_count": 0, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_wiki_pre_mounted():
    """Fixture 8：无挂载事件（环境预挂载）→ mount_status=UNKNOWN，read 成功 → Delivery=True。"""
    name = "08_wiki_pre_mounted"
    parts = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "read", {"file_path": "/wiki/x.md"}, "wiki content"),
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"outcome": "UNDETERMINED", "prediction": "UNDETERMINED",
                    "resolver_status": "NO_FINDING", "validation_result": "NA"},
        "knowledge": {"access": True, "delivery": True, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 1, "finding_count": 0, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_token_reasoning_excluded():
    """Fixture 9：reasoning_in_output=true → effective = input+output（不重复加 reasoning）。"""
    name = "09_token_reasoning_excluded"
    parts = [_make_part(1, "step-start", {"step_no": 1})]
    sess = _build_session_row(tokens_input=1000, tokens_output=500, tokens_reasoning=200)
    write_trace_db(FIXTURE_DIR / name / "trace.db", sess, parts)
    expected = {
        "outcome": {"outcome": "UNDETERMINED", "prediction": "UNDETERMINED",
                    "resolver_status": "NO_FINDING", "validation_result": "NA"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 0, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_token_reasoning_included():
    """Fixture 10：reasoning_in_output=false → effective = input+output+reasoning。"""
    name = "10_token_reasoning_included"
    parts = [_make_part(1, "step-start", {"step_no": 1})]
    sess = _build_session_row(tokens_input=1000, tokens_output=500, tokens_reasoning=200)
    write_trace_db(FIXTURE_DIR / name / "trace.db", sess, parts)
    expected = {
        "_token_schema": {"reasoning_in_output": False},
        "outcome": {"outcome": "UNDETERMINED", "prediction": "UNDETERMINED",
                    "resolver_status": "NO_FINDING", "validation_result": "NA"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 0, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1700, "steps": 1, "duration_ms": 93000, "time_valid": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_step_mismatch():
    """Fixture 11：step-start=2, step-finish=1 → STEP_INTEGRITY_WARNING（取 step-start）。"""
    name = "11_step_mismatch"
    parts = [
        _make_part(1, "step-start", {"step_no": 1}),
        _make_part(2, "step-start", {"step_no": 2}),
        _make_part(3, "step-finish", {"step_no": 1}),  # mismatch
    ]
    write_trace_db(FIXTURE_DIR / name / "trace.db", _build_session_row(), parts)
    expected = {
        "outcome": {"outcome": "UNDETERMINED", "prediction": "UNDETERMINED",
                    "resolver_status": "NO_FINDING", "validation_result": "NA"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 0, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 2, "duration_ms": 93000, "time_valid": True,
                     "step_integrity_warning": True},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_time_invalid():
    """Fixture 12：time_updated < time_created → duration<0 → time_valid=False, ΔTime=NA。"""
    name = "12_time_invalid"
    parts = [_make_part(1, "step-start", {"step_no": 1})]
    sess = _build_session_row(time_created=1700000093000, time_updated=1700000000000)  # updated < created
    write_trace_db(FIXTURE_DIR / name / "trace.db", sess, parts)
    expected = {
        "outcome": {"outcome": "UNDETERMINED", "prediction": "UNDETERMINED",
                    "resolver_status": "NO_FINDING", "validation_result": "NA"},
        "knowledge": {"access": False, "delivery": False, "mount_status": "UNKNOWN"},
        "behavior": {"kg_count": 0, "finding_count": 0, "code_count": 0, "shell_count": 0, "other_count": 0},
        "resource": {"effective_tokens": 1500, "steps": 1, "duration_ms": -93000, "time_valid": False},
    }
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


# ===== Pair fixtures（KG + NoKG 各一 trace，用于 PairDerivedFact / JSD / pair_transition）=====

def fixture_both_no_tool_call():
    """Fixture 13：KG + NoKG 双方无 tool call → JSD=0（行为完全相同，NO_ACTION padding）。"""
    name = "13_both_no_tool_call"
    parts_kg = [_make_part(1, "step-start", {"step_no": 1})]
    parts_nogk = [_make_part(1, "step-start", {"step_no": 1})]
    write_trace_db(FIXTURE_DIR / name / "kg.db", _build_session_row(), parts_kg)
    write_trace_db(FIXTURE_DIR / name / "nogk.db", _build_session_row(tokens_output=400), parts_nogk)
    expected = {"pair": {"pair_match_status": "VALID_PAIR", "pair_transition": "NA",
                         "outcome_valid": False,  # 无 finding → UNDETERMINED，transition=NA
                         "jsd": 0.0, "jsd_status": "CALCULATED"}}
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_kg_side_no_tool():
    """Fixture 14：KG 无 tool call，NoKG 有 → JSD 可计算（行为差异）。"""
    name = "14_kg_side_no_tool"
    parts_kg = [_make_part(1, "step-start", {"type": "step-start"})]
    parts_nogk = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "bash", {"command": "ls"}),
    ]
    write_trace_db(FIXTURE_DIR / name / "kg.db", _build_session_row(), parts_kg)
    write_trace_db(FIXTURE_DIR / name / "nogk.db", _build_session_row(), parts_nogk)
    expected = {"pair": {"pair_match_status": "VALID_PAIR", "jsd_gt_zero": True, "jsd_status": "CALCULATED"}}
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_pair_fingerprint_mismatch():
    """Fixture 15：KG/NoKG experiment_fingerprint 不一致 → pair_experiment_valid=False（MISMATCH）。"""
    name = "15_pair_fingerprint_mismatch"
    parts_kg = [_make_part(1, "step-start", {"step_no": 1})]
    parts_nogk = [_make_part(1, "step-start", {"step_no": 1})]
    write_trace_db(FIXTURE_DIR / name / "kg.db", _build_session_row(), parts_kg)
    write_trace_db(FIXTURE_DIR / name / "nogk.db", _build_session_row(), parts_nogk)
    expected = {"pair": {"pair_match_status": "VALID_PAIR", "pair_experiment_valid": False,
                         "pair_fingerprint_status": "MISMATCH"}}
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def fixture_recovered_pair():
    """Fixture 16：NoKG FAIL + KG SUCCESS → RECOVERED（C 流，救回）。"""
    name = "16_recovered_pair"
    parts_nogk = [  # NoKG: update FALSE_POSITIVE, GT=VULN → FN→FAIL
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "vuln_hunt_update_finding", {"finding_id": "F-T001", "validation_result": "FALSE_POSITIVE"}, ts=1700000050000),
    ]
    parts_kg = [
        _make_part(1, "step-start", {"type": "step-start"}),
        _tool(2, "vuln_hunt_update_finding", {"finding_id": "F-T001", "validation_result": "CONFIRMED"}, ts=1700000050000),
    ]
    write_trace_db(FIXTURE_DIR / name / "kg.db", _build_session_row(), parts_kg)
    write_trace_db(FIXTURE_DIR / name / "nogk.db", _build_session_row(tokens_output=400), parts_nogk)
    expected = {"pair": {"pair_match_status": "VALID_PAIR", "pair_experiment_valid": True,
                         "outcome_valid": True, "pair_transition": "RECOVERED",
                         "nogk_outcome": "FAIL", "kg_outcome": "SUCCESS"}}
    (FIXTURE_DIR / name / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return name


def build_all_fixtures():
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    return [
        fixture_normal_tp(),
        fixture_insert_no_update(),
        fixture_normal_fn(),
        fixture_normal_fp(),
        fixture_normal_tn(),
        fixture_multi_finding(),
        fixture_wiki_mount_failed(),
        fixture_wiki_pre_mounted(),
        fixture_token_reasoning_excluded(),
        fixture_token_reasoning_included(),
        fixture_step_mismatch(),
        fixture_time_invalid(),
        fixture_both_no_tool_call(),
        fixture_kg_side_no_tool(),
        fixture_pair_fingerprint_mismatch(),
        fixture_recovered_pair(),
    ]


if __name__ == "__main__":
    for n in build_all_fixtures():
        print("built:", n)
