#!/usr/bin/env python3
"""Engine 级 smoke：DataPack → CaseAnalysisPort → causal chain → DTS issue。"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from athena_eval_engine.v2.causal_chain.analyzer import CausalChainAnalyzer
from athena_eval_engine.v2.core.data_pack import DataPack
from athena_eval_engine.v2.core.raw_event import RawEvent
from athena_eval_engine.v2.dts.issue import generate_dts_issues
from athena_eval_engine.v2.infra import pipeline_warnings as pw
from athena_eval_engine.v2.lifecycle.case_analysis_port import (
    CaseAnalysisSettings,
    build_case_analysis_adapter,
)


def _data_packs(request: dict) -> list[DataPack]:
    fields = RawEvent.__dataclass_fields__.keys()
    groups: dict[str, list[RawEvent]] = {}
    for session in request.get("sessions") or []:
        agent = str(session.get("agent_type") or "unknown")
        bucket = groups.setdefault(agent, [])
        for event in session.get("events") or []:
            bucket.append(RawEvent(**{
                k: v for k, v in event.items() if k in fields
            }))
    graph = request.get("session_graph") or {}
    return [
        DataPack(
            task_run_id="smoke", evaluation_id=request.get("evaluation_id", ""),
            task_id="smoke", agent_type=agent, condition="KG",
            events=events, session_graph=graph, session_meta={},
            session_phase_labels={}, session_phase_source={},
        )
        for agent, events in groups.items()
    ]


def _case(request: dict) -> dict:
    case = dict(request.get("case") or {})
    case["mining_sessions"] = list(
        ((request.get("chains") or {}).get("mining") or {}).get(
            "session_chain") or [])
    case["verify_sessions"] = list(
        ((request.get("chains") or {}).get("verification") or {}).get(
            "session_chain") or [])
    return case


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--request-file", required=True)
    ap.add_argument("--base-url", default="")
    ap.add_argument("--mode", default="")
    ap.add_argument("--skip-dts", action="store_true")
    args = ap.parse_args()

    with open(args.request_file, "r", encoding="utf-8") as f:
        request = json.load(f)
    settings = CaseAnalysisSettings.from_config()
    if args.base_url or args.mode:
        settings = CaseAnalysisSettings(
            **{**settings.__dict__,
               **({"base_url": args.base_url} if args.base_url else {}),
               **({"mode": args.mode} if args.mode else {})})
    adapter = build_case_analysis_adapter(settings=settings)
    results = adapter.analyze(
        request.get("evaluation_id", ""), [_case(request)],
        _data_packs(request),
        project_id=str((request.get("context") or {}).get("project_id", "")))
    if len(results) != 1:
        raise RuntimeError(f"期望 1 个 case 结果，实际 {len(results)}")
    result = results[0]

    causal = CausalChainAnalyzer().analyze(
        request.get("evaluation_id", ""), results)
    summary = {
        "ok": True,
        "case_id": result.get("case_id"),
        "mining_cause": (result.get("mining") or {}).get("primary_cause", ""),
        "verification_cause": (
            result.get("verification") or {}).get("primary_cause", ""),
        "mining_chain": (result.get("mining") or {}).get("session_chain", []),
        "verification_chain": (
            result.get("verification") or {}).get("session_chain", []),
        "causal_cases": len(causal.get("per_case_breakpoints", [])),
        "causal_breakpoints": sum(
            len(c.get("breakpoints", []))
            for c in causal.get("per_case_breakpoints", [])),
        "data_quality_warnings": pw.peek(
            request.get("evaluation_id", "")),
    }
    if not args.skip_dts:
        with tempfile.TemporaryDirectory() as tmp:
            issues = generate_dts_issues(
                request.get("evaluation_id", ""), causal, results,
                task_id="smoke", reports_dir=tmp)
        summary["dts_issues"] = len(issues)
        summary["dts_cause_codes"] = [i.get("cause_code", "") for i in issues]
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
