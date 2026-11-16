"""Mock 分析器：优先使用集群真实样本 fixture，否则基于真实 events 确定性生成。"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


CAUSE_TO_LEVEL = {
    "A": "L2", "B": "L3", "C": "L4", "D": "L5", "E": "L6",
    "F": "L7", "G": "L7", "H": "L8", "I": "L8", "J": "L8", "K": "L8",
}
CAUSE_TO_RESPONSIBILITY = {
    "A": "agent", "B": "agent", "C": "knowledge", "D": "knowledge",
    "E": "agent", "F": "agent", "G": "knowledge", "H": "agent",
    "I": "agent", "J": "agent", "K": "agent",
}
CAUSE_TO_CATEGORY = {
    "A": "reasoning_flaw", "B": "query_inaccurate", "C": "knowledge_gap",
    "D": "link_error", "E": "reasoning_flaw", "F": "reasoning_flaw",
    "G": "knowledge_error", "H": "process_flaw", "I": "reasoning_flaw",
    "J": "reasoning_flaw", "K": "verification_dimension_missing",
}


def load_fixture(fixture_dir: str | None = None) -> dict:
    """加载 ``fixtures/cluster_sample.json``；不存在时返回空 fixture。"""
    base = Path(fixture_dir or os.environ.get(
        "MOCK_FIXTURE_DIR",
        str(Path(__file__).resolve().parent / "fixtures"),
    ))
    path = base / "cluster_sample.json"
    if not path.exists():
        return {"cases": {}}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {"cases": {}}


def analyze_request(payload: dict, fixture: dict | None = None) -> tuple[dict, dict]:
    """返回 (公开结果, detail artifact)。"""
    case = payload.get("case") or {}
    case_id = str(case.get("case_id", ""))
    chains = payload.get("chains") or {}
    fixture_result = _match_fixture(case_id, chains, fixture or {})
    if fixture_result is not None:
        return _from_fixture(case, chains, fixture_result)
    return _deterministic(case, chains, payload.get("sessions") or [])


def _match_fixture(case_id: str, chains: dict, fixture: dict) -> dict | None:
    item = (fixture.get("cases") or {}).get(case_id)
    if not isinstance(item, dict):
        return None
    result = item.get("result") or item
    if not isinstance(result, dict):
        return None
    for chain_type in ("mining", "verification"):
        expected = list(
            ((result.get(chain_type) or {}).get("session_chain") or []))
        requested = list(
            ((chains.get(chain_type) or {}).get("session_chain") or []))
        if expected != requested:
            return None
    return item


def _from_fixture(case: dict, chains: dict, item: dict) -> tuple[dict, dict]:
    result = json.loads(json.dumps(item.get("result") or item, ensure_ascii=False))
    detail = json.loads(json.dumps(item.get("detail") or {}, ensure_ascii=False))
    result.setdefault("schema_version", "1.0")
    result["case_id"] = str(case.get("case_id", ""))
    result["outcome"] = str(case.get("outcome", ""))
    result.setdefault("provenance", {
        "analyzer_version": "mock-cluster-sample-1.0",
        "prompt_version": "cluster-sample",
        "model": "fixture",
    })
    for chain_type in ("mining", "verification"):
        chain = result.setdefault(chain_type, {})
        chain["agent_type"] = str(
            ((chains.get(chain_type) or {}).get("agent_type") or
             chain.get("agent_type") or ""))
        chain["session_chain"] = list(
            ((chains.get(chain_type) or {}).get("session_chain") or []))
        _normalize_chain(chain, chain_type)
    return result, detail


def _normalize_chain(chain: dict, chain_type: str) -> None:
    hypotheses = chain.get("hypotheses") or []
    if not isinstance(hypotheses, list):
        hypotheses = []
    for idx, hyp in enumerate(hypotheses):
        if not isinstance(hyp, dict):
            continue
        hyp.setdefault("hypothesis_id", f"{chain_type.upper()}-H{idx + 1}")
    chain["hypotheses"] = hypotheses
    if hypotheses:
        chain.setdefault("primary_hypothesis_id", hypotheses[0]["hypothesis_id"])
        chain["primary_cause"] = hypotheses[0].get("cause_code", "")
        chain["primary_hypothesis"] = hypotheses[0].get("hypothesis", "")
    else:
        chain.setdefault("primary_hypothesis_id", "")
        chain.setdefault("primary_cause", "")
        chain.setdefault("primary_hypothesis", "")

    bps = chain.get("l0_l7_breakpoints") or []
    if not isinstance(bps, list):
        bps = []
    for idx, bp in enumerate(bps):
        if isinstance(bp, dict):
            bp.setdefault("ref", bp.get("_bp_ref") or
                          f"{chain_type.upper()}-BP-{idx + 1}")
    chain["l0_l7_breakpoints"] = bps
    if "insufficient_evidence" not in chain:
        chain["insufficient_evidence"] = bool(
            chain.get("root_cause", {}).get("insufficient_evidence", False))
    chain.setdefault("status", (
        "skipped" if not chain.get("session_chain") else
        "insufficient_evidence" if chain["insufficient_evidence"] else "ok"
    ))
    chain.setdefault("root_cause", {
        "category": "no_session" if not chain.get("session_chain") else "unknown",
        "description": "无 session" if not chain.get("session_chain") else "",
    })
    chain.setdefault("fix_suggestion", [])
    chain.setdefault("label_quality", {})


def _deterministic(
    case: dict, chains: dict, sessions: list[dict],
) -> tuple[dict, dict]:
    session_map = {
        str(s.get("session_id", "")): s
        for s in sessions if isinstance(s, dict)
    }
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "case_id": str(case.get("case_id", "")),
        "outcome": str(case.get("outcome", "")),
        "provenance": {
            "analyzer_version": "mock-remote-engine-1.0",
            "prompt_version": "deterministic-mock-v1",
            "model": "mock",
        },
    }
    detail_chain: dict[str, dict] = {}
    for chain_type in ("mining", "verification"):
        spec = chains.get(chain_type) or {}
        chain = list(spec.get("session_chain") or [])
        agent_type = str(spec.get("agent_type", "") or "")
        result[chain_type], detail_chain[chain_type] = _analyze_chain(
            chain_type, chain, agent_type, session_map,
        )
    detail = {
        "schema_version": "1.0",
        "case_id": str(case.get("case_id", "")),
        "compressed_summaries": {
            k: v.get("compressed_summaries", [])
            for k, v in detail_chain.items()
        },
        "merge_summary": {
            k: v.get("merge_summary", "") for k, v in detail_chain.items()
        },
        "knowledge_memory_summary": {
            k: v.get("knowledge_memory_summary", {})
            for k, v in detail_chain.items()
        },
        "l4_independent_verification": {
            k: v.get("l4_independent_verification", {})
            for k, v in detail_chain.items()
        },
        "audit": {k: v.get("audit", []) for k, v in detail_chain.items()},
    }
    return result, detail


def _analyze_chain(
    chain_type: str, chain: list[str], agent_type: str,
    session_map: dict[str, dict],
) -> tuple[dict, dict]:
    if not chain:
        return (
            {
                "status": "skipped",
                "root_cause": {"category": "no_session",
                               "description": f"无 {chain_type} session"},
                "hypotheses": [],
                "primary_hypothesis_id": "",
                "l0_l7_breakpoints": [],
                "fix_suggestion": [],
                "label_quality": {},
                "insufficient_evidence": False,
                "session_chain": [],
                "agent_type": agent_type,
            },
            {
                "compressed_summaries": [], "merge_summary": "",
                "knowledge_memory_summary": {},
                "l4_independent_verification": {}, "audit": [],
            },
        )

    summaries: list[dict] = []
    all_events: list[dict] = []
    for step, sid in enumerate(chain, 1):
        session = session_map.get(sid) or {}
        events = [e for e in (session.get("events") or []) if isinstance(e, dict)]
        all_events.extend(events)
        cards = _evidence_cards(sid, events)
        summaries.append({
            "session_id": sid,
            "step": step,
            "summary": f"session {sid} 共 {len(events)} 个事件（mock 基于真实事件结构）",
            "key_findings": [
                f"工具调用 {sum(1 for e in events if e.get('event_type') == 'TOOL_CALL')} 次",
                f"知识/记忆交互标记 {sum(1 for e in events if e.get('is_kg_interaction') or e.get('is_memory_interaction'))} 次",
            ],
            "evidence_cards": cards,
            "retention_check": [
                {"item": "知识/记忆访问", "status": "preserved",
                 "evidence_ids": [c["evidence_id"] for c in cards[:2]]},
            ],
            "insufficient_evidence": False,
            "insufficient_reason": "",
            "l0_l7": [],
            "truncated_evidence": 0,
        })

    kg_events = [
        e for e in all_events
        if e.get("is_kg_interaction") or e.get("is_memory_interaction")
    ]
    kg_results = [
        e for e in kg_events
        if e.get("event_type") == "TOOL_RESULT" and
        (e.get("output_json") not in (None, "", [], {}))
    ]
    if not kg_events:
        cause = "A"
        description = "session 中没有知识/记忆访问，未发起检索"
        action = "在漏洞结论前查询 Athena/记忆中的同类漏洞判定方法"
    elif not kg_results:
        cause = "D"
        description = "发起了知识/记忆访问，但未成功取回内容（工具失败或结果为空）"
        action = "检查 athena/mem 工具调用链路、超时与返回解析"
    else:
        cause = "E"
        description = "知识/记忆内容已取回，但推理未引用返回内容"
        action = "要求 agent 在结论中显式引用知识返回的关键事实"
    level = CAUSE_TO_LEVEL[cause]
    evidence_ids = [
        c["evidence_id"] for s in summaries for c in s["evidence_cards"]
    ][:2]
    primary_sid = chain[-1]
    bp_ref = f"{chain_type.upper()}-BP-1"
    bp = {
        "ref": bp_ref,
        "session_id": primary_sid,
        "l0_source": "知识库" if any(
            e.get("is_kg_interaction") for e in kg_events) else "记忆" if kg_events else "空",
        "l1_need": True,
        "l2_initiated": bool(kg_events),
        "l3_accurate": True if kg_events else None,
        "l4_exists": bool(kg_results) if kg_events else None,
        "l5_retrieved": bool(kg_results) if kg_events else None,
        "l6_used": False if cause == "E" else None,
        "l7_influenced": None,
        "breakpoint": level,
        "cause_code": cause,
        "confidence": 0.82,
        "evidence_refs": evidence_ids,
        "query_content": _first_query(kg_events) or "mock：未发现知识/记忆查询",
        "returned_content": _first_return(kg_results),
        "fix_suggestion": action,
    }
    for summary in summaries:
        if summary["session_id"] == primary_sid:
            summary["l0_l7"] = [bp]
    fix = {
        "target": "agent_prompt",
        "agent_type": agent_type or ("turing" if chain_type == "mining"
                                     else "webvuln_verify"),
        "knowledge_source": "",
        "location": f"{chain_type} 链 {'知识访问' if cause == 'A' else '知识引用'}流程",
        "action": action,
        "expected_effect": "减少同类误报/漏报，提升根因定位可复核性",
    }
    hypothesis = {
        "hypothesis_id": f"{chain_type.upper()}-H1",
        "hypothesis": description,
        "probability": 0.82,
        "confidence": 0.82,
        "responsibility": CAUSE_TO_RESPONSIBILITY[cause],
        "cause_code": cause,
        "evidence_refs": evidence_ids,
        "counter_evidence": "mock 结果用于链路联调，不替代真实 LLM 判定。",
        "evidence": "；".join(
            f"{c['evidence_id']}: {str(c.get('quote', ''))[:120]}"
            for s in summaries for c in s["evidence_cards"][:1]
        ),
        "session_id": primary_sid,
        "supporting_breakpoints": [bp_ref],
        "agent_can_resolve": True,
        "blocked_by": "",
        "needed_external_data": [],
        "fix_suggestion": fix,
    }
    result = {
        "status": "ok",
        "root_cause": {
            "category": CAUSE_TO_CATEGORY[cause],
            "description": description,
            "human_confirmation_reason": "",
            "insufficient_evidence": False,
        },
        "hypotheses": [hypothesis],
        "primary_hypothesis_id": hypothesis["hypothesis_id"],
        "primary_cause": cause,
        "primary_hypothesis": description,
        "l0_l7_breakpoints": [bp],
        "fix_suggestion": [fix],
        "label_quality": {
            "precision": "precise",
            "needs_label_confirmation": False,
            "reason": "mock：基于真实事件中的工具调用与知识标记生成。",
            "follow_up_questions": [],
        },
        "insufficient_evidence": False,
        "session_chain": chain,
        "agent_type": agent_type,
    }
    detail = {
        "compressed_summaries": summaries,
        "merge_summary": f"{chain_type} 链共 {len(chain)} 个 session；{description}",
        "knowledge_memory_summary": {
            "access_count": len(kg_events),
            "accesses": [{
                "source": "knowledge_base" if any(
                    e.get("is_kg_interaction") for e in kg_events) else "memory",
                "query": _first_query(kg_events),
                "returned": _first_return(kg_results),
                "used_in_reasoning": cause != "E",
                "effect": "negative" if cause == "E" else "none",
                "session_id": primary_sid,
            }] if kg_events else [],
            "overall_effect": "negative" if cause == "E" else "none",
            "impact_on_conclusion": description,
        },
        "l4_independent_verification": {
            "checked": True,
            "knowledge_found": bool(kg_results),
            "note": "mock 不执行外部 Athena 检索，仅记录链路字段。",
        },
        "audit": [
            {"rule": "每个线索均有 evidence_refs", "pass": True,
             "note": "mock 从真实事件生成证据卡。"},
            {"rule": "证据不足时不给结论", "pass": True, "note": ""},
        ],
    }
    return result, detail


def _evidence_cards(sid: str, events: list[dict]) -> list[dict]:
    cards: list[dict] = []
    chosen = [
        e for e in events
        if e.get("event_type") in ("TOOL_CALL", "TOOL_RESULT", "TEXT")
    ]
    for ev in chosen[:6]:
        quote = ev.get("output_json")
        if quote in (None, "", [], {}):
            quote = ev.get("input_json")
        if quote in (None, "", [], {}):
            continue
        if not isinstance(quote, str):
            quote = json.dumps(quote, ensure_ascii=False, default=str)
        cards.append({
            "evidence_id": f"E-{sid.replace('ses_', '')[:8]}-{len(cards) + 1}",
            "event_idx": int(ev.get("event_index", 0)),
            "source": str(ev.get("tool_name") or ev.get("raw_type") or "event"),
            "quote": quote,
            "fact_type": (
                "knowledge_access"
                if ev.get("is_kg_interaction") or ev.get("is_memory_interaction")
                else "repo_fact"
            ),
        })
    if not cards:
        cards.append({
            "evidence_id": f"E-{sid.replace('ses_', '')[:8]}-1",
            "event_idx": 0,
            "source": "session",
            "quote": f"session {sid} 无可用事件内容",
            "fact_type": "omission",
        })
    return cards


def _first_query(events: list[dict]) -> str:
    for ev in events:
        inp = ev.get("input_json")
        if isinstance(inp, dict):
            for key in ("query", "command", "question", "q"):
                if inp.get(key):
                    return str(inp[key])
    return ""


def _first_return(events: list[dict]) -> str:
    for ev in events:
        out = ev.get("output_json")
        if out not in (None, "", [], {}):
            return out if isinstance(out, str) else json.dumps(
                out, ensure_ascii=False, default=str)
    return ""


def artifact_sha256(detail: dict) -> str:
    return hashlib.sha256(_artifact_bytes(detail)).hexdigest()


def _artifact_bytes(detail: dict) -> bytes:
    return json.dumps(
        detail, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), default=str,
    ).encode("utf-8")
