"""AI FindingBenchmarkMatch（§8.6 Stage 1B）— 用 LLM 把 Agent 报的 finding 匹配到 benchmark target。

流程：
1. 从 trace 提取所有 finding（insert_finding 的 title/description/vuln_type + update_finding 的 validation_result）
2. 用 LLM 判定哪个 finding 对应 benchmark 的目标漏洞
3. 返回 matched finding 的 validation_result → Outcome

Agent 的 finding 结构：
  insert_finding input: detection_id, title, description, severity, vuln_type, source, sink, call_chain
  insert_finding output: "Success: Finding F-023 (id=UUID) inserted"
  update_finding input: finding_id(UUID), validation_result(CONFIRMED/FALSE_POSITIVE)
"""
from __future__ import annotations
import json
import re
from ..domain.raw_event import RawEvent
from ..domain.facts import OutcomeFact, Evidence
from ..domain.task_run import TaskRun, BenchmarkItem
from ..domain.enums import Outcome, Prediction, Confusion
from ..infrastructure import llm as llm_mod


def _extract_findings(events: list[RawEvent]) -> list[dict]:
    """从 events 提取 finding 列表，关联 insert→update 的 validation_result。

    支持两种平台格式：
    - Turing（opencode.db）：vuln-hunt_insert_finding + vuln-hunt_update_finding（validation_result）
    - Argo（Claude Code JSONL）：ReportFindings（findings[].outcome）
    """
    findings: dict[str, dict] = {}  # finding_id(UUID) → {title, vuln_type, ...}

    for e in events:
        if not e.is_tool_call():
            continue
        tool = e.tool_name or ""
        inp = e.input_json or {}
        out_str = ""
        if e.output_json is not None:
            out_str = e.output_json if isinstance(e.output_json, str) else json.dumps(e.output_json, ensure_ascii=False)

        # --- Turing: vuln-hunt_insert_finding ---
        if tool in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding"):
            m = re.search(r"id=([a-f0-9-]+)", out_str)
            fid = m.group(1) if m else inp.get("detection_id", "?")
            display = re.search(r"Finding\s+(\S+)", out_str)
            findings[fid] = {
                "finding_id": fid,
                "display_id": display.group(1) if display else "",
                "title": inp.get("title", ""),
                "description": inp.get("description", ""),
                "vuln_type": inp.get("vuln_type", ""),
                "severity": inp.get("severity", ""),
                "source": str(inp.get("source", "")),
                "sink": str(inp.get("sink", "")),
                "validation_result": None,
                "platform": "turing",
                "session_id": e.session_id,
            }

        # --- Argo: ReportFindings ---
        elif tool == "ReportFindings" or tool == "reportfindings":
            for f in (inp.get("findings") or []):
                fid = f.get("id", f.get("finding_id", ""))
                if not fid:
                    # Argo 格式没有 id/finding_id，用 file:line 生成唯一 key
                    fid = f"{f.get('file','')}:{f.get('line','')}"
                outcome = f.get("outcome", "")
                vr = "CONFIRMED" if outcome == "confirmed" else ("FALSE_POSITIVE" if outcome == "no_change_needed" else None)
                findings[fid] = {
                    "finding_id": fid,
                    "display_id": fid,
                    "title": f.get("short_summary", ""),
                    "description": f.get("summary", ""),
                    "vuln_type": f.get("category", ""),
                    "severity": "",
                    "source": f.get("file", ""),
                    "sink": "",
                    "validation_result": vr,
                    "platform": "argo",
                    "failure_scenario": f.get("failure_scenario", ""),
                    "session_id": e.session_id,
                }

        # --- WebVulnVerify: vulnerability_analyze / vulnerability_verify ---
        elif tool in ("vulnerability_analyze", "vulnerability_verify"):
            vid = str(inp.get("vulnerability_id", "?"))
            status = inp.get("status", "")
            vr = "CONFIRMED" if status in ("VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE") else ("FALSE_POSITIVE" if status == "NOT_VULNERABLE" else None)
            findings[vid] = {
                "finding_id": vid,
                "display_id": vid,
                "title": inp.get("category", ""),
                "description": inp.get("result", ""),
                "vuln_type": inp.get("category", ""),
                "severity": "",
                "source": "",
                "sink": "",
                "validation_result": vr,
                "platform": "webvulnverify",
                "confidence": inp.get("confidence"),
                "session_id": e.session_id,
            }

    # 关联 Turing: vuln-hunt_update_finding 的 validation_result
    for e in events:
        if not e.is_tool_call():
            continue
        tool = e.tool_name or ""
        if tool in ("vuln-hunt_update_finding", "vuln_hunt_update_finding"):
            inp = e.input_json or {}
            fid = inp.get("finding_id", "")
            vr = inp.get("validation_result", "")
            if fid in findings and vr in ("CONFIRMED", "FALSE_POSITIVE"):
                findings[fid]["validation_result"] = vr

    return list(findings.values())


def _ev(e: RawEvent, fp=None):
    return Evidence(trace_id=e.trace_id, session_id=e.session_id, message_id=e.message_id,
                    part_id=e.part_id, tool_name=e.tool_name, event_timestamp=e.timestamp_ms, field_path=fp)


def _pre_filter_findings(findings: list[dict], benchmarks: list, top_n: int = 10) -> list[dict]:
    """按关键词相似度排序 findings，取最可能匹配基线的前 top_n 个。

    避免只取前 N 个而错过匹配的 finding（Agent 可能提交 100+ 个 finding）。
    """
    if len(findings) <= top_n:
        return findings

    # 提取基线关键词
    baseline_keywords = set()
    for b in benchmarks:
        md = b.metadata or {}
        for field in ("description", "vulnerability_type"):
            text = md.get(field, "") or ""
            # 提取单词（>=3 字符）
            baseline_keywords.update(w.lower() for w in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', text))

    # 为每个 finding 计算与基线的相似度
    def _score(f):
        text = " ".join(str(f.get(k, "")) for k in ("title", "description", "vuln_type", "source", "sink"))
        finding_words = set(w.lower() for w in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', text))
        return len(finding_words & baseline_keywords)

    # 按相似度降序排序，取前 top_n
    sorted_f = sorted(findings, key=_score, reverse=True)
    return sorted_f[:top_n]


def ai_match_outcome(task_run: TaskRun, benchmarks: list, events: list[RawEvent]) -> OutcomeFact:
    """Stage 1B：AI 匹配 Agent findings → 基线漏洞列表 → outcome。

    基线可能有多个漏洞 case，Agent 也提交多个 finding。
    逐个对比基线 case 与 Agent finding，判断 Agent 是否找到了全部基线漏洞。
    """
    from ..domain.enums import Prediction, Confusion
    from ..workers.resolvers import OutcomeResolverImpl

    # 无 benchmark → UNDETERMINED
    if not benchmarks:
        return OutcomeFact.undetermined(
            task_run.task_run_id, task_run.evaluation_id, task_run.condition,
            task_run.condition_source, reason="NO_GT", benchmark_item_id=None,
        ), []

    # 过滤掉 expected_label=None 的 benchmark
    benchmarks = [b for b in benchmarks if b and b.expected_label]
    if not benchmarks:
        return OutcomeFact.undetermined(
            task_run.task_run_id, task_run.evaluation_id, task_run.condition,
            task_run.condition_source, reason="NO_GT", benchmark_item_id=None,
        ), []

    findings = _extract_findings(events)

    # Agent 没提交任何发现 → 基线有漏洞 → 全部漏报
    if not findings:
        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmarks[0].benchmark_item_id,
            gt_label=benchmarks[0].expected_label, prediction=Prediction.NEGATIVE,
            outcome=Outcome.FAIL, confusion_label=Confusion.FN,
            target_finding_id=benchmarks[0].target_finding_id,
            validation_result=None, resolver_status="NO_FINDING",
        ), []

    # 预过滤：按关键词相似度取最可能匹配基线的前 10 个 finding
    findings = _pre_filter_findings(findings, benchmarks, top_n=10)

    # 构建 LLM 输入：基线漏洞列表（含描述）+ Agent finding 列表（含完整详情）
    baseline_json = [{
        "case_id": b.benchmark_item_id or "",
        "expected_label": b.expected_label.value,
        "description": (b.metadata or {}).get("description", ""),
        "vulnerability_type": (b.metadata or {}).get("vulnerability_type", ""),
    } for b in benchmarks]

    findings_json = [{
        "id": f["display_id"] or f["finding_id"][:8],
        "title": f["title"][:200],
        "vuln_type": f["vuln_type"],
        "severity": f["severity"],
        "validation": f["validation_result"] or "UNVALIDATED",
        "description": (f.get("description") or "")[:500],
        "source": f.get("source", ""),
        "sink": f.get("sink", ""),
        "failure_scenario": f.get("failure_scenario", ""),
    } for f in findings[:10]]

    prompt = [
        {"role": "system", "content": (
            "# 角色\n"
            "你是漏洞匹配判定器。\n\n"
            "# 背景\n"
            "V-Bench 基线定义了项目的真实漏洞列表（含漏洞描述和漏洞类型）。"
            "安全 Agent 挖掘后提交了若干 finding（含标题、描述、漏洞类型、source/sink）。\n"
            "注意：基线和 finding 的信息以文字描述为主，可能没有精确的源文件路径和行号。\n\n"
            "# 任务\n"
            "判断 Agent 提交的每个 finding 与哪个基线漏洞描述的是同一个漏洞。\n\n"
            "# 判断标准（按优先级）\n"
            "1. 漏洞涉及的功能/接口是否相同：是否针对同一个功能模块、同一个 API 接口或同一个代码区域\n"
            "2. 漏洞描述是否一致：描述的漏洞行为、利用方式是否吻合\n"
            "3. 漏洞类型是否匹配：SQL注入、XSS、DoS、权限绕过等类型是否一致\n"
            "4. source/sink 是否吻合（如果有的话）：Agent 填的入口/汇点与基线描述的触发位置是否对应\n\n"
            "# 注意\n"
            "- 同一个漏洞的不同描述也算匹配（如基线说「SQL注入」，Agent 说「数据库查询拼接」）\n"
            "- 仅漏洞类型相同但涉及完全不同功能/接口的，不是同一个漏洞\n"
            "- 如果 finding 的 description 明确指向基线描述的漏洞位置和行为，即使措辞不同也算匹配\n\n"
            "只返回 JSON，不要任何额外文字。"
        )},
        {"role": "user", "content": json.dumps({
            "baseline_vulnerabilities": baseline_json,
            "agent_findings": findings_json,
        }, ensure_ascii=False, indent=2) + (
            "\n\n对 Agent 提交的每个 finding，判断它是否与某个基线漏洞是同一个漏洞。\n"
            "返回 JSON 数组：\n"
            "[{\"finding_id\": \"Agent finding id\", \"matched_case_id\": \"匹配的基线漏洞id，无匹配则null\", \"is_same_vulnerability\": true/false, \"reason\": \"中文说明为什么是/不是同一个漏洞\"}]"
        )},
    ]

    try:
        result = llm_mod.chat_json(prompt, temperature=0, timeout=120)
        matches = result if isinstance(result, list) else result.get("matches", [])
    except Exception:
        # LLM 失败 → 规则判断
        matches = []

    # 构建 per-case 混淆矩阵
    case_results = []
    matched_case_ids = set(m.get("matched_case_id") for m in matches if m.get("is_same_vulnerability") and m.get("matched_case_id"))
    for b in benchmarks:
        cid = b.benchmark_item_id or ""
        is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
        is_matched = cid in matched_case_ids
        if is_vuln:
            confusion = "TP" if is_matched else "FN"
        else:
            confusion = "FP" if is_matched else "TN"
        matched_fid = next((m.get("finding_id") for m in matches if m.get("is_same_vulnerability") and m.get("matched_case_id") == cid), None)
        # 找到该 finding 的 session_id
        finding_session = next((f.get("session_id", "") for f in findings if f.get("finding_id") == matched_fid or f.get("display_id") == matched_fid), "")
        case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                            "matched": is_matched, "matched_finding_id": matched_fid, "confusion": confusion,
                            "session_id": finding_session})

    # 聚合 outcome
    vuln_cases = [c for c in case_results if c["confusion"] in ("TP", "FN")]
    all_vuln_matched = all(c["confusion"] == "TP" for c in vuln_cases) if vuln_cases else False
    # 用 LLM 返回的 finding_id 关联回原始 finding，取 validation_result
    matched_fids = set(m.get("finding_id") for m in matches if m.get("is_same_vulnerability"))
    matched_findings = [f for f in findings if (f["display_id"] or f["finding_id"][:8]) in matched_fids]
    vr = matched_findings[0]["validation_result"] if matched_findings else None

    if all_vuln_matched:
        pred = "POSITIVE"; outcome = Outcome.SUCCESS; confusion_label = Confusion.TP; resolver_status = "AI_MATCHED"
    else:
        pred = "NEGATIVE"; outcome = Outcome.FAIL; confusion_label = Confusion.FN
        resolver_status = "AI_PARTIAL_MATCH" if matched_case_ids else "AI_UNMATCHED"

    oc = OutcomeFact(
        outcome_fact_id=f"ocf-{task_run.task_run_id}",
        task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
        condition=task_run.condition, condition_source=task_run.condition_source,
        benchmark_item_id=benchmarks[0].benchmark_item_id,
        gt_label=benchmarks[0].expected_label, prediction=Prediction(pred),
        outcome=outcome, confusion_label=confusion_label,
        target_finding_id=benchmarks[0].target_finding_id,
        validation_result=vr, resolver_status=resolver_status,
        resolver_version="ai-1.0",
    )
    return oc, case_results


# 复用 OutcomeResolverImpl._classify
from .resolvers import OutcomeResolverImpl
