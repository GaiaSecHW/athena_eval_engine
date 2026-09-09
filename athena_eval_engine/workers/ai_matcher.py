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

    支持多种平台格式：
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

        # --- SecMate: findings-store MCP ---
        elif tool == "mcp__findings-store__store_finding":
            # 返回值是 JSON 字符串，其中 result 字段又是一个 JSON 字符串。
            finding_id = ""
            try:
                result = json.loads(out_str)
                nested = result.get("result", result) if isinstance(result, dict) else result
                if isinstance(nested, str):
                    nested = json.loads(nested)
                if isinstance(nested, dict):
                    finding_id = str(nested.get("finding_id", ""))
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
            finding_id = finding_id or str(inp.get("finding_id", "")) or f"secmate-{e.event_id}"
            findings[finding_id] = {
                "finding_id": finding_id,
                "display_id": finding_id,
                "title": inp.get("title", "") or inp.get("vuln_type", ""),
                "description": inp.get("description", ""),
                "vuln_type": inp.get("vuln_type", "") or inp.get("category", ""),
                "severity": inp.get("severity", "") or inp.get("score", ""),
                "source": str(inp.get("source", "") or inp.get("source_refs", "") or inp.get("file_path", "")),
                "sink": str(inp.get("sink", "") or inp.get("function_name", "")),
                "validation_result": None,
                "platform": "secmate",
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
    print(f"[AI_MATCH] {task_run.condition.value} findings_extracted={len(findings)}", flush=True)
    for i, f in enumerate(findings[:5]):
        print(f"[AI_MATCH]   finding[{i}] id={f.get('display_id') or f.get('finding_id','')[:12]} "
              f"title={str(f.get('title',''))[:60]} vuln_type={str(f.get('vuln_type',''))[:30]} "
              f"validation={f.get('validation_result')}", flush=True)
    if len(findings) > 5:
        print(f"[AI_MATCH]   ...还有 {len(findings)-5} 条 finding", flush=True)

    # Agent 没提交任何发现 → 基线有漏洞 → 全部漏报
    if not findings:
        print(f"[AI_MATCH] {task_run.condition.value} NO_FINDING → outcome=FAIL/FN", flush=True)
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

    # 预过滤：取前 20 个 finding（避免过多）
    findings = _pre_filter_findings(findings, benchmarks, top_n=20)

    # 1 对 1 对比：每个 (finding, baseline) 对独立判断 true/false
    # 先按文件名预筛，只发文件/函数有交集的对（避免 token 超限）
    # 如果基线没有 source_file/function（V-Bench 模式），跳过预筛全发
    import os as _os
    has_source_info = any((b.metadata or {}).get("source_file") or (b.metadata or {}).get("source_function") for b in benchmarks)
    pairs = []
    for fi, f in enumerate(findings):
        f_text = " ".join(str(f.get(k, "")) for k in ("title", "description", "source", "sink", "vuln_type"))
        for bi, b in enumerate(benchmarks):
            md = b.metadata or {}
            b_file = md.get("source_file") or ""
            b_func = md.get("source_function") or ""
            b_file_name = _os.path.basename(b_file) if b_file else ""
            if has_source_info:
                # 有 source 信息：按文件名/函数名预筛
                if (b_file_name and b_file_name in f_text) or (b_func and b_func in f_text):
                    pairs.append({"finding_idx": fi, "baseline_idx": bi,
                        "baseline": {"case_id": b.benchmark_item_id or "",
                                    "vulnerability_type": md.get("vulnerability_type", ""),
                                    "description": md.get("description", "")[:300],
                                    "source_file": b_file, "source_function": b_func},
                        "finding": {"title": f["title"][:200], "vuln_type": f["vuln_type"],
                                    "description": (f.get("description") or "")[:300],
                                    "source": f.get("source", ""), "sink": f.get("sink", "")}})
            else:
                # 无 source 信息（V-Bench 模式）：全发，不做预筛
                pairs.append({"finding_idx": fi, "baseline_idx": bi,
                    "baseline": {"case_id": b.benchmark_item_id or "",
                                "vulnerability_type": md.get("vulnerability_type", ""),
                                "description": md.get("description", "")[:300],
                                "source_file": "", "source_function": ""},
                    "finding": {"title": f["title"][:200], "vuln_type": f["vuln_type"],
                                "description": (f.get("description") or "")[:300],
                                "source": f.get("source", ""), "sink": f.get("sink", "")}})
    print(f"[AI_MATCH] {task_run.condition.value} 预筛后 {len(pairs)} 对（findings={len(findings)} baselines={len(benchmarks)}）", flush=True)

    # 无候选对 → 全部未匹配
    if not pairs:
        matches = []
        matched_case_ids = set()
    else:
        prompt = [
            {"role": "system", "content": (
                "# 角色\n"
                "你是漏洞匹配判定器。判断每对 finding 和 baseline 是否是同一个漏洞。\n\n"
                "# 判断规则\n"
                "1. 如果基线有 source_file 和 source_function：source 和 sink 必须完全匹配（文件名相同 + 函数名相同）\n"
                "2. 如果基线没有 source_file（配置类或无文件信息）：按漏洞类型和描述判断是否同一个漏洞\n"
                "3. 配置类漏洞无 source 时，按 sink 所在文件和函数判断\n"
                "4. 漏洞行为一致：描述的漏洞行为和利用方式吻合\n"
                "5. 仅漏洞类型相同但功能/文件不同的，不是同一个漏洞\n"
                "6. 每个 baseline 只能匹配一个 finding\n\n"
                "# 输出格式\n"
                "只返回 JSON 布尔数组，不要任何额外文字。每个对返回 true 或 false：\n"
                "[true, false, true] 表示第 0 对是同一个漏洞，第 1 对不是，第 2 对是\n"
                "数组长度必须等于输入的对数。"
            )},
            {"role": "user", "content": json.dumps({"pairs": pairs}, ensure_ascii=False, indent=2)},
        ]

        try:
            result = llm_mod.chat_json(prompt, temperature=0, timeout=120, max_tokens=16000)
            bools = result if isinstance(result, list) else []
        except Exception as e:
            print(f"[AI_MATCH] {task_run.condition.value} LLM 匹配失败: {e}", flush=True)
            bools = []

        # 布尔数组 → 匹配的 (finding_idx, baseline_idx)
        matches = []
        matched_case_ids = set()
        for i, is_same in enumerate(bools):
            if is_same and i < len(pairs):
                p = pairs[i]
                cid = benchmarks[p["baseline_idx"]].benchmark_item_id or ""
                if cid and cid not in matched_case_ids:  # 先到先得
                    matched_case_ids.add(cid)
                    matches.append((p["finding_idx"], p["baseline_idx"]))
        print(f"[AI_MATCH] {task_run.condition.value} LLM 返回 {len(bools)} 个判断, matched={len(matched_case_ids)}", flush=True)
    print(f"[AI_MATCH] {task_run.condition.value} baseline={len(benchmarks)} cases, matched={len(matched_case_ids)}", flush=True)
    case_results = []
    for b in benchmarks:
        cid = b.benchmark_item_id or ""
        is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
        is_matched = cid in matched_case_ids
        if not is_matched:
            md_desc = str((b.metadata or {}).get("vulnerability_type", ""))[:40]
            print(f"[AI_MATCH]   UNMATCHED case={cid[:20]} label={b.expected_label.value if b.expected_label else 'NA'} "
                  f"vuln_type={md_desc}", flush=True)
        cid = b.benchmark_item_id or ""
        is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
        is_matched = cid in matched_case_ids
        if is_vuln:
            confusion = "TP" if is_matched else "FN"
        else:
            confusion = "FP" if is_matched else "TN"
        # 从索引对或旧格式中找到匹配的 finding
        matched_fid = None
        finding_session = ""
        if isinstance(matches, list):
            for m in matches:
                if isinstance(m, (list, tuple)) and len(m) == 2:
                    # 索引对：(finding_idx, baseline_idx)
                    fi, ci = m[0], m[1]
                    if ci < len(benchmarks) and (benchmarks[ci].benchmark_item_id or "") == cid:
                        if fi < len(findings):
                            matched_fid = findings[fi].get("display_id") or findings[fi].get("finding_id", "")[:8]
                            finding_session = findings[fi].get("session_id", "")
                        break
                elif isinstance(m, dict):
                    # 兼容旧格式
                    _key = "is_same" if "is_same" in m else "is_same_vulnerability"
                    if m.get(_key) and m.get("matched_case_id") == cid:
                        matched_fid = m.get("finding_id")
                        break
            if not finding_session and matched_fid:
                finding_session = next((f.get("session_id", "") for f in findings if f.get("finding_id") == matched_fid or f.get("display_id") == matched_fid), "")
        case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                            "matched": is_matched, "matched_finding_id": matched_fid, "confusion": confusion,
                            "session_id": finding_session})

    # 聚合 outcome
    vuln_cases = [c for c in case_results if c["confusion"] in ("TP", "FN")]
    all_vuln_matched = all(c["confusion"] == "TP" for c in vuln_cases) if vuln_cases else False
    # 从索引对提取匹配的 finding IDs
    matched_fids = set()
    if isinstance(matches, list):
        for m in matches:
            if isinstance(m, list) and len(m) == 2:
                if m[0] < len(findings):
                    matched_fids.add(findings[m[0]].get("display_id") or findings[m[0]].get("finding_id", "")[:8])
            elif isinstance(m, dict):
                _key = "is_same" if "is_same" in m else "is_same_vulnerability"
                if m.get(_key):
                    matched_fids.add(m.get("finding_id", ""))
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
