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


def _secmate_tag_to_vr(tag: str) -> str | None:
    """Map SecMate review_verdict tag to validation_result.

    tag 值含义（从实际 trace 数据验证）：
    - review_positive / confirm_positive → CONFIRMED
    - review_negative / reviewer_fp → FALSE_POSITIVE
    - conditional / needs_review → None（不确定，不算确认）
    """
    if not tag:
        return None
    tag_l = tag.lower()
    if "review_positive" in tag_l or "confirm_positive" in tag_l:
        return "CONFIRMED"
    if "review_negative" in tag_l or "reviewer_fp" in tag_l:
        return "FALSE_POSITIVE"
    return None


def _extract_findings(events: list[RawEvent]) -> list[dict]:
    """从 events 提取 finding 列表，关联 insert→update 的 validation_result。

    支持多种平台格式：
    - Turing（opencode.db）：vuln-hunt_insert_finding + vuln-hunt_update_finding（validation_result=CONFIRMED/LIKELY/POSSIBLE/FALSE_POSITIVE）
    - Argo（Claude Code JSONL）：Bash cat findings.json → TOOL_RESULT 含 verdict=CONFIRMED/MANUAL_REVIEW
    - SecMate（Claude SDK JSONL）：store_finding（level=review_verdict, tag=review_negative/reviewer_fp/conditional）
    - DataflowVulnScan（pi-agent JSONL）：assistant TEXT 中 {"candidates":[{judgment:"confirmed"}]}
    """
    findings: dict[str, dict] = {}  # finding_id(UUID) → {title, vuln_type, ...}

    for _ei, e in enumerate(events):
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
                "_event_idx": _ei,
            }

        # --- Argo: ReportFindings ---
        elif tool == "ReportFindings" or tool == "reportfindings":
            for f in (inp.get("findings") or []):
                fid = f.get("id", f.get("finding_id", ""))
                if not fid:
                    # Argo 格式没有 id/finding_id，用 file:line 生成唯一 key
                    fid = f"{f.get('file','')}:{f.get('line','')}"
                outcome = f.get("outcome", "")
                vr = "CONFIRMED" if outcome in ("confirmed", "fixed", "needs_review") else ("FALSE_POSITIVE" if outcome == "no_change_needed" else None)
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
            vr = "CONFIRMED" if status in ("VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE", "UNIT_TEST_EXPLOITABLE", "LOCAL_VALIDATION_EXPLOITABLE") else ("FALSE_POSITIVE" if status in ("NOT_VULNERABLE", "NOT_EXPLOITABLE") else None)
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

        # --- SecMate: store_finding（findings-store MCP 或 workflow-tools alias） ---
        elif tool in ("mcp__findings-store__store_finding", "mcp__workflow-tools__store_finding"):
            level = str(inp.get("level", ""))
            tag = str(inp.get("tag", ""))
            if level == "review_verdict":
                # review_verdict = 最终判定（结论点），通过 parent_id 关联到原 finding
                vr = _secmate_tag_to_vr(tag)
                parent_id = str(inp.get("parent_id", ""))
                if parent_id and parent_id in findings:
                    findings[parent_id]["validation_result"] = vr
                else:
                    fid = parent_id or f"secmate-verdict-{e.event_id}"
                    findings[fid] = {
                        "finding_id": fid,
                        "display_id": fid,
                        "title": str(inp.get("vuln_type", ""))[:120] or str(inp.get("description", ""))[:120],
                        "description": str(inp.get("description", "")),
                        "vuln_type": str(inp.get("vuln_type", ""))[:60],
                        "severity": str(inp.get("score", "")),
                        "source": str(inp.get("file_path", "")),
                        "sink": str(inp.get("function_name", "")),
                        "validation_result": vr,
                        "platform": "secmate",
                        "session_id": e.session_id,
                    }
            else:
                # 非 review_verdict = 中间 finding 提交，finding_id 在 output 中
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
                    "title": str(inp.get("title", "")) or str(inp.get("vuln_type", "")),
                    "description": str(inp.get("description", "")),
                    "vuln_type": str(inp.get("vuln_type", "")) or str(inp.get("category", "")),
                    "severity": str(inp.get("severity", "")) or str(inp.get("score", "")),
                    "source": str(inp.get("source", "") or inp.get("source_refs", "") or inp.get("file_path", "")),
                    "sink": str(inp.get("sink", "") or inp.get("function_name", "")),
                    "validation_result": None,
                    "platform": "secmate",
                    "session_id": e.session_id,
                }

        # --- SecMate 新格式: store_tiered_finding（中间 finding） ---
        elif tool.startswith("mcp__workflow-tools__store_tiered_fing"):
            # finding_id 在 result 中（tool output）
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
            finding_id = finding_id or f"secmate-{e.event_id}"
            findings[finding_id] = {
                "finding_id": finding_id,
                "display_id": finding_id,
                "title": str(inp.get("vuln_type", ""))[:120],
                "description": inp.get("description", ""),
                "vuln_type": inp.get("vuln_type", ""),
                "severity": inp.get("severity", "") or str(inp.get("score", "")),
                "source": str(inp.get("file_path", "")),
                "sink": str(inp.get("function_name", "")),
                "validation_result": None,
                "platform": "secmate",
                "session_id": e.session_id,
            }

        # --- SecMate: store_tracer_verdict / store_final_verdict（最终判定，旧格式 fallback） ---
        elif tool in ("mcp__workflow-tools__store_tracer_verdict",
                       "mcp__workflow-tools__store_final_verdict"):
            tag = str(inp.get("tag", ""))
            outcome = str(inp.get("outcome", ""))
            vr = _secmate_tag_to_vr(tag) or (
                "CONFIRMED" if outcome in ("confirmed", "conditional")
                else ("FALSE_POSITIVE" if outcome == "refuted" else None)
            )
            # finding_id 在 result 中
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
            finding_id = finding_id or f"secmate-verdict-{e.event_id}"
            findings[finding_id] = {
                "finding_id": finding_id,
                "display_id": finding_id,
                "title": str(inp.get("title", ""))[:120] or str(inp.get("vuln_type", ""))[:120],
                "description": inp.get("description", ""),
                "vuln_type": inp.get("vuln_type", ""),
                "severity": inp.get("severity", ""),
                "source": str(inp.get("file_path", "") or inp.get("primary_location", "")),
                "sink": str(inp.get("function_name", "")),
                "validation_result": vr,
                "platform": "secmate",
                "session_id": e.session_id,
            }

        # --- CVulnVerify: write 工具写 vuln_verify_final_verdict.json ---
        elif tool == "write":
            fp = str(inp.get("file_path") or inp.get("path") or "")
            if "vuln_verify_final_verdict" in fp:
                content = inp.get("content", "")
                if isinstance(content, str):
                    try:
                        vdata = json.loads(content)
                        case_id = str(vdata.get("case_id", "")) or f"cvv-{e.event_id}"
                        verdict = vdata.get("verdict", "")
                        vr = "CONFIRMED" if verdict == "confirmed" else ("FALSE_POSITIVE" if verdict == "ruled_out" else None)
                        findings[case_id] = {
                            "finding_id": case_id,
                            "display_id": case_id,
                            "title": f"CVulnVerify {case_id}",
                            "description": str(vdata.get("ruled_out_by", "")),
                            "vuln_type": "",
                            "severity": "",
                            "source": "",
                            "sink": "",
                            "validation_result": vr,
                            "platform": "cvuln-verify",
                            "session_id": e.session_id,
                        }
                    except (json.JSONDecodeError, TypeError):
                        pass

    # 关联 Turing: vuln-hunt_update_finding 的 validation_result
    for e in events:
        if not e.is_tool_call():
            continue
        tool = e.tool_name or ""
        if tool in ("vuln-hunt_update_finding", "vuln_hunt_update_finding"):
            inp = e.input_json or {}
            fid = inp.get("finding_id", "")
            vr = inp.get("validation_result", "")
            if fid in findings and vr in ("CONFIRMED", "LIKELY", "POSSIBLE", "FALSE_POSITIVE"):
                findings[fid]["validation_result"] = "CONFIRMED" if vr in ("CONFIRMED", "LIKELY", "POSSIBLE") else "FALSE_POSITIVE"

    # --- DataflowVulnScan: assistant 文本中的 candidates JSON（TEXT 事件） ---
    # DVS agent 输出 {"candidates":[{vuln_type,severity,function_name,line,reason,judgment,confidence,...}]}
    # judgment="confirmed" → CONFIRMED，空 candidates = 无漏洞
    for e in events:
        if e.event_type != "TEXT" or not e.output_json:
            continue
        text = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
        if '"candidates"' not in text:
            continue
        m = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
        if not m:
            continue
        try:
            data = json.loads(m.group(1))
            for f in (data.get("candidates") or []):
                fn = str(f.get("function_name", ""))
                ln = str(f.get("line", ""))
                fid = f"dvs-{fn}:{ln}" if fn or ln else f"dvs-{e.event_id}"
                judgment = f.get("judgment", "")
                vr = "CONFIRMED" if judgment == "confirmed" else None
                findings[fid] = {
                    "finding_id": fid,
                    "display_id": fid,
                    "title": str(f.get("vuln_type", ""))[:120],
                    "description": str(f.get("reason", "")),
                    "vuln_type": str(f.get("vuln_type", ""))[:60],
                    "severity": str(f.get("severity", "")),
                    "source": str(f.get("source_evidence", ""))[:100],
                    "sink": fn[:100],
                    "validation_result": vr,
                    "platform": "dataflow-vuln-scan",
                    "session_id": e.session_id,
                }
        except (json.JSONDecodeError, TypeError):
            pass

    # --- Argo: TOOL_RESULT 中含 findings JSON（findings.json 的 cat 结果） ---
    # Argo agent 通过 Bash cat 读取 findings.json，tool result 含 finding 数组
    for e in events:
        if e.event_type != "TOOL_RESULT" or not e.output_json:
            continue
        out_str = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
        if '"verdict"' not in out_str or '"finding_id"' not in out_str:
            continue
        try:
            data = json.loads(out_str)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(data, list):
            continue
        for f in data:
            fid = str(f.get("id", "") or f.get("finding_id", ""))
            if not fid:
                continue
            verdict = f.get("verdict", "")
            vr = "CONFIRMED" if verdict in ("CONFIRMED", "MANUAL_REVIEW") \
                else ("FALSE_POSITIVE" if verdict == "FALSE_POSITIVE" else None)
            findings[fid] = {
                "finding_id": fid,
                "display_id": fid,
                "title": str(f.get("description", ""))[:120],
                "description": f.get("description", ""),
                "vuln_type": str(f.get("cwe", "")),
                "severity": f.get("severity", ""),
                "source": str(f.get("file", "")),
                "sink": str(f.get("sink", "")),
                "validation_result": vr,
                "platform": "argo",
                "session_id": e.session_id,
            }

    # 为每个 finding 关联提交事件索引（用于后续提取挖掘过程上下文）
    for fid, f in findings.items():
        if "_event_idx" not in f:
            # 在 events 中搜索包含该 finding_id 的事件
            for i, e in enumerate(events):
                combined = str(e.input_json or "") + str(e.output_json or "")
                if fid and fid != "?" and fid in combined:
                    f["_event_idx"] = i
                    break
            else:
                f["_event_idx"] = 0

    return list(findings.values())


def _extract_mining_context(events: list[RawEvent], finding: dict, max_events: int = 40) -> dict:
    """从 finding 提交前的事件中提取挖掘过程上下文。

    收集 finding 提交前的 TOOL_CALL（read/grep/bash）和 REASONING 事件，
    提取读取的文件、搜索的模式、代码片段和推理摘要。
    不同平台描述同一漏洞的方式不同，但挖掘过程（读了哪些文件、分析了哪些函数）
    能帮助 LLM 判断是否在调查同一个漏洞。
    """
    idx = finding.get("_event_idx", 0)
    session_id = finding.get("session_id", "")
    start = max(0, idx - max_events)

    files_read: list[str] = []
    patterns_searched: list[str] = []
    code_snippets: list[str] = []
    reasoning_parts: list[str] = []

    for e in events[start:idx]:
        if e.session_id != session_id:
            continue
        if e.event_type == "TOOL_CALL":
            tool = e.tool_name or ""
            inp = e.input_json or {}
            outp = e.output_json or ""
            if tool in ("read", "cat", "view"):
                path = inp.get("file_path") or inp.get("path") or ""
                if path:
                    files_read.append(path)
                out_str = outp if isinstance(outp, str) else str(outp)
                if out_str:
                    code_snippets.append(out_str[:300])
            elif tool in ("grep", "rg", "search"):
                pattern = inp.get("pattern") or inp.get("regex") or ""
                if pattern:
                    patterns_searched.append(pattern)
            elif tool == "bash":
                cmd = inp.get("command", "")
                if cmd and len(cmd) < 200:
                    code_snippets.append(f"$ {cmd}")
        elif e.event_type == "REASONING":
            text = e.output_json if isinstance(e.output_json, str) else str(e.output_json or "")
            if text:
                reasoning_parts.append(text[:300])

    return {
        "files_read": list(dict.fromkeys(files_read))[:10],
        "patterns_searched": list(dict.fromkeys(patterns_searched))[:10],
        "code_snippets": code_snippets[:5],
        "reasoning": reasoning_parts[:3],
    }


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
    # 所有 CONFIRMED + FALSE_POSITIVE 的 finding 参与匹配，UNDETERMINED(None) 不参与
    active_findings = [f for f in findings if f.get("validation_result") in ("CONFIRMED", "FALSE_POSITIVE")]
    print(f"[AI_MATCH] {task_run.condition.value} findings_extracted={len(findings)} active={len(active_findings)} "
          f"(CONFIRMED={sum(1 for f in active_findings if f.get('validation_result')=='CONFIRMED')} "
          f"FALSE_POSITIVE={sum(1 for f in active_findings if f.get('validation_result')=='FALSE_POSITIVE')})", flush=True)
    for i, f in enumerate(active_findings[:5]):
        print(f"[AI_MATCH]   finding[{i}] id={f.get('display_id') or f.get('finding_id','')[:12]} "
              f"title={str(f.get('title',''))[:60]} vuln_type={str(f.get('vuln_type',''))[:30]} "
              f"validation={f.get('validation_result')}", flush=True)
    if len(active_findings) > 5:
        print(f"[AI_MATCH]   ...还有 {len(active_findings)-5} 条 finding", flush=True)

    # Agent 没提交任何有效 finding → 基线有漏洞则 FN，非漏洞则 TN
    if not active_findings:
        print(f"[AI_MATCH] {task_run.condition.value} NO_ACTIVE_FINDING → outcome=FAIL", flush=True)
        case_results = []
        for b in benchmarks:
            cid = b.benchmark_item_id or ""
            is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
            case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                                "matched": False, "matched_finding_id": None,
                                "confusion": "FN" if is_vuln else "TN",
                                "session_id": "", "agent_validation": None})
        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmarks[0].benchmark_item_id,
            gt_label=benchmarks[0].expected_label, prediction=Prediction.NEGATIVE,
            outcome=Outcome.FAIL, confusion_label=Confusion.FN,
            target_finding_id=benchmarks[0].target_finding_id,
            validation_result=None, resolver_status="NO_FINDING",
        ), case_results

    # 预过滤：取前 20 个 finding（避免过多）
    active_findings = _pre_filter_findings(active_findings, benchmarks, top_n=20)

    # 为每个 finding 提取挖掘过程上下文（读了哪些文件、搜了什么、推理了什么）
    for f in active_findings:
        f["_mining_context"] = _extract_mining_context(events, f)

    # 构建基线和 finding 的精简描述
    baseline_list = []
    for b in benchmarks:
        md = b.metadata or {}
        baseline_list.append({
            "case_id": b.benchmark_item_id or "",
            "vulnerability_type": md.get("vulnerability_type", ""),
            "description": (md.get("description") or "")[:300],
            "source_file": md.get("source_file") or "",
            "source_function": md.get("source_function") or "",
        })
    finding_list = []
    for f in active_findings:
        finding_list.append({
            "title": (f.get("title") or "")[:200],
            "vuln_type": f.get("vuln_type", ""),
            "description": (f.get("description") or "")[:300],
            "source": f.get("source", ""),
            "sink": f.get("sink", ""),
            "mining_context": f.get("_mining_context", {}),
        })

    # 1 对 1 LLM 调用 + finding 一对一约束 + 基线匹配即停
    available_indices = list(range(len(active_findings)))  # 候选 finding 池
    matches = []  # [(finding_idx, baseline_idx)]
    matched_case_ids = set()
    llm_call_count = 0

    for bi, b in enumerate(benchmarks):
        cid = b.benchmark_item_id or ""
        matched = False
        for fi in list(available_indices):
            llm_call_count += 1
            prompt = [
                {"role": "system", "content": (
                    "# 角色\n"
                    "你是漏洞匹配判定器。判断给定的 finding 和 baseline 是否描述的是同一个漏洞。\n\n"
                    "# 判断规则\n"
                    "1. 同一个漏洞 = 相同漏洞类型 + 相同入口/source + 相同 sink + 相同文件/函数位置\n"
                    "2. 路径格式可能不同：如 'src/main/java/.../FileService.java' 和 'FileService.java' 可能是同一文件\n"
                    "3. 函数名相同是强信号，但描述的漏洞行为也需吻合\n"
                    "4. 漏洞类型可能用不同术语：如 '注入' 和 'SQL Injection' 是同一类型\n"
                    "5. 仅漏洞类型相同但位置/函数不同的，不是同一个漏洞\n"
                    "6. 不看结论对错：即使 finding 和 baseline 对该漏洞的结论不同（一个是漏洞、一个不是），只要描述的是同一个漏洞就返回 true\n"
                    "7. mining_context（读过的文件、搜索模式、推理摘要）作为辅助参考\n\n"
                    "# 输出格式\n"
                    '只返回 JSON：{"is_same": true} 或 {"is_same": false}，不要任何额外文字。'
                )},
                {"role": "user", "content": json.dumps({
                    "baseline": baseline_list[bi],
                    "finding": finding_list[fi],
                }, ensure_ascii=False, indent=2)},
            ]

            try:
                result = llm_mod.chat_json(prompt, temperature=0, max_tokens=500)
                is_same = bool(result.get("is_same", False)) if isinstance(result, dict) else bool(result)
            except Exception as e:
                print(f"[AI_MATCH] {task_run.condition.value} LLM 匹配失败 (f{fi},b{bi}): {e}", flush=True)
                is_same = False

            if is_same:
                matches.append((fi, bi))
                matched_case_ids.add(cid)
                available_indices.remove(fi)  # finding 一对一：从候选池移除
                matched = True
                print(f"[AI_MATCH]   MATCHED case={cid[:20]} ← finding[{fi}] "
                      f"id={active_findings[fi].get('display_id','')[:20]}", flush=True)
                break  # 基线匹配即停

        if not matched:
            md_desc = str((b.metadata or {}).get("vulnerability_type", ""))[:40]
            print(f"[AI_MATCH]   UNMATCHED case={cid[:20]} label={b.expected_label.value if b.expected_label else 'NA'} "
                  f"vuln_type={md_desc}", flush=True)

    print(f"[AI_MATCH] {task_run.condition.value} baseline={len(benchmarks)} matched={len(matched_case_ids)} "
          f"llm_calls={llm_call_count}", flush=True)

    # per-case confusion 矩阵（考虑 agent validation_result）
    case_results = []
    for bi, b in enumerate(benchmarks):
        cid = b.benchmark_item_id or ""
        is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
        is_matched = cid in matched_case_ids

        matched_fid = None
        finding_session = ""
        matched_vr = None
        if is_matched:
            for fi, ci in matches:
                if ci == bi:
                    matched_fid = active_findings[fi].get("display_id") or active_findings[fi].get("finding_id", "")[:8]
                    finding_session = active_findings[fi].get("session_id", "")
                    matched_vr = active_findings[fi].get("validation_result")
                    break

        # confusion 矩阵：baseline 标签 + agent validation_result
        if is_vuln:
            # VULNERABLE 基线：agent CONFIRMED → TP，agent FALSE_POSITIVE 或无匹配 → FN
            confusion = "TP" if (is_matched and matched_vr == "CONFIRMED") else "FN"
        else:
            # NON_VULNERABLE 基线：agent CONFIRMED → FP，agent FALSE_POSITIVE 或无匹配 → TN
            confusion = "FP" if (is_matched and matched_vr == "CONFIRMED") else "TN"

        case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                            "matched": is_matched, "matched_finding_id": matched_fid, "confusion": confusion,
                            "session_id": finding_session, "agent_validation": matched_vr})

    # 聚合 outcome：所有 case 都是 TP 或 TN → SUCCESS，否则 FAIL
    all_correct = all(c["confusion"] in ("TP", "TN") for c in case_results) if case_results else False
    matched_fids = set()
    for fi, _ in matches:
        matched_fids.add(active_findings[fi].get("display_id") or active_findings[fi].get("finding_id", "")[:8])
    matched_findings = [f for f in active_findings if (f.get("display_id") or f.get("finding_id", "")[:8]) in matched_fids]
    vr = matched_findings[0]["validation_result"] if matched_findings else None

    if all_correct:
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
