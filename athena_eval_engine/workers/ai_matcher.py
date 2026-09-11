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


def _extract_webvv_task_data(events: list[RawEvent]) -> dict[str, dict]:
    """从 WebVulnVerify trace 的 User message (task_data) 中提取 source/sink 等信息。

    T002 的 User message 包含 T001 上报的 finding 数据，格式为：
    <task_data>
    VULNERABILITY INFORMATION:
    - Vulnerability ID: 50318
    - File URI: DPOrderFulfillmentService/.../FileBucketService.java
    - URL: /rest/dp/order/fulfillment/v1/order/supplement
    - Source: supplement() 方法接收...
    - Sink: FileBucketService.getInputStream()...
    </task_data>

    返回 {vulnerability_id: {source, sink, file_uri, url}} 映射。
    """
    result_map: dict[str, dict] = {}
    for e in events:
        text = ""
        if isinstance(e.input_json, str):
            text = e.input_json
        elif isinstance(e.output_json, str):
            text = e.output_json
        elif e.output_json is not None:
            text = str(e.output_json)
        elif e.input_json is not None:
            text = str(e.input_json)

        if not text or "task_data" not in text:
            continue

        vid_m = re.search(r'[Vv]ulnerability[_ ]?[Ii][Dd][:：]\s*(\S+)', text)
        if not vid_m:
            continue
        vid = vid_m.group(1).strip()

        def _extract_field(label: str) -> str:
            m = re.search(rf'-\s*{label}[:：]\s*(.+?)(?=\n\s*-|\Z)', text, re.DOTALL)
            return m.group(1).strip() if m else ""

        result_map[vid] = {
            "source": _extract_field("Source"),
            "sink": _extract_field("Sink"),
            "file_uri": _extract_field("File URI"),
            "url": _extract_field("URL"),
        }

    return result_map


def _extract_webvv_title(result_text: str) -> str:
    """从 WebVulnVerify 的验证报告 (result 字段) 中提取具体标题。

    优先提取"一句话结论"，其次提取元数据表中的"漏洞类型"。
    如果都提取不到，返回空字符串（调用方回退到 category）。
    """
    if not result_text:
        return ""

    # 1. "一句话结论：xxx" → 取结论文本
    m = re.search(r'一句话结论[：:]\s*(.+?)(?=\n\n|\n#|\n-|\Z)', result_text, re.DOTALL)
    if m:
        return m.group(1).strip()

    # 2. 元数据表 "| 漏洞类型 | xxx |" → 取值
    m = re.search(r'漏洞类型\s*\|\s*(.+?)\s*\|', result_text)
    if m:
        return m.group(1).strip()

    return ""


def _extract_findings(events: list[RawEvent]) -> list[dict]:
    """从 events 提取 finding 列表，关联 insert→update 的 validation_result。

    支持多种平台格式：
    - Turing（opencode.db）：vuln-hunt_insert_finding + vuln-hunt_update_finding（validation_result=CONFIRMED/LIKELY/POSSIBLE/FALSE_POSITIVE）
    - Argo（Claude Code JSONL）：Bash cat findings.json → TOOL_RESULT 含 verdict=CONFIRMED/MANUAL_REVIEW
    - SecMate（Claude SDK JSONL）：store_finding（level=review_verdict, tag=review_negative/reviewer_fp/conditional）
    - DataflowVulnScan（pi-agent JSONL）：assistant TEXT 中 {"candidates":[{judgment:"confirmed"}]}
    """
    findings: dict[str, dict] = {}  # finding_id(UUID) → {title, vuln_type, ...}

    # 预提取 WebVulnVerify 的 task_data（T001 上报的 source/sink 等信息）
    _webvv_task_data = _extract_webvv_task_data(events)

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
            result_text = inp.get("result", "")
            # 从 task_data 提取 source/sink（T001 上报的原始 finding 信息）
            td = _webvv_task_data.get(vid, {})
            # 从验证报告中提取具体标题（一句话结论），回退到 category
            title = _extract_webvv_title(result_text) or inp.get("category", "")
            findings[vid] = {
                "finding_id": vid,
                "display_id": vid,
                "title": title,
                "description": result_text,
                "vuln_type": inp.get("category", ""),
                "severity": "",
                "source": td.get("source", ""),
                "sink": td.get("sink", ""),
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
                        "title": str(inp.get("vuln_type", "")) or str(inp.get("description", "")),
                        "description": str(inp.get("description", "")),
                        "vuln_type": str(inp.get("vuln_type", "")),
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
                "title": str(inp.get("vuln_type", "")),
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
                "title": str(inp.get("title", "")) or str(inp.get("vuln_type", "")),
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
                    "title": str(f.get("vuln_type", "")),
                    "description": str(f.get("reason", "")),
                    "vuln_type": str(f.get("vuln_type", "")),
                    "severity": str(f.get("severity", "")),
                    "source": str(f.get("source_evidence", "")),
                    "sink": fn,
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
                "title": str(f.get("description", "")),
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
    跨 session 收集：不限制同一 session，包含子 agent session 的挖掘行为。
    """
    idx = finding.get("_event_idx", 0)
    start = max(0, idx - max_events)

    files_read: list[str] = []
    patterns_searched: list[str] = []
    code_snippets: list[str] = []
    reasoning_parts: list[str] = []

    for e in events[start:idx]:
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
                    code_snippets.append(out_str)
            elif tool in ("grep", "rg", "search"):
                pattern = inp.get("pattern") or inp.get("regex") or ""
                if pattern:
                    patterns_searched.append(pattern)
            elif tool == "bash":
                cmd = inp.get("command", "")
                if cmd:
                    code_snippets.append(f"$ {cmd}")
        elif e.event_type == "REASONING":
            text = e.output_json if isinstance(e.output_json, str) else str(e.output_json or "")
            if text:
                reasoning_parts.append(text)

    return {
        "files_read": list(dict.fromkeys(files_read)),
        "patterns_searched": list(dict.fromkeys(patterns_searched)),
        "code_snippets": code_snippets,
        "reasoning": reasoning_parts,
    }


def _ev(e: RawEvent, fp=None):
    return Evidence(trace_id=e.trace_id, session_id=e.session_id, message_id=e.message_id,
                    part_id=e.part_id, tool_name=e.tool_name, event_timestamp=e.timestamp_ms, field_path=fp)


def _sort_findings_by_relevance(findings: list[dict], benchmarks: list) -> list[dict]:
    """按关键词相似度排序 findings，使最可能匹配基线的 finding 排在前面。

    不截断：返回全部 findings，仅按相关性排序（优化"基线匹配即停"策略）。
    """
    if len(findings) <= 1:
        return findings

    # 提取基线关键词
    baseline_keywords = set()
    for b in benchmarks:
        md = b.metadata or {}
        for field in ("description", "vulnerability_type"):
            text = md.get(field, "") or ""
            baseline_keywords.update(w.lower() for w in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', text))

    # 为每个 finding 计算与基线的相似度
    def _score(f):
        text = " ".join(str(f.get(k, "")) for k in ("title", "description", "vuln_type", "source", "sink"))
        finding_words = set(w.lower() for w in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', text))
        return len(finding_words & baseline_keywords)

    return sorted(findings, key=_score, reverse=True)


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
        print(f"[AI_MATCH]   finding[{i}] id={f.get('display_id') or f.get('finding_id','')} "
              f"title={str(f.get('title',''))} vuln_type={str(f.get('vuln_type',''))} "
              f"validation={f.get('validation_result')}", flush=True)
    if len(active_findings) > 5:
        print(f"[AI_MATCH]   ...还有 {len(active_findings)-5} 条 finding", flush=True)

    # Agent 没提交任何有效 finding → VULNERABLE=NA（未找到），NON-VULNERABLE=TN（正确）
    if not active_findings:
        print(f"[AI_MATCH] {task_run.condition.value} NO_ACTIVE_FINDING → outcome=FAIL", flush=True)
        case_results = []
        for b in benchmarks:
            cid = b.benchmark_item_id or ""
            is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
            case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                                "matched": False, "matched_finding_id": None,
                                "confusion": "NA" if is_vuln else "TN",
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

    # 按相关性排序（不截断，优化"基线匹配即停"策略）
    active_findings = _sort_findings_by_relevance(active_findings, benchmarks)

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
            "description": md.get("description") or "",
            "source_file": md.get("source_file") or "",
            "source_function": md.get("source_function") or "",
        })
    finding_list = []
    for f in active_findings:
        finding_list.append({
            "title": f.get("title") or "",
            "vuln_type": f.get("vuln_type", ""),
            "description": f.get("description") or "",
            "source": f.get("source", ""),
            "sink": f.get("sink", ""),
            "mining_context": f.get("_mining_context", {}),
        })

    # 1 对 1 LLM 调用 + finding 一对一约束 + 基线匹配即停 + 并行发送
    from concurrent.futures import ThreadPoolExecutor, as_completed

    available_indices = list(range(len(active_findings)))  # 候选 finding 池
    matches = []  # [(finding_idx, baseline_idx)]
    matched_case_ids = set()
    llm_call_count = 0

    _sys_prompt = (
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
    )

    def _check_pair(fi: int, bi: int, bl_desc: dict, fd_desc: dict) -> tuple[int, bool]:
        """单次 LLM 判断：finding 和 baseline 是否同一漏洞。

        chat_json 内部已做 20 次重试；重试耗尽后 raise RuntimeError，
        此处不 catch，让异常向上传播使评测变 FAILED。
        """
        prompt = [
            {"role": "system", "content": _sys_prompt},
            {"role": "user", "content": json.dumps({
                "baseline": bl_desc, "finding": fd_desc,
            }, ensure_ascii=False, indent=2)},
        ]
        result = llm_mod.chat_json(prompt, temperature=0, max_tokens=500)
        is_same = bool(result.get("is_same", False)) if isinstance(result, dict) else bool(result)
        return fi, is_same

    # baseline 串行（finding 一对一约束），每个 baseline 内 finding 并行发送
    with ThreadPoolExecutor(max_workers=6) as pool:
        for bi, b in enumerate(benchmarks):
            cid = b.benchmark_item_id or ""
            if not available_indices:
                break  # 候选池已空，剩余 baseline 都不会匹配

            # 并行提交所有候选 finding 的 LLM 判断
            futures = {}
            for fi in list(available_indices):
                fut = pool.submit(_check_pair, fi, bi, baseline_list[bi], finding_list[fi])
                futures[fut] = fi
                llm_call_count += 1

            matched = False
            for fut in as_completed(futures):
                try:
                    fi, is_same = fut.result()
                except Exception as e:
                    # LLM 重试耗尽 → 取消剩余 futures 并向上抛出，让评测变 FAILED
                    _fi = futures.get(fut, -1)
                    print(f"[AI_MATCH] {task_run.condition.value} LLM 重试耗尽 (f{_fi},b{bi}): {e}", flush=True)
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    raise
                if is_same and fi in available_indices:
                    matches.append((fi, bi))
                    matched_case_ids.add(cid)
                    available_indices.remove(fi)  # finding 一对一：从候选池移除
                    matched = True
                    print(f"[AI_MATCH]   MATCHED case={cid} ← finding[{fi}] "
                          f"id={active_findings[fi].get('display_id','')}", flush=True)
                    break  # 基线匹配即停

            # 取消未完成的 LLM 调用（已发出的不可取消，结果丢弃）
            for f in futures:
                if not f.done():
                    f.cancel()

            if not matched:
                md_desc = str((b.metadata or {}).get("vulnerability_type", ""))
                print(f"[AI_MATCH]   UNMATCHED case={cid} label={b.expected_label.value if b.expected_label else 'NA'} "
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
        finding_ts = None
        if is_matched:
            for fi, ci in matches:
                if ci == bi:
                    f = active_findings[fi]
                    matched_fid = f.get("display_id") or f.get("finding_id", "")
                    finding_session = f.get("session_id", "")
                    matched_vr = f.get("validation_result")
                    # finding 提交时间戳（用于 KG 分析倒推挖掘链）
                    _ei = f.get("_event_idx")
                    if _ei is not None and _ei < len(events):
                        finding_ts = events[_ei].timestamp_ms
                    break

        # confusion 矩阵：baseline 标签 + agent validation_result
        # 四种状态：
        #   漏洞→漏洞(TP): agent确认漏洞，基线是漏洞
        #   漏洞→非漏洞(FP): agent确认漏洞，基线非漏洞
        #   非漏洞→漏洞(FN): agent判非漏洞，基线是漏洞
        #   未发现→漏洞(NA): agent没找到，基线是漏洞
        #   非漏洞→非漏洞(TN): agent判非漏洞，基线非漏洞（正确，不在四种状态里）
        if is_matched and matched_vr == "CONFIRMED":
            confusion = "TP" if is_vuln else "FP"
        elif is_matched:
            confusion = "FN" if is_vuln else "TN"
        else:
            confusion = "NA" if is_vuln else "TN"

        case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                            "matched": is_matched, "matched_finding_id": matched_fid, "confusion": confusion,
                            "session_id": finding_session, "agent_validation": matched_vr,
                            "finding_ts": finding_ts})

    # 聚合 outcome：VULNERABLE 基线需 TP，NON_VULNERABLE 基线需 TN
    all_correct = all(c["confusion"] in ("TP", "TN") for c in case_results) if case_results else False
    matched_fids = set()
    for fi, _ in matches:
        matched_fids.add(active_findings[fi].get("display_id") or active_findings[fi].get("finding_id", ""))
    matched_findings = [f for f in active_findings if (f.get("display_id") or f.get("finding_id", "")) in matched_fids]
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
