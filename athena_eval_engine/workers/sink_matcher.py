"""Sink 点匹配器 — 基于基线漏洞 sink 点（文件+行号/方法名）定位 session 链。

流程：
1. 扫描 trace 所有工具读文件操作，构建文件读取索引
2. 对每个基线，用 sink 点（文件名+行号/方法名）匹配文件读取记录
3. 命中的 session 通过 session graph 分组为链
4. 确定性 confusion：finding 匹配 source_file + validation_result + expected_label
5. 收集链数据（chain_actions, session_chain）供报告展示用
"""
from __future__ import annotations
import re
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..raw_event import RawEvent
    from ..infrastructure import llm as llm_mod
    from ..infrastructure.log_util import log

from ..infrastructure.log_util import log


def _basename(path: str) -> str:
    """跨平台 basename：同时处理 / 和 \\ 分隔符。
    _basename 在 Windows 上只认 \\，但 trace 数据来自 Linux 容器用 /。
    """
    if not path:
        return ""
    parts = re.split(r'[/\\]', path)
    return parts[-1] if parts else path


def build_file_read_index(events: list) -> list[dict]:
    """从 trace 事件中提取所有文件读取操作。

    覆盖 read 工具和 bash 工具（cat/grep/head/tail/sed）。
    通过 call_id 配对 TOOL_RESULT 获取返回内容。

    返回: [{file_path, basename, offset, limit, content, session_id, timestamp}, ...]
    """
    import time
    _n = len(events)
    _start = time.time()
    # 构建 call_id → TOOL_RESULT 映射
    result_by_call_id: dict[str, str] = {}
    for idx, e in enumerate(events):
        if _n > 10000 and idx > 0 and idx % 50000 == 0:
            log("SINK_MATCH", f"build_file_read_index phase1 {idx}/{_n} events "
                  f"elapsed={int(time.time()-_start)}s")
        if e.event_type == "TOOL_RESULT" and e.call_id:
            output = e.output_json
            if isinstance(output, str):
                result_by_call_id[e.call_id] = output
            elif output is not None:
                result_by_call_id[e.call_id] = str(output)

    reads: list[dict] = []
    for idx, e in enumerate(events):
        if _n > 10000 and idx > 0 and idx % 50000 == 0:
            log("SINK_MATCH", f"build_file_read_index phase2 {idx}/{_n} events "
                  f"elapsed={int(time.time()-_start)}s reads={len(reads)}")
        if e.event_type != "TOOL_CALL":
            continue
        tool = e.tool_name or ""
        inp = e.input_json or {}
        content = result_by_call_id.get(e.call_id, "") if e.call_id else ""

        if tool == "read":
            fp = str(inp.get("file_path") or inp.get("filePath") or inp.get("path") or "")
            if not fp:
                continue
            offset = inp.get("offset")
            limit = inp.get("limit")
            reads.append({
                "file_path": fp,
                "basename": _basename(fp),
                "offset": int(offset) if offset is not None and str(offset).isdigit() else None,
                "limit": int(limit) if limit is not None and str(limit).isdigit() else None,
                "content": content,
                "session_id": e.session_id,
                "timestamp": e.timestamp_ms or 0,
            })
        elif tool == "bash":
            cmd = str(inp.get("command") or "")
            if not cmd:
                continue
            # 从命令行提取文件路径（与 build_session_graph 相同的正则）
            for match in re.findall(r'[\w\-./]+\.[a-zA-Z]{1,6}', cmd):
                basename = _basename(match)
                if not basename or len(basename) >= 80 or basename.startswith('.'):
                    continue
                reads.append({
                    "file_path": match,
                    "basename": basename,
                    "offset": None,
                    "limit": None,
                    "content": content,
                    "session_id": e.session_id,
                    "timestamp": e.timestamp_ms or 0,
                })

    log("SINK_MATCH", f"文件读取索引: {len(reads)} 条 "
          f"(read={sum(1 for r in reads if r.get('offset') is not None)}, "
          f"bash={sum(1 for r in reads if r.get('offset') is None)})")
    return reads


def find_sink_sessions(file_reads: list[dict], source_file: str,
                       source_line: str, source_function: str) -> list[str]:
    """检查文件读取是否覆盖了基线的 sink 点。

    匹配条件：文件名一致 AND（行号在 read 范围内 OR 行号在返回内容里 OR 方法名在返回内容里）

    返回: 命中的 session_id 列表（去重）
    """
    if not source_file:
        return []

    target_basename = _basename(source_file)
    has_line = bool(source_line)
    has_func = bool(source_function)

    # 无行号也无方法名 → 文件名匹配即可（弱信号）
    if not has_line and not has_func:
        matched_sessions = set()
        for r in file_reads:
            if r["basename"] == target_basename:
                matched_sessions.add(r["session_id"])
        return list(matched_sessions)

    target_line = None
    if has_line:
        try:
            target_line = int(source_line)
        except ValueError:
            target_line = None

    matched_sessions = set()
    for r in file_reads:
        if r["basename"] != target_basename:
            continue
        # 检查行号
        if target_line is not None:
            # read 工具有 offset/limit → 行号范围匹配
            if r["offset"] is not None and r["limit"] is not None:
                if r["offset"] <= target_line <= r["offset"] + r["limit"]:
                    matched_sessions.add(r["session_id"])
                    continue
            # 检查行号是否在返回内容里（行首匹配，避免内容中的数字误匹配）
            if re.search(r'(?:^|\n)' + str(target_line) + r'\b', r["content"]):
                matched_sessions.add(r["session_id"])
                continue
        # 检查方法名是否在返回内容里（词边界匹配，避免 "get" 匹配 "forget"）
        if has_func and re.search(r'\b' + re.escape(source_function) + r'\b', r["content"]):
            matched_sessions.add(r["session_id"])
            continue

    return list(matched_sessions)


def group_chains(sink_session_ids: list[str], session_graph: dict) -> list[set[str]]:
    """将 sink 命中的 session 按 session graph 连通性分组为链。

    连通的 session（BFS 可达）合并为一条链，不连通的分开。

    返回: [set of session_ids, ...] — 每个集合是一条链
    """
    if not sink_session_ids:
        return []

    edges = session_graph.get("edges", {}) if session_graph else {}

    # 对每个 sink 命中 session 做 BFS，获取可达集合
    reachable_sets = []
    for sid in sink_session_ids:
        visited = {sid}
        queue = [sid]
        while queue:
            cur = queue.pop(0)
            for related in edges.get(cur, set()):
                if related not in visited:
                    visited.add(related)
                    queue.append(related)
        reachable_sets.append(visited)

    # 合并相交的集合（两个 sink session 的 BFS 结果有交集 → 同一条链）
    # 重复合并直到稳定，保证传递性（A∩B, B∩C → A∪B∪C）
    chains: list[set[str]] = [rs.copy() for rs in reachable_sets]
    changed = True
    while changed:
        changed = False
        for i in range(len(chains)):
            for j in range(i + 1, len(chains)):
                if chains[i] & chains[j]:  # 有交集
                    chains[i] = chains[i] | chains[j]
                    chains.pop(j)
                    changed = True
                    break
            if changed:
                break

    return chains


def collect_chain_actions(chain_sessions: set[str], events: list, parser,
                          session_chain_order: list[str] | None = None) -> list[dict]:
    """收集链上所有 session 的工具调用行为。

    有 session_chain_order 时按 (链位置, 时间) 排序，无时按时间排序。
    复用 parser._extract_action 提取工具行为摘要。
    """
    if parser is None:
        return []
    actions = []
    _n = len(events)
    for idx, ev in enumerate(events):
        if not ev.is_tool_call():
            continue
        if ev.session_id not in chain_sessions:
            continue
        a = parser._extract_action(ev)
        if a:
            actions.append(a)
    if session_chain_order:
        _pos = {sid: i for i, sid in enumerate(session_chain_order)}
        actions.sort(key=lambda a: (_pos.get(a.get("session_id", ""), 999), a.get("ts", 0)))
    else:
        actions.sort(key=lambda a: a.get("ts", 0))
    return actions


def collect_chain_findings(chain_sessions: set[str], findings: list[dict]) -> list[dict]:
    """找到在链上 session 提交的 finding。"""
    return [f for f in findings if f.get("session_id", "") in chain_sessions]


def build_session_chain(chain_sessions: set[str], events: list,
                        sink_hit_sessions: list[str] | None = None,
                        finding_sessions: list[str] | None = None,
                        session_graph: dict | None = None) -> list[dict]:
    """构建 session 链，按调用关系（parent_map）排序，标注 sink/finding。

    有 parent_map 时按父子调用关系排序（根→子→孙），无 parent_map 时退化为时间排序。
    返回: [{session_id, has_sink, has_finding, first_ts}, ...]
    """
    if not chain_sessions:
        return []

    sink_set = set(sink_hit_sessions or [])
    finding_set = set(finding_sessions or [])

    # 找每个 session 的最早事件时间戳
    session_first_ts: dict[str, int] = {}
    _n = len(events)
    for idx, e in enumerate(events):
        sid = e.session_id
        if sid not in chain_sessions:
            continue
        ts = e.timestamp_ms or 0
        if sid not in session_first_ts or ts < session_first_ts[sid]:
            session_first_ts[sid] = ts

    # 从 session_graph 提取 parent_map（有方向的父子关系）
    parent_map: dict[str, str] = {}
    if session_graph:
        parent_map = session_graph.get("parent_map", {})

    # 构建链内的 children 映射（仅限 chain_sessions 内的 parent→child）
    children: dict[str, list[str]] = {}
    has_parent_in_chain: set[str] = set()
    for sid in chain_sessions:
        pid = parent_map.get(sid)
        if pid and pid in chain_sessions:
            children.setdefault(pid, []).append(sid)
            has_parent_in_chain.add(sid)

    result: list[dict] = []

    def _make_entry(sid: str) -> dict:
        return {
            "session_id": sid,
            "has_sink": sid in sink_set,
            "has_finding": sid in finding_set,
            "first_ts": session_first_ts.get(sid, 0),
        }

    def _dfs(sid: str):
        """前序遍历：父→子→孙，兄弟按时间排序。"""
        result.append(_make_entry(sid))
        kids = children.get(sid, [])
        kids.sort(key=lambda s: session_first_ts.get(s, 0))
        for k in kids:
            _dfs(k)

    if children:
        # 有 parent_map：找根（在链内但 parent 不在链内的 session）
        roots = [sid for sid in chain_sessions if sid not in has_parent_in_chain]
        roots.sort(key=lambda s: session_first_ts.get(s, 0))
        for r in roots:
            _dfs(r)
    else:
        # 无 parent_map：退化为时间排序
        for sid in sorted(chain_sessions, key=lambda s: session_first_ts.get(s, 0)):
            result.append(_make_entry(sid))

    return result


def collect_chain_knowledge_interactions(chain_sessions: set[str], events: list,
                                         session_chain_order: list[str] | None = None) -> list[dict]:
    """提取链上的知识/记忆交互（完整问答对）。

    有 session_chain_order 时按 (链位置, 时间) 排序，无时按时间排序。
    通过 call_id 配对 TOOL_CALL → TOOL_RESULT，获取查询命令和返回内容。
    返回: [{tool, query, response, session_id, timestamp, is_kg, is_memory}, ...]
    """
    # 构建 call_id → TOOL_RESULT 映射
    result_by_call_id: dict[str, str] = {}
    _n = len(events)
    for idx, e in enumerate(events):
        if e.event_type == "TOOL_RESULT" and e.call_id:
            output = e.output_json
            if isinstance(output, str):
                result_by_call_id[e.call_id] = output
            elif output is not None:
                result_by_call_id[e.call_id] = str(output)

    interactions = []
    for idx, e in enumerate(events):
        if e.session_id not in chain_sessions:
            continue
        if not e.is_tool_call():
            continue
        if not (e.is_kg_interaction or e.is_memory_interaction):
            continue
        inp = e.input_json or {}
        query = str(inp.get("command") or inp.get("query") or inp.get("question") or inp.get("file_path") or "")
        response = result_by_call_id.get(e.call_id, "") if e.call_id else ""
        interactions.append({
            "tool": e.tool_name or "",
            "query": query,
            "response": response,
            "session_id": e.session_id,
            "timestamp": e.timestamp_ms or 0,
            "is_kg": e.is_kg_interaction,
            "is_memory": e.is_memory_interaction,
        })
    if session_chain_order:
        _pos = {sid: i for i, sid in enumerate(session_chain_order)}
        interactions.sort(key=lambda x: (_pos.get(x.get("session_id", ""), 999), x["timestamp"]))
    else:
        interactions.sort(key=lambda x: x["timestamp"])
    return interactions


def _match_finding_to_baseline(baseline_metadata: dict, findings: list[dict]) -> dict | None:
    """确定性匹配：baseline source_file basename vs finding source/sink/file basename。"""
    baseline_file = _basename(baseline_metadata.get("source_file", ""))
    if not baseline_file:
        return None
    for f in findings:
        for field in ("source", "sink", "file", "source_file"):
            val = f.get(field, "")
            if val and _basename(val) == baseline_file:
                return f
    return None


def sink_match_baselines(task_run, benchmarks: list, events: list, parser=None,
                         findings_override=None, progress_cb=None,
                         session_graph=None) -> tuple:
    """Sink 点匹配主入口 — 确定性匹配 + 链数据收集。

    流程：
    1. 提取 findings
    2. 构建文件读取索引
    3. 对每个基线做 sink 覆盖检查 → 定位 session → 分组链
    4. 确定性 confusion：finding 匹配 source_file + validation_result + expected_label
    5. 收集链数据（chain_actions, session_chain）供报告展示用

    返回: (OutcomeFact, case_results)
    """
    from ..domain.enums import Prediction, ExpectedLabel, Outcome
    from ..domain.facts import OutcomeFact

    def _progress(text):
        if progress_cb:
            try:
                progress_cb(text)
            except Exception:
                pass

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

    # Step 1: 提取 findings
    findings = findings_override if findings_override is not None else parser.extract_findings(events)
    active_findings = [f for f in findings if f.get("validation_result") in ("CONFIRMED", "FALSE_POSITIVE")]
    log("SINK_MATCH", f"{task_run.condition.value} findings={len(findings)} active={len(active_findings)}")

    # Agent 没提交任何有效 finding → VULNERABLE=NA, NON_VULNERABLE=TN
    if not active_findings:
        log("SINK_MATCH", f"{task_run.condition.value} NO_ACTIVE_FINDING → outcome=FAIL")
        case_results = []
        for b in benchmarks:
            cid = b.benchmark_item_id or ""
            is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
            case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                                "matched": False, "matched_finding_id": None, "finding_title": "",
                                "confusion": "NA" if is_vuln else "TN",
                                "session_id": "", "agent_validation": None,
                                "finding_ts": None,
                                "candidate_findings": [],
                                "sink_info": "", "sink_analysis": "", "no_finding_reason": "",
                                "knowledge_intervention": None, "chain_actions": [],
                                "mined": False, "sink_hit": False,
                                "sink_sessions": [], "sink_hit_sessions": [], "finding_session": "",
                                "session_chain": []})
        has_vuln = any(b.expected_label and b.expected_label.value == "VULNERABLE" for b in benchmarks)
        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmarks[0].benchmark_item_id,
            gt_label=ExpectedLabel.VULNERABLE if has_vuln else benchmarks[0].expected_label,
            prediction=Prediction.NEGATIVE,
            outcome=Outcome.FAIL,
            target_finding_id=benchmarks[0].target_finding_id,
            validation_result=None, resolver_status="NO_FINDING",
        ), case_results

    # Step 2: 构建文件读取索引
    file_reads = build_file_read_index(events)

    # Step 3: 构建 session graph（如调用方已构建则复用，避免重复遍历百万级 events）
    if session_graph is None:
        session_graph = parser.build_session_graph(events) if parser else {}

    # Step 4: 对每个基线做 sink 匹配 + 链分析
    _progress(f"Sink 匹配: 0/{len(benchmarks)} 基线完成")
    case_results = []
    matched_case_ids = set()
    matched_findings_info = {}  # case_id → finding info

    log("SINK_MATCH", f"{task_run.condition.value} 开始 sink 覆盖检查: {len(benchmarks)} 基线, "
          f"events={len(events)}, findings={len(active_findings)}")

    # 对每个基线，先做 sink 覆盖检查（确定性，无 LLM）
    sink_results: dict[int, dict] = {}  # baseline_idx → {sink_sessions, chains, has_sink_info}
    for bi, b in enumerate(benchmarks):
        md = b.metadata or {}
        source_file = md.get("source_file", "")
        source_line = md.get("source_line", "")
        source_function = md.get("source_function", "")

        if not source_file:
            # 无 sink 信息 → 无法预筛选，标记为需要 LLM 兜底
            sink_results[bi] = {"has_sink_info": False, "sink_sessions": [], "chains": []}
            continue

        sink_sessions = find_sink_sessions(file_reads, source_file, source_line, source_function)
        chains = group_chains(sink_sessions, session_graph)
        sink_results[bi] = {
            "has_sink_info": True,
            "sink_sessions": sink_sessions,
            "chains": chains,
        }
        log("SINK_MATCH", f"baseline[{bi}] case={b.benchmark_item_id} "
              f"file={_basename(source_file)} "
              f"sink_sessions={len(sink_sessions)} chains={len(chains)}")

    # Step 5: 确定性 confusion + 收集链数据
    for bi, b in enumerate(benchmarks):
        cid = b.benchmark_item_id or ""
        is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
        sr = sink_results[bi]
        md = b.metadata or {}

        # 确定性 finding 匹配
        matched_finding = _match_finding_to_baseline(md, active_findings)

        if matched_finding:
            vr = matched_finding.get("validation_result")
            if is_vuln:
                confusion = "TP" if vr == "CONFIRMED" else "FN"
            else:
                confusion = "FP" if vr == "CONFIRMED" else "TN"
            matched_case_ids.add(cid)
            matched_findings_info[cid] = matched_finding
            matched_fid = matched_finding.get("display_id") or matched_finding.get("finding_id", "")
            finding_title = matched_finding.get("title") or matched_finding.get("vuln_type", "")
            finding_session = matched_finding.get("session_id", "")
            _ei = matched_finding.get("_event_idx")
            finding_ts = events[_ei].timestamp_ms if _ei is not None and 0 <= _ei < len(events) else None
            log("SINK_MATCH", f"MATCHED case={cid} finding={matched_fid}")
        else:
            confusion = "FN" if is_vuln else "TN"
            matched_fid = ""
            finding_title = ""
            finding_session = ""
            finding_ts = None

        # 收集链数据（供报告展示用）
        if sr.get("has_sink_info") and sr.get("chains"):
            _chain_sessions = sr["chains"][0]
            _finding_sessions = [f.get("session_id", "") for f in active_findings if f.get("session_id")]
            _session_chain = build_session_chain(_chain_sessions, events, sr["sink_sessions"],
                                                  _finding_sessions, session_graph) if _chain_sessions else []
            _chain_order = [e["session_id"] for e in _session_chain]
            chain_actions = collect_chain_actions(_chain_sessions, events, parser, _chain_order) if _chain_sessions else []
            chain_finds = collect_chain_findings(_chain_sessions, active_findings) if _chain_sessions else []
            if not chain_finds and active_findings:
                chain_finds = list(active_findings)
            sink_info = f"命中 ({len(sr['chains'])}链, sessions={len(sr['sink_sessions'])})"
            sink_hit = True
        else:
            _session_chain = []
            chain_actions = []
            chain_finds = []
            sink_info = f"未命中 (file={_basename(md.get('source_file',''))})" if sr.get("has_sink_info") else "无 sink 信息"
            sink_hit = False
            _chain_sessions = set()

        case_results.append({
            "case_id": cid,
            "expected_label": b.expected_label.value if b.expected_label else "NA",
            "matched": matched_finding is not None,
            "matched_finding_id": matched_fid or None,
            "finding_title": finding_title,
            "confusion": confusion,
            "session_id": finding_session,
            "agent_validation": matched_finding.get("validation_result") if matched_finding else None,
            "finding_ts": finding_ts,
            "ac_case_id": matched_finding.get("ac_case_id", "") if matched_finding else "",
            "candidate_findings": [{
                "finding_id": f.get("display_id") or f.get("finding_id", ""),
                "title": f.get("title") or f.get("vuln_type") or "",
                "vuln_type": f.get("vuln_type", ""),
                "description": f.get("description") or "",
                "source": f.get("source") or "",
                "sink": f.get("sink") or "",
                "validation_result": f.get("validation_result"),
                "session_id": f.get("session_id", ""),
            } for f in chain_finds],
            "sink_info": sink_info,
            "sink_analysis": "",  # REPORTING 阶段由统一 LLM 填充
            "no_finding_reason": "",  # REPORTING 阶段由统一 LLM 填充
            "knowledge_intervention": None,  # REPORTING 阶段由统一 LLM 填充
            "chain_actions": chain_actions,
            "mined": matched_finding is not None,
            "sink_hit": sink_hit,
            "sink_sessions": sorted(_chain_sessions) if _chain_sessions else [],
            "sink_hit_sessions": sr.get("sink_sessions", []),
            "finding_session": finding_session,
            "session_chain": _session_chain,
        })

        _progress(f"Sink 匹配: {bi+1}/{len(benchmarks)} 基线完成")

    # Step 7: 聚合 outcome
    all_correct = all(c["confusion"] in ("TP", "TN") for c in case_results) if case_results else False
    has_vuln = any(b.expected_label and b.expected_label.value == "VULNERABLE" for b in benchmarks)

    # 找到 matched finding 的 validation_result
    vr = None
    for cid, f in matched_findings_info.items():
        vr = f.get("validation_result")
        break

    if all_correct:
        pred = "POSITIVE"; outcome = Outcome.SUCCESS; resolver_status = "SINK_MATCHED"
    else:
        pred = "NEGATIVE"; outcome = Outcome.FAIL
        resolver_status = "SINK_PARTIAL_MATCH" if matched_case_ids else "SINK_UNMATCHED"

    log("SINK_MATCH", f"{task_run.condition.value} baselines={len(benchmarks)} matched={len(matched_case_ids)}")

    oc = OutcomeFact(
        outcome_fact_id=f"ocf-{task_run.task_run_id}",
        task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
        condition=task_run.condition, condition_source=task_run.condition_source,
        benchmark_item_id=benchmarks[0].benchmark_item_id,
        gt_label=ExpectedLabel.VULNERABLE if has_vuln else benchmarks[0].expected_label,
        prediction=Prediction(pred),
        outcome=outcome,
        target_finding_id=benchmarks[0].target_finding_id,
        validation_result=vr, resolver_status=resolver_status,
        resolver_version="sink-1.0",
    )
    return oc, case_results
