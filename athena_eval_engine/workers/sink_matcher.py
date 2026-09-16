"""Sink 点匹配器 — 基于基线漏洞 sink 点（文件+行号/方法名）定位 session 链。

流程：
1. 扫描 trace 所有工具读文件操作，构建文件读取索引
2. 对每个基线，用 sink 点（文件名+行号/方法名）匹配文件读取记录
3. 命中的 session 通过 session graph 分组为链
4. 对每条链做 LLM 分析，判断是否是基线漏洞的挖掘过程
5. 根据 LLM 结论 + finding 提交情况赋值 confusion
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
    # 构建 call_id → TOOL_RESULT 映射
    result_by_call_id: dict[str, str] = {}
    for e in events:
        if e.event_type == "TOOL_RESULT" and e.call_id:
            output = e.output_json
            if isinstance(output, str):
                result_by_call_id[e.call_id] = output
            elif output is not None:
                result_by_call_id[e.call_id] = str(output)

    reads: list[dict] = []
    for e in events:
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
            # 检查行号是否在返回内容里（词边界匹配，避免 "5" 匹配 "15"/"50"）
            if re.search(r'\b' + str(target_line) + r'\b', r["content"]):
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


def collect_chain_actions(chain_sessions: set[str], events: list, parser) -> list[dict]:
    """收集链上所有 session 的工具调用行为（按时间排序）。

    复用 parser._extract_action 提取工具行为摘要。
    """
    if parser is None:
        return []
    actions = []
    for ev in events:
        if not ev.is_tool_call():
            continue
        if ev.session_id not in chain_sessions:
            continue
        a = parser._extract_action(ev)
        if a:
            actions.append(a)
    actions.sort(key=lambda a: a.get("ts", 0))
    return actions


def collect_chain_findings(chain_sessions: set[str], findings: list[dict]) -> list[dict]:
    """找到在链上 session 提交的 finding。"""
    return [f for f in findings if f.get("session_id", "") in chain_sessions]


def collect_chain_knowledge_interactions(chain_sessions: set[str], events: list) -> list[dict]:
    """提取链上的知识/记忆交互（完整问答对）。

    通过 call_id 配对 TOOL_CALL → TOOL_RESULT，获取查询命令和返回内容。
    返回: [{tool, query, response, session_id, timestamp, is_kg, is_memory}, ...]
    """
    # 构建 call_id → TOOL_RESULT 映射
    result_by_call_id: dict[str, str] = {}
    for e in events:
        if e.event_type == "TOOL_RESULT" and e.call_id:
            output = e.output_json
            if isinstance(output, str):
                result_by_call_id[e.call_id] = output
            elif output is not None:
                result_by_call_id[e.call_id] = str(output)

    interactions = []
    for e in events:
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
    interactions.sort(key=lambda x: x["timestamp"])
    return interactions


def analyze_chain_llm(chain_actions: list[dict], chain_findings: list[dict],
                      baseline: dict, llm_module,
                      chain_knowledge_interactions: list[dict] | None = None) -> dict:
    """LLM 分析整条 session 链，判断是否是基线漏洞的挖掘过程。

    如果判定为是且链上无 finding，会进一步分析：
    - agent 是否分析后认为非漏洞（合理排除）
    - 知识/记忆是否介入了决策：问了什么、回复了什么、做了什么决策、决策影响

    返回: {"is_mining": bool, "reason": str, "no_finding_reason": str,
           "knowledge_intervention": {"query": ..., "response": ..., "decision": ..., "impact": ...} | None}
    """
    # 格式化挖掘行为摘要
    action_lines = []
    for i, a in enumerate(chain_actions[:200]):
        tool = a.get("tool", "")
        action = a.get("action", "")
        sid = a.get("session_id", "")[-8:]
        action_lines.append(f"[{i+1}] {tool}: {action} (session:{sid})")
    if len(chain_actions) > 200:
        action_lines.append(f"... 还有 {len(chain_actions)-200} 条行为")

    # 格式化链上 finding
    finding_lines = []
    for f in chain_findings:
        title = f.get("title", "")
        vuln_type = f.get("vuln_type", "")
        vr = f.get("validation_result", "")
        finding_lines.append(f"- 标题: {title}, 类型: {vuln_type}, 判定: {vr}")

    sink_loc = baseline.get("source_file", "")
    if baseline.get("source_line"):
        sink_loc += f":行{baseline['source_line']}"
    elif baseline.get("source_function"):
        sink_loc += f":{baseline['source_function']}"

    has_finding = len(chain_findings) > 0
    has_knowledge = bool(chain_knowledge_interactions)

    # 格式化知识/记忆交互
    ki_lines = []
    if has_knowledge:
        for i, ki in enumerate(chain_knowledge_interactions):
            ki_type = "知识" if ki.get("is_kg") else "记忆" if ki.get("is_memory") else "知识/记忆"
            ki_lines.append(f"[{i+1}] {ki_type}查询 ({ki.get('tool','')}): {ki.get('query','')[:200]}")
            ki_lines.append(f"    回复: {ki.get('response','')[:200]}")

    system_prompt = (
        "你是漏洞挖掘过程分析器。下面给你一条 session 链的工具调用行为记录和基线漏洞信息。\n"
        "请判断这条 session 链是否是在挖掘指定基线漏洞。\n\n"
        "# 判断依据\n"
        "1. 链上的文件读取/搜索行为是否指向基线漏洞的 sink 点（文件+行号/方法名）\n"
        "2. 链上的工具调用是否围绕基线漏洞描述的漏洞类型展开\n"
        "3. 链上提交的 finding 是否与基线漏洞描述的是同一个漏洞\n"
        "4. Agent 可能挖掘多个漏洞，只有与基线漏洞 sink 点直接相关的行为才算\n"
        "5. 碰巧读了同一个文件但挖掘的是不同漏洞的，不算\n\n"
        "# 输出格式\n"
        '只返回 JSON: {"is_mining": true/false, "reason": "简要说明判断依据"'
    )

    # 如果链上无 finding，追加分析
    if not has_finding:
        system_prompt += (
            ', "no_finding_reason": "分析 agent 为什么没有为此漏洞生成 finding。'
            '可能的原因：agent 分析后认为非漏洞（合理排除）、知识不足、推理错误、工具限制等。"}'
        )
        if has_knowledge:
            system_prompt += (
                ', "knowledge_intervention": {'
                '"query": "agent 向知识/记忆系统问了什么（概括）", '
                '"response": "知识/记忆系统回复了什么（概括）", '
                '"decision": "agent 得到回复后做了什么决策", '
                '"impact": "positive/negative/neutral — 此决策对此漏洞挖掘的影响"}'
            )
        else:
            system_prompt += (
                ', "knowledge_intervention": null'
            )
        system_prompt += '}'
    else:
        system_prompt += '"}'
    system_prompt += '\n不要输出其他内容。'

    user_data = {
        "基线漏洞": {
            "漏洞类型": baseline.get("vulnerability_type", ""),
            "描述": baseline.get("description", ""),
            "sink点位置": sink_loc,
        },
        "链上挖掘行为": "\n".join(action_lines),
        "链上提交的finding": "\n".join(finding_lines) if finding_lines else "无",
    }
    if has_knowledge:
        user_data["知识/记忆交互记录"] = "\n".join(ki_lines)

    prompt = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_data, ensure_ascii=False, indent=2)},
    ]

    try:
        result = llm_module.chat_json(prompt, temperature=0, max_tokens=2000)
        is_mining = bool(result.get("is_mining", False)) if isinstance(result, dict) else False
        reason = str(result.get("reason", "")) if isinstance(result, dict) else ""
        no_finding_reason = str(result.get("no_finding_reason", "")) if isinstance(result, dict) else ""
        ki = result.get("knowledge_intervention") if isinstance(result, dict) else None
        if ki is not None and not isinstance(ki, dict):
            ki = None
        return {"is_mining": is_mining, "reason": reason,
                "no_finding_reason": no_finding_reason,
                "knowledge_intervention": ki}
    except Exception as e:
        log("SINK_MATCH", f"LLM 链分析失败: {e}")
        return {"is_mining": False, "reason": f"LLM 分析失败: {e}",
                "no_finding_reason": "", "knowledge_intervention": None}


def sink_match_baselines(task_run, benchmarks: list, events: list, parser=None,
                         findings_override=None, progress_cb=None) -> tuple:
    """Sink 点匹配主入口 — 替换 ai_match_outcome 中的 LLM 匹配阶段。

    流程：
    1. 提取 findings（保留，用于 TP/FN 判断和报告展示）
    2. 构建文件读取索引
    3. 对每个基线做 sink 覆盖检查 → 定位 session → 分组链
    4. 对每条链 LLM 分析 → 是/不是基线漏洞的挖掘过程
    5. 根据 LLM 结论 + finding 提交情况赋值 confusion

    返回: (OutcomeFact, case_results)
    """
    from ..domain.enums import Prediction, Confusion, ExpectedLabel, Outcome
    from ..domain.facts import OutcomeFact
    from ..infrastructure import llm as llm_mod

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
                                "mined": False, "sink_hit": False})
        has_vuln = any(b.expected_label and b.expected_label.value == "VULNERABLE" for b in benchmarks)
        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmarks[0].benchmark_item_id,
            gt_label=ExpectedLabel.VULNERABLE if has_vuln else benchmarks[0].expected_label,
            prediction=Prediction.NEGATIVE,
            outcome=Outcome.FAIL, confusion_label=Confusion.NA if has_vuln else Confusion.TN,
            target_finding_id=benchmarks[0].target_finding_id,
            validation_result=None, resolver_status="NO_FINDING",
        ), case_results

    # Step 2: 构建文件读取索引
    file_reads = build_file_read_index(events)

    # Step 3: 构建 session graph
    session_graph = parser.build_session_graph(events) if parser else {}

    # Step 4: 对每个基线做 sink 匹配 + 链分析
    _progress(f"Sink 匹配: 0/{len(benchmarks)} 基线完成")
    case_results = []
    matched_case_ids = set()
    matched_findings_info = {}  # case_id → finding info

    from concurrent.futures import ThreadPoolExecutor, as_completed

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

    # Step 5: 对有 sink 命中的基线，并行做 LLM 链分析
    llm_tasks = []  # [(bi, chain_idx, chain_sessions), ...]
    for bi, sr in sink_results.items():
        if not sr["has_sink_info"] or not sr["chains"]:
            continue
        for ci, chain in enumerate(sr["chains"]):
            llm_tasks.append((bi, ci, chain))

    log("SINK_MATCH", f"LLM 链分析任务: {len(llm_tasks)} 条链")

    # 并行分析所有链
    chain_analyses: dict[tuple[int, int], dict] = {}  # (bi, ci) → {is_mining, reason}
    if llm_tasks and llm_mod.is_enabled():
        _progress(f"Sink 链分析: 0/{len(llm_tasks)} 链完成")
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {}
            for bi, ci, chain in llm_tasks:
                b = benchmarks[bi]
                md = b.metadata or {}
                baseline_info = {
                    "vulnerability_type": md.get("vulnerability_type", ""),
                    "description": md.get("description", ""),
                    "source_file": md.get("source_file", ""),
                    "source_line": md.get("source_line", ""),
                    "source_function": md.get("source_function", ""),
                }
                chain_actions = collect_chain_actions(chain, events, parser)
                chain_finds = collect_chain_findings(chain, active_findings)
                chain_kis = collect_chain_knowledge_interactions(chain, events)
                fut = pool.submit(analyze_chain_llm, chain_actions, chain_finds,
                                  baseline_info, llm_mod, chain_kis)
                futures[fut] = (bi, ci)

            done = 0
            for fut in as_completed(futures):
                bi, ci = futures[fut]
                try:
                    result = fut.result()
                    chain_analyses[(bi, ci)] = result
                except Exception as e:
                    log("SINK_MATCH", f"链分析失败 (b{bi},c{ci}): {e}")
                    chain_analyses[(bi, ci)] = {"is_mining": False, "reason": f"分析失败: {e}",
                                                "no_finding_reason": "", "knowledge_intervention": None}
                done += 1
                _progress(f"Sink 链分析: {done}/{len(llm_tasks)} 链完成")

    # Step 6: 赋值 confusion
    for bi, b in enumerate(benchmarks):
        cid = b.benchmark_item_id or ""
        is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
        sr = sink_results[bi]

        if not sr["has_sink_info"]:
            # 无 sink 信息 → 走原 LLM 匹配兜底（标记为需要 LLM 兜底）
            # 暂时按未匹配处理
            confusion = "NA" if is_vuln else "TN"
            case_results.append({
                "case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                "matched": False, "matched_finding_id": None, "finding_title": "",
                "confusion": confusion, "session_id": "", "agent_validation": None,
                "finding_ts": None,
                "candidate_findings": [],
                "sink_info": "无 sink 信息", "sink_analysis": "", "no_finding_reason": "",
                "knowledge_intervention": None, "chain_actions": [],
                "mined": False, "sink_hit": False,
            })
            continue

        if not sr["chains"]:
            # sink 未命中 → FN (VULNERABLE) / TN (NON_VULNERABLE)
            confusion = "NA" if is_vuln else "TN"
            case_results.append({
                "case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                "matched": False, "matched_finding_id": None, "finding_title": "",
                "confusion": confusion, "session_id": "", "agent_validation": None,
                "finding_ts": None,
                "candidate_findings": [],
                "sink_info": f"未命中 (file={_basename((b.metadata or {}).get('source_file',''))})",
                "sink_analysis": "", "no_finding_reason": "",
                "knowledge_intervention": None, "chain_actions": [],
                "mined": False, "sink_hit": False,
            })
            continue

        # 有 sink 命中 → 检查 LLM 链分析结果
        any_mining = False
        mining_chain = None
        mining_reason = ""
        no_finding_reason = ""
        knowledge_intervention = None
        for ci, chain in enumerate(sr["chains"]):
            analysis = chain_analyses.get((bi, ci), {"is_mining": False, "reason": "未分析"})
            if analysis.get("is_mining"):
                any_mining = True
                mining_chain = chain
                mining_reason = analysis.get("reason", "")
                no_finding_reason = analysis.get("no_finding_reason", "")
                knowledge_intervention = analysis.get("knowledge_intervention")
                break

        # 收集链上行为和 finding（用于报告展示）
        chain_actions = []
        chain_findings = []
        if mining_chain:
            chain_actions = collect_chain_actions(mining_chain, events, parser)
            chain_findings = collect_chain_findings(mining_chain, active_findings)
        else:
            # LLM 判定非挖掘，仍收集第一条链的行为供报告参考
            if sr["chains"]:
                chain_actions = collect_chain_actions(sr["chains"][0], events, parser)
                chain_findings = collect_chain_findings(sr["chains"][0], active_findings)

        if any_mining and chain_findings:
            # LLM=是 + 有 finding → TP
            confusion = "TP" if is_vuln else "FP"
            matched_case_ids.add(cid)
            f = chain_findings[0]
            matched_fid = f.get("display_id") or f.get("finding_id", "")
            finding_title = f.get("title") or f.get("vuln_type") or ""
            finding_session = f.get("session_id", "")
            matched_vr = f.get("validation_result")
            matched_findings_info[cid] = f
            _ei = f.get("_event_idx")
            finding_ts = events[_ei].timestamp_ms if _ei is not None and 0 <= _ei < len(events) else None
            log("SINK_MATCH", f"MATCHED case={cid} ← finding={matched_fid} reason={mining_reason}")
            case_results.append({
                "case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                "matched": True, "matched_finding_id": matched_fid, "finding_title": finding_title,
                "confusion": confusion, "session_id": finding_session, "agent_validation": matched_vr,
                "finding_ts": finding_ts,
                "candidate_findings": [{
                    "finding_id": f.get("display_id") or f.get("finding_id", ""),
                    "title": f.get("title") or f.get("vuln_type") or "",
                    "vuln_type": f.get("vuln_type", ""),
                    "description": f.get("description") or "",
                    "source": f.get("source") or "",
                    "sink": f.get("sink") or "",
                    "validation_result": f.get("validation_result"),
                    "session_id": f.get("session_id", ""),
                } for f in chain_findings],
                "sink_info": f"命中 ({len(sr['chains'])}链, reason={mining_reason[:50]})",
                "sink_analysis": mining_reason,
                "no_finding_reason": "",
                "knowledge_intervention": None,
                "chain_actions": chain_actions,
                "mined": True, "sink_hit": True,
            })
        elif any_mining and not chain_findings:
            # LLM=是 + 无 finding → FN（挖了但没报）
            # no_finding_reason 由 LLM 分析为什么没有生成 finding
            confusion = "FN" if is_vuln else "TN"
            log("SINK_MATCH", f"MINED_NO_FINDING case={cid} reason={no_finding_reason[:80]}")
            case_results.append({
                "case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                "matched": False, "matched_finding_id": None, "finding_title": "",
                "confusion": confusion, "session_id": "", "agent_validation": None,
                "finding_ts": None,
                "candidate_findings": [],
                "sink_info": f"命中但无finding ({mining_reason[:50]})",
                "sink_analysis": mining_reason,
                "no_finding_reason": no_finding_reason,
                "knowledge_intervention": knowledge_intervention,
                "chain_actions": chain_actions,
                "mined": True, "sink_hit": True,
            })
        else:
            # LLM=不是 → 检查是否有 finding
            if chain_findings:
                # LLM=不是 + 有 finding → FP
                confusion = "FP" if is_vuln else "TN"
            else:
                # LLM=不是 + 无 finding → TN
                confusion = "TN"
            case_results.append({
                "case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                "matched": False, "matched_finding_id": None, "finding_title": "",
                "confusion": confusion, "session_id": "", "agent_validation": None,
                "finding_ts": None,
                "candidate_findings": [],
                "sink_info": f"LLM判定非挖掘 ({len(sr['chains'])}链)",
                "sink_analysis": "",
                "no_finding_reason": "",
                "knowledge_intervention": None,
                "chain_actions": chain_actions,
                "mined": False, "sink_hit": True,
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
        pred = "POSITIVE"; outcome = Outcome.SUCCESS; confusion_label = Confusion.TP; resolver_status = "SINK_MATCHED"
    else:
        pred = "NEGATIVE"; outcome = Outcome.FAIL
        confusions = {c["confusion"] for c in case_results}
        if "NA" in confusions:
            confusion_label = Confusion.NA
        elif "FN" in confusions:
            confusion_label = Confusion.FN
        elif "FP" in confusions:
            confusion_label = Confusion.FP
        else:
            confusion_label = Confusion.FN
        resolver_status = "SINK_PARTIAL_MATCH" if matched_case_ids else "SINK_UNMATCHED"

    log("SINK_MATCH", f"{task_run.condition.value} baselines={len(benchmarks)} matched={len(matched_case_ids)} "
          f"llm_chains={len(llm_tasks)}")

    oc = OutcomeFact(
        outcome_fact_id=f"ocf-{task_run.task_run_id}",
        task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
        condition=task_run.condition, condition_source=task_run.condition_source,
        benchmark_item_id=benchmarks[0].benchmark_item_id,
        gt_label=ExpectedLabel.VULNERABLE if has_vuln else benchmarks[0].expected_label,
        prediction=Prediction(pred),
        outcome=outcome, confusion_label=confusion_label,
        target_finding_id=benchmarks[0].target_finding_id,
        validation_result=vr, resolver_status=resolver_status,
        resolver_version="sink-1.0",
    )
    return oc, case_results
