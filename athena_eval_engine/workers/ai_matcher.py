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
from ..domain.raw_event import RawEvent
from ..domain.facts import OutcomeFact, Evidence
from ..domain.task_run import TaskRun, BenchmarkItem
from ..domain.enums import Outcome, Prediction, Confusion, ExpectedLabel
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log


def _ev(e: RawEvent, fp=None):
    return Evidence(trace_id=e.trace_id, session_id=e.session_id, message_id=e.message_id,
                    part_id=e.part_id, tool_name=e.tool_name, event_timestamp=e.timestamp_ms, field_path=fp)


def match_alert_center_to_findings(alert_center_cases: list[dict], findings: list[dict],
                                    progress_cb=None) -> tuple[dict[int, int], set[int]]:
    """AI 匹配告警中心 cases ↔ trace findings（跟基线一样的方案）。

    告警中心 case 为锚点（同 ai_match_outcome 中基线为锚点），
    两阶段匹配：标题预筛 → 1vs1 LLM。
    一对一约束：匹配上的 finding 从候选池移除。

    返回:
      matched: {finding_idx: ac_case_idx} — 匹配上的 finding → 告警中心 case
      unmatched_ac_indices: set[int] — 未匹配上任何 finding 的告警中心 case 索引
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _progress(text):
        if progress_cb:
            try:
                progress_cb(text)
            except Exception:
                pass

    if not alert_center_cases or not findings:
        log("AC_MATCH", f"ac_cases={len(alert_center_cases)} findings={len(findings)} → 跳过匹配")
        return {}, set(range(len(alert_center_cases)))

    # 只取有 validation_result 的 finding 参与匹配，记录原始索引映射
    active_to_orig: dict[int, int] = {}  # active_idx → original_idx
    active_findings = []
    for i, f in enumerate(findings):
        if f.get("validation_result") in ("CONFIRMED", "FALSE_POSITIVE"):
            active_to_orig[len(active_findings)] = i
            active_findings.append(f)
    if not active_findings:
        log("AC_MATCH", "无 active findings → 全部告警中心 case 未匹配")
        return {}, set(range(len(alert_center_cases)))

    log("AC_MATCH", f"ac_cases={len(alert_center_cases)} active_findings={len(active_findings)}")

    # 构建精简描述
    ac_list = []
    for c in alert_center_cases:
        ac_list.append({
            "case_id": c.get("case_id") or "",
            "title": c.get("title") or "",
            "summary": c.get("summary") or "",
        })
    finding_list = []
    for f in active_findings:
        finding_list.append({
            "title": f.get("title") or "",
            "vuln_type": f.get("vuln_type", ""),
            "description": f.get("description") or "",
            "source": f.get("source", ""),
            "sink": f.get("sink", ""),
        })

    def _abbrev(s: str, n: int = 200) -> str:
        s = s or ""
        if len(s) <= n:
            return s
        h = n // 2
        return s[:h] + "..." + s[-h:]

    # === Phase 1: 标题预筛选（每告警中心 case 1 次 LLM，O(M) 调用）===
    _PREFILTER_LIMIT = 50
    available_finding_indices = list(range(len(active_findings)))
    matched: dict[int, int] = {}  # finding_idx → ac_case_idx
    matched_ac_ids: set[str] = set()

    _progress(f"告警中心匹配 预筛选: 0/{len(alert_center_cases)} 完成")
    _prefilter_sys = (
        "下面是一些代码安全漏洞的标题和描述摘要。"
        "请从标题和描述分析哪些漏洞报告跟该告警中心案例描述的是同一个漏洞。"
        "将可能匹配的漏洞的 ID 原样返回，便于核对。"
        "只返回 JSON：{\"possible_ids\": [\"ID1\", \"ID2\"]}。"
        "无匹配返回空数组 []。"
    )

    def _prefilter_one(ai: int) -> tuple[int, list[int]]:
        """预筛选：告警中心 case 标题+摘要 + finding 标题+描述 → 候选 finding 索引。"""
        ac = ac_list[ai]
        id_to_idx: dict[str, int] = {}
        lines = [
            f"告警中心案例标题：{ac.get('title', '')}",
            f"案例摘要：{_abbrev(ac.get('summary') or '')}",
            "",
            "以下是要比较的漏洞报告：",
        ]
        for i, f in enumerate(active_findings[:_PREFILTER_LIMIT]):
            fid = f.get("display_id") or f.get("finding_id", "") or str(i)
            id_to_idx[fid] = i
            _title = finding_list[i].get("title", "")
            _desc = _abbrev(finding_list[i].get("description") or "")
            lines.append(f"[{fid}] {_title} {_desc}")
        user_msg = "\n".join(lines)
        prompt = [
            {"role": "system", "content": _prefilter_sys},
            {"role": "user", "content": user_msg},
        ]
        result = llm_mod.chat_json(prompt, temperature=0, max_tokens=2000)
        indices = []
        if isinstance(result, dict):
            raw_ids = result.get("possible_ids", [])
            indices = [id_to_idx[x] for x in raw_ids
                       if isinstance(x, str) and x in id_to_idx]
        return ai, indices

    prefilter_candidates: dict[int, list[int]] = {}
    prefilter_done = 0
    with ThreadPoolExecutor(max_workers=8) as pre_pool:
        pre_futures = {}
        for ai in range(len(alert_center_cases)):
            fut = pre_pool.submit(_prefilter_one, ai)
            pre_futures[fut] = ai
        for fut in as_completed(pre_futures):
            ai = pre_futures[fut]
            try:
                _, indices = fut.result()
                prefilter_candidates[ai] = indices
            except Exception as e:
                prefilter_candidates[ai] = list(range(len(active_findings)))
                log("AC_MATCH", f"prefilter FAILED (ac{ai}): {e}, fallback all")
            prefilter_done += 1
            _progress(f"告警中心匹配 预筛选: {prefilter_done}/{len(alert_center_cases)} 完成")

    total_cand = sum(len(v) for v in prefilter_candidates.values())
    log("AC_MATCH", f"prefilter: {len(alert_center_cases)} ac_cases, {total_cand} candidates "
          f"(avg {total_cand / max(len(alert_center_cases), 1):.1f}/case)")

    # === Phase 2: 详细 1vs1 对比 ===
    _progress(f"告警中心匹配 详细对比: 0/{len(alert_center_cases)} 完成 (已匹配 0)")
    _sys_prompt = (
        "# 角色\n"
        "你是漏洞匹配判定器。判断给定的告警中心案例和漏洞报告是否描述的是同一个漏洞。\n\n"
        "# 判断规则\n"
        "1. 同一个漏洞 = 相同漏洞类型 + 相同入口/source + 相同 sink + 相同文件/函数位置\n"
        "2. 路径格式可能不同：如 'src/main/java/.../FileService.java' 和 'FileService.java' 可能是同一文件\n"
        "3. 函数名相同是强信号，但描述的漏洞行为也需吻合\n"
        "4. 漏洞类型可能用不同术语：如 '注入' 和 'SQL Injection' 是同一类型\n"
        "5. 仅漏洞类型相同但位置/函数不同的，不是同一个漏洞\n"
        "6. 不看结论对错：只要描述的是同一个漏洞就返回 true\n\n"
        "# 输出格式\n"
        '只返回 JSON：{"is_same": true} 或 {"is_same": false}，不要任何额外文字。'
    )

    def _check_pair(ai: int, fi: int, ac_desc: dict, fd_desc: dict) -> tuple[int, int, bool]:
        prompt = [
            {"role": "system", "content": _sys_prompt},
            {"role": "user", "content": json.dumps({
                "告警中心案例": ac_desc, "漏洞报告": fd_desc,
            }, ensure_ascii=False, indent=2)},
        ]
        result = llm_mod.chat_json(prompt, temperature=0, max_tokens=2000)
        is_same = bool(result.get("is_same", False)) if isinstance(result, dict) else bool(result)
        return ai, fi, is_same

    llm_call_count = 0
    # 告警中心 case 串行（一对一约束），每个 case 内候选 finding 并行
    with ThreadPoolExecutor(max_workers=8) as pool:
        for ai in range(len(alert_center_cases)):
            if not available_finding_indices:
                break

            candidates = prefilter_candidates.get(ai, list(range(len(active_findings))))
            candidates = [fi for fi in candidates if fi in available_finding_indices]
            if not candidates:
                _progress(f"告警中心匹配 详细对比: {ai+1}/{len(alert_center_cases)} 完成 (已匹配 {len(matched_ac_ids)})")
                continue

            futures = {}
            for fi in candidates:
                fut = pool.submit(_check_pair, ai, fi, {
                    "title": ac_list[ai].get("title", ""),
                    "summary": ac_list[ai].get("summary", ""),
                }, finding_list[fi])
                futures[fut] = fi
                llm_call_count += 1

            case_matched = False
            for fut in as_completed(futures):
                try:
                    _, fi, is_same = fut.result()
                except Exception as e:
                    log("AC_MATCH", f"LLM 重试耗尽 (ac{ai},f{fi}): {e}")
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    raise
                if is_same and fi in available_finding_indices:
                    orig_fi = active_to_orig[fi]
                    matched[orig_fi] = ai
                    matched_ac_ids.add(ac_list[ai].get("case_id", ""))
                    available_finding_indices.remove(fi)
                    case_matched = True
                    log("AC_MATCH", f"MATCHED ac_case[{ai}]={ac_list[ai].get('case_id','')} ← finding[{orig_fi}]")
                    break

            for f in futures:
                if not f.done():
                    f.cancel()

            if not case_matched:
                log("AC_MATCH", f"UNMATCHED ac_case[{ai}] id={ac_list[ai].get('case_id','')}")
            _progress(f"告警中心匹配 详细对比: {ai+1}/{len(alert_center_cases)} 完成 (已匹配 {len(matched_ac_ids)})")

    unmatched_ac_indices = set(range(len(alert_center_cases))) - {v for v in matched.values()}
    log("AC_MATCH", f"ac_cases={len(alert_center_cases)} matched={len(matched)} "
          f"unmatched_ac={len(unmatched_ac_indices)} detail_llm={llm_call_count}")

    return matched, unmatched_ac_indices


def ai_match_outcome(task_run: TaskRun, benchmarks: list, events: list[RawEvent], parser=None, progress_cb=None,
                     findings_override=None) -> tuple[OutcomeFact, list]:
    """Stage 1B：AI 匹配 Agent findings → 基线漏洞列表 → outcome。

    基线可能有多个漏洞 case，Agent 也提交多个 finding。
    逐个对比基线 case 与 Agent finding，判断 Agent 是否找到了全部基线漏洞。

    progress_cb: 可选回调 fn(text: str)，用于向前端报告匹配进度。
    """
    from ..domain.enums import Prediction, Confusion
    from ..workers.resolvers import OutcomeResolverImpl

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

    findings = findings_override if findings_override is not None else parser.extract_findings(events)
    # 所有 CONFIRMED + FALSE_POSITIVE 的 finding 参与匹配，UNDETERMINED(None) 不参与
    active_findings = [f for f in findings if f.get("validation_result") in ("CONFIRMED", "FALSE_POSITIVE")]
    log("AI_MATCH", f"{task_run.condition.value} findings_extracted={len(findings)} active={len(active_findings)} "
          f"(CONFIRMED={sum(1 for f in active_findings if f.get('validation_result')=='CONFIRMED')} "
          f"FALSE_POSITIVE={sum(1 for f in active_findings if f.get('validation_result')=='FALSE_POSITIVE')})")
    for i, f in enumerate(active_findings[:5]):
        log("AI_MATCH", f"finding[{i}] id={f.get('display_id') or f.get('finding_id','')} "
              f"title={str(f.get('title',''))} vuln_type={str(f.get('vuln_type',''))} "
              f"validation={f.get('validation_result')}")
    if len(active_findings) > 5:
        log("AI_MATCH", f"...还有 {len(active_findings)-5} 条 finding")

    # Agent 没提交任何有效 finding → VULNERABLE=NA（未找到），NON-VULNERABLE=TN（正确）
    if not active_findings:
        log("AI_MATCH", f"{task_run.condition.value} NO_ACTIVE_FINDING → outcome=FAIL")
        case_results = []
        for b in benchmarks:
            cid = b.benchmark_item_id or ""
            is_vuln = b.expected_label and b.expected_label.value == "VULNERABLE"
            case_results.append({"case_id": cid, "expected_label": b.expected_label.value if b.expected_label else "NA",
                                "matched": False, "matched_finding_id": None,
                                "confusion": "NA" if is_vuln else "TN",
                                "session_id": "", "agent_validation": None})
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
        })

    # === 两阶段匹配：Phase 1 标题预筛选 → Phase 2 详细 1vs1 ===
    from concurrent.futures import ThreadPoolExecutor, as_completed

    _PREFILTER_LIMIT = 50  # 预筛选 finding 数量上限，防止 token 超限
    available_indices = list(range(len(active_findings)))
    matches = []  # [(finding_idx, baseline_idx)]
    matched_case_ids = set()

    # --- Phase 1: 标题预筛选（每基线 1 次 LLM，O(N) 调用）---
    _progress(f"漏洞匹配 预筛选: 0/{len(benchmarks)} 基线完成")
    _prefilter_sys = (
        "下面是一些代码安全漏洞的标题和描述摘要。"
        "请从标题和描述分析哪些漏洞跟基线描述的是同一个漏洞。"
        "将可能匹配的漏洞的 ID 原样返回，便于核对。"
        "只返回 JSON：{\"possible_ids\": [\"ID1\", \"ID2\"]}。"
        "无匹配返回空数组 []。"
    )

    def _prefilter_one(bi: int) -> tuple[int, list[int]]:
        """预筛选：基线标题+描述摘要 + 漏洞报告标题+描述摘要 → 候选漏洞报告索引。"""
        def _abbrev(s: str, n: int = 200) -> str:
            """取前 n/2 + ... + 后 n/2，不足 n 的全显示。"""
            s = s or ""
            if len(s) <= n:
                return s
            h = n // 2
            return s[:h] + "..." + s[-h:]
        bl = baseline_list[bi]
        baseline_title = bl.get("vulnerability_type", "")
        baseline_desc = _abbrev(bl.get("description") or "")
        # ID → finding_list 索引映射（用于核对返回的 ID）
        id_to_idx: dict[str, int] = {}
        lines = [f"基线漏洞标题：{baseline_title}", f"基线漏洞描述：{baseline_desc}", "", "以下是要比较的漏洞："]
        for i, f in enumerate(active_findings[:_PREFILTER_LIMIT]):
            fid = f.get("display_id") or f.get("finding_id", "") or str(i)
            id_to_idx[fid] = i
            _title = finding_list[i].get("title", "")
            _desc = _abbrev(finding_list[i].get("description") or "")
            lines.append(f"[{fid}] {_title} {_desc}")
        user_msg = "\n".join(lines)
        prompt = [
            {"role": "system", "content": _prefilter_sys},
            {"role": "user", "content": user_msg},
        ]
        result = llm_mod.chat_json(prompt, temperature=0, max_tokens=2000)
        indices = []
        if isinstance(result, dict):
            raw_ids = result.get("possible_ids", [])
            indices = [id_to_idx[x] for x in raw_ids
                       if isinstance(x, str) and x in id_to_idx]
        return bi, indices

    prefilter_candidates: dict[int, list[int]] = {}
    prefilter_llm_calls = 0
    prefilter_done = 0
    with ThreadPoolExecutor(max_workers=8) as pre_pool:
        pre_futures = {}
        for bi in range(len(benchmarks)):
            fut = pre_pool.submit(_prefilter_one, bi)
            pre_futures[fut] = bi
            prefilter_llm_calls += 1
        for fut in as_completed(pre_futures):
            bi = pre_futures[fut]
            try:
                _, indices = fut.result()
                prefilter_candidates[bi] = indices
            except Exception as e:
                # 预筛选失败 → fallback 到全部 finding
                prefilter_candidates[bi] = list(range(len(active_findings)))
                log("AI_MATCH", f"{task_run.condition.value} prefilter FAILED (b{bi}): {e}, fallback all")
            prefilter_done += 1
            _progress(f"漏洞匹配 预筛选: {prefilter_done}/{len(benchmarks)} 基线完成")

    total_cand = sum(len(v) for v in prefilter_candidates.values())
    log("AI_MATCH", f"{task_run.condition.value} prefilter: {len(benchmarks)} baselines, "
          f"{prefilter_llm_calls} calls, {total_cand} candidates "
          f"(avg {total_cand / max(len(benchmarks), 1):.1f}/baseline, "
          f"was {len(benchmarks) * len(active_findings)} pairs)")

    # --- Phase 2: 详细 1vs1 对比（仅对预筛选候选）---
    _progress(f"漏洞匹配 详细对比: 0/{len(benchmarks)} 基线完成 (已匹配 0)")
    _sys_prompt = (
        "# 角色\n"
        "你是漏洞匹配判定器。判断给定的漏洞报告和基线漏洞是否描述的是同一个漏洞。\n\n"
        "# 判断规则\n"
        "1. 同一个漏洞 = 相同漏洞类型 + 相同入口/source + 相同 sink + 相同文件/函数位置\n"
        "2. 路径格式可能不同：如 'src/main/java/.../FileService.java' 和 'FileService.java' 可能是同一文件\n"
        "3. 函数名相同是强信号，但描述的漏洞行为也需吻合\n"
        "4. 漏洞类型可能用不同术语：如 '注入' 和 'SQL Injection' 是同一类型\n"
        "5. 仅漏洞类型相同但位置/函数不同的，不是同一个漏洞\n"
        "6. 不看结论对错：即使漏洞报告和基线对该漏洞的结论不同（一个是漏洞、一个不是），只要描述的是同一个漏洞就返回 true\n\n"
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
                "基线漏洞": bl_desc, "漏洞报告": fd_desc,
            }, ensure_ascii=False, indent=2)},
        ]
        result = llm_mod.chat_json(prompt, temperature=0, max_tokens=2000)
        is_same = bool(result.get("is_same", False)) if isinstance(result, dict) else bool(result)
        return fi, is_same

    llm_call_count = 0

    # baseline 串行（finding 一对一约束），每个 baseline 内候选 finding 并行发送
    with ThreadPoolExecutor(max_workers=8) as pool:
        for bi, b in enumerate(benchmarks):
            cid = b.benchmark_item_id or ""
            if not available_indices:
                _progress(f"漏洞匹配 详细对比: {len(benchmarks)}/{len(benchmarks)} 基线完成 (已匹配 {len(matched_case_ids)})")
                break  # 候选池已空，剩余 baseline 都不会匹配

            # 只提交预筛选通过的候选 finding
            candidates = prefilter_candidates.get(bi, list(range(len(active_findings))))
            candidates = [fi for fi in candidates if fi in available_indices]
            if not candidates:
                _progress(f"漏洞匹配 详细对比: {bi+1}/{len(benchmarks)} 基线完成 (已匹配 {len(matched_case_ids)})")
                continue

            futures = {}
            for fi in candidates:
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
                    log("AI_MATCH", f"{task_run.condition.value} LLM 重试耗尽 (f{_fi},b{bi}): {e}")
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    raise
                if is_same and fi in available_indices:
                    matches.append((fi, bi))
                    matched_case_ids.add(cid)
                    available_indices.remove(fi)  # finding 一对一：从候选池移除
                    matched = True
                    log("AI_MATCH", f"MATCHED case={cid} ← finding[{fi}] "
                          f"id={active_findings[fi].get('display_id','')}")
                    break  # 基线匹配即停

            # 取消未完成的 LLM 调用（已发出的不可取消，结果丢弃）
            for f in futures:
                if not f.done():
                    f.cancel()

            if not matched:
                md_desc = str((b.metadata or {}).get("vulnerability_type", ""))
                log("AI_MATCH", f"UNMATCHED case={cid} label={b.expected_label.value if b.expected_label else 'NA'} "
                      f"vuln_type={md_desc}")
            _progress(f"漏洞匹配 详细对比: {bi+1}/{len(benchmarks)} 基线完成 (已匹配 {len(matched_case_ids)})")

    log("AI_MATCH", f"{task_run.condition.value} baseline={len(benchmarks)} matched={len(matched_case_ids)} "
          f"prefilter_llm={prefilter_llm_calls} detail_llm={llm_call_count} "
          f"total_llm={prefilter_llm_calls + llm_call_count}")

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

    has_vuln = any(b.expected_label and b.expected_label.value == "VULNERABLE" for b in benchmarks)
    if all_correct:
        pred = "POSITIVE"; outcome = Outcome.SUCCESS; confusion_label = Confusion.TP; resolver_status = "AI_MATCHED"
    else:
        pred = "NEGATIVE"; outcome = Outcome.FAIL
        # 按实际 case_results 聚合 confusion_label，而非无条件 FN
        confusions = {c["confusion"] for c in case_results}
        if "NA" in confusions:
            confusion_label = Confusion.NA       # agent 没找到漏洞
        elif "FN" in confusions:
            confusion_label = Confusion.FN      # agent 找到但判错
        elif "FP" in confusions:
            confusion_label = Confusion.FP      # agent 误报
        else:
            confusion_label = Confusion.FN       # 兜底
        resolver_status = "AI_PARTIAL_MATCH" if matched_case_ids else "AI_UNMATCHED"

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
        resolver_version="ai-1.0",
    )
    return oc, case_results


# 复用 OutcomeResolverImpl._classify
from .resolvers import OutcomeResolverImpl
