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
import json, re
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log, with_eval_ctx
from ..infrastructure.concurrency import get as _conc_get


def _norm_path(path: str) -> str:
    """归一化源文件路径用于比对。"""
    if not path:
        return ""
    path = path.strip()
    path = re.sub(r':\d+(-\d+)?$', '', path)
    path = re.sub(r':[^/]+$', '', path)  # 去掉 :function_name
    m = re.search(r'com/huawei/(.+)', path)
    if m:
        return m.group(1).lower().strip()
    m = re.search(r'/src/(.+)', path)
    if m:
        return m.group(1).lower().strip()
    return path.lower().strip("/")


def _verify_sink(baseline_sink: str, finding_sink: str) -> bool | None:
    """代码校验 sink 路径是否一致。返回 True/False，None=无法确定。"""
    bl = _norm_path(baseline_sink)
    fl = _norm_path(finding_sink)
    if not bl or not fl:
        return None
    if bl == fl:
        return True
    if bl in fl or fl in bl:
        return True
    bl_parts = bl.split("/")
    fl_parts = fl.split("/")
    for n in (3, 2):
        if len(bl_parts) >= n and len(fl_parts) >= n:
            if bl_parts[-n:] == fl_parts[-n:]:
                return True
    broad = {"controller", "service", "impl", "common", "config", "utils",
             "fintech", "huawei", "src", "com", "app", "main", "java",
             "sdk", "api", "core", "biz", "ws", "restful"}
    common = set(bl_parts) & set(fl_parts) - broad
    if not common:
        return False
    return None


def _parse_bool(val) -> bool:
    """解析 LLM 返回的 bool 值。"""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower().strip() == "true"
    return False


def match_alert_center_to_findings(alert_center_cases: list[dict], findings: list[dict],
                                    progress_cb=None, cancel_cb=None) -> tuple[dict[int, int], set[int]]:
    """AI 匹配告警中心 cases ↔ trace findings（跟基线一样的方案）。

    告警中心 case 为锚点（同 ai_match_outcome 中基线为锚点），
    两阶段匹配：标题预筛 → 1vs1 LLM。
    一对一约束：匹配上的 finding 从候选池移除。

    返回:
      matched: {finding_idx: ac_case_idx} — 匹配上的 finding → 告警中心 case
      unmatched_ac_indices: set[int] — 未匹配上任何 finding 的告警中心 case 索引
    """
    from concurrent.futures import ThreadPoolExecutor
    from ..infrastructure.parallel import iter_completed

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
        subject = c.get("subject", {}) or {}
        ac_list.append({
            "case_id": c.get("case_id") or "",
            "title": c.get("title") or "",
            "summary": c.get("summary") or "",
            "locator": subject.get("locator", "") if isinstance(subject, dict) else "",
        })
    finding_list = []
    for f in active_findings:
        finding_list.append({
            "title": f.get("title") or "",
            "vuln_type": f.get("vuln_type", ""),
            "description": f.get("description") or "",
            "source": f.get("source") or "",
            "sink": f.get("sink") or "",
        })

    # === Phase 1: 标题预筛选（每告警中心 case 1 次 LLM，O(M) 调用）===
    _PREFILTER_LIMIT = 50
    available_finding_indices = list(range(len(active_findings)))
    matched: dict[int, int] = {}  # finding_idx → ac_case_idx
    matched_ac_ids: set[str] = set()

    _progress(f"告警中心匹配 预筛选: 0/{len(alert_center_cases)} 完成")
    _prefilter_sys = (
        "下面是一些代码安全漏洞的标题和描述。"
        "请从标题和描述分析哪些漏洞报告跟该告警中心案例可能是同一个漏洞。"
        "宁可多选不要遗漏。"
        "将可能匹配的漏洞的 ID 原样返回，便于核对。"
        "只返回 JSON：{\"possible_ids\": [\"ID1\", \"ID2\"]}。"
        "无匹配返回空数组 []。"
    )

    def _prefilter_one(ai: int) -> tuple[int, list[int]]:
        """预筛选：告警中心 case 标题 + finding 标题 → 候选 finding 索引。"""
        ac = ac_list[ai]
        id_to_idx: dict[str, int] = {}
        _ac_desc = (ac.get("summary", "") or "")[:500]
        lines = [
            f"告警中心案例标题：{ac.get('title', '')}",
            f"告警中心案例描述：{_ac_desc}",
            "",
            "以下是要比较的漏洞报告：",
        ]
        for i, f in enumerate(active_findings[:_PREFILTER_LIMIT]):
            fid = f.get("display_id") or f.get("finding_id", "") or str(i)
            id_to_idx[fid] = i
            _title = finding_list[i].get("title", "")
            _desc = (finding_list[i].get("description", "") or "")[:500]
            lines.append(f"[{fid}] {_title}\n描述：{_desc}")
        user_msg = "\n".join(lines)
        prompt = [
            {"role": "system", "content": _prefilter_sys},
            {"role": "user", "content": user_msg},
        ]
        result = llm_mod.chat_json(prompt, temperature=0, reasoning_effort="low")
        indices = []
        if isinstance(result, dict):
            raw_ids = result.get("possible_ids", [])
            indices = [id_to_idx[x] for x in raw_ids
                       if isinstance(x, str) and x in id_to_idx]
        return ai, indices

    prefilter_candidates: dict[int, list[int]] = {}
    prefilter_done = 0
    pre_pool = ThreadPoolExecutor(max_workers=_conc_get("ai_match_workers"))
    try:
        pre_futures = {}
        for ai in range(len(alert_center_cases)):
            fut = pre_pool.submit(with_eval_ctx(_prefilter_one), ai)
            pre_futures[fut] = ai
        for fut, _ in iter_completed(pre_futures, cancel_cb=cancel_cb):
            ai = pre_futures[fut]
            try:
                _, indices = fut.result()
                if not indices:
                    indices = list(range(len(active_findings)))
                    log("AC_MATCH", f"prefilter 0 candidates (ac{ai}): fallback all")
                prefilter_candidates[ai] = indices
            except Exception as e:
                prefilter_candidates[ai] = list(range(len(active_findings)))
                log("AC_MATCH", f"prefilter FAILED (ac{ai}): {e}, fallback all")
            prefilter_done += 1
            _progress(f"告警中心匹配 预筛选: {prefilter_done}/{len(alert_center_cases)} 完成")
    except Exception:
        pre_pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        # wait=True：确保所有 LLM 线程完成，结果不丢弃
        pre_pool.shutdown(wait=True)

    total_cand = sum(len(v) for v in prefilter_candidates.values())
    log("AC_MATCH", f"prefilter: {len(alert_center_cases)} ac_cases, {total_cand} candidates "
          f"(avg {total_cand / max(len(alert_center_cases), 1):.1f}/case)")

    # === Phase 2: 全量并行 1vs1 + 串行冲突解决 ===
    _progress(f"告警中心匹配 详细对比: 0/{len(alert_center_cases)} 完成")
    _sys_prompt = (
        "你是漏洞匹配判定器。给你一个参考漏洞和一个待判定的漏洞，"
        "每个漏洞有标题、描述和代码文件路径，请从三个方面判断它们是不是同一个漏洞：\n"
        "1. 代码位置：漏洞出现在哪个代码文件里\n"
        "2. 触发入口：漏洞是通过哪个接口或功能触发的\n"
        "3. 漏洞类型：属于什么类别的问题（如SQL注入、命令注入、越权、IDOR、SSRF等）\n\n"
        "注意：两边的标题和描述可能写法不同，但说的可能是同一个问题。请仔细阅读全部内容，结合具体细节综合判断，不要只看标题字面不一样就认为不是同一个。\n\n"
        "先从标题和描述中提取各自的三个方面信息，代码文件路径作为参考，再逐一判断是否相同。\n"
        "判断标准：\n"
        "- 代码位置要求严格：文件路径必须明确对应，不同文件就是不同漏洞\n"
        "- 触发入口可以宽松：写法不同但指向同一个接口或功能的，视为相同。"
        "如'generateParameters接口'与'参数生成接口'、'POST /api/parameterGenerate'与'参数生成接口'是同一个入口\n"
        "- 漏洞类型可以宽松：说法不同但属于同一类问题的，视为相同。"
        "如'OS命令注入'与'远程命令注入'、'SQL注入'与'SQL Injection'是同一类型\n\n"
        "desc_similarity是描述相似度（0.0-1.0），表示两边描述讲的是同一个问题的程度。\n\n"
        '只返回JSON：\n'
        '{\n'
        '  "baseline": {"sink": "...", "source": "...", "vuln_type": "..."},\n'
        '  "candidate": {"sink": "...", "source": "...", "vuln_type": "..."},\n'
        '  "same_sink": true/false,\n'
        '  "same_source": true/false,\n'
        '  "same_vuln_type": true/false,\n'
        '  "desc_similarity": 0.0-1.0,\n'
        '  "reason": "简要说明每个方面的判断理由"\n'
        '}'
    )

    def _check_pair(ai: int, fi: int, ac_title: str, ac_summary: str, ac_sink: str,
                    fd_title: str, fd_description: str, fd_sink: str) -> tuple[int, int, float]:
        ac_desc = f"标题: {ac_title}\n描述: {ac_summary}"
        if ac_sink:
            ac_desc += f"\n代码文件: {ac_sink}"
        fd_desc = f"标题: {fd_title}\n描述: {fd_description}"
        if fd_sink:
            fd_desc += f"\n代码文件: {fd_sink}"

        prompt = [
            {"role": "system", "content": _sys_prompt},
            {"role": "user", "content": (
                f"参考漏洞:\n{ac_desc}\n\n"
                f"待判定漏洞:\n{fd_desc}\n\n"
                f"提取三个方面信息并判断是否同一个漏洞。"
            )},
        ]
        try:
            result = llm_mod.chat_json(prompt, temperature=0, reasoning_effort="low")
            same_sink = _parse_bool(result.get("same_sink", False))
            same_source = _parse_bool(result.get("same_source", False))
            same_vuln_type = _parse_bool(result.get("same_vuln_type", False))
            desc_sim = result.get("desc_similarity")
            try:
                desc_sim = float(desc_sim) if desc_sim is not None else 0.0
            except (ValueError, TypeError):
                desc_sim = 0.0

            # 代码校验 sink
            sink_check = _verify_sink(ac_sink, fd_sink)
            if sink_check is False and same_sink:
                same_sink = False
            elif sink_check is True and not same_sink:
                same_sink = True

            # 匹配条件：vuln_type 必须为 true，且满足以下之一：
            # 1. sink 与 source 至少一个为 true，且描述相似度 >= 0.5
            # 2. sink 与 source 都为 false，但描述相似度 >= 0.6
            is_same = same_vuln_type and (((same_sink or same_source) and desc_sim >= 0.5) or ((not same_sink and not same_source) and desc_sim >= 0.6))
            return ai, fi, desc_sim if is_same else 0.0
        except Exception as e:
            log("AC_MATCH", f"LLM 判断失败 (ac{ai},f{fi}): {e}")
            return ai, fi, False

    # 收集所有 (ac_idx, finding_idx) 对
    all_pairs: list[tuple[int, int]] = []
    for ai in range(len(alert_center_cases)):
        candidates = prefilter_candidates.get(ai, list(range(len(active_findings))))
        candidates = [fi for fi in candidates if fi in available_finding_indices]
        for fi in candidates:
            all_pairs.append((ai, fi))

    llm_call_count = len(all_pairs)
    log("AC_MATCH", f"phase2: {len(all_pairs)} pairs to check "
          f"(ac_cases={len(alert_center_cases)}, "
          f"avg {len(all_pairs)/max(len(alert_center_cases),1):.1f}/case)")

    # 全量并行 1vs1
    pair_results: dict[tuple[int, int], float] = {}
    if all_pairs:
        pool = ThreadPoolExecutor(max_workers=_conc_get("ai_match_workers"))
        try:
            futures = {}
            for ai, fi in all_pairs:
                fut = pool.submit(with_eval_ctx(_check_pair), ai, fi,
                    ac_list[ai].get("title", ""),
                    ac_list[ai].get("summary", ""),
                    ac_list[ai].get("locator", ""),
                    finding_list[fi].get("title", ""),
                    finding_list[fi].get("description", ""),
                    finding_list[fi].get("sink", ""))
                futures[fut] = (ai, fi)
            done = 0
            for fut, _ in iter_completed(futures, cancel_cb=cancel_cb):
                ai, fi = futures[fut]
                try:
                    _, _, score = fut.result()
                    pair_results[(ai, fi)] = score
                except Exception as e:
                    pair_results[(ai, fi)] = 0.0
                    log("AC_MATCH", f"LLM 失败 (ac{ai},f{fi}): {e}")
                done += 1
                _progress(f"告警中心匹配 详细对比: {done}/{len(all_pairs)} LLM 调用完成")
        except Exception:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)

    # 串行冲突解决：按 AC case 顺序分配，先到先得（一对一约束）
    for ai in range(len(alert_center_cases)):
        if not available_finding_indices:
            break
        candidates = prefilter_candidates.get(ai, list(range(len(active_findings))))
        candidates = [fi for fi in candidates if fi in available_finding_indices]
        case_matched = False
        for fi in candidates:
            if pair_results.get((ai, fi), 0.0) >= 0.5:
                orig_fi = active_to_orig[fi]
                matched[orig_fi] = ai
                matched_ac_ids.add(ac_list[ai].get("case_id", ""))
                available_finding_indices.remove(fi)
                case_matched = True
                log("AC_MATCH", f"MATCHED ac_case[{ai}]={ac_list[ai].get('case_id','')} ← finding[{orig_fi}]")
                break
        if not case_matched:
            log("AC_MATCH", f"UNMATCHED ac_case[{ai}] id={ac_list[ai].get('case_id','')}")
        _progress(f"告警中心匹配 冲突解决: {ai+1}/{len(alert_center_cases)} 完成 (已匹配 {len(matched_ac_ids)})")

    unmatched_ac_indices = set(range(len(alert_center_cases))) - {v for v in matched.values()}
    log("AC_MATCH", f"ac_cases={len(alert_center_cases)} matched={len(matched)} "
          f"unmatched_ac={len(unmatched_ac_indices)} detail_llm={llm_call_count}")

    return matched, unmatched_ac_indices
