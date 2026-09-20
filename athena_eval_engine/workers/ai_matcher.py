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
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log
from ..infrastructure.concurrency import get as _conc_get


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
            "source": f.get("source") or "",
            "sink": f.get("sink") or "",
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
        result = llm_mod.chat_json(prompt, temperature=0)
        indices = []
        if isinstance(result, dict):
            raw_ids = result.get("possible_ids", [])
            indices = [id_to_idx[x] for x in raw_ids
                       if isinstance(x, str) and x in id_to_idx]
        return ai, indices

    prefilter_candidates: dict[int, list[int]] = {}
    prefilter_done = 0
    pre_pool = ThreadPoolExecutor(max_workers=_conc_get("ai_match_workers"))
    _pre_had_timeout = False
    try:
        pre_futures = {}
        for ai in range(len(alert_center_cases)):
            fut = pre_pool.submit(_prefilter_one, ai)
            pre_futures[fut] = ai
        for fut, _timeout in iter_completed(pre_futures, cancel_cb=cancel_cb, per_task_timeout=1800):
            ai = pre_futures[fut]
            if _timeout:
                _pre_had_timeout = True
                prefilter_candidates[ai] = list(range(len(active_findings)))
                log("AC_MATCH", f"prefilter TIMEOUT (ac{ai}): fallback all")
            else:
                try:
                    _, indices = fut.result()
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
        # 有超时时 wait=False：超时线程仍在 chat_json 重试中，wait=True 会阻塞整个评估
        pre_pool.shutdown(wait=not _pre_had_timeout, cancel_futures=_pre_had_timeout)

    total_cand = sum(len(v) for v in prefilter_candidates.values())
    log("AC_MATCH", f"prefilter: {len(alert_center_cases)} ac_cases, {total_cand} candidates "
          f"(avg {total_cand / max(len(alert_center_cases), 1):.1f}/case)")

    # === Phase 2: 全量并行 1vs1 + 串行冲突解决 ===
    _progress(f"告警中心匹配 详细对比: 0/{len(alert_center_cases)} 完成")
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
        result = llm_mod.chat_json(prompt, temperature=0)
        is_same = bool(result.get("is_same", False)) if isinstance(result, dict) else bool(result)
        return ai, fi, is_same

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
    pair_results: dict[tuple[int, int], bool] = {}
    if all_pairs:
        pool = ThreadPoolExecutor(max_workers=_conc_get("ai_match_workers"))
        _pair_had_timeout = False
        try:
            futures = {}
            for ai, fi in all_pairs:
                fut = pool.submit(_check_pair, ai, fi, {
                    "title": ac_list[ai].get("title", ""),
                    "summary": ac_list[ai].get("summary", ""),
                }, finding_list[fi])
                futures[fut] = (ai, fi)
            done = 0
            for fut, _timeout in iter_completed(futures, cancel_cb=cancel_cb, per_task_timeout=1800):
                ai, fi = futures[fut]
                if _timeout:
                    _pair_had_timeout = True
                    pair_results[(ai, fi)] = False
                    log("AC_MATCH", f"LLM 超时 (ac{ai},f{fi}): fallback false")
                else:
                    try:
                        _, _, is_same = fut.result()
                        pair_results[(ai, fi)] = is_same
                    except Exception as e:
                        pair_results[(ai, fi)] = False
                        log("AC_MATCH", f"LLM 失败 (ac{ai},f{fi}): {e}")
                done += 1
                _progress(f"告警中心匹配 详细对比: {done}/{len(all_pairs)} LLM 调用完成")
        except Exception:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            # 有超时时 wait=False：超时线程仍在 chat_json 重试中，wait=True 会阻塞整个评估
            pool.shutdown(wait=not _pair_had_timeout, cancel_futures=_pair_had_timeout)

    # 串行冲突解决：按 AC case 顺序分配，先到先得（一对一约束）
    for ai in range(len(alert_center_cases)):
        if not available_finding_indices:
            break
        candidates = prefilter_candidates.get(ai, list(range(len(active_findings))))
        candidates = [fi for fi in candidates if fi in available_finding_indices]
        case_matched = False
        for fi in candidates:
            if pair_results.get((ai, fi), False):
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
