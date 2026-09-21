"""FPR（误报率）分析模块 — 基线集 vs 漏洞中心/告警中心数据，批量 LLM 匹配。

在 REPORTING 阶段被调用，结果作为 tab 展示：
- source="vuln_center"  → 漏洞E2E分析 tab
- source="alert_center" → 漏洞挖掘误报率 tab

基线数据来源：case_details（benchmark_item 表），不再使用 CSV。
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from ..infrastructure.parallel import iter_completed

from ..infrastructure import vuln_center_client
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log, with_eval_ctx
from ..infrastructure.concurrency import get as _conc_get

_BATCH_SIZE = 10


def _norm_path(path: str) -> str:
    """归一化源文件路径用于比对。"""
    if not path:
        return ""
    import re
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
    # 无任何公共路径段 → 明确不一致
    broad = {"controller", "service", "impl", "common", "config", "utils",
             "fintech", "huawei", "src", "com", "app", "main", "java",
             "sdk", "api", "core", "biz", "ws", "restful"}
    common = set(bl_parts) & set(fl_parts) - broad
    if not common:
        return False
    return None


def _build_finding_desc(case: dict) -> str:
    """从漏洞中心 case 构建描述：标题 + 描述 + sink 路径。"""
    title = case.get("title", "")
    summary = case.get("summary", "") or case.get("display_summary", "") or ""
    if isinstance(summary, dict):
        summary = json.dumps(summary, ensure_ascii=False)
    if not isinstance(summary, str):
        summary = str(summary)
    subject = case.get("subject", {})
    if isinstance(subject, dict):
        locator = subject.get("locator", "")
    else:
        locator = ""
    parts = [f"标题: {title}"]
    if summary:
        parts.append(f"描述: {summary}")
    if locator:
        parts.append(f"Sink: {locator}")
    return "\n".join(parts)


def _llm_match_batch(baseline_content: str, baseline_sink: str,
                     batch_findings: list[tuple[int, str, str]]) -> tuple[list[tuple[int, float]], str]:
    """用 LLM 从一批漏洞中找出与基线匹配的候选。

    输入：标题 + 完整描述 + sink 路径（作为参考）。
    LLM 输出三维度提取值 + 三个 bool，程序判断：漏洞类型必须相同，且 sink 与 source 至少一个相同。
    sink 额外用代码校验，LLM 说 true 但路径明显不一致则推翻。

    batch_findings: [(original_fidx, finding_desc, finding_sink), ...]
    返回: [(original_fidx, confidence 0.0-1.0), ...]（空列表=无匹配），理由
    """
    if len(batch_findings) == 1:
        fidx, desc, finding_sink = batch_findings[0]
        prompt = [
            {
                "role": "system",
                "content": (
                    "你是漏洞匹配判定器。给定基线漏洞和候选漏洞的标题、描述和sink路径，"
                    "从中提取三个维度并判断是否指向同一漏洞：\n"
                    "1. sink点：漏洞代码位置（源文件名）\n"
                    "2. source入口：攻击入口（API端点/接口名）\n"
                    "3. 漏洞类型：漏洞类别（如SQL注入、命令注入、越权、IDOR、SSRF等）\n\n"
                    "先从标题和描述中提取各自的三个维度值，sink路径作为参考，再逐一判断是否相同。\n"
                    "判断标准：\n"
                    "- sink点从严：源文件路径需要明确对应（不同文件=不同漏洞）\n"
                    "- source入口从宽：不同语言/命名但指向同一API端点或接口的，视为相同。"
                    "如'generateParameters接口'与'参数生成接口'、'POST /api/parameterGenerate'与'参数生成接口'是同一入口\n"
                    "- 漏洞类型从宽：不同术语但属于同一漏洞类别的，视为相同。"
                    "如'OS命令注入'与'远程命令注入'、'SQL注入'与'SQL Injection'是同一类型\n\n"
                    "desc_similarity为描述相似度置信度（0.0-1.0），衡量基线与候选漏洞描述的相似程度。\n\n"
                    '只返回JSON：\n'
                    '{\n'
                    '  "baseline": {"sink": "...", "source": "...", "vuln_type": "..."},\n'
                    '  "candidate": {"sink": "...", "source": "...", "vuln_type": "..."},\n'
                    '  "same_sink": true/false,\n'
                    '  "same_source": true/false,\n'
                    '  "same_vuln_type": true/false,\n'
                    '  "desc_similarity": 0.0-1.0,\n'
                    '  "reason": "简要说明每个维度的判断理由"\n'
                    '}'
                ),
            },
            {
                "role": "user",
                "content": (
                    f"基线漏洞:\n{baseline_content}\n\n"
                    f"候选漏洞:\n{desc}\n\n"
                    f"提取三个维度并判断是否同一漏洞。"
                ),
            },
        ]
        try:
            result = llm_mod.chat_json(prompt, temperature=0)
            same_sink = _parse_bool(result.get("same_sink", False))
            same_source = _parse_bool(result.get("same_source", False))
            same_vuln_type = _parse_bool(result.get("same_vuln_type", False))
            desc_sim = result.get("desc_similarity")
            try:
                desc_sim = float(desc_sim) if desc_sim is not None else 0.0
            except (ValueError, TypeError):
                desc_sim = 0.0
            reason = result.get("reason", "")

            # 代码校验 sink
            sink_check = _verify_sink(baseline_sink, finding_sink)
            if sink_check is False and same_sink:
                same_sink = False
                reason += " [代码校验: sink路径不一致，推翻LLM判断]"
            elif sink_check is True and not same_sink:
                same_sink = True
                reason += " [代码校验: sink路径一致，推翻LLM判断]"

            # 匹配条件：vuln_type 必须为 true，且 sink 与 source 至少一个为 true，且描述相似度 >= 0.5
            if same_vuln_type and (same_sink or same_source) and desc_sim >= 0.5:
                return [(fidx, desc_sim)], reason
            return [], reason
        except Exception as e:
            log("FPR", f"LLM 判断失败: {e}")
            return [], f"LLM 错误: {e}"

    # 多条：批量判断，token 超限时自动降级
    current_batch = batch_findings
    while len(current_batch) > 1:
        lines = []
        for i, (fidx, desc, _) in enumerate(current_batch):
            lines.append(f"--- 候选{i+1} ---\n{desc}")
        candidates_text = "\n\n".join(lines)

        prompt = [
            {
                "role": "system",
                "content": (
                    "你是漏洞匹配判定器。给定一个基线漏洞和多个候选漏洞，"
                    "对每个候选提取三个维度并判断是否与基线指向同一漏洞：\n"
                    "1. sink点：漏洞代码位置（源文件名）\n"
                    "2. source入口：攻击入口（API端点/接口名）\n"
                    "3. 漏洞类型：漏洞类别\n\n"
                    "判断标准：\n"
                    "- sink点从严：源文件路径需要明确对应（不同文件=不同漏洞）\n"
                    "- source入口从宽：不同语言/命名但指向同一API端点或接口的，视为相同。"
                    "如'generateParameters接口'与'参数生成接口'是同一入口\n"
                    "- 漏洞类型从宽：不同术语但属于同一漏洞类别的，视为相同。"
                    "如'OS命令注入'与'远程命令注入'是同一类型\n\n"
                    "对每个候选，先从标题和描述中提取三维度值，sink路径作为参考，再逐一判断是否相同。"
                    "匹配条件：漏洞类型必须相同（same_vuln_type=true），且 sink 与 source 至少一个相同（same_sink=true 或 same_source=true），且描述相似度置信度（desc_similarity）>= 0.5。\n"
                    "desc_similarity为描述相似度置信度（0.0-1.0），衡量基线与候选漏洞描述的相似程度。\n"
                    '只返回JSON：\n'
                    '{\n'
                    '  "results": [\n'
                    '    {"no": 候选编号, "baseline": {"sink":"...","source":"...","vuln_type":"..."}, '
                    '"candidate": {"sink":"...","source":"...","vuln_type":"..."}, '
                    '"same_sink": true, "same_source": true, "same_vuln_type": true, '
                    '"desc_similarity": 0.0-1.0, "reason": "..."}\n'
                    '  ]\n'
                    '}\n'
                    '只包含漏洞类型相同且 sink 或 source 至少一个相同且描述相似度>=0.5的候选。如果没有匹配，results为[]。'
                ),
            },
            {
                "role": "user",
                "content": (
                    f"基线漏洞:\n{baseline_content}\n\n"
                    f"候选漏洞:\n{candidates_text}\n\n"
                    f"对每个候选提取三维度并判断是否同一漏洞，只返回漏洞类型相同且 sink 或 source 至少一个相同且描述相似度>=0.5的候选，"
                    f"编号1-{len(current_batch)}。"
                ),
            },
        ]
        try:
            result = llm_mod.chat_json(prompt, temperature=0)
            results_raw = result.get("results", [])
            reason = result.get("reason", "")
            if isinstance(results_raw, dict):
                results_raw = [results_raw]

            matched_pairs: list[tuple[int, float]] = []
            for item in results_raw:
                if not isinstance(item, dict):
                    continue
                no = item.get("no", 0)
                try:
                    no = int(no)
                except (ValueError, TypeError):
                    continue
                if not (1 <= no <= len(current_batch)):
                    continue

                fidx, _, finding_sink = current_batch[no - 1]
                same_sink = _parse_bool(item.get("same_sink", False))
                same_source = _parse_bool(item.get("same_source", False))
                same_vuln_type = _parse_bool(item.get("same_vuln_type", False))
                desc_sim = item.get("desc_similarity")
                try:
                    desc_sim = float(desc_sim) if desc_sim is not None else 0.0
                except (ValueError, TypeError):
                    desc_sim = 0.0

                # 代码校验 sink
                sink_check = _verify_sink(baseline_sink, finding_sink)
                if sink_check is False and same_sink:
                    same_sink = False
                elif sink_check is True and not same_sink:
                    same_sink = True

                # 匹配条件：vuln_type 必须为 true，且 sink 与 source 至少一个为 true，且描述相似度 >= 0.5
                if same_vuln_type and (same_sink or same_source) and desc_sim >= 0.5:
                    matched_pairs.append((fidx, desc_sim))

            if matched_pairs:
                return matched_pairs, reason
            return [], reason or "无匹配"
        except Exception as e:
            err_lower = str(e).lower()
            if any(kw in err_lower for kw in (
                "context length", "too long", "maximum context",
                "token limit", "context_window", "input too long",
                "prompt too long",
            )):
                half = len(current_batch) // 2
                log("FPR", f"token 超限 (batch={len(current_batch)})，降级到 {half}+{len(current_batch)-half}")
                left = current_batch[:half]
                right = current_batch[half:]
                left_matches, left_reason = _llm_match_batch(baseline_content, baseline_sink, left)
                if left_matches:
                    right_matches, _ = _llm_match_batch(baseline_content, baseline_sink, right)
                    return left_matches + right_matches, left_reason
                return _llm_match_batch(baseline_content, baseline_sink, right)
            log("FPR", f"LLM 批量判断失败: {e}")
            return [], f"LLM 错误: {e}"

    # 降级到 1 条
    return _llm_match_batch(baseline_content, baseline_sink, current_batch[:1])


def _parse_bool(val) -> bool:
    """解析 LLM 返回的 bool 值。"""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower().strip() == "true"
    return False


def _run_matching(findings: list[dict], baseline_rows: list[dict],
                  progress_cb=None, cancel_cb=None) -> list[dict]:
    """两阶段并行匹配：所有基线并行匹配 → 冲突解决（1:1 分配）。

    阶段 1：每个基线独立对所有 findings 并行匹配，选最佳候选。
    阶段 2：一个 finding 被多个基线选中时，按置信度高低分配给最高者。

    返回与 findings 等长的列表，每个元素含:
      match_idx (基线索引, -1=未匹配), reason, baseline 信息
    """
    # 阶段 1：所有基线并行匹配
    # 每个基线的结果: (bl_idx, best_fidx | None, best_conf, all_matches)
    bl_results: list[tuple[int, int | None, float, list[tuple[int, float]]]] = []
    _done_count = [0]
    _count_lock = __import__("threading").Lock()

    def _match_one_baseline(bl_idx: int) -> tuple[int, int | None, float, list[tuple[int, float]]]:
        bl = baseline_rows[bl_idx]
        bl_content = bl.get("content", "")
        bl_sink = bl.get("source_file", "")
        bl_title = bl.get("title", "")

        # 所有 findings 分批，每条带 sink 路径
        all_fidx = list(range(len(findings)))
        batches: list[list[tuple[int, str, str]]] = []
        for i in range(0, len(all_fidx), _BATCH_SIZE):
            chunk_idxs = all_fidx[i:i + _BATCH_SIZE]
            batch = [(f_idx, _build_finding_desc(findings[f_idx]),
                      (findings[f_idx].get("subject", {}) or {}).get("locator", "") or "")
                     for f_idx in chunk_idxs]
            batches.append(batch)

        all_matches: list[tuple[int, float]] = []
        _bl_had_timeout = False
        try:
            _bl_pool2 = ThreadPoolExecutor(max_workers=min(_conc_get("fpr_baseline_batch"), len(batches)))
            future_to_batch: dict = {}
            for batch in batches:
                fut = _bl_pool2.submit(with_eval_ctx(_llm_match_batch), bl_content, bl_sink, batch)
                future_to_batch[fut] = batch
            for fut, _timeout in iter_completed(future_to_batch, per_task_timeout=1800):
                if _timeout:
                    _bl_had_timeout = True
                    continue
                matched_pairs, _ = fut.result()
                all_matches.extend(matched_pairs)
        except Exception:
            _bl_pool2.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            # 有超时时 wait=False：超时线程仍在 chat_json 重试中，wait=True 会阻塞整个评估
            _bl_pool2.shutdown(wait=not _bl_had_timeout, cancel_futures=_bl_had_timeout)

        if all_matches:
            all_matches.sort(key=lambda x: x[1], reverse=True)
            best_fidx = all_matches[0][0]
            best_conf = all_matches[0][1]
        else:
            best_fidx = None
            best_conf = 0.0

        if progress_cb:
            with _count_lock:
                _done_count[0] += 1
                progress_cb(_done_count[0], len(baseline_rows))

        return bl_idx, best_fidx, best_conf, all_matches

    bl_pool = ThreadPoolExecutor(max_workers=min(_conc_get("fpr_baseline_workers"), len(baseline_rows)))
    _bl_had_timeout = False
    try:
        futures = [bl_pool.submit(with_eval_ctx(_match_one_baseline), i) for i in range(len(baseline_rows))]
        for fut, _timeout in iter_completed(futures, cancel_cb=cancel_cb, per_task_timeout=1800):
            if _timeout:
                _bl_had_timeout = True
                continue
            bl_results.append(fut.result())
    except Exception:
        bl_pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        # 有超时时 wait=False：超时线程仍在 chat_json 重试中，wait=True 会阻塞整个评估
        bl_pool.shutdown(wait=not _bl_had_timeout, cancel_futures=_bl_had_timeout)

    # 阶段 2：冲突解决 — 1:1 分配
    # 按置信度降序排列所有基线的最佳匹配，贪心分配
    _matched_count = sum(1 for r in bl_results if r[1] is not None)
    _conflict_count = sum(1 for r in bl_results if r[1] is not None and any(
        r[1] == other[1] for other in bl_results if other[0] != r[0] and other[1] is not None))
    log("FPR", f"阶段 1 完成: {_matched_count}/{len(baseline_rows)} 基线有候选, {_conflict_count} 个冲突待解决")
    bl_results.sort(key=lambda x: x[2], reverse=True)

    match_results = [
        {"match_idx": -1, "reason": "未匹配"} for _ in range(len(findings))
    ]
    assigned_findings: set[int] = set()

    for bl_idx, best_fidx, best_conf, all_matches in bl_results:
        bl_title = baseline_rows[bl_idx].get("title", "")

        # 尝试最佳候选，如果已被占用，尝试次佳
        matched_fidx = None
        matched_conf = 0.0
        for f_idx, conf in all_matches:
            if f_idx not in assigned_findings:
                matched_fidx = f_idx
                matched_conf = conf
                break

        if matched_fidx is not None:
            assigned_findings.add(matched_fidx)
            if len(all_matches) > 1:
                others = [f"[{f+1}({c:.1f})]" for f, c in all_matches[1:]]
                log("FPR", f"基线'{bl_title}' 有多个候选命中: [{matched_fidx+1}({matched_conf:.1f})] + {' '.join(others)}，取置信度最高")
            else:
                log("FPR", f"基线'{bl_title}' 匹配 [{matched_fidx+1}] 置信度={matched_conf:.1f}")
            match_results[matched_fidx] = {
                "match_idx": bl_idx,
                "reason": f"置信度={matched_conf:.1f}",
            }
            log("FPR", f"[{bl_idx+1}/{len(baseline_rows)}] 基线'{bl_title}' → 匹配漏洞中心[{matched_fidx+1}]")
        else:
            log("FPR", f"[{bl_idx+1}/{len(baseline_rows)}] 基线'{bl_title}' → 无匹配")

    return match_results


def _calculate_fpr(match_results: list[dict], baseline_rows: list[dict]) -> tuple[float, int, int]:
    """计算误报率 = 匹配中基线=非漏洞的数量 / 总匹配数。"""
    matched = 0
    false_positive = 0
    for r in match_results:
        idx = r["match_idx"]
        if idx >= 0:
            matched += 1
            if baseline_rows[idx].get("label") == "NON_VULNERABLE":
                false_positive += 1
    fpr = false_positive / matched if matched > 0 else 0
    return fpr, matched, false_positive


def _build_match_detail(match_results: list[dict], findings: list[dict],
                        baseline_rows: list[dict]) -> list[dict]:
    """构建匹配明细，供前端渲染表格。"""
    detail = []
    for i, (finding, result) in enumerate(zip(findings, match_results)):
        match_idx = result["match_idx"]
        reason = result["reason"]

        finding_title = finding.get("title", "")
        finding_summary = (
            finding.get("summary", "")
            or finding.get("display_summary", "")
            or ""
        )
        finding_id = finding.get("id", "")
        finding_status = finding.get("confirmation_status", "")
        _subject = finding.get("subject", {}) or {}
        finding_sink = _subject.get("locator", "") if isinstance(_subject, dict) else ""

        if match_idx >= 0:
            bl = baseline_rows[match_idx]
            bl_case_id = bl.get("case_id", "")
            bl_title = bl.get("title", "")
            bl_label = bl.get("label", "")
            bl_category = bl.get("category", "")
            is_fp = bl_label == "NON_VULNERABLE"
            match_status = "已匹配"
            judgment = "误报" if is_fp else "真正"
        else:
            bl_case_id = ""
            bl_title = ""
            bl_label = ""
            bl_category = ""
            is_fp = False
            match_status = "未匹配"
            judgment = "未匹配"

        detail.append({
            "seq": i + 1,
            "finding_id": finding_id,
            "finding_title": finding_title,
            "finding_summary": finding_summary,
            "finding_sink": finding_sink,
            "finding_status": finding_status,
            "match_status": match_status,
            "bl_case_id": bl_case_id,
            "bl_title": bl_title,
            "bl_label": bl_label,
            "bl_category": bl_category,
            "reason": reason,
            "judgment": judgment,
            "is_fp": is_fp,
        })
    return detail


def derive_fpr_from_subset(alert_result: dict, vuln_center_case_ids: set[str]) -> dict:
    """从告警中心匹配结果中按 case ID 筛选漏洞中心子集，重新计算 FPR。

    保证一致性：不重新匹配，只筛选已有结果。
    漏洞中心 case ID 是告警中心的真子集（如 128/158）。
    """
    match_details = alert_result.get("match_details", [])

    # 筛选：只保留在漏洞中心中的 case
    subset_details = [d for d in match_details
                      if d.get("finding_id", "") in vuln_center_case_ids]

    # 重新计算 FPR
    matched = 0
    fp = 0
    for d in subset_details:
        if d.get("match_status") == "已匹配":
            matched += 1
            if d.get("is_fp", False):
                fp += 1
    tp = matched - fp
    fpr = fp / matched if matched > 0 else 0.0

    return {
        "fpr": fpr,
        "matched": matched,
        "fp": fp,
        "tp": tp,
        "total_findings": len(subset_details),
        "total_baseline": alert_result.get("total_baseline", 0),
        "match_details": subset_details,
    }


def run_fpr_analysis(project_id: str, task_id: str,
                     progress_cb=None, source: str = "vuln_center",
                     case_details: dict | None = None,
                     cancel_cb=None) -> dict | None:
    """主入口：基线 vs 漏洞中心/告警中心数据 → FPR + 匹配明细。

    source="vuln_center"  → 漏洞中心数据（E2E 分析）
    source="alert_center" → 告警中心数据（漏洞挖掘误报率）

    基线数据来自 case_details（与 benchmark_item 表同源，来自 benchmark.zip），
    不再依赖外部 CSV 文件。

    返回 dict:
      fpr, matched, fp, tp, total_findings, total_baseline, match_details
    若 case_details 为空，返回 None（不生成 tab）。
    """
    if not case_details:
        log("FPR", "case_details 为空，跳过 FPR 分析")
        return None

    # 从 case_details 构建基线行（与 benchmark_item 表同源）
    # vulnerability_type 已由 vbench_client 从 description 第一行提取（去掉 # 前缀）
    baseline_rows = []
    for cid, cd in case_details.items():
        _vuln_type = cd.get("vulnerability_type", "")
        _source_file = cd.get("source_file", "") or cd.get("locator", "") or ""
        _description = cd.get("description", "") or ""
        # 基线描述：标题 + 描述 + sink 路径
        _content_parts = [f"标题: {_vuln_type}"]
        if _description:
            _content_parts.append(f"描述: {_description}")
        if _source_file:
            _content_parts.append(f"Sink: {_source_file}")
        baseline_rows.append({
            "case_id": cid,
            "title": _vuln_type,
            "content": "\n".join(_content_parts),
            "source_file": _source_file,
            "label": cd.get("expected_label", "VULNERABLE"),
            "category": _vuln_type,
        })
    _vuln_n = sum(1 for r in baseline_rows if r["label"] == "VULNERABLE")
    _nonvuln_n = sum(1 for r in baseline_rows if r["label"] == "NON_VULNERABLE")
    log("FPR", f"基线 {len(baseline_rows)} 条（漏洞={_vuln_n} 非漏洞={_nonvuln_n}）")

    if source == "alert_center":
        log("FPR", f"从告警中心获取数据: project={project_id}, task={task_id}")
        findings = vuln_center_client.list_alert_center_cases(
            project_id=project_id,
            source_task_id=task_id,
        )
        log("FPR", f"告警中心返回 {len(findings)} 条")
        source_label = "告警中心"
    else:
        log("FPR", f"从漏洞中心获取数据: project={project_id}, task={task_id}")
        findings = vuln_center_client.list_vuln_cases(
            project_id=project_id,
            source_task_id=task_id,
        )
        log("FPR", f"漏洞中心返回 {len(findings)} 条")
        source_label = "漏洞中心"

    if not findings:
        log("FPR", f"{source_label}无数据，跳过 FPR 分析")
        return None

    log("FPR", f"批量 LLM 匹配: {len(baseline_rows)} 条基线 × {len(findings)} 条{source_label}数据 (batch={_BATCH_SIZE}, 基线并发={_conc_get('fpr_baseline_workers')})")
    if progress_cb:
        progress_cb(0, len(baseline_rows))
    match_results = _run_matching(findings, baseline_rows, progress_cb, cancel_cb)

    fpr, matched, fp = _calculate_fpr(match_results, baseline_rows)
    tp = matched - fp
    log("FPR", f"匹配 {matched} 条：真正 {tp}，误报 {fp}，FPR = {fpr:.1%}")

    match_details = _build_match_detail(match_results, findings, baseline_rows)

    return {
        "fpr": fpr,
        "matched": matched,
        "fp": fp,
        "tp": tp,
        "total_findings": len(findings),
        "total_baseline": len(baseline_rows),
        "match_details": match_details,
    }
