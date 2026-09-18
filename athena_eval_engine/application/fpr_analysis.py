"""FPR（误报率）分析模块 — 基线 CSV vs 漏洞中心/告警中心数据，批量 LLM 匹配。

在 REPORTING 阶段被调用，结果作为 tab 展示：
- source="vuln_center"  → 漏洞E2E分析 tab
- source="alert_center" → 漏洞挖掘误报率 tab

基线 CSV 来源：run8_reports_full.zip 生成的 run8_baseline.csv（含 VULNERABLE + NON_VULNERABLE）。
"""
from __future__ import annotations
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..infrastructure import vuln_center_client
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log

_BATCH_SIZE = 5


def _get_baseline_path() -> str:
    """从环境变量获取基线 CSV 路径，默认 /data/logs/baseline.csv。"""
    return os.environ.get("FPR_BASELINE_CSV", "/data/logs/baseline.csv")


def load_baseline(csv_path: str) -> list[dict]:
    """加载基线 CSV。"""
    rows: list[dict] = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def _build_finding_desc(case: dict) -> str:
    """从漏洞中心 case 构建完整漏洞描述（全量字段）。"""
    title = case.get("title", "")
    summary = case.get("summary", "") or ""
    display_summary = case.get("display_summary", "") or ""
    subject = case.get("subject", {})
    if isinstance(subject, dict):
        vuln_type = subject.get("type", "")
        locator = subject.get("locator", "")
        subj_name = subject.get("name", "")
    else:
        vuln_type = ""
        locator = ""
        subj_name = ""
    human_conf = case.get("human_confirmation", {})
    if isinstance(human_conf, dict):
        human_summary = human_conf.get("summary", "")
    else:
        human_summary = ""
    latest_decision = case.get("latest_human_decision", {})
    if isinstance(latest_decision, dict):
        decision_reason = latest_decision.get("reason", "")
    else:
        decision_reason = ""
    raw_report = case.get("raw_report_summary", "") or ""

    parts = [f"标题: {title}"]
    if vuln_type:
        parts.append(f"漏洞类型: {vuln_type}")
    if locator:
        parts.append(f"定位: {locator}")
    if subj_name:
        parts.append(f"对象: {subj_name}")
    if summary:
        parts.append(f"摘要: {summary}")
    if display_summary:
        parts.append(f"展示摘要: {display_summary}")
    if human_summary:
        parts.append(f"人工确认: {human_summary}")
    if decision_reason:
        parts.append(f"决策理由: {decision_reason}")
    if raw_report:
        parts.append(f"报告摘要: {raw_report}")
    return "\n".join(parts)


def _llm_match_batch(baseline_content: str,
                     batch_findings: list[tuple[int, str]]) -> tuple[list[tuple[int, float]], str]:
    """用 LLM 从一批漏洞中找出与基线匹配的候选，返回 (matched_list, reason)。

    batch_findings: [(original_fidx, finding_desc), ...]
    返回: [(original_fidx, confidence 0.0-1.0), ...]（空列表=无匹配），理由

    如果 token 超限，自动减半 batch size 重试，直到 1vs1。
    """
    if len(batch_findings) == 1:
        fidx, desc = batch_findings[0]
        prompt = [
            {
                "role": "system",
                "content": (
                    "你是漏洞匹配判定器。判断两个漏洞描述是否指的是同一个漏洞。\n"
                    "匹配标准：漏洞位置、攻击入口、漏洞类型、漏洞原理相同或高度相似。\n"
                    '只返回 JSON：{"is_same": true或false, "confidence": 0.0-1.0, "reason": "简要理由"}'
                ),
            },
            {
                "role": "user",
                "content": (
                    f"漏洞中心漏洞:\n{desc}\n\n"
                    f"基线漏洞:\n{baseline_content}\n\n"
                    f"判断这两个描述是否指的是同一个漏洞。"
                ),
            },
        ]
        try:
            result = llm_mod.chat_json(prompt, temperature=0, max_tokens=2000)
            is_same = result.get("is_same", False)
            reason = result.get("reason", "")
            if not isinstance(is_same, bool):
                is_same = str(is_same).lower() == "true"
            conf = result.get("confidence", 1.0)
            try:
                conf = float(conf)
            except (ValueError, TypeError):
                conf = 1.0
            return ([(fidx, conf)] if is_same else []), reason
        except Exception as e:
            log("FPR", f"LLM 判断失败: {e}")
            return [], f"LLM 错误: {e}"

    # 多条：批量判断，token 超限时自动降级
    current_batch = batch_findings
    while len(current_batch) > 1:
        lines = []
        for i, (fidx, desc) in enumerate(current_batch):
            lines.append(f"--- 候选{i+1} ---\n{desc}")
        candidates_text = "\n\n".join(lines)

        prompt = [
            {
                "role": "system",
                "content": (
                    "你是漏洞匹配判定器。给定一个基线漏洞和多个候选漏洞，"
                    "找出所有与基线指的是同一个漏洞的候选，并为每个命中的候选给出置信度。\n"
                    "匹配标准：漏洞位置、攻击入口、漏洞类型、漏洞原理相同或高度相似。\n"
                    "confidence 越高表示匹配越确信：1.0=完全确定，0.7=较可能，0.5=不确定。\n"
                    "如果没有匹配的候选，matched 为 []。\n"
                    '只返回 JSON：{"matched": [{"no": 候选编号, "confidence": 0.0-1.0}], "reason": "简要理由"}\n'
                    '示例：{"matched": [{"no": 1, "confidence": 0.9}], "reason": "候选1的漏洞位置和攻击入口与基线一致"}\n'
                    '示例：{"matched": [{"no": 1, "confidence": 0.9}, {"no": 3, "confidence": 0.6}], "reason": "候选1和3都与基线匹配，候选1更确信"}\n'
                    '示例：{"matched": [], "reason": "无匹配"}'
                ),
            },
            {
                "role": "user",
                "content": (
                    f"基线漏洞:\n{baseline_content}\n\n"
                    f"候选漏洞:\n{candidates_text}\n\n"
                    f"找出所有与基线漏洞是同一个漏洞的候选，给出编号和置信度（1-{len(current_batch)}），"
                    f"如果没有匹配则返回空列表 []。"
                ),
            },
        ]
        try:
            result = llm_mod.chat_json(prompt, temperature=0, max_tokens=2000)
            matched_raw = result.get("matched", [])
            reason = result.get("reason", "")
            # 解析为 [(fidx, confidence), ...]
            matched_pairs: list[tuple[int, float]] = []
            if isinstance(matched_raw, list):
                for item in matched_raw:
                    if isinstance(item, dict):
                        no = item.get("no", item.get("idx", item.get("candidate", 0)))
                        conf = item.get("confidence", 1.0)
                    elif isinstance(item, (int, float)):
                        no = item
                        conf = 1.0
                    elif isinstance(item, str):
                        import re
                        nums = re.findall(r'\d+', item)
                        if nums:
                            no = int(nums[0])
                        else:
                            continue
                        conf = 1.0
                    else:
                        continue
                    try:
                        no = int(no)
                        conf = float(conf)
                    except (ValueError, TypeError):
                        continue
                    if 1 <= no <= len(current_batch):
                        matched_pairs.append((current_batch[no - 1][0], conf))
            elif isinstance(matched_raw, int) and 1 <= matched_raw <= len(current_batch):
                matched_pairs.append((current_batch[matched_raw - 1][0], 1.0))
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
                # token 超限，减半 batch size 重试
                half = len(current_batch) // 2
                log("FPR", f"token 超限 (batch={len(current_batch)})，降级到 {half}+{len(current_batch)-half}")
                left = current_batch[:half]
                right = current_batch[half:]
                # 先查左半边
                left_matches, left_reason = _llm_match_batch(baseline_content, left)
                if left_matches:
                    # 左半边有匹配，合并右半边结果
                    right_matches, _ = _llm_match_batch(baseline_content, right)
                    return left_matches + right_matches, left_reason
                # 左半边无匹配，查右半边
                return _llm_match_batch(baseline_content, right)
            log("FPR", f"LLM 批量判断失败: {e}")
            return [], f"LLM 错误: {e}"

    # 降级到 1 条
    return _llm_match_batch(baseline_content, current_batch[:1])


def _run_matching(findings: list[dict], baseline_rows: list[dict],
                  progress_cb=None) -> list[dict]:
    """批量匹配：基线外循环，漏洞中心数据按 BATCH_SIZE 分批，每批一次 LLM 调用。

    多个候选命中时，取置信度最高的匹配，其余留在池中给后续基线匹配。

    返回与 findings 等长的列表，每个元素含:
      match_idx (基线索引, -1=未匹配), reason, baseline 信息
    """
    remaining = list(range(len(findings)))
    match_results = [
        {"match_idx": -1, "reason": "未匹配"} for _ in range(len(findings))
    ]

    for bl_idx, bl in enumerate(baseline_rows):
        if not remaining:
            log("FPR", f"漏洞中心数据已全部匹配完，跳过剩余基线 ({bl_idx+1}/{len(baseline_rows)})")
            break

        bl_content = bl.get("content", "")
        bl_title = bl.get("title", "")

        # 将剩余 findings 分批，每批 BATCH_SIZE 个
        batches: list[list[tuple[int, str]]] = []
        for i in range(0, len(remaining), _BATCH_SIZE):
            chunk_idxs = remaining[i:i + _BATCH_SIZE]
            batch = [(f_idx, _build_finding_desc(findings[f_idx]))
                     for f_idx in chunk_idxs]
            batches.append(batch)

        # 收集所有批次的匹配结果
        all_matches: list[tuple[int, float]] = []

        with ThreadPoolExecutor(max_workers=min(10, len(batches))) as pool:
            future_to_batch: dict = {}
            for batch in batches:
                fut = pool.submit(_llm_match_batch, bl_content, batch)
                future_to_batch[fut] = batch

            for fut in as_completed(future_to_batch):
                batch = future_to_batch[fut]
                matched_pairs, _ = fut.result()
                all_matches.extend(matched_pairs)

        if all_matches:
            # 按置信度降序排列，取最高的
            all_matches.sort(key=lambda x: x[1], reverse=True)
            matched_fidx = all_matches[0][0]
            best_conf = all_matches[0][1]
            if len(all_matches) > 1:
                others = [f"[{f+1}({c:.1f})]" for f, c in all_matches[1:]]
                log("FPR", f"基线'{bl_title}' 有多个候选命中: [{matched_fidx+1}({best_conf:.1f})] + {' '.join(others)}，取置信度最高")
            else:
                log("FPR", f"基线'{bl_title}' 匹配 [{matched_fidx+1}] 置信度={best_conf:.1f}")
            match_results[matched_fidx] = {
                "match_idx": bl_idx,
                "reason": f"置信度={best_conf:.1f}",
            }
            remaining.remove(matched_fidx)
            log("FPR", f"[{bl_idx+1}/{len(baseline_rows)}] 基线'{bl_title}' → 匹配漏洞中心[{matched_fidx+1}]")
        else:
            log("FPR", f"[{bl_idx+1}/{len(baseline_rows)}] 基线'{bl_title}' → 无匹配")

        if progress_cb:
            progress_cb(bl_idx + 1, len(baseline_rows))

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


def run_fpr_analysis(project_id: str, task_id: str,
                     progress_cb=None, source: str = "vuln_center") -> dict | None:
    """主入口：基线 CSV vs 漏洞中心/告警中心数据 → FPR + 匹配明细。

    source="vuln_center"  → 漏洞中心数据（E2E 分析）
    source="alert_center" → 告警中心数据（漏洞挖掘误报率）

    返回 dict:
      fpr, matched, fp, tp, total_findings, total_baseline, match_details
    若基线 CSV 未配置或不存在，返回 None（不生成 tab）。
    """
    csv_path = _get_baseline_path()
    if not csv_path:
        log("FPR", "未配置 FPR_BASELINE_CSV，跳过 FPR 分析")
        return None
    if not os.path.isfile(csv_path):
        log("FPR", f"基线 CSV 不存在: {csv_path}，跳过 FPR 分析")
        return None

    log("FPR", f"加载基线: {csv_path}")
    baseline_rows = load_baseline(csv_path)
    log("FPR", f"基线 {len(baseline_rows)} 条")

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

    log("FPR", f"批量 LLM 匹配: {len(baseline_rows)} 条基线 × {len(findings)} 条{source_label}数据 (batch={_BATCH_SIZE})")
    match_results = _run_matching(findings, baseline_rows, progress_cb)

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
