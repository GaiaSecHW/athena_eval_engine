"""FPR（误报率）分析模块 — 基线 CSV vs 漏洞中心数据，嵌套循环 1vs1 LLM 匹配。

在 REPORTING 阶段被调用，结果作为第三个 tab（漏洞E2E结果）展示。
基线 CSV 来源：run8_reports_full.zip 生成的 run8_baseline.csv（含 VULNERABLE + NON_VULNERABLE）。
"""
from __future__ import annotations
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..infrastructure import vuln_center_client
from ..infrastructure import llm as llm_mod
from ..infrastructure.log_util import log


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


def _llm_match_pair(finding_desc: str, baseline_content: str) -> tuple[bool, str]:
    """用 LLM 判断两个漏洞描述是否为同一个漏洞，返回 (is_same, reason)。"""
    prompt = [
        {
            "role": "system",
            "content": (
                "你是漏洞匹配判定器。判断两个漏洞描述是否指的是同一个漏洞。\n"
                "匹配标准：漏洞位置、漏洞类型、漏洞原理相同或高度相似。\n"
                "只返回 JSON：{\"is_same\": true或false, \"reason\": \"简要理由\"}"
            ),
        },
        {
            "role": "user",
            "content": (
                f"漏洞中心漏洞:\n{finding_desc}\n\n"
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
        return is_same, reason
    except Exception as e:
        log("FPR", f"LLM 判断失败: {e}")
        return False, f"LLM 错误: {e}"


def _run_matching(findings: list[dict], baseline_rows: list[dict],
                  progress_cb=None) -> list[dict]:
    """嵌套循环匹配：基线外循环，漏洞中心数据内循环，1vs1对比。

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

        matched_fidx = None
        matched_reason = ""

        with ThreadPoolExecutor(max_workers=min(10, len(remaining))) as pool:
            future_to_fidx: dict = {}
            for f_idx in remaining:
                finding_desc = _build_finding_desc(findings[f_idx])
                fut = pool.submit(_llm_match_pair, finding_desc, bl_content)
                future_to_fidx[fut] = f_idx

            for fut in as_completed(future_to_fidx):
                f_idx = future_to_fidx[fut]
                is_same, reason = fut.result()
                if is_same and matched_fidx is None:
                    matched_fidx = f_idx
                    matched_reason = reason

        if matched_fidx is not None:
            match_results[matched_fidx] = {
                "match_idx": bl_idx,
                "reason": matched_reason,
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
                     progress_cb=None) -> dict | None:
    """主入口：基线 CSV vs 漏洞中心数据 → FPR + 匹配明细。

    返回 dict:
      fpr, matched, fp, tp, total_findings, total_baseline, match_details
    若基线 CSV 未配置或不存在，返回 None（不生成第三个 tab）。
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

    log("FPR", f"从漏洞中心获取数据: project={project_id}, task={task_id}")
    findings = vuln_center_client.list_vuln_cases(
        project_id=project_id,
        source_task_id=task_id,
    )
    log("FPR", f"漏洞中心返回 {len(findings)} 条")

    if not findings:
        log("FPR", "漏洞中心无数据，跳过 FPR 分析")
        return None

    log("FPR", f"LLM 匹配: {len(baseline_rows)} 条基线(外循环) × {len(findings)} 条漏洞中心数据(内循环)")
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
