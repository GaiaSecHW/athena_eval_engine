"""FN 漏报分析器 — 开发态下基线 VULNERABLE 但 LLM 未匹配上原始数据的真漏洞。

对每个 LLM 未匹配上的 VULNERABLE 基线 case：
1. 用 LLM 从 case description 中提取结构化 sink 信息（文件、函数、行号）
2. 用结构化 sink 信息在 trace 中做精确匹配
   - 精确命中：trace event 中同时出现 sink 文件 + sink 函数名，或
     sink 文件 + sink 行号在范围内 → agent 真正接触了 sink 点
   - 文件级命中：trace event 中只出现 sink 文件，没出现 sink 函数/行号
     → agent 可能只是搜索时在结果列表里碰到路径，未真正读到 sink 点
3. 分类漏报原因：
   - sink_found_no_report: sink 点精确命中但 agent 未上报漏洞
     → 用 LLM 细分漏报成因（调用链中断/知识误导/幻觉/验证遗漏等）
   - sink_not_found: 无精确命中（可能仅有文件级命中）→ 漏洞挖掘方向问题

数据保存到 debug 的 case_matching 步骤下新增子段展示。
"""
from __future__ import annotations

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log
from .sink_search_scanner import SinkSearchScanner
from .sink_info_extractor import SinkInfoExtractor
from .miss_detail_analyzer import MissDetailAnalyzer, MISS_SUB_CATEGORIES


class FnMissAnalyzer:
    """FN 漏报分析器。"""

    def analyze(
        self,
        evaluation_id: str,
        case_details: dict[str, dict],
        case_matches: list[dict],
        data_packs: list[DataPack],
        eval_mode: str = "dev",
        cancel_cb=None,
    ) -> list[dict]:
        """对 LLM 未匹配上的 VULNERABLE 基线 case 做 FN 漏报分析。

        Args:
            evaluation_id: 评测 ID
            case_details: 基线 case 详情 {case_id: {vuln_title, description, expected_label, source_file, ...}}
            case_matches: INGESTING 阶段的 LLM 匹配结果
            data_packs: 全部 DataPack（挖掘 + 验证 agent）
            eval_mode: 评测模式（仅 dev 模式下执行）
            cancel_cb: 取消回调

        Returns:
            FN 漏报分析结果列表，每项含：
            - case_id: 基线 case_id
            - vuln_title: 漏洞标题
            - source_file: 基线 sink 文件路径（原始 locator）
            - sink_info: LLM 提取的结构化 sink 信息
            - expected_label: 应为 "VULNERABLE"
            - sink_found: bool — trace 中是否找到 sink 点（函数级或文件级）
            - sink_found_function_level: bool — 是否有函数级命中
            - miss_category: "sink_not_found" | "sink_found_no_report"
            - hit_sessions: {agent_type: [session_id, ...]} — 所有命中的 session
            - function_level_sessions: {agent_type: [session_id, ...]} — 函数级命中
            - file_level_sessions: {agent_type: [session_id, ...]} — 文件级命中
            - hit_events: [{session_id, event_type, tool_name, ...}]
              命中的 event 上下文（含 match_precision 字段）
            - miss_reason: str — 漏报原因描述
            - raw_matched: bool — LLM 是否匹配上原始数据（应为 false）
        """
        if eval_mode != "dev":
            log("FN_MISS",
                f"非 dev 模式（{eval_mode}），跳过 FN 漏报分析",
                eval_id=evaluation_id)
            return []

        # 找出 LLM 未匹配上的 VULNERABLE 基线 case
        matched_baseline_ids: set[str] = set()
        for m in case_matches:
            bid = m.get("matched_baseline_case_id") or ""
            if bid:
                matched_baseline_ids.add(bid)

        unmatched_vuln_cases: list[tuple[str, dict]] = []
        for cid, cd in case_details.items():
            if cd.get("expected_label") != "VULNERABLE":
                continue
            if cid in matched_baseline_ids:
                continue
            unmatched_vuln_cases.append((cid, cd))

        if not unmatched_vuln_cases:
            log("FN_MISS",
                "无 LLM 未匹配的 VULNERABLE 基线 case，跳过 FN 漏报分析",
                eval_id=evaluation_id)
            return []

        log("FN_MISS",
            f"FN 漏报分析: {len(unmatched_vuln_cases)} 个 VULNERABLE 基线 "
            f"LLM 未匹配上原始数据，开始提取 sink 信息并匹配 trace",
            eval_id=evaluation_id)

        # Step 1: 用 LLM 提取每个 case 的结构化 sink 信息
        extractor = SinkInfoExtractor()
        sink_infos: dict[str, dict] = {}
        for cid, cd in unmatched_vuln_cases:
            if cancel_cb:
                cancel_cb()
            sink_infos[cid] = extractor.extract(cd, cancel_cb=cancel_cb)

        log("FN_MISS",
            f"LLM sink 信息提取完成: {len(sink_infos)} 个 case",
            eval_id=evaluation_id)

        # Step 2: 用结构化 sink 信息在 trace 中做精确匹配
        # 文件级命中（仅文件名，无函数/行号级）直接忽略——
        # 只有 agent 确实读到过疑似 sink 点（函数或行号级命中）才算找到过
        scanner = SinkSearchScanner()
        results: list[dict] = []

        # 预建 session_id → events 索引（供 MissDetailAnalyzer 取精确命中
        # session 的完整事件上下文）
        session_events: dict[str, list] = {}
        for dp in data_packs:
            for ev in (dp.events or []):
                sid = ev.session_id or ""
                if sid:
                    session_events.setdefault(sid, []).append(ev)
        miss_detail_analyzer = MissDetailAnalyzer()

        for cid, cd in unmatched_vuln_cases:
            vuln_title = cd.get("vuln_title", "")
            source_file = cd.get("source_file", "")
            description = cd.get("description", "")
            summary = cd.get("summary", "")
            sink_info = sink_infos.get(cid, {})

            # 用结构化 sink 信息扫描 trace
            scan_result = scanner.scan_with_sink_info(sink_info, data_packs)
            found_precise = scan_result.get("found_precise", False)
            hit_sessions = scan_result.get("hit_sessions", {})
            precise_sessions = scan_result.get("precise_sessions", {})
            hits_by_agent = scan_result.get("hits_by_agent", {})

            # 分类漏报原因：
            # sink 找到 = 有精确命中（函数或行号级）——agent 确实读到过疑似 sink 点
            # 文件级命中直接忽略——grep/glob 输出列表碰巧含路径不算找到
            miss_detail: dict = {}
            if found_precise:
                sink_found = True
                miss_category = "sink_found_no_report"
                # 只收集精确命中的 event 上下文（文件级命中忽略）
                hit_events: list[dict] = []
                for agent_type, events in hits_by_agent.items():
                    for ev_info in events:
                        if ev_info.get("match_precision") != "precise":
                            continue
                        hit_events.append({
                            "agent_type": agent_type,
                            **ev_info,
                        })
                total_precise = sum(
                    len(sids) for sids in precise_sessions.values())
                miss_reason = (
                    f"trace 中找到疑似 sink 点（{total_precise} 个 session "
                    f"精确命中——agent 确实读到过 sink 函数/行号），"
                    f"但 agent 未上报漏洞")

                # ── 细分漏报成因（LLM 分析精确命中 session 上下文）──
                # sink_found_no_report 内部成因多样：调用链中断、知识误导、
                # 幻觉、验证遗漏等。用 LLM 判定最可能的细分成因。
                miss_detail = miss_detail_analyzer.analyze(
                    evaluation_id,
                    {
                        "case_id": cid,
                        "vuln_title": vuln_title,
                        "description": description,
                        "sink_info": sink_info,
                        "precise_sessions": precise_sessions,
                    },
                    session_events,
                    cancel_cb=cancel_cb,
                )
                sub_label = miss_detail.get(
                    "miss_sub_category_label", "其他")
                miss_reason = (
                    f"{miss_reason}——细分漏报成因：{sub_label}"
                    f"（{miss_detail.get('reason', '')[:150]}）"
                    if miss_detail.get("reason") else miss_reason)
            else:
                sink_found = False
                miss_category = "sink_not_found"
                hit_events = []
                miss_reason = (
                    "trace 中未找到疑似 sink 点——agent 从未读到过 "
                    "sink 函数/行号，漏洞挖掘方向都没有，"
                    "属于挖掘范围/路径覆盖问题")

            results.append({
                "case_id": cid,
                "vuln_title": vuln_title,
                "source_file": source_file,
                "summary": summary,
                "description": description,
                "expected_label": "VULNERABLE",
                "raw_matched": False,
                "sink_found": sink_found,
                "sink_found_precise": found_precise,
                "miss_category": miss_category,
                "miss_detail": miss_detail,
                "sink_info": sink_info,
                "hit_sessions": precise_sessions,
                "precise_sessions": precise_sessions,
                "hit_events": hit_events,
                "miss_reason": miss_reason,
            })

            log("FN_MISS",
                f"case {cid}: sink_found={sink_found}, "
                f"precise={found_precise}, "
                f"category={miss_category}"
                + (f", sub={miss_detail.get('miss_sub_category', '')}"
                   if miss_detail else ""),
                eval_id=evaluation_id)

        # 统计
        sink_found_count = sum(1 for r in results if r["sink_found"])
        sink_not_found_count = len(results) - sink_found_count
        precise_count = sum(
            1 for r in results if r.get("sink_found_precise"))
        log("FN_MISS",
            f"FN 漏报分析完成: {len(results)} 个 case, "
            f"sink_found={sink_found_count} "
            f"(precise={precise_count}), "
            f"sink_not_found={sink_not_found_count}",
            eval_id=evaluation_id)

        return results
