"""FN 漏报分析器 — 开发态下基线 VULNERABLE 但 LLM 未匹配上原始数据的真漏洞。

对每个 LLM 未匹配上的 VULNERABLE 基线 case：
1. 用 LLM 从 case description 中提取结构化 sink 信息（文件、函数、行号）
2. 用结构化 sink 信息在 trace 中做精确匹配
   - 函数级命中：trace event 中同时出现 sink 文件和 sink 函数名
   - 文件级命中：trace event 中只出现 sink 文件，没出现 sink 函数名
3. 分类漏报原因：
   - sink_found_no_report: sink 找到（函数级或文件级命中）但 agent 未上报漏洞
     → 漏洞识别能力问题
   - sink_not_found: sink 没找到（没有任何命中）→ 漏洞挖掘方向问题

数据保存到 debug 的 case_matching 步骤下新增子段展示。
"""
from __future__ import annotations

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log
from .sink_search_scanner import SinkSearchScanner
from .sink_info_extractor import SinkInfoExtractor


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
        scanner = SinkSearchScanner()
        results: list[dict] = []

        for cid, cd in unmatched_vuln_cases:
            vuln_title = cd.get("vuln_title", "")
            source_file = cd.get("source_file", "")
            description = cd.get("description", "")
            summary = cd.get("summary", "")
            sink_info = sink_infos.get(cid, {})

            # 用结构化 sink 信息扫描 trace
            scan_result = scanner.scan_with_sink_info(sink_info, data_packs)
            sink_found = scan_result.get("found", False)
            found_func_level = scan_result.get("found_function_level", False)
            hit_sessions = scan_result.get("hit_sessions", {})
            func_level_sessions = scan_result.get("function_level_sessions", {})
            file_level_sessions = scan_result.get("file_level_sessions", {})
            hits_by_agent = scan_result.get("hits_by_agent", {})

            # 分类漏报原因
            if sink_found:
                miss_category = "sink_found_no_report"
                # 收集命中的 event 上下文（按 agent_type 分组）
                hit_events: list[dict] = []
                for agent_type, events in hits_by_agent.items():
                    for ev_info in events:
                        hit_events.append({
                            "agent_type": agent_type,
                            **ev_info,
                        })
                total_sessions = sum(
                    len(sids) for sids in hit_sessions.values())
                total_func = sum(
                    len(sids) for sids in func_level_sessions.values())
                total_file = sum(
                    len(sids) for sids in file_level_sessions.values())
                if found_func_level:
                    miss_reason = (
                        f"trace 中找到 sink 点（{total_sessions} 个 session "
                        f"命中，其中 {total_func} 个函数级命中、"
                        f"{total_file} 个文件级命中），"
                        f"但 agent 未上报漏洞——"
                        f"属于漏洞识别能力问题")
                else:
                    miss_reason = (
                        f"trace 中找到 sink 文件（{total_sessions} 个 session "
                        f"文件级命中，无函数级命中——agent 读了文件但"
                        f"可能未碰到 sink 函数），但 agent 未上报漏洞——"
                        f"属于漏洞识别能力问题")
            else:
                miss_category = "sink_not_found"
                hit_events = []
                miss_reason = (
                    "trace 中没有任何 session 搜索过 sink 文件——"
                    "漏洞挖掘方向都没有，属于挖掘范围/路径覆盖问题")

            results.append({
                "case_id": cid,
                "vuln_title": vuln_title,
                "source_file": source_file,
                "summary": summary,
                "description": description,
                "expected_label": "VULNERABLE",
                "raw_matched": False,
                "sink_found": sink_found,
                "sink_found_function_level": found_func_level,
                "miss_category": miss_category,
                "sink_info": sink_info,
                "hit_sessions": hit_sessions,
                "function_level_sessions": func_level_sessions,
                "file_level_sessions": file_level_sessions,
                "hit_events": hit_events,
                "miss_reason": miss_reason,
            })

            log("FN_MISS",
                f"case {cid}: sink_found={sink_found}, "
                f"func_level={found_func_level}, "
                f"category={miss_category}, "
                f"hit_sessions={sum(len(s) for s in hit_sessions.values())}",
                eval_id=evaluation_id)

        # 统计
        sink_found_count = sum(1 for r in results if r["sink_found"])
        sink_not_found_count = len(results) - sink_found_count
        func_level_count = sum(
            1 for r in results if r.get("sink_found_function_level"))
        log("FN_MISS",
            f"FN 漏报分析完成: {len(results)} 个 case, "
            f"sink_found={sink_found_count} "
            f"(func_level={func_level_count}), "
            f"sink_not_found={sink_not_found_count}",
            eval_id=evaluation_id)

        return results
