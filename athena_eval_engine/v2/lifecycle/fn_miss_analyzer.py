"""FN 漏报分析器 — 开发态下基线 VULNERABLE 但 LLM 未匹配上原始数据的真漏洞。

对每个 LLM 未匹配上的 VULNERABLE 基线 case，用 source_file 与 trace
一个个匹配，查找漏报原因。两种结果：

1. sink 找到（trace 中有搜索该 source_file 的 session）：
   定位为什么没上报漏洞——agent 搜到了 sink 文件但没识别为漏洞，
   属于漏洞识别能力问题
2. sink 没找到（trace 中没有任何 session 搜索过该 source_file）：
   漏洞挖掘方向都没有——agent 根本没碰到这个文件，
   属于挖掘范围/路径覆盖问题

数据保存到 debug 的 case_matching 步骤下新增子段展示。
"""
from __future__ import annotations

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log
from .sink_search_scanner import SinkSearchScanner


class FnMissAnalyzer:
    """FN 漏报分析器。"""

    def analyze(
        self,
        evaluation_id: str,
        case_details: dict[str, dict],
        case_matches: list[dict],
        data_packs: list[DataPack],
        eval_mode: str = "dev",
    ) -> list[dict]:
        """对 LLM 未匹配上的 VULNERABLE 基线 case 做 FN 漏报分析。

        Args:
            evaluation_id: 评测 ID
            case_details: 基线 case 详情 {case_id: {vuln_title, description, expected_label, source_file, ...}}
            case_matches: INGESTING 阶段的 LLM 匹配结果
            data_packs: 全部 DataPack（挖掘 + 验证 agent）
            eval_mode: 评测模式（仅 dev 模式下执行）

        Returns:
            FN 漏报分析结果列表，每项含：
            - case_id: 基线 case_id
            - vuln_title: 漏洞标题
            - source_file: 基线 sink 文件路径
            - expected_label: 应为 "VULNERABLE"
            - sink_found: bool — trace 中是否找到 sink 文件
            - miss_category: "sink_not_found" | "sink_found_no_report"
              sink_not_found: 漏洞挖掘方向都没有（trace 没碰到 sink 文件）
              sink_found_no_report: sink 找到但没上报漏洞（漏洞识别能力问题）
            - hit_sessions: {agent_type: [session_id, ...]} — sink 命中的 session
            - hit_events: [{session_id, event_type, tool_name, input_preview, output_preview, ...}]
              sink 命中的 event 上下文（仅 sink_found=true 时有值）
            - miss_reason: str — 漏报原因描述
            - raw_matched: bool — LLM 是否匹配上原始数据（应为 false）
        """
        if eval_mode != "dev":
            log("FN_MISS",
                f"非 dev 模式（{eval_mode}），跳过 FN 漏报分析",
                eval_id=evaluation_id)
            return []

        # 找出 LLM 未匹配上的 VULNERABLE 基线 case
        # case_matches 里 matched_baseline_case_id=None 的基线是未匹配上的
        # 但 case_matches 是按原始数据组织的，需要反推哪些基线被匹配上
        matched_baseline_ids: set[str] = set()
        for m in case_matches:
            bid = m.get("matched_baseline_case_id") or ""
            if bid:
                matched_baseline_ids.add(bid)

        # 找出 VULNERABLE 且 LLM 未匹配上的基线 case
        unmatched_vuln_cases: list[tuple[str, dict]] = []
        for cid, cd in case_details.items():
            if cd.get("expected_label") != "VULNERABLE":
                continue
            if cid in matched_baseline_ids:
                continue  # LLM 已匹配上，不是漏报
            unmatched_vuln_cases.append((cid, cd))

        if not unmatched_vuln_cases:
            log("FN_MISS",
                "无 LLM 未匹配的 VULNERABLE 基线 case，跳过 FN 漏报分析",
                eval_id=evaluation_id)
            return []

        log("FN_MISS",
            f"FN 漏报分析: {len(unmatched_vuln_cases)} 个 VULNERABLE 基线 "
            f"LLM 未匹配上原始数据，开始与 trace 一个个匹配",
            eval_id=evaluation_id)

        scanner = SinkSearchScanner()
        results: list[dict] = []

        for cid, cd in unmatched_vuln_cases:
            vuln_title = cd.get("vuln_title", "")
            source_file = cd.get("source_file", "")
            description = cd.get("description", "")
            summary = cd.get("summary", "")

            # 用 source_file 扫描 trace
            scan_result = scanner.scan_detailed(source_file, data_packs)
            sink_found = scan_result.get("found", False)
            hit_sessions = scan_result.get("hit_sessions", {})
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
                miss_reason = (
                    f"trace 中找到 sink 文件（{total_sessions} 个 session "
                    f"搜索过），但 agent 未上报漏洞——"
                    f"属于漏洞识别能力问题")
            else:
                miss_category = "sink_not_found"
                hit_events = []
                miss_reason = (
                    "trace 中没有任何 session 搜索过该 sink 文件——"
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
                "miss_category": miss_category,
                "hit_sessions": hit_sessions,
                "hit_events": hit_events,
                "miss_reason": miss_reason,
            })

            log("FN_MISS",
                f"case {cid}: sink_found={sink_found}, "
                f"category={miss_category}, "
                f"hit_sessions={sum(len(s) for s in hit_sessions.values())}",
                eval_id=evaluation_id)

        # 统计
        sink_found_count = sum(1 for r in results if r["sink_found"])
        sink_not_found_count = len(results) - sink_found_count
        log("FN_MISS",
            f"FN 漏报分析完成: {len(results)} 个 case, "
            f"sink_found={sink_found_count}, "
            f"sink_not_found={sink_not_found_count}",
            eval_id=evaluation_id)

        return results
