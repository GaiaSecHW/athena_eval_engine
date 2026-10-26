"""case↔session 匹配器。

运行态和开发态共用。

匹配策略：
- 只对误报（NON_VULNERABLE）case 进行匹配
- 在 trace 中找漏洞 finding 记录（title 精确匹配，多个用 description 消歧）
- 命中的 session 按 DataPack.agent_type 分类：
  - 挖掘 agent session：turing/argo/secmate/dataflow 的 session
  - 验证 agent session：cvuln_verify/webvuln_verify 的 session
- Turing 的 vuln-hunt-validate 是挖掘 agent 内部的验证阶段，
  不是独立验证 agent，归类为挖掘 agent session

匹配链：
- 基线 case ←LLM 语义匹配→ 原始 case（告警中心，case_matches）
- 原始 case ←程序精确匹配→ trace session（用 title 精确匹配，多个用 description 消歧）

Turing 平台匹配方式：
- 从 vuln-hunt-validate session 的 vuln_hunt_query_finding 工具调用
  output 解析漏洞 title + description
- 命中的 session 归类为挖掘 agent session（Turing 是挖掘 agent）

其他平台（webvuln_verify / cvuln_verify）：
- DataPack.agent_type 即为验证 agent，整个 DataPack 都是验证 agent session
- 从验证工具调用提取 title + description

运行态：基线 case_id 就是告警中心 case_id，直接映射
开发态：从 case_matches（LLM 匹配结果）提取基线→告警中心映射

- 基线 NON_VULNERABLE + finding 命中 = FP，未命中 = TN
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from ..core.data_pack import DataPack
from ..core.agents import MINING_AGENT_SET, VERIFY_AGENT_SET
from ...infrastructure.log_util import log


class CaseSessionMatcher:
    """case↔session 匹配器。"""

    # 挖掘 / 验证 agent 类型（集中配置，见 v2/core/agents.py）
    _MINING_AGENT_TYPES = MINING_AGENT_SET
    _VERIFY_AGENT_TYPES = VERIFY_AGENT_SET

    # session_id → session_type 查找表（match() 每次构建，_classify_session 用）
    _session_type_map: dict[str, str] = {}

    def match(
        self,
        evaluation_id: str,
        data_packs: list[DataPack],
        case_details: dict[str, dict],
        case_matches: list[dict] | None = None,
        eval_mode: str = "runtime",
        alert_center_data: dict | None = None,
    ) -> list[dict]:
        """对基线 case，在 trace 中找到挖掘 agent session 和验证 agent session。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表（含挖掘 + 验证 agent）
            case_details: 基线 case 详情 {case_id: {vuln_title, description, expected_label, ...}}
            case_matches: INGESTING 阶段的 LLM 匹配结果（开发态用）
            eval_mode: "runtime"（运行态）| "dev"（开发态）
            alert_center_data: 告警中心数据（运行态用，含 cases 列表，
                               每条含 case_id 和 title）

        Returns:
            匹配结果列表，每项含：
            - case_id: 基线 case_id
            - ac_case_id: 告警中心 case_id（匹配上的）
            - vuln_title, expected_label
            - mining_sessions: [session_id, ...]  挖掘 agent 命中的 session
            - verify_sessions: [session_id, ...]  验证 agent 命中的 session
            - outcome: "FP" / "TN"
            - match_method: "matched" / "unmatched"
            - match_detail: 匹配细节
        """
        # 场景区分：运行态误报 vs 开发态漏报
        # - 运行态（runtime）：误报 FP 用 session_type 分类（verify session 不该
        #   进 mining_sessions——修复一个 case 匹配多个 mining session）
        # - 开发态（dev）/漏报 FN：查所有 session（漏报是 agent 没上报，需要
        #   查全部接触过 sink/相关代码的 session，包括 verify 类型）
        #   注意：开发态基线来自预置集，漏报分析要全量 session。
        self._use_session_type = (eval_mode == "runtime")

        # 构建 session_id → session_type 查找表（investigate/verify/reason/None）
        # 用于 _classify_session 按 session 实际类型分类，而不是只看 agent_type。
        # argo 的 DataPack agent_type=argo，但一个 pack 内同时含 investigate 和
        # verify session（挖掘 + 验证混合），仅按 agent_type 分类会把 verify
        # session 误放 mining_sessions（导致一个 case 匹配多个 mining session）。
        # 存实例属性（match 每次调用刷新）
        self._session_type_map = {}
        for dp in data_packs:
            sg = dp.session_graph or {}
            sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
            if isinstance(sessions, dict):
                for sid, sdata in sessions.items():
                    if not isinstance(sdata, dict):
                        continue
                    st = sdata.get("session_type") or sdata.get("task_type") or ""
                    if st:
                        self._session_type_map[sid] = str(st).lower()

        # 构建基线 case_id → 告警中心 case_id 的映射
        baseline_to_ac = self._build_baseline_ac_map(
            case_details, case_matches, eval_mode)

        # 构建告警中心 case_id → 原始 case title 的映射
        ac_title_map: dict[str, str] = {}
        if case_matches:
            for m in case_matches:
                raw_id = str(m.get("raw_case_id", "") or "")
                raw_title = str(m.get("raw_title", "") or "")
                if raw_id and raw_title:
                    ac_title_map[raw_id] = raw_title
        elif alert_center_data:
            for c in alert_center_data.get("cases", []):
                cid = str(c.get("case_id") or c.get("id") or "")
                title = str(c.get("title") or "")
                if cid and title:
                    ac_title_map[cid] = title

        # 误报 case（NON_VULNERABLE）：finding 命中 = FP，未命中 = TN
        # 漏报 case（VULNERABLE）：finding 命中 = TP，未命中 = FN
        # FN case 用基线 sink 点 source_file 扫描 trace 找 session
        target_cases = [(cid, cd) for cid, cd in case_details.items()
                        if cd.get("expected_label") in ("NON_VULNERABLE", "VULNERABLE")]

        log("MATCH",
            f"{eval_mode} 匹配: {len(target_cases)} 个 case, "
            f"{len(data_packs)} 个 data_packs",
            eval_id=evaluation_id)

        # 按 DataPack.agent_type 分类
        mining_packs = [dp for dp in data_packs
                        if dp.agent_type in self._MINING_AGENT_TYPES]
        verify_packs = [dp for dp in data_packs
                        if dp.agent_type in self._VERIFY_AGENT_TYPES]

        # Turing 内部：含 finding 的 session（vuln-hunt-validate/web-validate）
        # 这些是挖掘 agent 内部的验证阶段 session，归类为挖掘 agent session
        from .findings import collect_turing_finding_sids
        turing_finding_sids: set[str] = collect_turing_finding_sids(mining_packs)

        log("MATCH",
            f"mining_packs={len(mining_packs)}, "
            f"verify_packs={len(verify_packs)}, "
            f"turing_finding_sids={len(turing_finding_sids)}",
            eval_id=evaluation_id)

        # 构建 title → [(session_id, description, agent_type)] 索引
        # 跨全部 agent 类型，命中后按 agent_type 分类到 mining/verify
        finding_index = self._build_finding_index(
            data_packs, turing_finding_sids)

        results: list[dict] = []
        for cid, cd in target_cases:
            ac_case_id = baseline_to_ac.get(cid, "")
            vuln_title = cd.get("vuln_title", "")
            expected_label = cd.get("expected_label", "")
            baseline_desc = cd.get("description", "")
            baseline_summary = cd.get("summary", "")

            mining_sessions: list[str] = []
            verify_sessions: list[str] = []
            match_method_used = ""

            # 匹配策略：用原始 case title 去 finding title 精确匹配
            raw_title = ac_title_map.get(ac_case_id, "")
            if raw_title and raw_title in finding_index:
                entries = finding_index[raw_title]
                if len(entries) == 1:
                    sid, _, agent_type = entries[0]
                    self._classify_session(sid, agent_type,
                                           mining_sessions, verify_sessions)
                    match_method_used = "raw_title"
                elif len(entries) > 1:
                    # 多个匹配，用漏洞摘要精确匹配消歧
                    matched_any = False
                    for sid, desc, agent_type in entries:
                        if desc and baseline_summary and desc == baseline_summary:
                            self._classify_session(sid, agent_type,
                                                   mining_sessions, verify_sessions)
                            match_method_used = "raw_title+summary"
                            matched_any = True
                            break
                    if not matched_any:
                        # 摘要没匹配上，用全部 session
                        for sid, _, agent_type in entries:
                            self._classify_session(sid, agent_type,
                                                   mining_sessions, verify_sessions)
                        match_method_used = "raw_title_multi"

            # Argo 挖掘 agent 回退：vuln_title ↔ finding description 精确匹配
            # Argo finding 无 title（只有 description），告警中心 title 与 description
            # 不同源，raw_title 匹配不到。运行态下 finding 上报漏洞中心，其
            # description 成为漏洞中心 case 的 title（vuln_title），直接精确匹配。
            # 只在挖掘 session 尚未匹配到且运行态时启用（开发态由 LLM 匹配处理）。
            if not mining_sessions and eval_mode == "runtime" and vuln_title:
                if vuln_title in finding_index:
                    entries = finding_index[vuln_title]
                    matched_any = False
                    for sid, fkey, agent_type in entries:
                        if agent_type in self._MINING_AGENT_TYPES:
                            self._classify_session(sid, agent_type,
                                                   mining_sessions, verify_sessions)
                            matched_any = True
                    if matched_any:
                        match_method_used = (match_method_used +
                            "+mining_vuln_title" if match_method_used
                            else "mining_vuln_title")
                        # 检查是否有 session 丢失的 fallback entry（sid 为空）
                        has_lost = any(
                            not sid for sid, _, at in entries
                            if at in self._MINING_AGENT_TYPES
                        )
                        if has_lost:
                            match_method_used += "+session_lost(上报session文件丢失)"

            # 验证 agent 回退：用 session_graph.vuln_id_to_sessions 匹配
            # WebVulnVerify/CVulnVerify 的 session metadata 含 chimera_vuln_id（= case_id）
            # 和 vulnerability_id（数字）。v2s 双 key（数字 ID + case_id）——
            # 用基线 case_id（cid）或 LLM 匹配的原始 case_id（ac_case_id）查找。
            # CVulnVerify 用 finding_to_session（case_id → session），v2s 为空时兜底。
            #
            # WebVulnVerify 的 case↔session 父子关系权威源：gaiasec-server API
            # 在 PARSING 阶段（parser.build_session_graph）调用，构建到
            # session_graph.sessions/parent_map。case_session_matcher 直接读
            # session_graph（与 trace 解析同源，调用链一套规则），不再单独调 API。
            verify_match_detail = ""
            if not verify_sessions:
                for dp in verify_packs:
                    sg = dp.session_graph or {}
                    v2s = sg.get("vuln_id_to_sessions", {})
                    # case_id 可能带前缀（case-20260730-...），也可能只有数字 ID
                    sids = set()
                    if v2s:
                        sids = set(v2s.get(cid, set())) or set(v2s.get(ac_case_id, set()))
                        if not sids:
                            # 尝试用数字 ID 匹配（case_id 中提取数字部分）
                            for vid, vid_sids in v2s.items():
                                if vid == cid or vid == ac_case_id:
                                    sids = set(vid_sids)
                                    break
                    # CVulnVerify 兜底：finding_to_session（case_id → session）
                    if not sids:
                        f2s = sg.get("finding_to_session", {})
                        for key in (cid, ac_case_id):
                            f_sid = f2s.get(key, "")
                            if f_sid:
                                sids.add(f_sid)
                    if sids:
                        # 去重父子关系：同一 vuln_id 可能关联多个 session，
                        # 其中存在父子关系（如 analyze + verify session）。
                        # 只保留根 session（parent_id 为空或不在集合中的），
                        # 与挖掘链处理方式一致——_analyze_chain 只压缩命中的
                        # 根 session，不展开子 session。
                        sids = self._filter_child_sessions(sids, dp)
                        for sid in sids:
                            self._classify_session(sid, dp.agent_type,
                                                   mining_sessions, verify_sessions)
                        if not match_method_used:
                            match_method_used = "vuln_id_map"
                        else:
                            match_method_used += "+vuln_id_map"
                        break

            # ── 挖掘 session 回退：验证 session 有但挖掘 session 无时，反推挖掘 session ──
            # 用户洞察：验证 agent 的数据来源于挖掘 agent，验证能找到 session
            # 说明挖掘链一定存在。以下策略按可信度从高到低尝试：
            # 1. 跨 agent parent_map：验证 session 的 parent_id 指向挖掘 session
            #    （WebVulnVerify session 由 Turing session 调起时 parent_id 指向 Turing）
            # 2. 模糊标题匹配：精确标题不匹配但子串包含或关键词高度重叠
            mining_match_detail = ""
            if verify_sessions and not mining_sessions:
                mining_match_detail = self._find_mining_via_parent_map(
                    verify_sessions, verify_packs,
                    mining_packs, mining_sessions)
                if mining_match_detail:
                    match_method_used = (match_method_used +
                        "+mining_parent_map" if match_method_used
                        else "mining_parent_map")
                if not mining_sessions:
                    fuzzy_detail = self._fuzzy_match_mining(
                        finding_index, raw_title, vuln_title,
                        baseline_summary, baseline_desc,
                        mining_sessions)
                    if fuzzy_detail:
                        mining_match_detail = fuzzy_detail
                        match_method_used = (match_method_used +
                            "+mining_fuzzy" if match_method_used
                            else "mining_fuzzy")

            # ── 验证 session 缺失诊断 ──
            # 有挖掘 session 但无验证 session 时，扫描验证 agent 全部 events
            # 查找 case_id 的任何出现，明确报告数据断链位置：
            #   - 验证 agent trace 中根本不存在此 case_id（挖掘→验证之间数据断链）
            #   - 存在但匹配逻辑未命中（匹配逻辑需改进）
            if mining_sessions and not verify_sessions:
                verify_match_detail = self._diagnose_verify_gap(
                    cid, ac_case_id, verify_packs)

            # 判定 outcome：
            # - 误报 case（NON_VULNERABLE）：finding 命中 = FP，未命中 = TN
            # - 漏报 case（VULNERABLE）：
            #   * 挖掘 CONFIRMED + 验证 CONFIRMED → TP（正确上报）
            #   * 挖掘 CONFIRMED + 验证否定 → FN（验证 agent 否定真漏洞，
            #     根因在验证链——agent 漏报）
            #   * 无 session → FN（挖掘方向问题）
            #   * 只有文件级命中 → FN（挖掘方向问题）
            # FN case 用基线 sink 点 source_file 扫描 trace 找 session
            all_sessions = mining_sessions + verify_sessions
            verify_verdict = ""
            if expected_label == "NON_VULNERABLE":
                outcome = "FP" if all_sessions else "TN"
            else:  # VULNERABLE
                if verify_sessions:
                    # 有验证 session：检查验证 agent 最终判定
                    # 挖掘 agent 上报 CONFIRMED，但验证 agent 否定 → 漏报，根因在验证链
                    verify_verdict = self._get_verify_verdict(
                        verify_packs, verify_sessions)
                    if verify_verdict == "FALSE_POSITIVE":
                        outcome = "FN"
                        match_method_used = (match_method_used +
                            "+verify_negated" if match_method_used
                            else "verify_negated")
                    else:
                        outcome = "TP"
                elif all_sessions:
                    # 有挖掘 session 无验证 session：保持 TP（挖掘已上报），
                    # match_detail 提示验证链缺失
                    outcome = "TP"
                else:
                    # FN case：用 source_file 扫描 trace 找 session
                    source_file = cd.get("source_file", "")
                    if source_file:
                        from .sink_search_scanner import SinkSearchScanner
                        scanner = SinkSearchScanner()
                        sink_hits = scanner.scan(source_file, data_packs)
                        for at, sids in sink_hits.items():
                            for sid in sids:
                                self._classify_session(
                                    sid, at,
                                    mining_sessions, verify_sessions)
                        if sink_hits:
                            match_method_used = (match_method_used +
                                "+sink_scan" if match_method_used
                                else "sink_scan")
                    all_sessions = mining_sessions + verify_sessions
                    outcome = "FN" if not all_sessions else "TP"

            matched = bool(all_sessions)
            method = "matched" if matched else "unmatched"
            detail_parts = []
            if all_sessions:
                detail_parts.append(
                    f"{len(mining_sessions)} × mining, "
                    f"{len(verify_sessions)} × verify ({match_method_used})")
                # 验证 agent 判定结果（挖掘 CONFIRMED + 验证否定 → FN，根因在验证链）
                if verify_verdict:
                    detail_parts.append(
                        f"验证判定: {verify_verdict}")
                    if outcome == "FN" and verify_verdict == "FALSE_POSITIVE":
                        detail_parts.append(
                            "漏报根因: 验证 agent 否定真漏洞（挖掘 CONFIRMED，"
                            "验证否定），根因在验证链")
                if verify_match_detail:
                    detail_parts.append(verify_match_detail)
                if mining_match_detail:
                    detail_parts.append(mining_match_detail)
            else:
                detail_parts.append("未匹配")
                if verify_match_detail:
                    detail_parts.append(verify_match_detail)
                if mining_match_detail:
                    detail_parts.append(mining_match_detail)
            detail = " | ".join(detail_parts)

            results.append({
                "case_id": cid,
                "ac_case_id": ac_case_id,
                "vuln_title": vuln_title,
                "summary": baseline_summary,
                "description": baseline_desc,
                "expected_label": expected_label,
                "mining_sessions": mining_sessions,
                "verify_sessions": verify_sessions,
                "verify_verdict": verify_verdict,
                "outcome": outcome,
                "match_method": method,
                "match_detail": detail,
            })

            log("MATCH",
                f"case {cid}: outcome={outcome}, method={method}, "
                f"mining={len(mining_sessions)}, verify={len(verify_sessions)} "
                f"sessions ({match_method_used})"
                + (f" | {verify_match_detail}" if verify_match_detail else "")
                + (f" | {mining_match_detail}" if mining_match_detail else ""),
                eval_id=evaluation_id)

        matched_count = sum(1 for r in results if r["match_method"] != "unmatched")
        outcome_counts = {
            o: sum(1 for r in results if r["outcome"] == o)
            for o in ("FP", "TN", "TP", "FN")
        }
        log("MATCH",
            f"匹配完成: {matched_count}/{len(target_cases)} case 命中, "
            f"FP={outcome_counts['FP']}, TN={outcome_counts['TN']}, "
            f"TP={outcome_counts['TP']}, FN={outcome_counts['FN']}",
            eval_id=evaluation_id)

        return results

    def _classify_session(
        self,
        sid: str,
        agent_type: str,
        mining_sessions: list[str],
        verify_sessions: list[str],
    ):
        """按 agent_type 分类到挖掘或验证列表。

        每个 agent 的 session 只在自己的体系内：
        - 挖掘 agent（argo/turing/secmate/dataflow）的 session → mining_sessions
          （不管 session_type 是 investigate 还是 verify——argo 的 verify session
          是挖掘 agent 内部的验证阶段，不是验证 agent 的 session）
        - 验证 agent（WebVulnVerify/CVulnVerify）的 session → verify_sessions
        """
        # 空 sid（上报 session 丢失的 fallback entry）不加入任何列表
        if not sid:
            return
        if agent_type in CaseSessionMatcher._VERIFY_AGENT_TYPES:
            if sid not in verify_sessions:
                verify_sessions.append(sid)
        else:
            if sid not in mining_sessions:
                mining_sessions.append(sid)

    @staticmethod
    def _filter_child_sessions(
        sids, dp: "DataPack",
    ) -> list[str]:
        """从 session 集合中优先保留子 session（verify），没有子 session 才保留根 session（analyze）。

        WebVulnVerify 一个 case 有两个 session：
        - analyze session（无 parent_id，根节点）
        - verify session（parent_id 指向 analyze session，子节点）

        verify_sessions 应该取 verify session（子节点），但如果 analyze
        session 无子节点（只有 analyze，没有 verify），则取 analyze session。

        Args:
            sids: vuln_id_to_sessions 返回的 session 集合（set 或 list）。
            dp: 所属 DataPack，用于取 parent_map。

        Returns:
            session_id 列表——优先子节点（verify），无子节点时取根节点（analyze）。
        """
        sid_list = list(sids) if not isinstance(sids, (list, tuple)) else list(sids)
        sid_set = set(sid_list)
        if len(sid_set) <= 1:
            return sid_list

        sg = dp.session_graph or {}
        parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}

        # 子 session：parent_id 在集合中的 session（verify session）
        children: list[str] = []
        roots: list[str] = []
        for sid in sid_list:
            pid = parent_map.get(sid, "")
            if pid and pid in sid_set:
                # 有 parent_id 且 parent 在集合中 → 子节点（verify session）
                if sid not in children:
                    children.append(sid)
            else:
                # 无 parent_id 或 parent 不在集合中 → 根节点（analyze session）
                if sid not in roots:
                    roots.append(sid)

        # 优先返回子节点（verify session），没有子节点才返回根节点（analyze session）
        return children if children else roots

    def _diagnose_verify_gap(
        self,
        case_id: str,
        ac_case_id: str,
        verify_packs: list[DataPack],
    ) -> str:
        """诊断验证 session 缺失原因。

        有挖掘 session 但无验证 session 时，扫描验证 agent 全部 events，
        查找 case_id 的任何出现，明确报告数据断链位置：

        - case_id 出现在验证 agent events 中但未命中匹配逻辑
          → 匹配逻辑有 bug，需改进
        - case_id 完全不出现在验证 agent events 中
          → 挖掘 agent 上报的漏洞未传递给验证 agent（数据断链在挖掘→验证之间）

        Returns:
            诊断描述字符串。空字符串表示无法诊断（无验证 agent data pack）。
        """
        if not verify_packs:
            return "无验证 agent trace（挖掘→验证之间数据断链）"

        # 收集验证 agent trace 中所有出现过的 case_id
        # 搜索范围：input_json/output_json 的所有值 + session_graph 的 vuln_id_to_sessions keys
        found_case_ids: set[str] = set()
        found_locations: list[str] = []  # 记录 case_id 出现的位置（供调试）

        search_ids = {case_id}
        if ac_case_id and ac_case_id != case_id:
            search_ids.add(ac_case_id)

        for dp in verify_packs:
            # 1. 从 vuln_id_to_sessions 收集所有已知 vuln_id
            v2s = (dp.session_graph or {}).get("vuln_id_to_sessions", {})
            if v2s:
                found_case_ids.update(str(k) for k in v2s.keys())

            # 2. 扫描 events 的 input_json / output_json
            for ev in (dp.events or []):
                for search_id in search_ids:
                    if self._event_contains(ev, search_id):
                        loc = (f"{dp.agent_type}/{ev.session_id or '?'}"
                               f"/{ev.tool_name or ev.event_type}")
                        if loc not in found_locations:
                            found_locations.append(loc)
                        found_case_ids.add(search_id)

            # 3. 扫描 session_graph.sessions 的 metadata
            sessions = (dp.session_graph or {}).get("sessions", {})
            for sid, sdata in sessions.items():
                sdata_d = sdata if isinstance(sdata, dict) else {}
                # session metadata 可能含 chimera_vuln_id / vulnerability_id
                for meta_key in ("chimera_vuln_id", "vulnerability_id",
                                 "vuln_id", "case_id"):
                    meta_val = str(sdata_d.get(meta_key, "") or "")
                    if meta_val:
                        found_case_ids.add(meta_val)
                        if meta_val in search_ids:
                            loc = f"{dp.agent_type}/{sid}/metadata.{meta_key}"
                            if loc not in found_locations:
                                found_locations.append(loc)

        # 生成诊断
        if found_locations:
            # case_id 出现在验证 agent trace 中但匹配逻辑未命中
            return (f"验证 agent trace 中存在 case_id 但匹配逻辑未命中"
                    f"（出现在: {', '.join(found_locations[:3])}"
                    f"{'...' if len(found_locations) > 3 else ''}）")

        # case_id 完全不出现在验证 agent trace 中
        # 报告验证 agent trace 中实际有哪些 vuln_id（供对比）
        known_vuln_ids = sorted(found_case_ids)[:10]
        if known_vuln_ids:
            return (f"验证 agent trace 中不存在此 case_id"
                    f"（挖掘→验证之间数据断链；"
                    f"验证 agent 共有 {len(found_case_ids)} 个 vuln_id: "
                    f"{', '.join(known_vuln_ids)}"
                    f"{'...' if len(found_case_ids) > 10 else ''}）")
        return ("验证 agent trace 中不存在此 case_id"
                "（挖掘→验证之间数据断链；验证 agent 无 vuln_id 记录）")

    @staticmethod
    def _event_contains(ev, search_id: str) -> bool:
        """检查 RawEvent 的 input_json / output_json 中是否包含 search_id。"""
        if not search_id:
            return False

        def _search_in_obj(obj) -> bool:
            if obj is None:
                return False
            if isinstance(obj, str):
                return search_id in obj
            if isinstance(obj, dict):
                for v in obj.values():
                    if _search_in_obj(v):
                        return True
                return False
            if isinstance(obj, list):
                for item in obj:
                    if _search_in_obj(item):
                        return True
                return False
            return False

        if _search_in_obj(ev.input_json):
            return True
        if _search_in_obj(ev.output_json):
            return True
        return False

    @staticmethod
    def _get_verify_verdict(
        verify_packs: list[DataPack],
        verify_sessions: list[str],
    ) -> str:
        """提取验证 agent 的最终判定（CONFIRMED / FALSE_POSITIVE / 空）。

        扫描验证 agent 的判定写入工具（WebVulnVerify 的 vulnerability_verify、
        CVulnVerify 的 vuln_verify_final_verdict），取命中的验证 session
        的最终判定。判定值归一化为 CONFIRMED / FALSE_POSITIVE。

        WebVulnVerify status:
          VULNERABLE / EXTERNAL_REQUEST_EXPLOITABLE / INTERNAL_REQUEST_EXPLOITABLE
          / UNIT_TEST_EXPLOITABLE → CONFIRMED
          NOT_VULNERABLE / NOT_EXPLOITABLE → FALSE_POSITIVE
        CVulnVerify verdict:
          confirmed → CONFIRMED
          ruled_out → FALSE_POSITIVE
        """
        session_set = set(verify_sessions)
        if not session_set:
            return ""

        for dp in verify_packs:
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                if (ev.session_id or "") not in session_set:
                    continue
                tool = ev.tool_name or ""
                inp = ev.input_json or {}
                if not isinstance(inp, dict):
                    continue

                # WebVulnVerify: vulnerability_verify（判定上报）
                if tool == "vulnerability_verify":
                    status = str(inp.get("status", "") or "")
                    if status:
                        if status in (
                            "VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE",
                            "INTERNAL_REQUEST_EXPLOITABLE",
                            "UNIT_TEST_EXPLOITABLE",
                        ):
                            return "CONFIRMED"
                        if status in ("NOT_VULNERABLE", "NOT_EXPLOITABLE"):
                            return "FALSE_POSITIVE"

                # CVulnVerify: write 写 vuln_verify_final_verdict.json
                if tool == "write":
                    fp = str(inp.get("file_path") or inp.get("path") or "")
                    if "vuln_verify_final_verdict" in fp:
                        content = inp.get("content", "")
                        if isinstance(content, str):
                            verdict = _extract_verdict_value(content)
                            if verdict == "confirmed":
                                return "CONFIRMED"
                            if verdict == "ruled_out":
                                return "FALSE_POSITIVE"

        return ""

    def _find_mining_via_parent_map(
        self,
        verify_sessions: list[str],
        verify_packs: list[DataPack],
        mining_packs: list[DataPack],
        mining_sessions: list[str],
    ) -> str:
        """通过跨 agent parent_map 反推挖掘 agent session。

        验证 agent session 的 parent_id 可能指向挖掘 agent session
        （WebVulnVerify/CVulnVerify session 由 Turing session 调起时，
        parent_id 会指向 Turing session）。

        策略：
        1. 在验证 agent DataPack 的 parent_map 中沿 verify_session 向上追溯
        2. 如果追溯到的祖先 session_id 出现在挖掘 agent DataPack 的 sessions 中，
           则将其归类为挖掘 agent session

        Returns:
            诊断描述字符串。空字符串表示未找到。
        """
        # 构建挖掘 agent session_id 集合（跨所有 mining_packs）
        mining_session_set: set[str] = set()
        mining_session_to_agent: dict[str, str] = {}
        for dp in mining_packs:
            sg = dp.session_graph or {}
            sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
            for sid in sessions:
                mining_session_set.add(sid)
                mining_session_to_agent[sid] = dp.agent_type

        if not mining_session_set:
            return ""

        # 沿 verify_session 的 parent_map 向上追溯
        found_mining: list[str] = []
        for dp in verify_packs:
            sg = dp.session_graph or {}
            parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}

            for vsid in verify_sessions:
                cur = vsid
                visited: set[str] = set()
                # 向上追溯最多 10 层，防止环
                while cur and cur not in visited and len(visited) < 10:
                    visited.add(cur)
                    # 当前 session 在挖掘 agent DataPack 中 → 找到了
                    if cur in mining_session_set:
                        if cur not in found_mining:
                            found_mining.append(cur)
                        break
                    # 继续向上
                    cur = parent_map.get(cur, "")

        if not found_mining:
            return ""

        for sid in found_mining:
            # parent_map 反推到的 session 应在 mining_session_to_agent 中，
            # 不在则跳过（避免错误归类为某个 agent）
            agent_type = mining_session_to_agent.get(sid, "")
            if not agent_type:
                continue
            # 运行态：反推到的 session 若实际类型是 verify，跳过（不是挖掘 session，
            # 加进 mining 后会被 _classify_session 吞掉导致结果空）。
            # 开发态漏报：查所有 session（不跳过 verify）。
            use_st = getattr(self, "_use_session_type", False)
            if use_st:
                st = (self._session_type_map or {}).get(sid, "")
                if st == "verify":
                    continue
            self._classify_session(sid, agent_type,
                                   mining_sessions, verify_sessions)

        return (f"挖掘 session 反推成功（parent_map 追溯: "
                f"{','.join(found_mining[:3])}"
                f"{'...' if len(found_mining) > 3 else ''}）")

    def _fuzzy_match_mining(
        self,
        finding_index: dict[str, list[tuple[str, str, str]]],
        raw_title: str,
        vuln_title: str,
        baseline_summary: str,
        baseline_desc: str,
        mining_sessions: list[str],
    ) -> str:
        """模糊标题匹配挖掘 agent session。

        精确标题不匹配但子串包含或关键词高度重叠时使用。
        只匹配挖掘 agent 的 finding（agent_type 在 _MINING_AGENT_TYPES 中）。

        策略：
        1. 子串包含：raw_title 或 vuln_title 是 finding title 的子串，或反之
        2. 关键词重叠：从标题提取关键词（去停用词），Jaccard ≥ 0.5

        Returns:
            诊断描述字符串。空字符串表示未找到。
        """
        # 收集所有挖掘 agent 的 finding 条目
        # 注意：运行态下只收集 investigate 类型 session（排除 verify 类型）——
        # argo finding_index 中 verify session 也贡献 description（verify: 前缀 key），
        # 但挖掘匹配必须只找挖掘 session，否则 _classify_session 会把 verify
        # session 加进局部空列表导致 mining_sessions 空（匹配"成功"但结果空）。
        # 开发态漏报查所有 session（不排除 verify——漏报需全量排查）。
        use_st = getattr(self, "_use_session_type", False)
        mining_entries: list[tuple[str, str, str]] = []  # (title, sid, desc, agent_type)
        for title, entries in finding_index.items():
            for sid, desc, agent_type in entries:
                if agent_type not in self._MINING_AGENT_TYPES:
                    continue
                if use_st:
                    st = (self._session_type_map or {}).get(sid, "")
                    if st == "verify":
                        continue  # 运行态：verify session 不是挖掘 session
                mining_entries.append((title, sid, desc, agent_type))

        if not mining_entries:
            return ""

        # 候选标题列表
        query_titles = [t for t in (raw_title, vuln_title) if t]
        if not query_titles:
            return ""

        # 摘要也作为关键词来源（不直接做子串匹配，避免过短摘要误匹配）
        extra_keyword_sources = [baseline_summary, baseline_desc]

        # 策略 1：子串包含
        for ftitle, sid, desc, agent_type in mining_entries:
            for qt in query_titles:
                if not ftitle or not qt:
                    continue
                # 避免过短标题误匹配（< 6 字符的子串包含不可靠）
                if len(qt) < 6 or len(ftitle) < 6:
                    continue
                if qt in ftitle or ftitle in qt:
                    self._classify_session(sid, agent_type,
                                           mining_sessions, [])
                    return (f"挖掘 session 模糊匹配成功（子串包含: "
                            f"'{ftitle[:40]}' ↔ '{qt[:40]}'）")

        # 策略 2：关键词 Jaccard 重叠
        _STOP_WORDS = {"的", "了", "和", "与", "或", "在", "为", "是", "及",
                       "the", "a", "an", "of", "in", "on", "to", "for",
                       "and", "or", "with", "by", "is", "be", "as", "at",
                       "from", "that", "this", "it", "an"}

        def _tokenize(text: str) -> set[str]:
            """简易分词：中文按字、英文按空格+标点。"""
            if not text:
                return set()
            tokens: set[str] = set()
            # 英文单词（≥3 字符）
            for m in re.finditer(r'[A-Za-z_][A-Za-z0-9_]{2,}', text):
                w = m.group(0).lower()
                if w not in _STOP_WORDS:
                    tokens.add(w)
            # 中文字符（单字，去停用词）
            for ch in text:
                if '\u4e00' <= ch <= '\u9fff' and ch not in _STOP_WORDS:
                    tokens.add(ch)
            # 过滤过短 token
            return {t for t in tokens if len(t) >= 2 or
                    (len(t) == 1 and '\u4e00' <= t <= '\u9fff')}

        query_tokens: set[str] = set()
        for qt in query_titles:
            query_tokens |= _tokenize(qt)
        # 摘要/描述的关键词也加入候选（增加召回率）
        for src in extra_keyword_sources:
            if src and isinstance(src, str):
                query_tokens |= _tokenize(src)

        if not query_tokens:
            return ""

        best_matches: list[tuple[float, str, str, str]] = []  # (jaccard, sid, ftitle, agent_type)
        for ftitle, sid, desc, agent_type in mining_entries:
            if not ftitle:
                continue
            ftokens = _tokenize(ftitle)
            if not ftokens:
                continue
            inter = len(query_tokens & ftokens)
            union = len(query_tokens | ftokens)
            if union == 0:
                continue
            jaccard = inter / union
            if jaccard >= 0.5:
                best_matches.append((jaccard, sid, ftitle, agent_type))

        if not best_matches:
            return ""

        # 按 Jaccard 降序，取前 3
        best_matches.sort(key=lambda x: x[0], reverse=True)
        added: list[str] = []
        for jaccard, sid, ftitle, agent_type in best_matches[:3]:
            self._classify_session(sid, agent_type,
                                   mining_sessions, [])
            added.append(f"{sid}(J={jaccard:.2f})")

        return (f"挖掘 session 模糊匹配成功（关键词 Jaccard: "
                f"{', '.join(added)}）")

    def _build_baseline_ac_map(
        self,
        case_details: dict[str, dict],
        case_matches: list[dict] | None,
        eval_mode: str,
    ) -> dict[str, str]:
        """构建基线 case_id → 告警中心 case_id 的映射。

        运行态：基线就是告警中心子集，case_id 直接映射
        开发态：从 case_matches（LLM 匹配结果）提取映射
        """
        mapping: dict[str, str] = {}

        if eval_mode == "runtime":
            for cid in case_details:
                mapping[cid] = cid
            return mapping

        if not case_matches:
            return mapping

        for m in case_matches:
            raw_id = str(m.get("raw_case_id", "") or "")
            baseline_id = str(m.get("matched_baseline_case_id", "") or "")
            if raw_id and baseline_id:
                mapping[baseline_id] = raw_id

        log("MATCH",
            f"开发态: 从 case_matches 构建 {len(mapping)} 条 "
            f"基线→告警中心映射",
            eval_id="")
        return mapping

    def _build_finding_index(
        self,
        data_packs: list[DataPack],
        turing_finding_sids: set[str],
    ) -> dict[str, list[tuple[str, str, str]]]:
        """构建 title → [(session_id, description, agent_type)] 索引。

        跨全部 agent 类型扫描 finding，命中后按 agent_type 分类。
        各 agent 的提取逻辑由 findings/ 子包的 FindingExtractor 策略类负责，
        此处仅按 data_pack.agent_type 路由到对应 extractor 并合并索引。
        新增 agent 只需在 findings/ 下加实现类，无需改动本方法。
        """
        from .findings import get_finding_extractor

        index: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        seen_agent_types: set[str] = set()

        for dp in data_packs:
            at = dp.agent_type or ""
            if not at or at in seen_agent_types:
                continue
            seen_agent_types.add(at)
            extractor = get_finding_extractor(at)
            if extractor is None:
                continue
            extractor.extract([dp], turing_finding_sids=turing_finding_sids)
            for title, entries in extractor.index().items():
                for entry in entries:
                    if entry not in index[title]:
                        index[title].append(entry)

        return dict(index)


def _extract_verdict_value(content: str) -> str:
    """从 CVulnVerify verdict JSON 内容中提取 verdict 值。

    verdict 文件格式：{"verdict": "confirmed" | "ruled_out", ...}
    content 可能是 JSON 字符串，也可能被 bash heredoc 包裹。
    """
    if not content:
        return ""
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return str(data.get("verdict", "") or "")
    except (json.JSONDecodeError, TypeError):
        pass
    # bash heredoc 场景：从文本中匹配 "verdict": "confirmed"
    m = re.search(r'"verdict"\s*:\s*"(\w+)"', content)
    if m:
        return m.group(1)
    return ""
