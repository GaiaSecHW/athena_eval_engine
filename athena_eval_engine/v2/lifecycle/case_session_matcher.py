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
from ...infrastructure.log_util import log


class CaseSessionMatcher:
    """case↔session 匹配器。"""

    # 挖掘 agent 的 DataPack.agent_type
    _MINING_AGENT_TYPES = {"turing", "argo", "secmate", "dataflow"}

    # 验证 agent 的 DataPack.agent_type
    _VERIFY_AGENT_TYPES = {"cvuln_verify", "webvuln_verify"}

    # Turing 平台：含漏洞 finding 的 session agent 名（挖掘 agent 内部阶段）
    _TURING_FINDING_AGENTS = {
        "vuln-hunt-validate",  # 旧版命名
        "web-validate",         # 新版命名
    }

    # Turing 平台：提取 finding 的工具名（已归一化，横线→下划线）
    _TURING_FINDING_TOOLS = {
        "vuln_hunt_query_finding",
        "vuln_hunt_update_finding",
    }

    # WebVulnVerify 平台：提取 finding 的工具名
    _WEBVV_FINDING_TOOLS = {
        "vulnerability_analyze",
        "vulnerability_verify",
    }

    # CVulnVerify 平台：提取 finding 的工具名
    _CVULN_FINDING_TOOLS = {
        "vulnerability_verify",
        "vulnerability_cvss",
        "vulnerability_analyze",
    }

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
        turing_finding_sids: set[str] = set()
        for dp in mining_packs:
            if dp.agent_type != "turing":
                continue
            for sid, sdata in (dp.session_graph.get("sessions") or {}).items():
                if sdata.get("agent") in self._TURING_FINDING_AGENTS:
                    turing_finding_sids.add(sid)

        log("MATCH",
            f"mining_packs={len(mining_packs)}, "
            f"verify_packs={len(verify_packs)}, "
            f"turing_finding_sids={len(turing_finding_sids)}",
            eval_id=evaluation_id)

        # 构建 title → [(session_id, description, agent_type)] 索引
        # 跨全部 agent 类型，命中后按 agent_type 分类到 mining/verify
        finding_index = self._build_finding_index(
            mining_packs, verify_packs, turing_finding_sids)

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

            # 验证 agent 回退：用 session_graph.vuln_id_to_sessions 匹配
            # WebVulnVerify/CVulnVerify 的 session metadata 含 chimera_vuln_id（= case_id），
            # 但 vulnerability_analyze/verify 的 result 文本标题与告警中心 title 不一致，
            # 导致 title 精确匹配失败。用 case_id 直接从 vuln_id_to_sessions 查找。
            verify_match_detail = ""
            if not verify_sessions:
                for dp in verify_packs:
                    v2s = (dp.session_graph or {}).get("vuln_id_to_sessions", {})
                    if not v2s:
                        continue
                    # case_id 可能带前缀（case-20260730-...），也可能只有数字 ID
                    sids = v2s.get(cid, set()) or v2s.get(ac_case_id, set())
                    if not sids:
                        # 尝试用数字 ID 匹配（case_id 中提取数字部分）
                        for vid, vid_sids in v2s.items():
                            if vid == cid or vid == ac_case_id:
                                sids = vid_sids
                                break
                    if sids:
                        # 去重父子关系：同一 vuln_id 可能关联多个 session，
                        # 其中存在父子关系（如 analyze + verify session）。
                        # 只保留根 session（parent_id 为空或不在集合中的），
                        # 与挖掘链处理方式一致——_analyze_chain 只压缩命中的
                        # 根 session，不展开子 session。
                        sids = self._filter_root_sessions(sids, dp)
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
            # - 漏报 case（VULNERABLE）：finding 命中 = TP，未命中 = FN
            #   FN case 用基线 sink 点 source_file 扫描 trace 找 session
            all_sessions = mining_sessions + verify_sessions
            if expected_label == "NON_VULNERABLE":
                outcome = "FP" if all_sessions else "TN"
            else:  # VULNERABLE
                if all_sessions:
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

    @staticmethod
    def _classify_session(
        sid: str,
        agent_type: str,
        mining_sessions: list[str],
        verify_sessions: list[str],
    ):
        """按 agent_type 将 session 分类到挖掘或验证列表。"""
        if agent_type in CaseSessionMatcher._VERIFY_AGENT_TYPES:
            if sid not in verify_sessions:
                verify_sessions.append(sid)
        else:
            if sid not in mining_sessions:
                mining_sessions.append(sid)

    @staticmethod
    def _filter_root_sessions(
        sids, dp: "DataPack",
    ) -> list[str]:
        """从 session 集合中只保留根 session（去除父子关系中的子 session）。

        同一 vuln_id 可能关联多个 session，其中存在父子关系
        （如 WebVulnVerify 的 analyze + verify session，verify 的
        parent_id 指向 analyze）。只保留根 session——parent_id 为空
        或 parent_id 不在集合中的 session——与挖掘链处理方式一致：
        _analyze_chain 只压缩命中的根 session，不展开子 session。

        Args:
            sids: vuln_id_to_sessions 返回的 session 集合（set 或 list）。
            dp: 所属 DataPack，用于取 parent_map。

        Returns:
            根 session_id 列表（保留原顺序，如 sids 是 list）。
        """
        sid_list = list(sids) if not isinstance(sids, (list, tuple)) else list(sids)
        sid_set = set(sid_list)
        if len(sid_set) <= 1:
            return sid_list

        sg = dp.session_graph or {}
        parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}

        roots: list[str] = []
        for sid in sid_list:
            pid = parent_map.get(sid, "")
            # parent_id 为空，或 parent_id 不在集合中（父 session 不属于此 vuln）→ 根
            if not pid or pid not in sid_set:
                if sid not in roots:
                    roots.append(sid)

        # 极端情况：所有 session 都有父子关系形成环（不应发生），回退返回原列表
        if not roots:
            return sid_list

        return roots

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
            agent_type = mining_session_to_agent.get(sid, "turing")
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
        mining_entries: list[tuple[str, str, str]] = []  # (sid, desc, agent_type)
        for title, entries in finding_index.items():
            for sid, desc, agent_type in entries:
                if agent_type in self._MINING_AGENT_TYPES:
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
        mining_packs: list[DataPack],
        verify_packs: list[DataPack],
        turing_finding_sids: set[str],
    ) -> dict[str, list[tuple[str, str, str]]]:
        """构建 title → [(session_id, description, agent_type)] 索引。

        跨全部 agent 类型扫描 finding，命中后按 agent_type 分类。
        """
        index: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

        # ── Turing 平台（挖掘 agent）──
        # 从 vuln-hunt-validate session 的工具调用提取 finding
        for dp in mining_packs:
            if dp.agent_type != "turing":
                continue
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                if ev.session_id not in turing_finding_sids:
                    continue
                tool = ev.tool_name or ""
                if tool not in self._TURING_FINDING_TOOLS:
                    continue
                title, desc = self._extract_title_desc_turing(ev)
                if title:
                    sid = ev.session_id or ""
                    if sid:
                        entry = (sid, desc, dp.agent_type)
                        if entry not in index[title]:
                            index[title].append(entry)

        # ── WebVulnVerify 平台（验证 agent）──
        for dp in verify_packs:
            if dp.agent_type != "webvuln_verify":
                continue
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in self._WEBVV_FINDING_TOOLS:
                    continue
                title, desc = self._extract_title_desc_webvv(ev)
                if title:
                    sid = ev.session_id or ""
                    if sid:
                        entry = (sid, desc, dp.agent_type)
                        if entry not in index[title]:
                            index[title].append(entry)

        # ── CVulnVerify 平台（验证 agent）──
        for dp in verify_packs:
            if dp.agent_type != "cvuln_verify":
                continue
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in self._CVULN_FINDING_TOOLS:
                    continue
                inp = ev.input_json or {}
                key = (
                    inp.get("vulnerability_id")
                    or inp.get("case_id")
                    or ""
                )
                if key:
                    sid = ev.session_id or ""
                    if sid:
                        entry = (sid, "", dp.agent_type)
                        if entry not in index[str(key)]:
                            index[str(key)].append(entry)

        return dict(index)

    @staticmethod
    def _extract_title_desc_turing(ev) -> tuple[str, str]:
        """从 Turing 工具调用事件中提取漏洞 title + description。

        vuln_hunt_query_finding 的 output_json 结构：
        {"result": "{...JSON string with title/description...}"}
        或直接是 JSON 字符串

        Returns:
            (title, description)
        """
        outp = ev.output_json
        if not outp:
            return "", ""

        if isinstance(outp, str):
            try:
                outp = json.loads(outp)
            except (json.JSONDecodeError, ValueError):
                return "", ""
        if not isinstance(outp, dict):
            return "", ""

        result_str = outp.get("result", "")
        if isinstance(result_str, str):
            try:
                result = json.loads(result_str)
            except (json.JSONDecodeError, ValueError):
                return "", ""
        elif isinstance(result_str, dict):
            result = result_str
        else:
            return "", ""

        if not isinstance(result, dict):
            return "", ""

        title = result.get("title") or ""
        desc = result.get("description") or ""
        return (str(title) if title else "", str(desc) if desc else "")

    @staticmethod
    def _extract_title_desc_webvv(ev) -> tuple[str, str]:
        """从 WebVulnVerify 工具调用事件中提取漏洞 title + description。

        vulnerability_analyze / vulnerability_verify 的 input_json 含：
        - result: 验证报告文本（含"一句话结论"或"漏洞类型"表格行）
        - category: 漏洞分类标签
        - description: 漏洞描述

        优先从 result 提取一句话结论作为 title，
        其次提取漏洞类型表格行，
        回退到 category。
        description 从 input_json 的 description 字段提取。

        Returns:
            (title, description)
        """
        inp = ev.input_json
        if not isinstance(inp, dict):
            return "", ""

        desc = str(inp.get("description", "") or "")

        result_text = str(inp.get("result", "") or "")
        if result_text:
            m = re.search(
                r'一句话结论[：:]\s*(.+?)(?=\n\n|\n#|\n-|\Z)',
                result_text, re.DOTALL,
            )
            if m:
                return m.group(1).strip(), desc
            m = re.search(r'漏洞类型\s*\|\s*(.+?)\s*\|', result_text)
            if m:
                return m.group(1).strip(), desc

        category = inp.get("category", "") or inp.get("vuln_type", "") or ""
        return (str(category) if category else "", desc)
