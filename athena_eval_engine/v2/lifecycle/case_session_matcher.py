"""case↔session 匹配器。

运行态和开发态共用。

匹配策略：
- 只对误报（NON_VULNERABLE）case 进行匹配
- 在验证 agent（叶子节点）的 session 中找漏洞验证记录
- 验证 agent 是叶子节点（Phase 5·验证），漏洞判定只看验证 session
- 挖掘 agent 的 finding 提交在 Phase 3，不是叶子节点，不参与匹配
- 找到 verify_sessions 后，沿 parent_map 追溯到根节点，
  链上角色为 mining 的 session 作为 mining_sessions 返回

匹配链：
- 基线 case ←LLM 语义匹配→ 原始 case（告警中心，case_matches）
- 原始 case ←程序精确匹配→ trace session（用 title 精确匹配，多个用 description 消歧）

Turing 平台匹配方式：
- 验证 session 的 agent ∈ {"vuln-hunt-validate", "web-validate"}
- 工具调用 vuln_hunt_query_finding 的 output 含漏洞 title + description
- 用原始 case title 精确匹配 finding title

其他平台（webvuln_verify / cvuln_verify）：
- DataPack.agent_type 即为验证 agent，整个 DataPack 都是验证 session
- 从验证工具调用提取 title + description

运行态：基线 case_id 就是告警中心 case_id，直接映射
开发态：从 case_matches（LLM 匹配结果）提取基线→告警中心映射

- 基线 NON_VULNERABLE + 验证 session 命中 = FP，未命中 = TN
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log


class CaseSessionMatcher:
    """case↔session 匹配器。"""

    # Turing 平台：验证 session 的 agent 名（多版本命名）
    _TURING_VERIFY_AGENTS = {
        "vuln-hunt-validate",  # 旧版命名
        "web-validate",         # 新版命名
    }

    # Turing 平台：验证 session 的工具名（已归一化，横线→下划线）
    _TURING_VERIFY_TOOLS = {
        "vuln_hunt_query_finding",
        "vuln_hunt_update_finding",
    }

    # WebVulnVerify 平台：验证工具名
    _WEBVV_VERIFY_TOOLS = {
        "vulnerability_analyze",
        "vulnerability_verify",
    }

    # CVulnVerify 平台：验证工具名（暂保留旧工具名，后续适配）
    _OTHER_VERIFY_TOOLS = {
        "vulnerability_verify",
        "vulnerability_cvss",
        "vulnerability_analyze",
    }

    # 挖掘 agent 的 DataPack.agent_type（与 root_cause_analyzer 一致）
    _MINING_AGENT_TYPES = {"turing", "argo", "secmate", "dataflow"}

    # 验证 agent 的 DataPack.agent_type
    _VERIFY_AGENT_TYPES = {"cvuln_verify", "webvuln_verify"}

    def match(
        self,
        evaluation_id: str,
        data_packs: list[DataPack],
        case_details: dict[str, dict],
        case_matches: list[dict] | None = None,
        eval_mode: str = "runtime",
        alert_center_data: dict | None = None,
    ) -> list[dict]:
        """对基线 case，在 trace 中找到挖掘 + 验证 session。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表（含挖掘 + 验证 agent）
            case_details: 基线 case 详情 {case_id: {vulnerability_type, description, expected_label, ...}}
            case_matches: INGESTING 阶段的 LLM 匹配结果（开发态用）
            eval_mode: "runtime"（运行态）| "dev"（开发态）
            alert_center_data: 告警中心数据（运行态用，含 cases 列表，
                               每条含 case_id 和 title）

        Returns:
            匹配结果列表，每项含：
            - case_id: 基线 case_id
            - ac_case_id: 告警中心 case_id（匹配上的）
            - vulnerability_type, expected_label
            - verify_sessions: [session_id, ...]  验证 agent 命中的 session（叶子节点）
            - mining_sessions: [session_id, ...]  挖掘 agent 的 session（从 verify 沿 parent_map 追溯）
            - outcome: "TP" / "FP" / "FN" / "TN"
            - match_method: "matched" / "unmatched"
            - match_detail: 匹配细节
        """
        # 构建基线 case_id → 告警中心 case_id 的映射
        baseline_to_ac = self._build_baseline_ac_map(
            case_details, case_matches, eval_mode)

        # 构建告警中心 case_id → 原始 case title 的映射
        # 原始 case 就是 agent 上报的漏洞结果，原始 case title 跟 trace 中
        # finding title 一致，可以用来精确匹配验证 session
        ac_title_map: dict[str, str] = {}
        if case_matches:
            # 开发态：从 case_matches 提取 raw_case_id → raw_title
            for m in case_matches:
                raw_id = str(m.get("raw_case_id", "") or "")
                raw_title = str(m.get("raw_title", "") or "")
                if raw_id and raw_title:
                    ac_title_map[raw_id] = raw_title
        elif alert_center_data:
            # 运行态：从告警中心 cases 提取 case_id → title
            for c in alert_center_data.get("cases", []):
                cid = str(c.get("case_id") or c.get("id") or "")
                title = str(c.get("title") or "")
                if cid and title:
                    ac_title_map[cid] = title

        # 只对误报（NON_VULNERABLE）case 进行匹配
        target_cases = [(cid, cd) for cid, cd in case_details.items()
                        if cd.get("expected_label") == "NON_VULNERABLE"]

        log("MATCH",
            f"{eval_mode} 匹配: {len(target_cases)} 个 case, "
            f"{len(data_packs)} 个 data_packs",
            eval_id=evaluation_id)

        # 筛选验证 agent 的 DataPack 和 session
        # 1. 其他平台（cvuln_verify / webvuln_verify）：整个 DataPack 是验证 agent
        verify_packs = [dp for dp in data_packs
                        if dp.agent_type in ("webvuln_verify", "cvuln_verify")]
        # 2. Turing 平台：验证 session 在 turing pack 里，按 session.agent 过滤
        turing_packs = [dp for dp in data_packs if dp.agent_type == "turing"]
        turing_verify_sids: set[str] = set()
        for dp in turing_packs:
            for sid, sdata in (dp.session_graph.get("sessions") or {}).items():
                if sdata.get("agent") in self._TURING_VERIFY_AGENTS:
                    turing_verify_sids.add(sid)
        log("MATCH",
            f"verify_packs={len(verify_packs)}, "
            f"turing_packs={len(turing_packs)}, "
            f"turing_verify_sids={len(turing_verify_sids)}",
            eval_id=evaluation_id)

        # 预构建验证 agent 的 title → [(session_id, description)] 索引
        verify_index = self._build_verify_index(
            verify_packs, turing_packs, turing_verify_sids)

        # 合并全部 DataPack 的 session_graph，构建 parent_map + sid_role
        # 用于从 verify_sessions 追溯到挖掘 session
        all_parent_map: dict[str, str] = {}
        all_sessions: dict[str, dict] = {}
        sid_role: dict[str, str] = {}
        for dp in data_packs:
            sg = dp.session_graph or {}
            sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
            parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}
            for sid, sdata in sessions.items():
                all_sessions[sid] = sdata
                session_agent = (sdata or {}).get("agent", "")
                if session_agent in self._TURING_VERIFY_AGENTS:
                    sid_role[sid] = "verify"
                elif dp.agent_type in self._VERIFY_AGENT_TYPES:
                    sid_role[sid] = "verify"
                elif dp.agent_type in self._MINING_AGENT_TYPES:
                    sid_role[sid] = "mining"
            for sid, pid in parent_map.items():
                if sid in sessions:
                    all_parent_map[sid] = pid

        results: list[dict] = []
        for cid, cd in target_cases:
            ac_case_id = baseline_to_ac.get(cid, "")
            vuln_type = cd.get("vulnerability_type", "")
            expected_label = cd.get("expected_label", "")
            baseline_desc = cd.get("description", "")

            verify_sessions: list[str] = []
            match_method_used = ""

            # 匹配策略：用原始 case title 去验证 session 的 finding title 精确匹配
            raw_title = ac_title_map.get(ac_case_id, "")
            if raw_title and raw_title in verify_index:
                entries = verify_index[raw_title]
                if len(entries) == 1:
                    # 只有一个，直接使用
                    verify_sessions = [entries[0][0]]
                    match_method_used = "raw_title"
                elif len(entries) > 1:
                    # 多个匹配，用漏洞描述精确匹配消歧
                    for sid, desc in entries:
                        if desc and baseline_desc and desc == baseline_desc:
                            verify_sessions = [sid]
                            match_method_used = "raw_title+desc"
                            break
                    if not verify_sessions:
                        # 描述没匹配上，用全部 session
                        verify_sessions = [e[0] for e in entries]
                        match_method_used = "raw_title_multi"

            # 从 verify_sessions 沿 parent_map 追溯到根节点，
            # 按 session 角色拆分为挖掘链和验证链
            mining_sessions = self._trace_mining_sessions(
                verify_sessions, all_parent_map, all_sessions, sid_role)

            # 判定 outcome：误报 case，验证 session 命中 = FP，未命中 = TN
            outcome = "FP" if verify_sessions else "TN"

            matched = bool(verify_sessions)
            method = "matched" if matched else "unmatched"
            detail = (f"{len(verify_sessions)} × verify, "
                      f"{len(mining_sessions)} × mining ({match_method_used})"
                      if verify_sessions else "未匹配")

            results.append({
                "case_id": cid,
                "ac_case_id": ac_case_id,
                "vulnerability_type": vuln_type,
                "expected_label": expected_label,
                "verify_sessions": verify_sessions,
                "mining_sessions": mining_sessions,
                "outcome": outcome,
                "match_method": method,
                "match_detail": detail,
            })

            log("MATCH",
                f"case {cid}: outcome={outcome}, method={method}, "
                f"verify={len(verify_sessions)}, mining={len(mining_sessions)} "
                f"sessions ({match_method_used})",
                eval_id=evaluation_id)

        matched = sum(1 for r in results if r["match_method"] != "unmatched")
        log("MATCH",
            f"匹配完成: {matched}/{len(target_cases)} case 命中",
            eval_id=evaluation_id)

        return results

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
            # 运行态：基线 case_id 就是告警中心 case_id
            for cid in case_details:
                mapping[cid] = cid
            return mapping

        # 开发态：从 case_matches 提取
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

    @staticmethod
    def _trace_mining_sessions(
        verify_sids: list[str],
        parent_map: dict[str, str],
        sessions: dict[str, dict],
        sid_role: dict[str, str],
    ) -> list[str]:
        """从 verify_sessions 沿 parent_map 追溯到根节点，返回挖掘 session 列表。

        与 root_cause_analyzer._trace_chain 同逻辑：从每个 verify session
        向上追溯 parent，收集链上全部 session_id，然后只保留角色为
        mining 的 session。
        """
        if not verify_sids:
            return []

        chain_set: set[str] = set()
        for vsid in verify_sids:
            cur = vsid
            while cur and cur in sessions and cur not in chain_set:
                chain_set.add(cur)
                cur = parent_map.get(cur, "")

        if not chain_set:
            return []

        return [sid for sid in chain_set if sid_role.get(sid) == "mining"]

    def _build_verify_index(
        self,
        verify_packs: list[DataPack],
        turing_packs: list[DataPack],
        turing_verify_sids: set[str],
    ) -> dict[str, list[tuple[str, str]]]:
        """构建 title → [(session_id, description)] 索引（验证 agent）。

        返回值中每个 title 对应一个列表，列表元素是 (session_id, description)。
        title 唯一时列表长度为 1，可直接使用；
        title 有多个匹配时用 description 精确匹配消歧。

        Turing 平台：
        - 只扫描 turing_verify_sids 中的 session 事件
        - 从 vuln_hunt_query_finding 的 output_json 解析漏洞 title + description

        WebVulnVerify 平台：
        - 整个 DataPack 都是验证 agent
        - 从 vulnerability_analyze/verify 的 input_json 提取 title + description

        CVulnVerify 平台：
        - 暂保留旧逻辑（vulnerability_id 匹配），后续适配
        """
        index: dict[str, list[tuple[str, str]]] = defaultdict(list)

        # ── Turing 平台 ──
        for dp in turing_packs:
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                if ev.session_id not in turing_verify_sids:
                    continue
                tool = ev.tool_name or ""
                if tool not in self._TURING_VERIFY_TOOLS:
                    continue
                title, desc = self._extract_title_desc_turing(ev)
                if title:
                    sid = ev.session_id or ""
                    if sid:
                        entry = (sid, desc)
                        if entry not in index[title]:
                            index[title].append(entry)

        # ── WebVulnVerify 平台 ──
        webvv_packs = [dp for dp in verify_packs
                       if dp.agent_type == "webvuln_verify"]
        for dp in webvv_packs:
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in self._WEBVV_VERIFY_TOOLS:
                    continue
                title, desc = self._extract_title_desc_webvv(ev)
                if title:
                    sid = ev.session_id or ""
                    if sid:
                        entry = (sid, desc)
                        if entry not in index[title]:
                            index[title].append(entry)

        # ── CVulnVerify 平台（旧逻辑，后续适配）──
        cvuln_packs = [dp for dp in verify_packs
                       if dp.agent_type == "cvuln_verify"]
        for dp in cvuln_packs:
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in self._OTHER_VERIFY_TOOLS:
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
                        entry = (sid, "")
                        if entry not in index[str(key)]:
                            index[str(key)].append(entry)

        return dict(index)

    @staticmethod
    def _extract_title_desc_turing(ev) -> tuple[str, str]:
        """从 Turing 验证工具调用事件中提取漏洞 title + description。

        vuln_hunt_query_finding 的 output_json 结构：
        {"result": "{...JSON string with title/description...}"}
        或直接是 JSON 字符串

        Returns:
            (title, description)
        """
        outp = ev.output_json
        if not outp:
            return "", ""

        # output_json 可能是 str 或 dict
        if isinstance(outp, str):
            try:
                outp = json.loads(outp)
            except (json.JSONDecodeError, ValueError):
                return "", ""
        if not isinstance(outp, dict):
            return "", ""

        # output 格式：{"result": "{...}"}
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
        """从 WebVulnVerify 验证工具调用事件中提取漏洞 title + description。

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

        # 提取 description
        desc = str(inp.get("description", "") or "")

        result_text = str(inp.get("result", "") or "")
        if result_text:
            # 1. "一句话结论：xxx"
            m = re.search(
                r'一句话结论[：:]\s*(.+?)(?=\n\n|\n#|\n-|\Z)',
                result_text, re.DOTALL,
            )
            if m:
                return m.group(1).strip(), desc
            # 2. "| 漏洞类型 | xxx |"
            m = re.search(r'漏洞类型\s*\|\s*(.+?)\s*\|', result_text)
            if m:
                return m.group(1).strip(), desc

        # 3. 回退到 category
        category = inp.get("category", "") or inp.get("vuln_type", "") or ""
        return (str(category) if category else "", desc)
