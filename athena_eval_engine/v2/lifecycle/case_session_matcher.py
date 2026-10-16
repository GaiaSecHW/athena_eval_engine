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

        # 只对误报（NON_VULNERABLE）case 进行匹配
        target_cases = [(cid, cd) for cid, cd in case_details.items()
                        if cd.get("expected_label") == "NON_VULNERABLE"]

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

            # 判定 outcome：误报 case，finding 命中 = FP，未命中 = TN
            all_sessions = mining_sessions + verify_sessions
            outcome = "FP" if all_sessions else "TN"

            matched = bool(all_sessions)
            method = "matched" if matched else "unmatched"
            detail = (f"{len(mining_sessions)} × mining, "
                      f"{len(verify_sessions)} × verify ({match_method_used})"
                      if all_sessions else "未匹配")

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
                f"sessions ({match_method_used})",
                eval_id=evaluation_id)

        matched_count = sum(1 for r in results if r["match_method"] != "unmatched")
        log("MATCH",
            f"匹配完成: {matched_count}/{len(target_cases)} case 命中",
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
