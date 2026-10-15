"""case↔session 匹配器。

运行态和开发态共用。

运行态：
- 基线就是告警中心子集
- 只取基线 NON_VULNERABLE case（误报）
- 验证 agent：用告警中心 case_id 精确匹配工具调用参数
- 挖掘 agent：用基线漏洞标题在 insert_finding 工具调用中匹配 title/vuln_type

开发态：
- 基线 ↔ 告警中心已在 INGESTING 阶段做 LLM 匹配（case_matches）
- 从 case_matches 拿到 基线 case_id → 告警中心 case_id 的映射
- 用告警中心 case_id 去验证 agent session 里精确匹配
- 用基线漏洞标题去挖掘 agent session 里文本匹配
- 基线 VULNERABLE + 匹配上 = TP，未匹配 = FN
- 基线 NON_VULNERABLE + 匹配上 = FP，未匹配 = TN
"""
from __future__ import annotations

from collections import defaultdict

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log


class CaseSessionMatcher:
    """case↔session 匹配器。"""

    # 验证 agent 的工具名（含 case_id 的工具调用）
    _VERIFY_TOOLS = {
        "vulnerability_verify",
        "vulnerability_cvss",
        "vulnerability_analyze",
    }

    # 挖掘 agent 的 finding 提交工具
    _MINING_FINDING_TOOLS = {
        "vuln_hunt_insert_finding",
        "vuln_hunt_update_finding",
        "insert_finding",
        "update_finding",
    }

    def match(
        self,
        evaluation_id: str,
        data_packs: list[DataPack],
        case_details: dict[str, dict],
        case_matches: list[dict] | None = None,
        eval_mode: str = "runtime",
    ) -> list[dict]:
        """对基线 case，在 trace 中找到挖掘 + 验证 session。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表（含挖掘 + 验证 agent）
            case_details: 基线 case 详情 {case_id: {vulnerability_type, description, expected_label, ...}}
            case_matches: INGESTING 阶段的 LLM 匹配结果（开发态用）
            eval_mode: "runtime"（运行态）| "dev"（开发态）

        Returns:
            匹配结果列表，每项含：
            - case_id: 基线 case_id
            - ac_case_id: 告警中心 case_id（匹配上的）
            - vulnerability_type, expected_label
            - mining_sessions: [session_id, ...]  挖掘 agent 命中的 session
            - verify_sessions: [session_id, ...]  验证 agent 命中的 session
            - outcome: "TP" / "FP" / "FN" / "TN"
            - match_method: "matched" / "unmatched"
            - match_detail: 匹配细节
        """
        # 构建基线 case_id → 告警中心 case_id 的映射
        baseline_to_ac = self._build_baseline_ac_map(
            case_details, case_matches, eval_mode)

        # 筛选要匹配的 case
        if eval_mode == "runtime":
            # 运行态：只取 NON_VULNERABLE（误报）
            target_cases = [
                (cid, cd) for cid, cd in case_details.items()
                if cd.get("expected_label") == "NON_VULNERABLE"
            ]
        else:
            # 开发态：全部 case
            target_cases = list(case_details.items())

        log("MATCH",
            f"{eval_mode} 匹配: {len(target_cases)} 个 case, "
            f"{len(data_packs)} 个 data_packs",
            eval_id=evaluation_id)

        # 按 agent 类型分组 DataPack
        mining_packs = [dp for dp in data_packs
                        if dp.agent_type in ("turing", "argo", "secmate", "dataflow")]
        verify_packs = [dp for dp in data_packs
                        if dp.agent_type in ("webvuln_verify", "cvuln_verify")]
        log("MATCH", f"mining_packs={len(mining_packs)}, verify_packs={len(verify_packs)}",
            eval_id=evaluation_id)

        # 预构建验证 agent 的 case_id → session 索引
        verify_index = self._build_verify_index(verify_packs)

        # 预构建挖掘 agent 的 标题 → session 索引
        mining_index = self._build_mining_index(mining_packs)

        results: list[dict] = []
        for cid, cd in target_cases:
            ac_case_id = baseline_to_ac.get(cid, "")
            vuln_type = cd.get("vulnerability_type", "")
            expected_label = cd.get("expected_label", "")

            # 验证 agent：用告警中心 case_id 精确匹配
            verify_sessions = verify_index.get(ac_case_id, []) if ac_case_id else []

            # 挖掘 agent：用漏洞标题文本匹配
            mining_sessions = mining_index.get(vuln_type, []) if vuln_type else []

            # 判定 outcome：验证 agent 命中即算匹配
            if expected_label == "VULNERABLE":
                outcome = "TP" if verify_sessions else "FN"
            else:
                outcome = "FP" if verify_sessions else "TN"

            matched = bool(verify_sessions or mining_sessions)
            method = "matched" if matched else "unmatched"
            parts = []
            if mining_sessions:
                parts.append(f"挖掘 {len(mining_sessions)} session")
            if verify_sessions:
                parts.append(f"验证 {len(verify_sessions)} session")
            detail = "、".join(parts) if parts else "未匹配"

            results.append({
                "case_id": cid,
                "ac_case_id": ac_case_id,
                "vulnerability_type": vuln_type,
                "expected_label": expected_label,
                "mining_sessions": mining_sessions,
                "verify_sessions": verify_sessions,
                "outcome": outcome,
                "match_method": method,
                "match_detail": detail,
            })

            log("MATCH",
                f"case {cid}: outcome={outcome}, method={method}, "
                f"mining={len(mining_sessions)}, verify={len(verify_sessions)} sessions",
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

    def _build_verify_index(
        self, verify_packs: list[DataPack],
    ) -> dict[str, list[str]]:
        """构建 case_id → session_id 索引（验证 agent）。

        扫描验证 agent 的 TOOL_CALL 事件，从 vulnerability_id / case_id 字段提取。
        """
        index: dict[str, list[str]] = defaultdict(list)
        for dp in verify_packs:
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in self._VERIFY_TOOLS:
                    continue
                inp = ev.input_json or {}
                cid = (
                    inp.get("vulnerability_id")
                    or inp.get("case_id")
                    or ""
                )
                if cid:
                    sid = ev.session_id or ""
                    if sid and sid not in index[str(cid)]:
                        index[str(cid)].append(sid)
        return dict(index)

    def _build_mining_index(
        self, mining_packs: list[DataPack],
    ) -> dict[str, list[str]]:
        """构建 漏洞标题 → session_id 索引（挖掘 agent）。

        扫描挖掘 agent 的 finding 提交工具调用，从 title / vuln_type 字段提取。
        用标题文本做 key，供基线漏洞标题匹配。
        """
        index: dict[str, list[str]] = defaultdict(list)
        for dp in mining_packs:
            for ev in (dp.events or []):
                if not ev.is_tool_call():
                    continue
                tool = ev.tool_name or ""
                if tool not in self._MINING_FINDING_TOOLS:
                    continue
                inp = ev.input_json or {}
                # 标题可能出现在 title 或 vuln_type 字段
                title = str(inp.get("title", "") or "").strip()
                vuln_type = str(inp.get("vuln_type", "") or "").strip()
                sid = ev.session_id or ""
                for key in (title, vuln_type):
                    if key and sid and sid not in index[key]:
                        index[key].append(sid)
        return dict(index)
