"""FP case 筛选模块。

从 case_session_matcher 的匹配结果中筛选 FP case（误报），
找到包含 verify_sessions 及其祖先 session 的 DataPack，
只保留有知识访问的 DataPack，供 L0-L7 分析。
"""
from __future__ import annotations

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log


class CaseFilter:
    """筛选 FP case 对应的 DataPack，供 L0-L7 分析。"""

    def filter_valid_cases(
        self, evaluation_id: str, data_packs: list,
        eval_mode: str = "dev",
        benchmark_source: str = "vbench_zip",
        alert_center_data: dict | None = None,
        case_details: dict | None = None,
        case_session_matches: list[dict] | None = None,
    ) -> list:
        """筛选需要 L0-L7 分析的 FP case DataPack。

        只筛选误报（FP）case：从 case_session_matches 中取 outcome=FP 的 case，
        用 verify_sessions 沿 parent_map 追溯找到包含这些 session 的 DataPack，
        只保留有知识访问的 DataPack。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表
            case_session_matches: case_session_matcher 的匹配结果，
                          用于 FP case 的 DataPack 筛选

        Returns:
            需要分析的 DataPack 列表
        """
        valid_packs: list[DataPack] = []

        # ── FP 筛选：从 case_session_matches 拿 outcome=FP 的 case ──
        fp_matches = [m for m in (case_session_matches or [])
                      if m.get("outcome") == "FP"]
        for m in fp_matches:
            cid = m.get("case_id", "")
            verify_sids = m.get("verify_sessions", [])
            if not verify_sids:
                continue

            # 找到包含 verify_sessions 的 DataPack
            # 一个 verify session 可能跨多个 DataPack（挖掘+验证）
            case_packs: list[DataPack] = []
            seen_packs: set[int] = set()
            for dp in data_packs:
                sg = dp.session_graph or {}
                sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
                parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}

                # 检查这个 DataPack 是否包含 verify_sessions 或其祖先 session
                # 沿 parent_map 追溯：verify_session → root
                chain_sids: set[str] = set()
                for vsid in verify_sids:
                    cur = vsid
                    while cur and cur in sessions and cur not in chain_sids:
                        chain_sids.add(cur)
                        cur = parent_map.get(cur, "")

                # 这个 DataPack 的 sessions 与 case 链有交集
                if chain_sids & set(sessions.keys()):
                    if id(dp) not in seen_packs:
                        seen_packs.add(id(dp))
                        case_packs.append(dp)

            # 只保留有知识访问的 DataPack
            kp = [dp for dp in case_packs
                  if dp.knowledge_fact is not None
                  and (getattr(dp.knowledge_fact, "access", False)
                       or getattr(dp.knowledge_fact, "memory_access", False))]

            if kp:
                log("CASE_FILTER",
                    f"FP case {cid}: {len(kp)} packs with knowledge "
                    f"(verify_sessions={verify_sids})",
                    eval_id=evaluation_id)
                valid_packs.extend(kp)
            else:
                log("CASE_FILTER",
                    f"FP case {cid}: no packs with knowledge access "
                    f"(verify_sessions={verify_sids})",
                    eval_id=evaluation_id)

        log("CASE_FILTER",
            f"filtered {len(valid_packs)}/{len(data_packs)} packs "
            f"from {len(fp_matches)} FP cases",
            eval_id=evaluation_id)

        return valid_packs
