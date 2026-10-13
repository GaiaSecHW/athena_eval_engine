"""回归验证模块。

从漏洞中心读取重放结果，判定 FP/FN 是否消除。

判定规则：
- FP case: 原始判定为误报
  - 重放 TN → FP 已消除 → passed
  - 重放 FP → FP 未消除 → failed
  - 重放 TP → 异常（误报变漏报）→ anomaly
- FN case: 原始判定为漏报
  - 重放 TP → FN 已消除 → passed
  - 重放 FN → FN 未消除 → failed
  - 重放 FP → 异常（漏报变误报）→ anomaly

FN 判定仅适用于开发态（运行态只分析 FP）。
"""
from __future__ import annotations

from typing import Any

from ...infrastructure.log_util import log


class ReplayVerifier:
    """回归验证器。

    从漏洞中心读取 Agent 重放后的判定结论，对比原始判定，
    判定 FP/FN 是否消除。
    """

    def verify_replay(
        self,
        case_id: str,
        case_type: str,  # "FP" or "FN"
        task_id: str,
        project_id: str = "",
    ) -> dict:
        """验证单个 case 的回归结果。

        Args:
            case_id: 原始 case 标识。
            case_type: "FP" 或 "FN"。
            task_id: 关联的 task ID。
            project_id: 项目 ID（用于查询漏洞中心）。

        Returns:
            {
                "case_id": ...,
                "case_type": "FP"|"FN",
                "original_result": "FP"|"FN",
                "replay_result": "TP"|"TN"|"FP"|"FN",
                "verdict": "passed"|"failed"|"anomaly",
                "reason": "...",
            }
        """
        # Read replay result from vuln center
        replay_verdict = self._read_replay_verdict(case_id, task_id, project_id)

        # Judge elimination
        verdict = self._judge_elimination(case_type, replay_verdict)

        result = {
            "case_id": case_id,
            "case_type": case_type,
            "original_result": case_type,
            "replay_result": replay_verdict,
            "verdict": verdict["verdict"],
            "reason": verdict["reason"],
        }

        log("REPLAY", f"verify_replay: case={case_id} type={case_type} "
              f"replay={replay_verdict} verdict={verdict['verdict']}")
        return result

    def verify_task_replay(
        self,
        task_id: str,
        dts_issues: list[dict],
        project_id: str = "",
    ) -> list[dict]:
        """验证一个 task（case）的全部 DTS 单的回归结果。

        一个 case 可能有多条 DTS 单，统一触发一次回归测试。
        全部 DTS 单共用同一个回归判定结果。

        Args:
            task_id: task ID。
            dts_issues: 该 task 的全部 DTS 单列表。
            project_id: 项目 ID。

        Returns:
            每条 DTS 单对应的回归结果列表。
        """
        if not dts_issues:
            return []

        # 取第一条 DTS 单的 case_type（同一 case 的所有 DTS 单 case_type 相同）
        case_type = dts_issues[0].get("case_type", "FP")

        # 从 DTS 单中提取 case_id
        case_id = dts_issues[0].get("task_run_id", "")

        # 验证回归
        result = self.verify_replay(case_id, case_type, task_id, project_id)

        # 为每条 DTS 单生成结果
        results = []
        for issue in dts_issues:
            results.append({
                "dts_id": issue.get("dts_id", ""),
                **result,
            })

        return results

    def _read_replay_verdict(
        self, case_id: str, task_id: str, project_id: str,
    ) -> str:
        """从漏洞中心读取重放后的判定结论。

        尝试从漏洞中心查询该 case 重放后的 verdict。
        如果漏洞中心不可用或未找到重放记录，返回原始 case_type（表示未消除）。

        Returns:
            "TP" / "TN" / "FP" / "FN"
        """
        try:
            from ...infrastructure.vuln_center_client import (
                get_alert_center_summary,
            )
            # Query alert center for replay results
            if project_id and task_id:
                ac_summary = get_alert_center_summary(project_id, task_id)
                cases = ac_summary.get("cases", [])
                for c in cases:
                    c_id = c.get("case_id") or c.get("id") or ""
                    if c_id == case_id:
                        status = c.get("confirmation_status", "").lower()
                        if status == "vulnerable":
                            return "TP"
                        elif status == "not_vulnerable":
                            return "TN"
            # No replay data found — can't determine
            log("REPLAY", f"no replay data found for case={case_id} "
                  f"task={task_id}, returning UNKNOWN")
            return "UNKNOWN"
        except Exception as e:
            log("REPLAY", f"read replay verdict failed: {str(e)[:200]}")
            return "UNKNOWN"

    def _judge_elimination(
        self, case_type: str, replay_result: str,
    ) -> dict:
        """判定 FP/FN 是否消除。

        Args:
            case_type: 原始判定 "FP" 或 "FN"。
            replay_result: 重放判定 "TP"/"TN"/"FP"/"FN"/"UNKNOWN"。

        Returns:
            {"verdict": "passed"|"failed"|"anomaly", "reason": "..."}
        """
        if replay_result == "UNKNOWN":
            return {
                "verdict": "failed",
                "reason": "无法获取重放结果，默认判定为未消除",
            }

        if case_type == "FP":
            if replay_result == "TN":
                return {
                    "verdict": "passed",
                    "reason": "FP 已消除：重放判定为 TN（正确排除）",
                }
            elif replay_result == "FP":
                return {
                    "verdict": "failed",
                    "reason": "FP 未消除：重放判定仍为 FP（仍误报）",
                }
            elif replay_result == "TP":
                return {
                    "verdict": "anomaly",
                    "reason": "异常：误报变漏报（FP→TP），知识改进可能引入新问题",
                }
        elif case_type == "FN":
            if replay_result == "TP":
                return {
                    "verdict": "passed",
                    "reason": "FN 已消除：重放判定为 TP（正确报告）",
                }
            elif replay_result == "FN":
                return {
                    "verdict": "failed",
                    "reason": "FN 未消除：重放判定仍为 FN（仍漏报）",
                }
            elif replay_result == "FP":
                return {
                    "verdict": "anomaly",
                    "reason": "异常：漏报变误报（FN→FP），知识改进可能引入新问题",
                }

        # Unexpected combination
        return {
            "verdict": "failed",
            "reason": f"未预期的判定组合：case_type={case_type}, replay={replay_result}",
        }
