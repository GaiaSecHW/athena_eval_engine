"""OutcomeResolver — 从 events 提取判定结果（§8.6）。

去平台化：不检查平台特定工具名（如 vuln-hunt_update_finding / vulnerability_verify）。
只消费标准化的 events。

Resolver 只消费标准化数据：
- 从 events 中提取 validation_result
"""
from __future__ import annotations

from ..core.raw_event import RawEvent
from ..core.task_run import TaskRun, BenchmarkItem
from ..core.facts import OutcomeFact, Evidence
from ..core.enums import (
    Condition, ConditionSource, Outcome, Prediction, ExpectedLabel,
)


def _ev(e: RawEvent, field_path: str | None = None) -> Evidence:
    """从 RawEvent 构建 Evidence。"""
    return Evidence(
        trace_id=e.trace_id, session_id=e.session_id, message_id=e.message_id,
        part_id=e.part_id, tool_name=e.tool_name, event_timestamp=e.timestamp_ms,
        field_path=field_path,
    )


class OutcomeResolver:
    """从 events 提取判定结果。不依赖平台特定工具名。

    数据来源：
    - events 中的 validation_result 字段
    """

    def __init__(self, config: dict | None = None):
        self.high_confidence_threshold = 0.85
        self.ambiguity_margin = 0.10

    def resolve(self, task_run: TaskRun, events: list[RawEvent],
                benchmark: BenchmarkItem | None = None) -> OutcomeFact:
        """从 events 提取判定结果。

        Args:
            task_run: TaskRun 实体
            events: RawEvent 列表
            benchmark: 基线 BenchmarkItem（含 expected_label）
        """
        # 无 GT（benchmark 未标注）→ UNDETERMINED
        if benchmark is None or benchmark.expected_label is None:
            return OutcomeFact.undetermined(
                task_run.task_run_id, task_run.evaluation_id, task_run.condition,
                task_run.condition_source, reason="NO_GT",
                benchmark_item_id=benchmark.benchmark_item_id if benchmark else None,
            )

        # 1. 从 events 提取 validation_result
        validation, submission_evs = self._extract_validation(events)

        if validation is None:
            # 有提交但无 validation_result → NO_UPDATE
            # 无任何提交 → NO_UPDATE
            reason = "NO_UPDATE"
            return OutcomeFact.undetermined(
                task_run.task_run_id, task_run.evaluation_id, task_run.condition,
                task_run.condition_source, reason=reason,
                benchmark_item_id=benchmark.benchmark_item_id,
            )

        # 2. 映射 validation → prediction
        pred = "POSITIVE" if validation == "CONFIRMED" else "NEGATIVE"
        outcome = self._classify(benchmark.expected_label.value, pred)

        # 3. 构建 evidence（取 validation_result 提交事件）
        evs = [_ev(e, "$.validation_result") for e in submission_evs[:1]]

        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmark.benchmark_item_id,
            gt_label=benchmark.expected_label, prediction=Prediction(pred),
            outcome=outcome,
            validation_result=validation, resolver_status="RESOLVED",
            evidence=evs,
        )

    def _extract_validation(
        self, events: list[RawEvent],
    ) -> tuple[str | None, list[RawEvent]]:
        """从 events 提取最新的 validation_result。

        数据来源：
        - events 中含 validation_result 的事件，从 input_json / output_json 中提取。

        Returns:
            (validation_result, submission_events)
            validation_result: "CONFIRMED" / "FALSE_POSITIVE" / None
            submission_events: 含 validation_result 的事件列表
        """
        candidates: list[tuple[int, str]] = []
        submission_evs: list[RawEvent] = []

        for e in events:
            vr = self._read_validation_from_event(e)
            if vr:
                submission_evs.append(e)
                candidates.append((e.timestamp_ms or 0, vr))

        if not candidates:
            return None, submission_evs

        # 取最新的 validation_result（按 timestamp 排序）
        candidates.sort(key=lambda x: x[0])
        return candidates[-1][1], submission_evs

    @staticmethod
    def _read_validation_from_event(e: RawEvent) -> str | None:
        """从事件中提取 validation_result。

        从 input_json / output_json 中读取 validation_result 字段。
        """
        # input_json 中的 validation_result（Turing: vuln-hunt_update_finding.input.validation_result）
        d = e.input_json or {}
        vr = d.get("validation_result")
        if vr in ("CONFIRMED", "LIKELY", "POSSIBLE"):
            return "CONFIRMED"
        if vr == "FALSE_POSITIVE":
            return "FALSE_POSITIVE"

        # output_json 中的 validation_result / verdict / status
        out = e.output_json
        if isinstance(out, dict):
            vr = out.get("validation_result")
            if vr in ("CONFIRMED", "FALSE_POSITIVE"):
                return vr
            verdict = str(out.get("verdict") or "").lower()
            if verdict in ("confirmed", "conditional"):
                return "CONFIRMED"
            if verdict in ("ruled_out", "refuted", "false_positive"):
                return "FALSE_POSITIVE"
            status = str(out.get("status") or "").upper()
            if status in ("VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE", "UNIT_TEST_EXPLOITABLE"):
                return "CONFIRMED"
            if status in ("NOT_VULNERABLE", "NOT_EXPLOITABLE"):
                return "FALSE_POSITIVE"

        return None

    @staticmethod
    def _classify(gt: str, pred: str) -> Outcome:
        """GT x Prediction -> SUCCESS/FAIL（§8.6 映射）。"""
        if pred == "POSITIVE":
            return Outcome.SUCCESS if gt == "VULNERABLE" else Outcome.FAIL
        else:
            return Outcome.FAIL if gt == "VULNERABLE" else Outcome.SUCCESS
