"""OutcomeResolver — 从 events + findings 提取判定结果（§8.6）。

去平台化：不检查平台特定工具名（如 vuln-hunt_update_finding / vulnerability_verify）。
只消费标准化的 is_finding_submission=True events + findings 列表。

parser 负责：
- 在 parse() 中设置 is_finding_submission flag
- 在 extract_findings() 中完成平台特定的 finding 提取（含 validation_result）

Resolver 只消费标准化数据：
- 从 is_finding_submission=True 的事件中提取 validation_result
- 从 findings 列表中读取 verdict/status
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
    """从 events + findings 提取判定结果。不依赖平台特定工具名。

    数据来源：
    1. findings 列表（parser.extract_findings() 输出）—— 每个 finding dict 含
       validation_result 字段（CONFIRMED / FALSE_POSITIVE），由 parser 完成平台特定提取。
    2. is_finding_submission=True 的事件 —— parser 在 parse() 中标记，Resolver 从
       input_json / output_json 中提取 validation_result 作为补充。
    """

    def __init__(self, config: dict | None = None):
        self.high_confidence_threshold = 0.85
        self.ambiguity_margin = 0.10

    def resolve(self, task_run: TaskRun, events: list[RawEvent],
                findings: list[dict],
                benchmark: BenchmarkItem | None = None) -> OutcomeFact:
        """从 events + findings 提取判定结果。

        Args:
            task_run: TaskRun 实体
            events: RawEvent 列表
            findings: parser.extract_findings() 输出的 finding dict 列表
            benchmark: 基线 BenchmarkItem（含 expected_label / target_finding_id）
        """
        # 无 GT（benchmark 未标注）→ UNDETERMINED
        if benchmark is None or benchmark.expected_label is None:
            return OutcomeFact.undetermined(
                task_run.task_run_id, task_run.evaluation_id, task_run.condition,
                task_run.condition_source, reason="NO_GT",
                benchmark_item_id=benchmark.benchmark_item_id if benchmark else None,
            )

        # 1. 从 findings 列表 + is_finding_submission events 提取 validation_result
        validation, submission_evs = self._extract_validation(events, findings, benchmark.target_finding_id)

        if validation is None:
            # 有 finding 提交但无 validation_result → NO_UPDATE
            # 无任何 finding 提交 → NO_FINDING
            has_submission = bool(submission_evs) or bool(findings)
            reason = "NO_UPDATE" if has_submission else "NO_FINDING"
            return OutcomeFact.undetermined(
                task_run.task_run_id, task_run.evaluation_id, task_run.condition,
                task_run.condition_source, reason=reason,
                benchmark_item_id=benchmark.benchmark_item_id,
            )

        # 2. 映射 validation → prediction
        pred = "POSITIVE" if validation == "CONFIRMED" else "NEGATIVE"
        outcome = self._classify(benchmark.expected_label.value, pred)

        # 3. 构建 evidence（取 finding submission 事件）
        evs = [_ev(e, "$.validation_result") for e in submission_evs[:1]]

        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmark.benchmark_item_id,
            gt_label=benchmark.expected_label, prediction=Prediction(pred),
            outcome=outcome,
            target_finding_id=benchmark.target_finding_id,
            validation_result=validation, resolver_status="RESOLVED",
            evidence=evs,
        )

    def _extract_validation(
        self, events: list[RawEvent], findings: list[dict],
        target_finding_id: str | None,
    ) -> tuple[str | None, list[RawEvent]]:
        """从 findings + is_finding_submission events 提取最新的 validation_result。

        数据来源：
        - findings 列表：parser.extract_findings() 输出，每个 finding dict 含
          validation_result / verdict / status 字段（由 parser 归一化）。
        - is_finding_submission=True 事件：parser 在 parse() 中标记的 finding 提交事件，
          从 input_json / output_json 中提取 validation_result 作为补充。

        Returns:
            (validation_result, submission_events)
            validation_result: "CONFIRMED" / "FALSE_POSITIVE" / None
            submission_events: is_finding_submission=True 的事件列表
        """
        candidates: list[tuple[int, str]] = []
        submission_evs: list[RawEvent] = []

        # 1. 从 findings 列表提取（parser 已完成平台特定提取）
        for f in findings:
            vr = self._read_validation_from_finding(f)
            if vr:
                ts = f.get("timestamp_ms") or f.get("timestamp") or 0
                candidates.append((int(ts), vr))

        # 2. 从 is_finding_submission=True 的事件提取（补充来源）
        for e in events:
            if not e.is_finding_submission:
                continue
            submission_evs.append(e)
            vr = self._read_validation_from_event(e)
            if vr:
                candidates.append((e.timestamp_ms or 0, vr))

        if not candidates:
            return None, submission_evs

        # 取最新的 validation_result（按 timestamp 排序）
        candidates.sort(key=lambda x: x[0])
        return candidates[-1][1], submission_evs

    @staticmethod
    def _read_validation_from_finding(f: dict) -> str | None:
        """从 finding dict 读取 validation_result。

        parser 已将各平台的 verdict/status/outcome 归一化到以下字段之一：
        - validation_result: "CONFIRMED" / "FALSE_POSITIVE"
        - verdict: "confirmed" / "ruled_out" / "CONFIRMED" / "FALSE_POSITIVE" / "MANUAL_REVIEW"
        - status: "VULNERABLE" / "NOT_VULNERABLE" 等
        - outcome: "confirmed" / "refuted" / "conditional"
        """
        # validation_result（已归一化）
        vr = f.get("validation_result")
        if vr in ("CONFIRMED", "FALSE_POSITIVE"):
            return vr

        # verdict
        verdict = str(f.get("verdict") or "").upper()
        if verdict in ("CONFIRMED", "LIKELY", "POSSIBLE", "MANUAL_REVIEW", "CONDITIONAL"):
            return "CONFIRMED"
        if verdict in ("FALSE_POSITIVE", "RULED_OUT", "REFUTED"):
            return "FALSE_POSITIVE"

        # status
        status = str(f.get("status") or "").upper()
        if status in ("VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE", "UNIT_TEST_EXPLOITABLE"):
            return "CONFIRMED"
        if status in ("NOT_VULNERABLE", "NOT_EXPLOITABLE"):
            return "FALSE_POSITIVE"

        # outcome
        outcome = str(f.get("outcome") or "").lower()
        if outcome in ("confirmed", "conditional"):
            return "CONFIRMED"
        if outcome in ("refuted", "ruled_out"):
            return "FALSE_POSITIVE"

        return None

    @staticmethod
    def _read_validation_from_event(e: RawEvent) -> str | None:
        """从 is_finding_submission=True 的事件中提取 validation_result。

        parser 已标记 is_finding_submission=True，Resolver 只需从 input_json / output_json
        中读取已归一化的 validation_result 字段。不检查平台特定工具名。
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
