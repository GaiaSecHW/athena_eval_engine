"""Phase 2（§8.13）：TaskPairMatcher + Pair Derived Facts（§7.26 / §8.5 / §9.9）。

- JSD_i = JSD(P_KG, P_NoKG)，counts 归一化为概率，÷ln2 归一化到 [0,1]（§9.9）
- ΔToken_i / ΔSteps_i / ΔTime_i = KG − NoKG
- PairTransition = RECOVERED/REGRESSED/PRESERVED/PERSISTED_FAILURE（§8.6）
- 空分布 NO_ACTION padding（§9.9）
"""
from __future__ import annotations
import math
from dataclasses import dataclass
from ..domain.task_run import TaskRun
from ..domain.facts import OutcomeFact, ToolActionFact, ResourceFact, PairDerivedFact, Evidence
from ..domain.enums import Condition, Outcome, PairTransition, PairMatchStatus

# 业务 4 Action（排除 KG，JSD 只比工作行为不含知识查询）+ NO_ACTION padding（§9.9）
_ACTIONS = ["FINDING", "CODE", "SHELL", "OTHER", "NO_ACTION"]


def _distribution(taf: ToolActionFact | None) -> list[float]:
    """counts → 归一化概率（sum=1）。排除 KG 工具调用（知识查询不计入行为偏移）。
    无 tool call → NO_ACTION=1。"""
    if taf is None or taf.total_tool_calls == 0:
        d = [0.0] * 4 + [1.0]  # NO_ACTION=1
        return d
    # 排除 kg_count：JSD 衡量工作行为差异，不含知识查询本身
    counts = [taf.finding_count, taf.code_count, taf.shell_count, taf.other_count]
    total = sum(counts)
    if total == 0:
        return [0.0] * 4 + [1.0]  # 全是 KG 调用，工作行为=无
    return [c / total for c in counts] + [0.0]  # NO_ACTION=0


def _jsd(p: list[float], q: list[float]) -> float:
    """JSD base=e → ÷ln2 归一化到 [0,1]（§9.9）。"""
    m = [(a + b) / 2 for a, b in zip(p, q)]
    def _kl(x, y):
        return sum(xi * math.log(xi / yi) if xi > 0 and yi > 0 else (0.0 if xi == 0 else float("inf"))
                   for xi, yi in zip(x, y))
    jsd_raw = 0.5 * _kl(p, m) + 0.5 * _kl(q, m)
    if jsd_raw == float("inf") or math.isnan(jsd_raw):
        return 0.0
    return jsd_raw / math.log(2)  # 归一化到 [0,1]


@dataclass
class TaskPair:
    task_pair_id: str
    evaluation_id: str
    task_id: str
    benchmark_item_id: str | None
    nogk_task_run_id: str
    kg_task_run_id: str
    pair_match_status: PairMatchStatus
    pair_experiment_valid: bool = False
    pair_fingerprint_status: str = "UNKNOWN"
    outcome_valid: bool = False
    pair_transition: PairTransition = PairTransition.NA


class TaskPairMatcherImpl:
    """按 (evaluation_id, task_id) 分组配对（§8.5）。
    双侧 benchmark_item_id 必须一致（P0-2），不一致 → UNMATCHED + BENCHMARK_ITEM_MISMATCH。
    KG/NoKG condition 必须正确。
    """

    def match(self, task_runs: list[TaskRun],
              fingerprints: dict[str, str] | None = None) -> list[TaskPair]:
        by_task: dict[tuple[str, str], list[TaskRun]] = {}
        for tr in task_runs:
            by_task.setdefault((tr.evaluation_id, tr.task_id), []).append(tr)
        pairs: list[TaskPair] = []
        for (eid, tid), runs in by_task.items():
            kg = [r for r in runs if r.condition == Condition.KG]
            nogk = [r for r in runs if r.condition == Condition.NOGK]
            unknown = [r for r in runs if r.condition == Condition.UNKNOWN]
            if unknown:
                continue  # condition=UNKNOWN 不参与配对（§8.5）
            if len(kg) != 1 or len(nogk) != 1:
                pairs.append(TaskPair(f"tp-{eid}-{tid}", eid, tid, None, "", "",
                                      PairMatchStatus.INCOMPLETE))
                continue
            k, n = kg[0], nogk[0]
            # P0-2 双侧 benchmark_item 一致
            if (k.benchmark_item_id or "") != (n.benchmark_item_id or "") or not k.benchmark_item_id:
                pairs.append(TaskPair(f"tp-{eid}-{tid}", eid, tid, k.benchmark_item_id,
                                      n.task_run_id, k.task_run_id, PairMatchStatus.UNMATCHED))
                continue
            # Fingerprint（§5：experiment_fingerprint KG==NoKG）
            fp_status = "SAME"
            exp_valid = True
            if fingerprints:
                fk = fingerprints.get(k.task_run_id); fn = fingerprints.get(n.task_run_id)
                if fk is not None and fn is not None and fk != fn:
                    fp_status = "MISMATCH"; exp_valid = False
            pairs.append(TaskPair(
                task_pair_id=f"tp-{eid}-{tid}", evaluation_id=eid, task_id=tid,
                benchmark_item_id=k.benchmark_item_id,
                nogk_task_run_id=n.task_run_id, kg_task_run_id=k.task_run_id,
                pair_match_status=PairMatchStatus.VALID_PAIR,
                pair_experiment_valid=exp_valid, pair_fingerprint_status=fp_status,
            ))
        return pairs


class PairDerivedFactComputer:
    """计算 Pair Derived Facts（§7.26 L2）。需 KG+NoKG 两侧 Fact。"""

    def compute(self, pair: TaskPair,
                kg_outcome: OutcomeFact | None, nogk_outcome: OutcomeFact | None,
                kg_tool: ToolActionFact | None, nogk_tool: ToolActionFact | None,
                kg_res: ResourceFact | None, nogk_res: ResourceFact | None) -> list[PairDerivedFact]:
        out: list[PairDerivedFact] = []
        eid = pair.evaluation_id; pid = pair.task_pair_id

        # PairTransition（需双方 OutcomeFact）
        if kg_outcome and nogk_outcome:
            t = self._transition(nogk_outcome.outcome, kg_outcome.outcome)
            out.append(PairDerivedFact(
                derived_fact_id=f"pdf-{pid}-PT", evaluation_id=eid, task_pair_id=pid,
                derived_fact_type="PAIR_TRANSITION", value_string=t.value,
                status="CALCULATED",
                source_fact_refs=[{"fact_type": "OUTCOME", "fact_id": kg_outcome.outcome_fact_id, "condition": "KG"},
                                  {"fact_type": "OUTCOME", "fact_id": nogk_outcome.outcome_fact_id, "condition": "NOGK"}],
            ))
            pair.pair_transition = t
            pair.outcome_valid = (
                pair.pair_match_status == PairMatchStatus.VALID_PAIR
                and pair.pair_experiment_valid
                and kg_outcome.outcome in (Outcome.SUCCESS, Outcome.FAIL)
                and nogk_outcome.outcome in (Outcome.SUCCESS, Outcome.FAIL)
            )
        else:
            out.append(PairDerivedFact(
                derived_fact_id=f"pdf-{pid}-PT", evaluation_id=eid, task_pair_id=pid,
                derived_fact_type="PAIR_TRANSITION", status="NA",
                reason_code="PAIR_OUTCOME_UNDETERMINED",
            ))

        # JSD_i
        if kg_tool is not None and nogk_tool is not None:
            p = _distribution(kg_tool); q = _distribution(nogk_tool)
            jsd = _jsd(p, q)
            out.append(PairDerivedFact(
                derived_fact_id=f"pdf-{pid}-JSD", evaluation_id=eid, task_pair_id=pid,
                derived_fact_type="JSD", value_numeric=jsd, status="CALCULATED",
                source_fact_refs=[{"fact_type": "TOOL_ACTION", "fact_id": kg_tool.tool_action_fact_id, "condition": "KG"},
                                  {"fact_type": "TOOL_ACTION", "fact_id": nogk_tool.tool_action_fact_id, "condition": "NOGK"}],
            ))
        else:
            out.append(PairDerivedFact(
                derived_fact_id=f"pdf-{pid}-JSD", evaluation_id=eid, task_pair_id=pid,
                derived_fact_type="JSD", status="NA", reason_code="TOOL_EVENT_MISSING",
            ))

        # ΔToken / ΔSteps / ΔTime
        for dt, k, n, reason in [
            ("DELTA_TOKEN", kg_res.effective_tokens if kg_res else None,
             nogk_res.effective_tokens if nogk_res else None, "TOKEN_INVALID"),
            ("DELTA_STEPS", kg_res.steps if kg_res else None,
             nogk_res.steps if nogk_res else None, "STEP_INVALID"),
            ("DELTA_TIME", kg_res.duration_ms if kg_res else None,
             nogk_res.duration_ms if nogk_res else None, "TIME_INVALID"),
        ]:
            if k is not None and n is not None:
                out.append(PairDerivedFact(
                    derived_fact_id=f"pdf-{pid}-{dt}", evaluation_id=eid, task_pair_id=pid,
                    derived_fact_type=dt, value_numeric=k - n, status="CALCULATED",
                    source_fact_refs=[{"fact_type": "RESOURCE", "fact_id": kg_res.resource_fact_id, "condition": "KG"},
                                      {"fact_type": "RESOURCE", "fact_id": nogk_res.resource_fact_id, "condition": "NOGK"}],
                ))
            else:
                out.append(PairDerivedFact(
                    derived_fact_id=f"pdf-{pid}-{dt}", evaluation_id=eid, task_pair_id=pid,
                    derived_fact_type=dt, status="NA", reason_code=reason,
                ))
        return out

    @staticmethod
    def _transition(nogk_o: Outcome, kg_o: Outcome) -> PairTransition:
        """§8.6 Transition：A=Preserved, B=Regressed, C=Recovered, D=PersistedFailure。"""
        if nogk_o == Outcome.SUCCESS and kg_o == Outcome.SUCCESS:
            return PairTransition.PRESERVED
        if nogk_o == Outcome.SUCCESS and kg_o == Outcome.FAIL:
            return PairTransition.REGRESSED
        if nogk_o == Outcome.FAIL and kg_o == Outcome.SUCCESS:
            return PairTransition.RECOVERED
        if nogk_o == Outcome.FAIL and kg_o == Outcome.FAIL:
            return PairTransition.PERSISTED_FAILURE
        return PairTransition.NA
