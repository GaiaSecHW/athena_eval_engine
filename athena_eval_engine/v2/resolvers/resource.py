"""ResourceResolver — 从 session_meta 提取 token/步数/耗时（§8.10）。

平台无关：只消费 session_meta dict，不依赖任何平台特定逻辑。
effective_tokens 经 G9 Gate：reasoning_in_output=true -> input+output；false -> input+output+reasoning。
steps = count(step-start)；step-start != step-finish -> STEP_INTEGRITY_WARNING。
duration = time_updated - time_created（ms epoch）。

从老代码拷贝，已经是平台无关的。
"""
from __future__ import annotations

from ..core.task_run import TaskRun
from ..core.facts import ResourceFact


class ResourceResolver:
    """从 session_meta 提取 token/步数/耗时。

    config 结构（可选）：
        token_schema:
            reasoning_in_output: bool  # reasoning 是否已含在 output 中（默认 True）
            cache_excluded: bool       # cache_read 是否排除（默认 True）
    """

    def __init__(self, config: dict | None = None):
        self.token_schema = (config or {}).get(
            "token_schema", {"reasoning_in_output": True, "cache_excluded": True}
        )

    def resolve(self, task_run: TaskRun, session: dict) -> ResourceFact:
        """从 session_meta dict 提取资源事实。

        Args:
            task_run: TaskRun 实体
            session: session 元数据 dict，含以下字段：
                tokens_input: int | None
                tokens_output: int | None
                tokens_reasoning: int | None
                cache_read_tokens: int | None
                _step_start_count: int | None
                _step_finish_count: int | None
                time_created: int | None (ms epoch)
                time_updated: int | None (ms epoch)
                _events_ts: list[int | None]  # events 首末 timestamp（回退用）
        """
        inp = session.get("tokens_input")
        out = session.get("tokens_output")
        rea = session.get("tokens_reasoning")
        cache = session.get("cache_read_tokens")

        # effective_tokens 经 G9 Gate
        eff = None
        token_valid = False
        if inp is not None and out is not None:
            if self.token_schema.get("reasoning_in_output", True):
                eff = inp + out
            else:
                eff = inp + out + (rea or 0)
            token_valid = eff >= 0

        # steps = count(step-start)；step-start != step-finish -> STEP_INTEGRITY_WARNING
        steps = session.get("_step_start_count")
        n_finish = session.get("_step_finish_count") or 0
        step_warning = steps is not None and steps != n_finish

        # duration = time_updated - time_created（ms epoch）
        # session 第一行常为 health probe（tc==tu），回退用 events 首末 timestamp
        tc = session.get("time_created")
        tu = session.get("time_updated")
        if (not tc or not tu or tc == tu) and session.get("_events_ts"):
            ts_list = [t for t in session["_events_ts"] if t]
            if ts_list:
                tc, tu = min(ts_list), max(ts_list)
        duration = (tu - tc) if (tc is not None and tu is not None) else None
        time_valid = duration is not None and duration >= 0

        if token_valid and time_valid:
            validity = "VALID"
        elif token_valid or time_valid:
            validity = "PARTIAL"
        else:
            validity = "INVALID"

        return ResourceFact(
            resource_fact_id=f"rf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            input_tokens=inp, output_tokens=out, reasoning_tokens=rea,
            cache_read_tokens=cache, effective_tokens=eff,
            token_schema_valid=token_valid,
            token_schema_version="1.0",
            steps=steps,
            step_source="step-start" if steps is not None else "NA",
            step_integrity_warning=step_warning,
            duration_ms=duration, time_valid=time_valid,
            validity_status=validity,
        )
