"""Resolver 实现（§8.6-8.10）— RawEvent → Fact。

机械规则配置化（不硬编码）。config 结构见 §8.7/§8.8/§8.6。
- OutcomeResolver：vuln_hunt_update_finding.validation_result → POSITIVE/NEGATIVE；insert 无 update → UNDETERMINED
- KnowledgeResolver：access_rules / delivery_rules
- ToolActionResolver：Canonical Action v1.0（KG>FINDING>CODE>SHELL>OTHER）
- ResourceResolver：effective_tokens / step-start 计数 / duration
"""
from __future__ import annotations
import re
from typing import Iterable
from ..domain.raw_event import RawEvent
from ..domain.task_run import TaskRun, BenchmarkItem
from ..domain.facts import (
    OutcomeFact, KnowledgeInteractionFact, ToolActionFact, ResourceFact, Evidence,
)
from ..domain.enums import (
    Condition, ConditionSource, Outcome, Prediction, Confusion, ExpectedLabel,
    CanonicalAction,
)


def _ev(e: RawEvent, field_path: str = None) -> Evidence:
    return Evidence(
        trace_id=e.trace_id, session_id=e.session_id, message_id=e.message_id,
        part_id=e.part_id, tool_name=e.tool_name, event_timestamp=e.timestamp_ms,
        field_path=field_path,
    )


def _path_of(e: RawEvent) -> str:
    """从 input_json 提取路径（read/bash 的 file_path / command）。"""
    d = e.input_json or {}
    return str(d.get("file_path") or d.get("path") or d.get("command") or "")


# ===== OutcomeResolver（§8.6）=====
class OutcomeResolverImpl:
    def __init__(self, config: dict | None = None):
        self.high_confidence_threshold = 0.85
        self.ambiguity_margin = 0.10

    def resolve(self, task_run: TaskRun, benchmark: BenchmarkItem, events: list[RawEvent]) -> OutcomeFact:
        # 无 GT（benchmark 未标注）→ UNDETERMINED（M1-M4 不可算，但 M5-M10/行为照算）
        if benchmark is None or benchmark.expected_label is None:
            return OutcomeFact.undetermined(
                task_run.task_run_id, task_run.evaluation_id, task_run.condition,
                task_run.condition_source, reason="NO_GT",
                benchmark_item_id=benchmark.benchmark_item_id if benchmark else None,
            )
        # 1. 找 target finding 的最终 validation_result
        validation = self._latest_validation(events, benchmark.target_finding_id)
        if validation is None:
            return OutcomeFact.undetermined(
                task_run.task_run_id, task_run.evaluation_id, task_run.condition,
                task_run.condition_source, reason="NO_UPDATE" if self._has_insert(events) else "NO_FINDING",
                benchmark_item_id=benchmark.benchmark_item_id,
            )
        pred = "POSITIVE" if validation == "CONFIRMED" else "NEGATIVE"
        confusion, outcome = self._classify(benchmark.expected_label.value, pred)
        evs = [e for e in events if e.tool_name and (e.tool_name.startswith("vuln-hunt_") or e.tool_name.startswith("vuln_hunt_") or e.tool_name == "ReportFindings" or e.tool_name in ("vulnerability_analyze", "vulnerability_verify"))][:1]
        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmark.benchmark_item_id,
            gt_label=benchmark.expected_label, prediction=Prediction(pred),
            outcome=outcome, confusion_label=confusion,
            target_finding_id=benchmark.target_finding_id,
            validation_result=validation, resolver_status="RESOLVED",
            evidence=[_ev(e, "$.validation_result") for e in evs],
        )

    def _latest_validation(self, events: list[RawEvent], target_finding_id: str | None) -> str | None:
        """取该 finding 的最后一个有效 validation_result（按 timestamp 排序）。
        CONFIRMED→POSITIVE / FALSE_POSITIVE→NEGATIVE / 无→None(UNDETERMINED)。
        支持 Turing（vuln-hunt_update_finding）、Argo（ReportFindings outcome）、
        WebVulnVerify（vulnerability_analyze status）。"""
        candidates = []
        for e in events:
            if not (e.tool_name and e.is_tool_call()):
                continue
            d = e.input_json or {}
            # Turing: vuln-hunt_update_finding
            if e.tool_name in ("vuln-hunt_update_finding", "vuln_hunt_update_finding"):
                fid = str(d.get("finding_id") or "")
                if target_finding_id and fid and fid != target_finding_id:
                    continue
                vr = d.get("validation_result")
                if vr in ("CONFIRMED", "FALSE_POSITIVE"):
                    candidates.append((e.timestamp_ms or 0, vr))
            # WebVulnVerify: vulnerability_analyze / vulnerability_verify
            elif e.tool_name in ("vulnerability_analyze", "vulnerability_verify"):
                fid = str(d.get("vulnerability_id") or "")
                if target_finding_id and fid and fid != target_finding_id:
                    continue
                status = d.get("status")
                if status in ("VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE"):
                    candidates.append((e.timestamp_ms or 0, "CONFIRMED"))
                elif status == "NOT_VULNERABLE":
                    candidates.append((e.timestamp_ms or 0, "FALSE_POSITIVE"))
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0])
        return candidates[-1][1]

    def _has_insert(self, events) -> bool:
        return any(e.tool_name in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding", "ReportFindings", "vulnerability_analyze", "vulnerability_verify", "mcp__findings-store__store_finding") for e in events)

    @staticmethod
    def _classify(gt: str, pred: str) -> tuple[Confusion, Outcome]:
        """GT×Prediction → TP/FP/FN/TN → SUCCESS/FAIL（§8.6 映射）。"""
        if pred == "POSITIVE":
            c = Confusion.TP if gt == "VULNERABLE" else Confusion.FP
        else:
            c = Confusion.FN if gt == "VULNERABLE" else Confusion.TN
        o = Outcome.SUCCESS if c in (Confusion.TP, Confusion.TN) else Outcome.FAIL
        return c, o


# ===== KnowledgeResolver（§8.7/§8.8）=====
class KnowledgeResolverImpl:
    def __init__(self, config: dict):
        self.access_rules = config.get("access_rules", {})
        self.delivery_rules = config.get("delivery_rules", {})
        self._reject_re = [re.compile(p) for p in self.delivery_rules.get("reject_patterns", [])]
        self._kg_success = self.delivery_rules.get("kg_success_patterns", ["knowledge persisted", "Success:", '"result"'])
        self._kg_tools = set(self.access_rules.get("kg_tools", []))
        self._text_patterns = self.access_rules.get("text_patterns", [])

    def _follow_up_summary(self, events: list, start: int, n: int = 3) -> list[dict]:
        """取后续 N 个事件的摘要（tool_name + command/output）。n=3 控制体积。
        存储到 DB 的 evidence_json 体积敏感，output 截断到 300。"""
        out = []
        for j in range(start + 1, min(start + 1 + n, len(events))):
            e = events[j]
            if not (e.is_tool_call() or e.is_tool_result()):
                continue
            path = _path_of(e)
            tool = e.tool_name or ""
            cmd = path or ""
            out_str = ""
            if e.output_json is not None:
                out_str = e.output_json if isinstance(e.output_json, str) else json.dumps(e.output_json, ensure_ascii=False)
            out.append({"tool": tool, "type": "CALL" if e.is_tool_call() else "RESULT",
                         "command": cmd[:200], "output": out_str[:300]})
        return out

    def resolve(self, task_run: TaskRun, events: list[RawEvent]) -> KnowledgeInteractionFact:
        access_evs: list[Evidence] = []
        read_evs: list[Evidence] = []
        delivery_ok = False
        mount_status = "UNKNOWN"
        text_access = False
        interactions: list[dict] = []  # 原始介入事件
        memory_interactions: list[dict] = []  # 记忆交互事件（只读）
        mem_call_part_ids: set[str] = set()  # 记忆 CALL 的 part_id（用于 RESULT 配对）
        mem_success_count = 0
        for idx, e in enumerate(events):
            # text part 含 Reference/Athena 指引 = prompt 注入了知识库（KG2.0 配置存在）
            if e.event_type == "TEXT" and self._text_patterns:
                raw = ""
                if isinstance(e.input_json, str):
                    raw = e.input_json
                elif e.output_json is not None:
                    raw = str(e.output_json)
                if any(p in raw for p in self._text_patterns):
                    text_access = True
                    access_evs.append(_ev(e, "$.text"))
                continue
            if not (e.is_tool_call() or e.is_tool_result()):
                continue
            path = _path_of(e)
            tool = e.tool_name or ""
            # 知识图谱交互由 parser 标记（is_kg_interaction），resolver 不再硬编码工具名
            is_kg = e.is_kg_interaction
            # 记忆交互由 parser 标记（is_memory_interaction=读取/检索，is_memory_write=写入）
            is_mem = getattr(e, "is_memory_interaction", False)
            if is_mem and e.is_tool_call():
                cmd = path if path else (e.input_json if isinstance(e.input_json, str) else json.dumps(e.input_json, ensure_ascii=False) if e.input_json else "")
                memory_interactions.append({"tool": e.tool_name or "", "type": "CALL", "command": cmd[:300], "output": "", "timestamp": e.timestamp_ms, "session_id": e.session_id})
                if e.part_id:
                    mem_call_part_ids.add(e.part_id)
            # 记忆 RESULT：与 CALL 配对（同 part_id 或同工具名紧随）
            if is_mem and e.is_tool_result():
                out = e.output_json
                out_str = out if isinstance(out, str) else (json.dumps(out, ensure_ascii=False) if out is not None else "")
                memory_interactions.append({"tool": e.tool_name or "", "type": "RESULT", "command": "", "output": (out_str or "")[:500], "timestamp": e.timestamp_ms, "session_id": e.session_id})
                # 有非空输出 = 成功读取
                if out_str and out_str.strip() not in ("", "[]", "{}", "null"):
                    mem_success_count += 1
            if is_kg and e.is_tool_call():
                access_evs.append(_ev(e, "$.tool_name|path"))
                # 捕获知识介入原始事件（TOOL_CALL — 命令/输入 + 后续行为窗口）
                cmd = path if path else (e.input_json if isinstance(e.input_json, str) else json.dumps(e.input_json, ensure_ascii=False) if e.input_json else "")
                follow_up = self._follow_up_summary(events, idx)
                interactions.append({"tool": tool, "type": "CALL", "command": cmd[:300], "output": "", "timestamp": e.timestamp_ms, "follow_up": follow_up, "session_id": e.session_id})
            # Delivery：有 output 的事件都检查（TOOL_RESULT 或 TOOL_CALL 带 output）
            if e.is_tool_result() or (e.is_tool_call() and e.output_json is not None):
                out = e.output_json
                out_str = out if isinstance(out, str) else (json.dumps(out, ensure_ascii=False) if out is not None else "")
                has_success = any(s in out_str for s in self._kg_success) if out_str else False
                if "NFS symlink set" in out_str:
                    mount_status = "SUCCESS"
                elif "No wiki mount" in out_str:
                    mount_status = "FAILED"
                # 只对知识图谱交互计 delivery，reject 匹配到的不算成功交付
                if is_kg and out_str and not any(r.search(out_str.strip()) for r in self._reject_re):
                    if has_success or out_str.strip() not in ("", "[]", "{}"):
                        read_evs.append(_ev(e, "$.output"))
                        delivery_ok = True
                # 捕获知识图谱 RESULT
                if is_kg:
                    if "submit_knowledge" in tool:
                        continue
                    out_preview = out_str[:500] if out_str else ""
                    interactions.append({"tool": tool, "type": "RESULT", "command": "", "output": out_preview, "timestamp": e.timestamp_ms, "session_id": e.session_id})
        # prompt 注入也算 access（KG2.0 配置存在）
        has_access = bool(access_evs) or text_access
        mem_call_count = len([m for m in memory_interactions if m.get("type") == "CALL"])
        return KnowledgeInteractionFact(
            knowledge_fact_id=f"kif-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            access=bool(access_evs), delivery=delivery_ok, mount_status=mount_status,
            access_event_count=len(access_evs), read_event_count=len(read_evs),
            successful_read_count=len(read_evs) if delivery_ok else 0,
            interactions=interactions,
            evidence=access_evs + read_evs,
            memory_access=mem_call_count > 0,
            memory_access_event_count=mem_call_count,
            memory_successful_read_count=mem_success_count,
            memory_interactions=memory_interactions,
        )

    def _is_kg_skill(self, tool: str) -> bool:
        return tool in set(self.access_rules.get("skill_names", []))

    @staticmethod
    def _skill_name(e: RawEvent) -> str:
        """skill 工具的 name 在 input.name（非 tool_name）。"""
        d = e.input_json or {}
        return str(d.get("name") or "")

    def _is_access(self, tool: str, path: str) -> bool:
        for p in self.access_rules.get("path_patterns", []):
            if p in path:
                return True
        for c in self.access_rules.get("command_patterns", []):
            if re.search(c, path):
                return True
        return False


import json  # noqa: E402


# ===== ToolActionResolver（§8.9）=====
class ToolActionResolverImpl:
    ACTION_SCHEMA = "1.0"
    # 优先级：KG > FINDING > CODE > SHELL > OTHER

    def __init__(self, config: dict | None = None):
        self.access_rules = (config or {}).get("access_rules", {})
        self._kg_tools = set(self.access_rules.get("kg_tools", []))

    def resolve(self, task_run: TaskRun, events: list[RawEvent], schema=None) -> ToolActionFact:
        counts = {a.value: 0 for a in CanonicalAction}
        for e in events:
            if not e.is_tool_call():
                continue
            action = self._classify(e)
            counts[action] += 1
        total = sum(counts.values())
        return ToolActionFact(
            tool_action_fact_id=f"taf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            action_schema_version=self.ACTION_SCHEMA,
            kg_count=counts["KG"], finding_count=counts["FINDING"],
            code_count=counts["CODE"], shell_count=counts["SHELL"], other_count=counts["OTHER"],
            total_tool_calls=total, action_distribution=counts,
        )

    def _classify(self, e: RawEvent) -> str:
        tool = e.tool_name or ""
        path = _path_of(e)
        skill_name = str((e.input_json or {}).get("name") or "")
        # KG：只有 athena CLI 命令算知识图谱调用（vuln_hunt_* 是内部黑板，不算 KG）
        if skill_name in set(self.access_rules.get("skill_names", [])):
            return "KG"
        for p in self.access_rules.get("path_patterns", []):
            if p in path:
                return "KG"
        for c in self.access_rules.get("command_patterns", []):
            if re.search(c, path):
                return "KG"
        # FINDING：只有实际提交漏洞发现的工具才算（insert_finding / ReportFindings）
        if tool in ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding", "ReportFindings", "reportfindings", "mcp__findings-store__store_finding"):
            return "FINDING"
        if tool in ("read", "grep", "glob") and "wiki" not in path:
            return "CODE"
        if tool == "bash" and "wiki" not in path:
            return "SHELL"
        return "OTHER"


# ===== ResourceResolver（§8.10）=====
class ResourceResolverImpl:
    def __init__(self, config: dict | None = None):
        self.token_schema = (config or {}).get("token_schema", {"reasoning_in_output": True, "cache_excluded": True})

    def resolve(self, task_run: TaskRun, session: dict) -> ResourceFact:
        inp = session.get("tokens_input")
        out = session.get("tokens_output")
        rea = session.get("tokens_reasoning")
        cache = session.get("cache_read_tokens")
        # effective_tokens 经 G9 Gate：reasoning_in_output=true → input+output；false → input+output+reasoning
        eff = None; token_valid = False
        if inp is not None and out is not None:
            if self.token_schema.get("reasoning_in_output", True):
                eff = inp + out
            else:
                eff = inp + out + (rea or 0)
            token_valid = eff >= 0
        # steps = count(step-start)；step-start ≠ step-finish → STEP_INTEGRITY_WARNING（§8.10）
        steps = session.get("_step_start_count")
        n_finish = session.get("_step_finish_count") or 0
        step_warning = steps is not None and steps != n_finish
        # duration = time_updated - time_created（ms epoch）；<0 → TIME_INVALID（§8.10）
        # session 第一行常为 health probe（tc==tu），回退用 events 首末 timestamp
        tc = session.get("time_created"); tu = session.get("time_updated")
        if (not tc or not tu or tc == tu) and session.get("_events_ts"):
            ts_list = [t for t in session["_events_ts"] if t]
            if ts_list: tc, tu = min(ts_list), max(ts_list)
        duration = (tu - tc) if (tc is not None and tu is not None) else None
        time_valid = duration is not None and duration >= 0
        validity = "VALID" if (token_valid and time_valid) else ("PARTIAL" if (token_valid or time_valid) else "INVALID")
        return ResourceFact(
            resource_fact_id=f"rf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            input_tokens=inp, output_tokens=out, reasoning_tokens=rea,
            cache_read_tokens=cache, effective_tokens=eff,
            token_schema_valid=token_valid,
            token_schema_version="1.0",
            steps=steps, step_source="step-start" if steps is not None else "NA",
            step_integrity_warning=step_warning,
            duration_ms=duration, time_valid=time_valid, validity_status=validity,
        )
