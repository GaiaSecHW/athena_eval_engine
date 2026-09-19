"""Resolver 实现（§8.6-8.10）— RawEvent → Fact。

机械规则配置化（不硬编码）。config 结构见 §8.7/§8.8/§8.6。
- OutcomeResolver：vuln_hunt_update_finding.validation_result → POSITIVE/NEGATIVE；insert 无 update → UNDETERMINED
- KnowledgeResolver：access_rules / delivery_rules
- ToolActionResolver：Canonical Action v1.0（KG>FINDING>CODE>SHELL>OTHER）
- ResourceResolver：effective_tokens / step-start 计数 / duration
"""
from __future__ import annotations
import re
import time
from typing import Iterable
from ..domain.raw_event import RawEvent
from ..domain.task_run import TaskRun, BenchmarkItem
from ..domain.facts import (
    OutcomeFact, KnowledgeInteractionFact, ToolActionFact, ResourceFact, Evidence,
)
from ..domain.enums import (
    Condition, ConditionSource, Outcome, Prediction, ExpectedLabel,
    CanonicalAction,
)
from ..infrastructure.log_util import log
from .parse_utils import parse_json_lenient, extract_json_payloads

_LOG_INTERVAL = 50000  # 每 5 万条事件输出一次进度


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
        outcome = self._classify(benchmark.expected_label.value, pred)
        evs = [e for e in events if e.tool_name and (e.tool_name.startswith("vuln-hunt_") or e.tool_name.startswith("vuln_hunt_") or e.tool_name == "ReportFindings" or e.tool_name in ("vulnerability_analyze", "vulnerability_verify", "vulnerability_cvss"))][:1]
        return OutcomeFact(
            outcome_fact_id=f"ocf-{task_run.task_run_id}",
            task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
            condition=task_run.condition, condition_source=task_run.condition_source,
            benchmark_item_id=benchmark.benchmark_item_id,
            gt_label=benchmark.expected_label, prediction=Prediction(pred),
            outcome=outcome,
            target_finding_id=benchmark.target_finding_id,
            validation_result=validation, resolver_status="RESOLVED",
            evidence=[_ev(e, "$.validation_result") for e in evs],
        )

    def _latest_validation(self, events: list[RawEvent], target_finding_id: str | None) -> str | None:
        """取该 finding 的最后一个有效 validation_result（按 timestamp 排序）。
        CONFIRMED→POSITIVE / FALSE_POSITIVE→NEGATIVE / 无→None(UNDETERMINED)。
        支持 Turing（vuln-hunt_update_finding）、Argo（findings.json verdict）、
        WebVulnVerify（vulnerability_analyze status）、
        CVulnVerify（write vuln_verify_final_verdict.json verdict）、
        DataflowVulnScan（assistant 文本 findings JSON）、
        SecMate（store_tracer_verdict outcome）。"""
        candidates = []
        _n = len(events)
        for idx, e in enumerate(events):
            if idx > 0 and idx % _LOG_INTERVAL == 0:
                log("RESOLVE", f"OutcomeResolver._latest_validation {idx}/{_n} events")
            # DataflowVulnScan: assistant 文本中的 findings JSON（TEXT 事件，非 tool call）
            if e.event_type == "TEXT" and e.output_json:
                text = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
                if '"findings"' in text:
                    for obj in extract_json_payloads(text, keywords=['"findings"']):
                        finds = obj.get("findings", [])
                        if finds:
                            candidates.append((e.timestamp_ms or 0, "CONFIRMED"))
                        else:
                            candidates.append((e.timestamp_ms or 0, "FALSE_POSITIVE"))
                        break
                continue
            # Argo: TOOL_RESULT 中含 findings JSON（findings.json 的 cat 结果）
            if e.event_type == "TOOL_RESULT" and e.output_json:
                out_str = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
                if '"verdict"' in out_str and '"finding_id"' in out_str:
                    try:
                        data = json.loads(out_str)
                    except (json.JSONDecodeError, TypeError):
                        data = parse_json_lenient(out_str)
                    if isinstance(data, list):
                        for f in data:
                            vr = f.get("verdict", "")
                            if vr in ("CONFIRMED", "FALSE_POSITIVE", "MANUAL_REVIEW"):
                                mapped = "CONFIRMED" if vr in ("CONFIRMED", "MANUAL_REVIEW") else "FALSE_POSITIVE"
                                candidates.append((e.timestamp_ms or 0, mapped))
                    elif isinstance(data, dict):
                        vr = data.get("verdict", "")
                        if vr in ("CONFIRMED", "FALSE_POSITIVE", "MANUAL_REVIEW"):
                            mapped = "CONFIRMED" if vr in ("CONFIRMED", "MANUAL_REVIEW") else "FALSE_POSITIVE"
                            candidates.append((e.timestamp_ms or 0, mapped))
                continue
            if not (e.tool_name and e.is_tool_call()):
                continue
            d = e.input_json or {}
            # Turing: vuln-hunt_update_finding
            if e.tool_name in ("vuln-hunt_update_finding", "vuln_hunt_update_finding"):
                fid = str(d.get("finding_id") or "")
                if target_finding_id and fid and fid != target_finding_id:
                    continue
                vr = d.get("validation_result")
                if vr in ("CONFIRMED", "LIKELY", "POSSIBLE", "FALSE_POSITIVE"):
                    mapped = "CONFIRMED" if vr in ("CONFIRMED", "LIKELY", "POSSIBLE") else "FALSE_POSITIVE"
                    candidates.append((e.timestamp_ms or 0, mapped))
            # WebVulnVerify: vulnerability_analyze / vulnerability_verify / vulnerability_cvss
            elif e.tool_name in ("vulnerability_analyze", "vulnerability_verify", "vulnerability_cvss"):
                # vulnerability_id 由 WebVulnVerifyTraceParser 归一化（analyze 从 result 文本提取）
                fid = str(d.get("vulnerability_id") or "")
                if target_finding_id and fid and fid != target_finding_id:
                    continue
                status = d.get("status")
                if status in ("VULNERABLE", "EXTERNAL_REQUEST_EXPLOITABLE", "UNIT_TEST_EXPLOITABLE"):
                    candidates.append((e.timestamp_ms or 0, "CONFIRMED"))
                elif status in ("NOT_VULNERABLE", "NOT_EXPLOITABLE"):
                    candidates.append((e.timestamp_ms or 0, "FALSE_POSITIVE"))
            # CVulnVerify: write 工具写 vuln_verify_final_verdict.json
            elif e.tool_name == "write":
                fp = str(d.get("file_path") or d.get("path") or "")
                if "vuln_verify_final_verdict" in fp:
                    content = d.get("content", "")
                    if isinstance(content, str):
                        vdata = parse_json_lenient(content)
                        if vdata:
                            verdict = vdata.get("verdict", "")
                            if verdict == "confirmed":
                                candidates.append((e.timestamp_ms or 0, "CONFIRMED"))
                            elif verdict == "ruled_out":
                                candidates.append((e.timestamp_ms or 0, "FALSE_POSITIVE"))
            # SecMate: mcp__workflow-tools__store_tracer_verdict（outcome 字段）
            elif e.tool_name == "mcp__workflow-tools__store_tracer_verdict":
                outcome = d.get("outcome", "")
                if outcome in ("confirmed", "conditional"):
                    candidates.append((e.timestamp_ms or 0, "CONFIRMED"))
                elif outcome == "refuted":
                    candidates.append((e.timestamp_ms or 0, "FALSE_POSITIVE"))
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0])
        return candidates[-1][1]

    def _has_insert(self, events) -> bool:
        # 工具调用型结论点（store_tiered_fing 用前缀匹配，处理 LLM 拼写变体）
        _exact = ("vuln-hunt_insert_finding", "vuln_hunt_insert_finding", "ReportFindings", "reportfindings",
                  "vulnerability_analyze", "vulnerability_verify", "vulnerability_cvss",
                  "mcp__findings-store__store_finding",
                  "mcp__workflow-tools__store_tracer_verdict")
        if any(e.tool_name in _exact or
               (e.tool_name and e.tool_name.startswith("mcp__workflow-tools__store_tiered_fing"))
               for e in events):
            return True
        # CVulnVerify: write vuln_verify_final_verdict.json
        for e in events:
            if e.tool_name == "write":
                fp = str((e.input_json or {}).get("file_path") or (e.input_json or {}).get("path") or "")
                if "vuln_verify_final_verdict" in fp:
                    return True
        # DataflowVulnScan: assistant 文本含 findings JSON
        for e in events:
            if e.event_type == "TEXT" and e.output_json:
                text = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
                if '"findings"' in text and "vuln_type" in text:
                    return True
        # Argo: TOOL_RESULT 含 findings JSON（findings.json 的 cat 结果）
        for e in events:
            if e.event_type == "TOOL_RESULT" and e.output_json:
                out_str = e.output_json if isinstance(e.output_json, str) else str(e.output_json)
                if '"verdict"' in out_str and '"finding_id"' in out_str:
                    return True
        return False

    @staticmethod
    def _classify(gt: str, pred: str) -> Outcome:
        """GT×Prediction → SUCCESS/FAIL（§8.6 映射）。"""
        if pred == "POSITIVE":
            return Outcome.SUCCESS if gt == "VULNERABLE" else Outcome.FAIL
        else:
            return Outcome.FAIL if gt == "VULNERABLE" else Outcome.SUCCESS


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
                         "command": cmd, "output": out_str})
        return out

    def resolve(self, task_run: TaskRun, events: list[RawEvent]) -> KnowledgeInteractionFact:
        # NOGK 条件不分析知识与记忆交互
        if task_run.condition == Condition.NOGK:
            return KnowledgeInteractionFact(
                knowledge_fact_id=f"kif-{task_run.task_run_id}",
                task_run_id=task_run.task_run_id, evaluation_id=task_run.evaluation_id,
                access=False, delivery=False, mount_status="UNKNOWN",
                access_event_count=0, read_event_count=0,
                successful_read_count=0,
                interactions=[],
                evidence=[],
                memory_access=False,
                memory_access_event_count=0,
                memory_successful_read_count=0,
                memory_interactions=[],
            )
        access_evs: list[Evidence] = []
        read_evs: list[Evidence] = []
        delivery_ok = False
        mount_status = "UNKNOWN"
        text_access = False
        interactions: list[dict] = []  # 原始介入事件
        memory_interactions: list[dict] = []  # 记忆交互事件（只读）
        mem_call_ids: set[str] = set()  # 记忆 CALL 的 call_id（用于 RESULT 精确配对）
        mem_success_count = 0
        _n = len(events)
        for idx, e in enumerate(events):
            if idx > 0 and idx % _LOG_INTERVAL == 0:
                log("RESOLVE", f"KnowledgeResolver {idx}/{_n} events")
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
                memory_interactions.append({"tool": e.tool_name or "", "type": "CALL", "command": cmd, "output": "", "timestamp": e.timestamp_ms, "session_id": e.session_id})
                if e.call_id:
                    mem_call_ids.add(e.call_id)
            # 记忆 RESULT：与 CALL 精确配对（通过 call_id）
            # TOOL_RESULT 不继承 is_memory_interaction 标记（避免重复统计），
            # 通过 call_id 在 mem_call_ids 中匹配识别记忆 RESULT
            # Turing trace 的 TOOL_CALL 含 output（call+result 合一），也要检查
            is_mem_result = (
                (e.is_tool_result() and e.call_id and e.call_id in mem_call_ids) or
                (is_mem and e.is_tool_call() and e.output_json is not None)
            )
            if is_mem_result:
                out = e.output_json
                out_str = out if isinstance(out, str) else (json.dumps(out, ensure_ascii=False) if out is not None else "")
                memory_interactions.append({"tool": e.tool_name or "", "type": "RESULT", "command": "", "output": out_str or "", "timestamp": e.timestamp_ms, "session_id": e.session_id})
                # 有非空输出 = 成功读取
                if out_str and out_str.strip() not in ("", "[]", "{}", "null"):
                    mem_success_count += 1
            if is_kg and e.is_tool_call():
                access_evs.append(_ev(e, "$.tool_name|path"))
                # 捕获知识介入原始事件（TOOL_CALL — 命令/输入 + 后续行为窗口）
                cmd = path if path else (e.input_json if isinstance(e.input_json, str) else json.dumps(e.input_json, ensure_ascii=False) if e.input_json else "")
                follow_up = self._follow_up_summary(events, idx)
                interactions.append({"tool": tool, "type": "CALL", "command": cmd, "output": "", "timestamp": e.timestamp_ms, "follow_up": follow_up, "session_id": e.session_id})
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
                    # has_success=明确成功标记；非空输出也算（但排除错误前缀，防止 API 失败被计为交付）
                    _err_like = out_str.strip().lower().startswith(("error", "execution error", "failed", "exception"))
                    if has_success or (out_str.strip() not in ("", "[]", "{}") and not _err_like):
                        read_evs.append(_ev(e, "$.output"))
                        delivery_ok = True
                # 捕获知识图谱 RESULT
                if is_kg:
                    if "submit_knowledge" in tool:
                        continue
                    out_preview = out_str or ""
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
        _n = len(events)
        for idx, e in enumerate(events):
            if idx > 0 and idx % _LOG_INTERVAL == 0:
                log("RESOLVE", f"ToolActionResolver {idx}/{_n} events")
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
        # KG：parser 已标记的知识图谱交互（athena CLI / athena_ask API）
        if e.is_kg_interaction:
            return "KG"
        # KG：config 配置的 skill / path / command 模式（向后兼容）
        if skill_name in set(self.access_rules.get("skill_names", [])):
            return "KG"
        for p in self.access_rules.get("path_patterns", []):
            if p in path:
                return "KG"
        for c in self.access_rules.get("command_patterns", []):
            if re.search(c, path):
                return "KG"
        # FINDING：parser 已标记的漏洞发现提交工具
        if e.is_finding_submission:
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
