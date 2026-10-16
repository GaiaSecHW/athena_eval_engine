"""L0-L7 误报根因全链路分析器（§4.1）。

对每次知识访问，在 Agent 级别逐级判定 L0-L7。
L0 标记知识的原始来源（provenance），不参与断链判定；
L1-L7 逐级判定断点，输出 cause_code（A-G）。

漏斗过滤逻辑：
  L0: 来源标记（程序判定，从 frontmatter/init.json 读取）
  L1: 需要知识？(LLM Prompt 2) — L1=False → 全链短路，无断点
  L2: 发起访问？(程序判定，is_kg_interaction/is_memory_interaction) — L2=False → 断点 A
  L3: 查询准确？(LLM Prompt 3) — L3=False → 断点 B
  L4: 知识存在？(程序判定，output_preview 非空) — L4=False → 断点 C
  L5: 成功取回？(程序判定，无 error/timeout) — L5=False → 断点 D
  L6: 推理引用？(LLM Prompt 4) — L6=False → 断点 E
  L7: 影响结论？(LLM Prompt 5, 在 evidence_chain.py 中实现) — L7=False → 断点 F
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..infra import llm as llm_mod
from ..infra import concurrency as concurrency_mod
from ..infra.parallel import iter_completed
from .case_filter import CaseFilter
from .evidence_chain import L7_CONFIDENCE_THRESHOLD
from ..persistence.kad_repo import upsert_knowledge_access_details
from ...infrastructure.log_util import log, with_eval_ctx, get_eval_ctx

# ── 安全上下文阈值（占 max_context 的比例）──
_CONTEXT_SAFETY_RATIO = 0.6  # 只用 60% 上下文窗口给 user_content，留余量给 system prompt + 输出
_DEFAULT_MAX_CONTEXT_TOKENS = 128_000  # 未从 400 错误中收集到时使用此默认值
_COMPRESS_THRESHOLD_CHARS = 4000  # 单个文本字段超过此字符数时触发压缩

# ── 统一 LLM 调用的 system prompt ──

_PROMPT_UNIFIED_SYSTEM = """你是知识访问全链路判定员。对一次知识访问执行 L1-L7 全部判定。

# 你收到的信息
1. vuln_title：基线漏洞标题
2. reasoning_context：知识访问前 Agent 的推理上下文
3. query_content：Agent 发给知识库的查询内容
4. returned_content：知识库返回的内容
5. reasoning_ref：知识访问后 Agent 的推理文本
6. judgment_conclusion：Agent 的判定结论（如"确认漏洞"/"排除误报"）
7. baseline_vuln_info：基线漏洞信息（漏洞类型、source、sink、文件、描述）

# 判定级别（逐级，不通过的级别即为断点，后续级别填 null）

## L1：该场景是否需要外部知识支撑？
知识包括：漏洞模式知识（source/sink 模式、绕过手法）、项目代码结构知识、历史挖掘经验。
- need_knowledge=true：推理任务本质上需要了解某类漏洞模式、项目结构或历史经验才能正确完成
- need_knowledge=false：仅凭当前代码上下文即可完成（如直接读代码定位 sink 点）
- 如果推理文本显示 Agent 已具备相关知识（如内联了模式描述），可能不需要外部知识

## L2：Agent 是否发起了知识访问？
- initiated=true：Agent 实际调用了知识库/记忆工具
- initiated=false：需要知识但没有发起访问

## L3：查询内容是否聚焦于当前任务？
- query_accurate=true：查询明确指向当前问题，包含具体技术上下文（漏洞类型、框架名、函数名等），范围适中
- query_accurate=false：查询与任务无关、过于宽泛（如只查"SQL注入"无上下文）、或存在明显错误

## L4：知识库是否有对应知识？
- knowledge_exists=true：返回内容非空且与查询相关
- knowledge_exists=false：返回空或"未找到"类内容

## L5：知识是否被成功取回？
- retrieved=true：返回内容有效，无 error/timeout 标记
- retrieved=false：返回内容含 error/timeout/exception/connection failed 等标记

## L6：Agent 推理文本是否引用了知识返回内容？
- used=true：推理文本中出现知识返回内容的关键词/函数名/模式描述，或基于知识改变了分析方向
- used=false：推理文本完全未提及知识返回内容，或结论在查询前已得出

## L7：知识是否影响了判定结论？
### 维度一：知识正确性（knowledge_correct）
对比知识内容与基线漏洞信息：
- correct=true：知识描述的漏洞模式、sink 函数、攻击路径等与基线一致
- correct=false：知识模式与基线漏洞类型不符、sink 不匹配、内容过时或不适用

### 维度二：方向一致性（direction_consistent）
- direction_consistent=true：知识方向（指向漏洞存在/不存在）与判定结论方向一致
- direction_consistent=false：知识方向与判定结论方向相反

### 维度三：置信度（confidence）
0.0-1.0，<0.6 表示证据不足无法判定

# 判定规则
- L1=false → L2-L7 全部 null，无断点
- L1=true, L2=false → 断点 A（该查没查），L3-L7 null
- L2=true, L3=false → 断点 B（查询太泛），L4-L7 null
- L3=true, L4=false → 断点 C（查了没得），L5-L7 null
- L4=true, L5=false → 断点 D（链路问题），L6-L7 null
- L5=true, L6=false → 断点 E（查到没用），L7 null
- L6=true → L7 判定：
  - knowledge_correct=true, direction_consistent=true, confidence>=0.6 → effect=POSITIVE（正向，知识推动了正确判定）
  - knowledge_correct=false, direction_consistent=true, confidence>=0.6 → effect=NEGATIVE, cause=G（知识错误导致误判）
  - direction_consistent=false, confidence>=0.6 → effect=NEUTRAL, cause=F（知识未推动结论）
  - confidence<0.6 → effect=null, cause=null（证据不足）

# reason 写作要求（500字以内）
第一句给出核心结论：断点在哪一级（或全链通过）。
然后分维度说明判断依据，必须引用具体内容作为证据。

只返回 JSON：
{
  "l1_need_knowledge": true/false,
  "l2_initiated": true/false/null,
  "l3_query_accurate": true/false/null,
  "l4_knowledge_exists": true/false/null,
  "l5_retrieved": true/false/null,
  "l6_used": true/false/null,
  "l7_knowledge_correct": true/false/null,
  "l7_direction_consistent": true/false/null,
  "l7_confidence": 0.0/null,
  "effect_label": "POSITIVE"/"NEGATIVE"/"NEUTRAL"/null,
  "cause_code": "A"/"B"/"C"/"D"/"E"/"F"/"G"/null,
  "reason": "500字以内中文，结论先行，分维度说明判断依据"
}
"""

# 知识返回内容中的 error/timeout 标记
_ERROR_MARKERS = ("error", "timeout", "timed out", "exception", "failed",
                  "execution error", "connection refused", "unreachable")


class LifecycleAnalyzer:
    """L0-L7 误报根因全链路分析器。

    对有效 case 的每次知识访问执行 L0-L7 逐级判定。
    L0 标记来源，L1-L6 在本模块判定，L7 委托给 EvidenceChain。
    """

    def __init__(self, llm_client=None):
        """初始化分析器。

        Args:
            llm_client: LLM 客户端模块（v2 infra.llm），None 时直接使用模块级函数。
                        主要用于测试注入 mock。
        """
        self.llm = llm_client

    def analyze(self, evaluation_id: str, data_packs: list,
                reports_dir: str, cancel_cb=None,
                eval_mode: str = "dev",
                benchmark_source: str = "vbench_zip",
                alert_center_data: dict | None = None,
                case_details: dict | None = None,
                case_session_matches: list[dict] | None = None) -> list[dict]:
        """对有效 case 的每次知识访问执行 L0-L7 分析。

        流程：
        1. 用 CaseFilter 按 eval_mode 筛选有效 case
           - runtime（运行态）：只分析 FP case（人工标注误报）
           - dev（开发态）：分析 FP + FN case（误报 + 漏报）
        2. 对每个有效 case 的知识访问执行 L0-L6 漏斗判定
        3. L7 判定委托给 EvidenceChain（延迟 import）
        4. 写入 knowledge_access_detail 表

        Args:
            benchmark_source: "vuln_center"（漏洞中心，纯代码匹配）|
                              "vbench_zip"（V-Bench 测评集，LLM 匹配）
            alert_center_data: 告警中心数据，用于 FN 判定
            case_session_matches: case_session_matcher 的匹配结果，用于 FP case 筛选

        Returns:
            list[dict]，每个 dict 是一条 knowledge_access_detail 记录
        """
        case_filter = CaseFilter()
        valid_packs = case_filter.filter_valid_cases(
            evaluation_id, data_packs, eval_mode=eval_mode,
            benchmark_source=benchmark_source,
            alert_center_data=alert_center_data,
            case_details=case_details,
            case_session_matches=case_session_matches,
        )

        all_records: list[dict] = []

        # 多 case 并行分析
        # case 级并发保持低——每个 case 内的 access 级并行由 submit_llm_batch + gate 控制
        # case 级只需足够让多个 case 同时推进即可，太高会导致线程暴涨
        max_workers = min(len(valid_packs), 3)
        log("LIFECYCLE",
            f"analyzing {len(valid_packs)} cases in parallel (workers={max_workers})",
            eval_id=evaluation_id)

        if max_workers <= 1:
            # 单 case 或并发=1，串行执行
            for dp in valid_packs:
                if cancel_cb:
                    cancel_cb()
                records = self._analyze_one_case(evaluation_id, dp, reports_dir, cancel_cb)
                all_records.extend(records)
        else:
            # 多 case 并行
            results: list[list[dict] | None] = [None] * len(valid_packs)

            def _run_case(idx_dp):
                idx, dp = idx_dp
                return idx, self._analyze_one_case(evaluation_id, dp, reports_dir, cancel_cb)

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_run_case, (i, dp)): i
                           for i, dp in enumerate(valid_packs)}
                for fut, _ in iter_completed(futures, cancel_cb=cancel_cb):
                    idx, records = fut.result()
                    results[idx] = records

            for r in results:
                if r is not None:
                    all_records.extend(r)

        # 将 case_filter 的 FPR 统计附加到实例，供 orchestrator 计算 M13
        self.case_filter_stats = getattr(case_filter, "fpr_stats", None)

        log("LIFECYCLE",
            f"analyze done: {len(all_records)} records from {len(valid_packs)} valid cases",
            eval_id=evaluation_id)
        return all_records

    def _analyze_one_case(self, evaluation_id: str, dp: DataPack,
                          reports_dir: str, cancel_cb=None) -> list[dict]:
        """分析单个 case 的全部知识访问。

        对每个 access 执行一次统一的 LLM 调用，一次性判定 L1-L7。
        """
        events = dp.events or []
        kf = dp.knowledge_fact
        if kf is None:
            return []

        # 收集全部知识访问（KG + 记忆），每个访问含 event_idx 和原始 interaction
        accesses = self._collect_accesses(events, kf)
        if not accesses:
            return []

        # 提取基线漏洞信息（整个 case 共享一份）
        baseline_vuln_info = self._get_baseline_vuln_info(dp)

        # access 级并行：每个 access 的 L1-L7 统一判定作为一个独立任务提交到 LLM gate
        records: list[dict | None] = [None] * len(accesses)

        if len(accesses) == 1:
            if cancel_cb:
                cancel_cb()
            try:
                records[0] = self._run_l1_l7(accesses[0], events, dp,
                                             baseline_vuln_info, cancel_cb)
            except Exception as e:
                log("LIFECYCLE",
                    f"L1-L7 failed for event_idx={accesses[0].get('event_idx')}: {str(e)[:200]}",
                    eval_id=evaluation_id)
                raise
        else:
            def _do_run(acc):
                return self._run_l1_l7(acc, events, dp, baseline_vuln_info, cancel_cb)

            futures = llm_mod.submit_llm_batch(
                _do_run,
                accesses,
                cancel_cb=cancel_cb,
            )

            for i, fut in enumerate(futures):
                try:
                    records[i] = fut.result()
                except Exception as e:
                    log("LIFECYCLE",
                        f"L1-L7 failed for event_idx={accesses[i].get('event_idx')}: {str(e)[:200]}",
                        eval_id=evaluation_id)
                    raise

        # 过滤 None（失败的 access）
        records = [r for r in records if r is not None]

        # 统计结果
        if records:
            stats = {}
            for r in records:
                label = r.get("effect_label") or "NULL"
                stats[label] = stats.get(label, 0) + 1
            log("LIFECYCLE",
                f"case done: {len(records)} records, results={stats}",
                eval_id=evaluation_id)

        # 批量写入 knowledge_access_detail
        if records:
            upsert_knowledge_access_details(records, evaluation_id, reports_dir)

        return records

    def _collect_accesses(self, events: list, kf) -> list[dict]:
        """从 events 和 KnowledgeInteractionFact 收集全部知识访问。

        每个 access 含：
        - event_idx: 事件在 events 列表中的序号
        - session_id: session 标识
        - source_system: "知识库" / "记忆进化"
        - interaction: 原始 interaction dict（含 command/output 等）
        - is_kg: 是否知识库交互
        - is_mem: 是否记忆交互
        """
        accesses: list[dict] = []

        # 预构建 (session_id, timestamp, tool_name) → idx 索引，O(1) 查找
        # 避免 1385 次 × 174K events 的 O(N²) 线性扫描
        ts_index: dict[tuple, int] = {}
        session_tool_index: dict[tuple, int] = {}
        for idx, e in enumerate(events):
            key = (e.session_id, e.timestamp_ms, e.tool_name or "")
            if key not in ts_index:
                ts_index[key] = idx
            key2 = (e.session_id, e.tool_name or "")
            if key2 not in session_tool_index and e.is_tool_call():
                session_tool_index[key2] = idx

        def _find_idx(session_id, timestamp, tool_name):
            if timestamp is not None:
                key = (session_id, timestamp, tool_name or "")
                if key in ts_index:
                    return ts_index[key]
            key2 = (session_id, tool_name or "")
            return session_tool_index.get(key2, -1)

        # 从 interactions（KG）收集 CALL 事件
        for inter in (kf.interactions or []):
            if inter.get("type") != "CALL":
                continue
            session_id = inter.get("session_id", "")
            event_idx = _find_idx(session_id,
                                  inter.get("timestamp"),
                                  inter.get("tool", ""))
            accesses.append({
                "event_idx": event_idx,
                "session_id": session_id,
                "source_system": "知识库",
                "interaction": inter,
                "is_kg": True,
                "is_mem": False,
            })

        # 从 memory_interactions 收集 CALL 事件
        for inter in (kf.memory_interactions or []):
            if inter.get("type") != "CALL":
                continue
            session_id = inter.get("session_id", "")
            event_idx = _find_idx(session_id,
                                  inter.get("timestamp"),
                                  inter.get("tool", ""))
            accesses.append({
                "event_idx": event_idx,
                "session_id": session_id,
                "source_system": "记忆进化",
                "interaction": inter,
                "is_kg": False,
                "is_mem": True,
            })

        return accesses

    def _extract_event_text(self, e: RawEvent) -> str:
        """从 RawEvent 提取文本内容（REASONING/MESSAGE/TEXT）。"""
        if e.input_json is not None:
            if isinstance(e.input_json, str):
                return e.input_json
            if isinstance(e.input_json, dict):
                # 常见字段名
                for key in ("content", "text", "message", "reasoning"):
                    val = e.input_json.get(key)
                    if val and isinstance(val, str):
                        return val
                return json.dumps(e.input_json, ensure_ascii=False)
        if e.output_json is not None:
            if isinstance(e.output_json, str):
                return e.output_json
            if isinstance(e.output_json, dict):
                for key in ("content", "text", "message", "reasoning"):
                    val = e.output_json.get(key)
                    if val and isinstance(val, str):
                        return val
                return json.dumps(e.output_json, ensure_ascii=False)
        return ""

    def _run_l1_l7(self, access: dict, events: list, dp: DataPack,
                   baseline_vuln_info: dict, cancel_cb=None) -> dict:
        """对单次知识访问执行 L1-L7 统一判定（一次 LLM 调用）。

        L0（来源标记）仍由程序判定。
        L1-L7 全部交给 LLM，一次调用输出全部结果。

        当文本数据超过 LLM 上下文窗口时，先用 LLM 逐字段压缩，
        再拼接压缩后的摘要发给统一判定 LLM。不截断。
        """
        task_run_id = dp.task_run_id
        event_idx = access.get("event_idx", 0)
        access_id = f"{dp.evaluation_id}_{task_run_id}_{event_idx}"
        source_system = access.get("source_system", "知识库")
        interaction = access.get("interaction", {})

        # L0: 来源标记（程序判定）
        l0_origin = self._determine_l0_origin(access, interaction, dp)

        # 提取推理上下文：知识访问前 agent 的行为上下文
        reasoning_context = self._extract_reasoning_context(events, event_idx)
        if not reasoning_context:
            reasoning_context = str(interaction.get("command", "") or "")

        # 提取查询内容
        query_content = str(interaction.get("command", "") or "")

        # 提取返回内容
        returned_content = self._get_output_preview(access, interaction)

        # 提取推理引用文本：知识访问后 agent 的行为上下文
        reasoning_ref = self._extract_reasoning_ref(events, event_idx)
        if not reasoning_ref:
            follow_up = interaction.get("follow_up")
            if follow_up:
                import json as _json
                reasoning_ref = _json.dumps(follow_up, ensure_ascii=False)
            else:
                reasoning_ref = str(interaction.get("output", "") or "")

        # 提取判定结论
        judgment_conclusion = self._get_judgment_conclusion(dp)

        # 获取漏洞标题
        vuln_title = self._get_vuln_title(dp)

        # 提取调用链经过的 session 列表
        session_chain = self._extract_session_chain(events, event_idx, dp)

        # LLM 不可用时降级为规则判定
        if not self._llm_available():
            return self._run_l1_l7_degraded(access, events, dp, baseline_vuln_info,
                                             access_id, event_idx, source_system,
                                             l0_origin, reasoning_context,
                                             query_content, returned_content,
                                             reasoning_ref, judgment_conclusion,
                                             vuln_title, session_chain)

        # ── 文本压缩：当总文本量可能超出上下文窗口时，逐字段 LLM 压缩 ──
        reasoning_context, query_content, returned_content, reasoning_ref = \
            self._compress_if_needed(
                reasoning_context, query_content, returned_content, reasoning_ref,
                dp.evaluation_id, cancel_cb)

        # 构建统一 LLM 调用
        baseline_source = baseline_vuln_info.get("source")
        if baseline_source is None:
            baseline_source_str = "（基线无结构化 source 信息，请从描述中推断）"
        else:
            baseline_source_str = str(baseline_source)

        user_content = (
            f"漏洞标题: {vuln_title}\n\n"
            f"推理上下文（知识访问前）:\n{reasoning_context}\n\n"
            f"查询内容:\n{query_content}\n\n"
            f"返回内容:\n{returned_content}\n\n"
            f"推理引用（知识访问后）:\n{reasoning_ref}\n\n"
            f"判定结论: {judgment_conclusion}\n\n"
            f"基线漏洞信息:\n"
            f"  漏洞标题: {baseline_vuln_info.get('vuln_title', '')}\n"
            f"  Source: {baseline_source_str}\n"
            f"  Sink: {baseline_vuln_info.get('sink', '')}\n"
            f"  文件: {baseline_vuln_info.get('file', '')}\n"
            f"  描述: {baseline_vuln_info.get('description', '')}\n\n"
            f"调用链经过的 session:\n{session_chain}\n\n"
            f"请对这次知识访问执行 L1-L7 全部判定。"
        )

        messages = [
            {"role": "system", "content": _PROMPT_UNIFIED_SYSTEM},
            {"role": "user", "content": user_content},
        ]

        try:
            result = self._call_llm_json(messages, cancel_cb=cancel_cb,
                                         reasoning_effort="low")
        except Exception as e:
            log("LIFECYCLE",
                f"L1-L7 LLM failed, falling back to rule: {str(e)[:200]}",
                eval_id=dp.evaluation_id)
            return self._run_l1_l7_degraded(access, events, dp, baseline_vuln_info,
                                             access_id, event_idx, source_system,
                                             l0_origin, reasoning_context,
                                             query_content, returned_content,
                                             reasoning_ref, judgment_conclusion,
                                             vuln_title, session_chain)

        # 从 LLM 结果构建 record
        l1 = result.get("l1_need_knowledge")
        l2 = result.get("l2_initiated")
        l3 = result.get("l3_query_accurate")
        l4 = result.get("l4_knowledge_exists")
        l5 = result.get("l5_retrieved")
        l6 = result.get("l6_used")
        l7_correct = result.get("l7_knowledge_correct")
        l7_consistent = result.get("l7_direction_consistent")
        l7_conf = result.get("l7_confidence")
        effect_label = result.get("effect_label")
        cause_code = result.get("cause_code")
        reason = result.get("reason", "")

        # 推断 l7_influenced
        l7_influenced = None
        if l7_conf is not None and l7_conf >= L7_CONFIDENCE_THRESHOLD:
            l7_influenced = l7_consistent

        evidence = {
            "l1_reason": reason,
            "l7_knowledge_correct": l7_correct,
            "l7_direction_consistent": l7_consistent,
            "l7_confidence": l7_conf,
            "session_chain": session_chain,
        }

        return self._make_record(
            access_id, dp, event_idx, source_system, l0_origin,
            l1_need_knowledge=l1, l2_initiated=l2, l3_query_accurate=l3,
            l4_knowledge_exists=l4, l5_retrieved=l5, l6_used=l6,
            l7_influenced=l7_influenced, l7_method="UNIFIED_LLM",
            effect_label=effect_label, cause_code=cause_code,
            query_content=query_content, returned_content=returned_content,
            reasoning_ref=reasoning_ref,
            judgment_conclusion=judgment_conclusion,
            evidence_json=evidence,
        )

    def _compress_if_needed(self, reasoning_context: str, query_content: str,
                            returned_content: str, reasoning_ref: str,
                            evaluation_id: str, cancel_cb=None
                            ) -> tuple[str, str, str, str]:
        """当文本总量可能超出上下文窗口时，用采样缩减文本量。

        策略（不截断）：
        1. 估算总 token 数（chars / chars_per_token）
        2. 如超过安全阈值，对超长字段用采样（取首/尾/中间完整句子）缩减
        3. 短字段不处理

        注意：不使用 LLM 压缩——LLM 压缩在 access 线程内同步调用会绕过 gate
        并发控制，导致实际 LLM 并发远超 gate 上限。
        """
        max_tokens = llm_mod.get_max_context_tokens() or _DEFAULT_MAX_CONTEXT_TOKENS
        chars_per_token = llm_mod.get_chars_per_token()
        safe_limit_chars = int(max_tokens * _CONTEXT_SAFETY_RATIO * chars_per_token)

        fields = [
            ("推理上下文", reasoning_context),
            ("查询内容", query_content),
            ("返回内容", returned_content),
            ("推理引用", reasoning_ref),
        ]

        total_chars = sum(len(v) for _, v in fields)
        if total_chars <= safe_limit_chars:
            # 总量在安全范围内，无需处理
            return reasoning_context, query_content, returned_content, reasoning_ref

        log("LIFECYCLE",
            f"文本总量 {total_chars} chars 超过安全阈值 {safe_limit_chars} chars "
            f"(max_tokens={max_tokens}, c/t={chars_per_token:.2f})，开始采样",
            eval_id=evaluation_id)

        sampled: list[str] = []
        for label, text in fields:
            if len(text) <= _COMPRESS_THRESHOLD_CHARS:
                sampled.append(text)
            else:
                result = self._sample_text(text)
                log("LIFECYCLE",
                    f"采样 {label}: {len(text)} → {len(result)} chars",
                    eval_id=evaluation_id)
                sampled.append(result)

        return sampled[0], sampled[1], sampled[2], sampled[3]

    def _sample_text(self, text: str) -> str:
        """LLM 压缩失败时的采样降级：取首/中/尾段，保留完整句子。

        不截断——用省略号标记采样边界，保留每段完整语义。
        """
        if len(text) <= 4000:
            return text
        third = len(text) // 3
        # 找到最近的句子边界
        def _find_sentence_boundary(s: str, start: int, direction: int = 1) -> int:
            for i in range(start, min(start + 200, len(s)), direction):
                if s[i] in '.。\n！!？?；;':
                    return i + 1
            return start

        part1_end = _find_sentence_boundary(text, third)
        part2_start = _find_sentence_boundary(text, third * 2)
        part2_end = _find_sentence_boundary(text, third * 2 + 1500)

        parts = [
            text[:part1_end],
            f"\n[...省略中间部分...]\n",
            text[part2_start:part2_end],
            f"\n[...省略后续部分...]\n",
            text[-1500:],
        ]
        return "".join(parts)

    def _extract_session_chain(self, events: list, event_idx: int,
                               dp: DataPack) -> str:
        """提取调用链经过的 session 列表。

        从 session_graph 的 parent_map 构建 task/session 调用链，
        格式化为 "session_id (agent_name) → session_id (agent_name) → ..." 字符串。

        session_graph 结构: {sessions: {sid: {...}}, edges: {sid: set()},
                              parent_map: {sid: parent_sid}}
        parent_map 同时包含 task_id 维度和 session_id 维度的父子关系。
        """
        session_graph = dp.session_graph or {}
        sessions = session_graph.get("sessions", {}) if isinstance(session_graph, dict) else {}
        parent_map = session_graph.get("parent_map", {}) if isinstance(session_graph, dict) else {}
        session_meta = dp.session_meta or {}

        # 收集所有涉及的 session
        session_ids = set()
        for e in events:
            if e.session_id:
                session_ids.add(e.session_id)

        if not session_ids:
            return "（无 session 信息）"

        # 构建 session 链（按 parent_map 关系排序）
        chain = []
        visited = set()
        # 找根 session（没有 parent 或 parent 不在涉及的 session 中）
        roots = []
        for sid in session_ids:
            parent = parent_map.get(sid)
            if not parent or parent not in session_ids:
                roots.append(sid)

        # BFS 从根开始构建链
        from collections import deque
        queue = deque(roots)
        while queue:
            sid = queue.popleft()
            if sid in visited:
                continue
            visited.add(sid)
            # 优先从 sessions dict 取 agent_name，其次从 session_meta
            sess_info = sessions.get(sid, {})
            agent_name = ""
            if isinstance(sess_info, dict):
                agent_name = sess_info.get("agent", "") or sess_info.get("task_type", "")
            if not agent_name:
                meta = session_meta.get(sid, {}) if isinstance(session_meta, dict) else {}
                if isinstance(meta, dict):
                    agent_name = meta.get("agent_name", "") or meta.get("task_type", "")
            chain.append(f"{sid} ({agent_name})" if agent_name else sid)

            # 找子 session（parent_map 中 parent == 当前 sid 的）
            for other_sid in session_ids:
                if other_sid in visited:
                    continue
                if parent_map.get(other_sid) == sid:
                    queue.append(other_sid)

        return " → ".join(chain) if chain else "（无法构建调用链）"

    def _run_l1_l7_degraded(self, access, events, dp, baseline_vuln_info,
                            access_id, event_idx, source_system,
                            l0_origin, reasoning_context,
                            query_content, returned_content,
                            reasoning_ref, judgment_conclusion,
                            vuln_title, session_chain) -> dict:
        """LLM 不可用时的降级规则判定。"""
        # L1: 默认需要知识
        l1 = True
        # L2: 程序判定
        l2 = access.get("is_kg", False) or access.get("is_mem", False)
        if not l2:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin,
                l1_need_knowledge=True, l2_initiated=False,
                l3_query_accurate=None, l4_knowledge_exists=None,
                l5_retrieved=None, l6_used=None,
                l7_influenced=None, l7_method="RULE",
                effect_label=None, cause_code="A",
                query_content=query_content, returned_content=returned_content,
                reasoning_ref=reasoning_ref,
                judgment_conclusion=judgment_conclusion,
                evidence_json={"degraded": True, "session_chain": session_chain},
            )
        # L3: 查询非空即准确
        l3 = bool(query_content and query_content.strip())
        # L4: 返回非空
        l4 = bool(returned_content and returned_content.strip()
                  and returned_content.strip() not in ("", "[]", "{}", "null"))
        # L5: 无 error
        l5 = not self._has_error(returned_content) if l4 else False
        # L6: 推理引用非空
        l6 = bool(reasoning_ref and reasoning_ref.strip()) if l5 else False

        cause = None
        if not l3: cause = "B"
        elif not l4: cause = "C"
        elif not l5: cause = "D"
        elif not l6: cause = "E"

        return self._make_record(
            access_id, dp, event_idx, source_system, l0_origin,
            l1_need_knowledge=l1, l2_initiated=l2, l3_query_accurate=l3,
            l4_knowledge_exists=l4, l5_retrieved=l5, l6_used=l6,
            l7_influenced=None, l7_method="RULE",
            effect_label=None, cause_code=cause,
            query_content=query_content, returned_content=returned_content,
            reasoning_ref=reasoning_ref,
            judgment_conclusion=judgment_conclusion,
            evidence_json={"degraded": True, "session_chain": session_chain},
        )

    def _determine_l0_origin(self, access: dict, interaction: dict,
                             dp: DataPack) -> str:
        """L0: 标记知识的原始来源。

        从以下途径获取：
        - 知识库返回内容的 frontmatter 中 source 字段
        - 记忆 init.json 的 source 字段
        - 默认值：知识库→"已有知识升华"，记忆→"历史漏洞经验"
        """
        if access.get("is_mem"):
            # 记忆来源
            output = interaction.get("output", "") or ""
            # 尝试从返回内容中提取 init.json 的 source 字段
            source = self._extract_source_from_output(output)
            if source:
                return source
            return "历史漏洞经验"
        else:
            # 知识库来源
            output = interaction.get("output", "") or ""
            source = self._extract_source_from_output(output)
            if source:
                return source
            return "已有知识升华"

    def _extract_source_from_output(self, output: str) -> str | None:
        """从知识返回内容中提取 source 字段（frontmatter 或 init.json）。"""
        if not output:
            return None
        # 尝试 frontmatter 中的 source 字段
        # 格式: source: xxx 或 "source": "xxx"
        patterns = [
            r'^source:\s*(.+)$',
            r'"source"\s*:\s*"([^"]+)"',
            r"'source'\s*:\s*'([^']+)'",
        ]
        for pattern in patterns:
            m = re.search(pattern, output, re.MULTILINE)
            if m:
                return m.group(1).strip()
        return None

    def _has_error(self, content: str) -> bool:
        """L5: 检查返回内容是否含 error/timeout 标记。"""
        if not content:
            return True
        content_lower = content.strip().lower()
        if content_lower in ("", "[]", "{}", "null"):
            return True
        # 检查是否以 error 开头
        if content_lower.startswith(_ERROR_MARKERS):
            return True
        # 检查是否包含 timeout
        if "timeout" in content_lower or "timed out" in content_lower:
            return True
        return False

    def _extract_reasoning_context(self, events: list,
                                   event_idx: int,
                                   window: int = 10) -> str:
        """提取知识访问前 window 条 REASONING/MESSAGE 事件文本。"""
        if event_idx < 0 or event_idx >= len(events):
            return ""
        start = max(0, event_idx - window)
        texts: list[str] = []
        for idx in range(start, event_idx + 1):
            e = events[idx]
            if e.event_type in ("REASONING", "MESSAGE", "TEXT"):
                text = self._extract_event_text(e)
                if text:
                    texts.append(text)
        return "\n".join(texts)

    def _extract_reasoning_ref(self, events: list,
                              event_idx: int,
                              window: int = 15) -> str:
        """提取知识访问后 window 条 REASONING/MESSAGE 事件文本（推理引用）。"""
        if event_idx < 0 or event_idx >= len(events):
            return ""
        end = min(len(events), event_idx + window + 1)
        texts: list[str] = []
        for idx in range(event_idx + 1, end):
            e = events[idx]
            if e.event_type in ("REASONING", "MESSAGE", "TEXT"):
                text = self._extract_event_text(e)
                if text:
                    texts.append(text)
        return "\n".join(texts)

    def _get_output_preview(self, access: dict, interaction: dict) -> str:
        """获取知识返回内容摘要。

        interaction dict 中 RESULT 事件的 output 字段。
        CALL 事件没有 output，需要从配对的 RESULT 获取。
        """
        # 如果 interaction 本身含 output
        output = interaction.get("output", "")
        if output:
            return str(output)
        # interaction 是 CALL，output 在 follow_up 或后续 RESULT 中
        follow_up = interaction.get("follow_up", "")
        if follow_up:
            return str(follow_up)
        return ""

    def _get_judgment_conclusion(self, dp: DataPack) -> str:
        """获取判定结论。"""
        if dp.outcome_fact is None:
            return ""
        of = dp.outcome_fact
        validation = getattr(of, "validation_result", None) or ""
        outcome = getattr(of, "outcome", None)
        outcome_str = str(outcome.value) if outcome else ""
        parts = [p for p in (validation, outcome_str) if p]
        return " / ".join(parts) if parts else ""

    def _get_vuln_title(self, dp: DataPack) -> str:
        """从 benchmark_item 获取漏洞标题。"""
        if dp.benchmark_item is None:
            return ""
        meta = getattr(dp.benchmark_item, "metadata", None) or {}
        return str(meta.get("vuln_title", "")
                  or meta.get("vulnerability_type", "")
                  or meta.get("type", ""))

    def _get_baseline_vuln_info(self, dp: DataPack) -> dict:
        """从 DataPack.benchmark_item 提取基线漏洞信息。

        参考 docs/l7-baseline-data-source.md：
        - vuln_title: metadata["vuln_title"]
        - description: metadata["description"]
        - file: metadata.get("source_file")  # 实际存的是 sink 点文件
        - sink: metadata.get("source_function") or metadata.get("locator")
        - source: None（缺失，标注为"不可用"）
        """
        if dp.benchmark_item is None:
            return {
                "vuln_title": "",
                "description": "",
                "file": "",
                "sink": "",
                "source": None,
            }

        meta = getattr(dp.benchmark_item, "metadata", None) or {}

        vuln_title = str(meta.get("vuln_title", "")
                        or meta.get("vulnerability_type", "")
                        or meta.get("type", ""))

        description = str(meta.get("description", "") or "")

        file = str(meta.get("source_file", "") or "")

        sink = str(meta.get("source_function", "")
                   or meta.get("locator", "")
                   or "")

        source = meta.get("source_entry") or meta.get("source")
        if not source:
            source = None

        return {
            "vuln_title": vuln_title,
            "description": description,
            "file": file,
            "sink": sink,
            "source": source,
        }

    def _llm_available(self) -> bool:
        """检查 LLM 是否可用。"""
        if self.llm is not None:
            # 注入的 mock 或自定义客户端
            if hasattr(self.llm, "is_enabled"):
                try:
                    return self.llm.is_enabled()
                except Exception:
                    return True
            return True
        try:
            return llm_mod.is_enabled()
        except Exception:
            return False

    def _call_llm_json(self, messages: list, **kwargs) -> dict:
        """调用 LLM chat_json，支持注入的客户端和模块级函数。"""
        cancel_cb = kwargs.pop("cancel_cb", None)
        reasoning_effort = kwargs.pop("reasoning_effort", "none")
        max_tokens = kwargs.pop("max_tokens", None)

        if self.llm is not None:
            # 注入的客户端
            if hasattr(self.llm, "chat_json"):
                return self.llm.chat_json(messages, temperature=0,
                                          reasoning_effort=reasoning_effort,
                                          max_tokens=max_tokens,
                                          cancel_cb=cancel_cb)
        # 使用模块级函数
        return llm_mod.chat_json(messages, temperature=0,
                                reasoning_effort=reasoning_effort,
                                max_tokens=max_tokens,
                                cancel_cb=cancel_cb)

    def _make_record(self, access_id: str, dp: DataPack, event_idx: int,
                     source_system: str, l0_origin: str,
                     l1_need_knowledge: bool | None,
                     l2_initiated: bool | None,
                     l3_query_accurate: bool | None,
                     l4_knowledge_exists: bool | None,
                     l5_retrieved: bool | None,
                     l6_used: bool | None,
                     l7_influenced: bool | None,
                     l7_method: str | None,
                     effect_label: str | None,
                     cause_code: str | None,
                     query_content: str = "",
                     returned_content: str = "",
                     reasoning_ref: str = "",
                     judgment_conclusion: str = "",
                     evidence_json: dict | None = None) -> dict:
        """构建 knowledge_access_detail 记录 dict。"""
        return {
            "access_id": access_id,
            "evaluation_id": dp.evaluation_id,
            "task_run_id": dp.task_run_id,
            "task_id": dp.task_id,
            "event_idx": event_idx,
            "source_system": source_system,
            "l0_origin": l0_origin,
            "business_phase": "UNKNOWN",
            "l1_need_knowledge": l1_need_knowledge,
            "l2_initiated": l2_initiated,
            "l3_query_accurate": l3_query_accurate,
            "l4_knowledge_exists": l4_knowledge_exists,
            "l5_retrieved": l5_retrieved,
            "l6_used": l6_used,
            "l7_influenced": l7_influenced,
            "l7_method": l7_method,
            "effect_label": effect_label,
            "cause_code": cause_code,
            "query_content": query_content or None,
            "returned_content": returned_content or None,
            "reasoning_ref": reasoning_ref or None,
            "judgment_conclusion": judgment_conclusion or None,
            "evidence_json": evidence_json,
        }
