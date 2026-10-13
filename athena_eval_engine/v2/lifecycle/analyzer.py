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
from ..persistence.kad_repo import upsert_knowledge_access_details
from ...infrastructure.log_util import log, with_eval_ctx, get_eval_ctx

# ── Prompt 2-4 的 system prompt ──

_PROMPT2_SYSTEM = """你是漏洞挖掘知识依赖分析员。判断某个场景是否需要外部知识支撑才能完成。

# 知识的定义
知识包括：
- 漏洞模式知识：某类漏洞的特征、source/sink 模式、绕过手法
- 项目代码结构知识：组件依赖、模块关系、框架特性
- 历史挖掘经验：过往漏洞案例、常见误报模式

# 判断规则
- 如果该场景的推理任务可以仅凭当前代码上下文完成（如直接读代码就能定位 sink 点），则不需要知识
- 如果该场景的推理任务本质上需要了解某类漏洞的模式、项目的组件结构、或历史经验才能正确完成，则需要知识
- 以上为典型情况，请结合实际推理上下文判断。如果推理文本显示 Agent 已经具备相关知识（如内联了模式描述），可能不需要外部知识

只返回 JSON：
{"need_knowledge": true/false, "reason": "简要说明该场景是否需要知识支撑及原因"}
"""

_PROMPT3_SYSTEM = """你是知识查询质量评估员。判断 Agent 的知识查询内容是否聚焦于当前任务。

# 判断规则
- 查询内容应与当前任务直接相关
- 查询应包含足够的上下文信息（如漏洞类型、技术栈、具体代码位置等），而非泛泛的通用查询
- 查询准确（query_accurate=true）的条件：
  - 查询内容明确指向当前需要解决的问题
  - 查询包含具体的技术上下文（如漏洞类型、框架名、函数名等）
  - 查询范围适中，不过宽也不过窄
- 查询不准确（query_accurate=false）的条件：
  - 查询内容与当前任务无关或偏离主题
  - 查询过于宽泛（如只查 "SQL注入" 而无具体上下文）
  - 查询范围过宽，可能返回大量不相关结果
  - 查询内容存在明显错误或误导性描述

只返回 JSON：
{"query_accurate": true/false, "reason": "简要说明查询是否聚焦于当前任务及原因"}
"""

_PROMPT4_SYSTEM = """你是知识使用检测员。判断 Agent 的推理文本是否引用了知识返回的内容。

# 引用的识别规则
以下情况视为"使用了知识"（used=true）：
1. 直接引用：推理文本中出现了知识返回内容中的关键词、函数名、模式描述
2. 转述引用：推理文本用不同表述复述了知识返回的核心结论
3. 基于知识的推理：推理文本中的判断逻辑明显基于知识返回的信息（如知识返回了 sink 函数列表，推理中据此筛选了候选 sink）
4. 知识引导的决策：推理文本因知识返回内容改变了分析方向或决策

以下情况视为"未使用知识"（used=false）：
1. 推理文本完全没有提及知识返回的内容
2. 推理文本虽然提到了相关概念，但可以从当前代码上下文直接推导，与知识返回无关
3. 推理文本在知识查询前就已得出相同结论，知识返回未产生影响

# 判断方法
- 仔细比对 interaction.output_preview（知识返回内容摘要）与推理文本
- 在推理文本中搜索知识返回内容的关键信息点（函数名、模式名、具体描述等）
- 如果找到明确引用或基于知识的推理，判定为 used=true
- 如果推理文本与知识返回内容无明确关联，判定为 used=false

只返回 JSON：
{"used": true/false, "reason": "简要说明推理文本是否引用了知识返回内容，引用了哪些具体内容"}
"""

# ── 挖掘 vs 验证 Agent 类型 ──

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
                case_details: dict | None = None) -> list[dict]:
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

        Returns:
            list[dict]，每个 dict 是一条 knowledge_access_detail 记录
        """
        case_filter = CaseFilter()
        valid_packs = case_filter.filter_valid_cases(
            evaluation_id, data_packs, eval_mode=eval_mode,
            benchmark_source=benchmark_source,
            alert_center_data=alert_center_data,
            case_details=case_details,
        )

        all_records: list[dict] = []

        # 多 case 并行分析，受 llm_max_concurrency 全局门控
        max_workers = min(len(valid_packs), concurrency_mod.get("llm_max_concurrency"))
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
        """分析单个 case 的全部知识访问。"""
        events = dp.events or []
        kf = dp.knowledge_fact
        if kf is None:
            return []

        # 收集全部知识访问（KG + 记忆），每个访问含 event_idx 和原始 interaction
        accesses = self._collect_accesses(events, kf)
        if not accesses:
            return []

        # 对每个访问执行 L0-L6（access 级串行，case 级已并行）
        records: list[dict] = []
        for acc in accesses:
            if cancel_cb:
                cancel_cb()

            try:
                record = self._run_l0_l6(acc, events, dp)
                records.append(record)
            except Exception as e:
                log("LIFECYCLE",
                    f"L0-L6 failed for event_idx={acc.get('event_idx')}: {str(e)[:200]}",
                    eval_id=evaluation_id)
                raise

        # L7 判定委托给 EvidenceChain（延迟 import，#52 可能还在实现中）
        if records:
            try:
                from .evidence_chain import EvidenceChain
                ec = EvidenceChain(llm_client=self.llm)
                records = ec.judge_l7(evaluation_id, records, dp, reports_dir, cancel_cb)
            except ImportError:
                # evidence_chain.py 尚未实现，L7 留空
                log("LIFECYCLE",
                    "evidence_chain not yet implemented, L7 left as None",
                    eval_id=evaluation_id)
            except Exception as e:
                log("LIFECYCLE",
                    f"L7 judgment failed: {str(e)[:300]}",
                    eval_id=evaluation_id)
                raise

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

    def _find_event_idx(self, events: list, session_id: str,
                        timestamp: int | None, tool_name: str) -> int:
        """通过 session_id + timestamp + tool_name 在 events 中找到 event_idx。

        KnowledgeInteractionFact 的 interactions 不直接存 event_idx，
        需要通过 session_id 和 timestamp 回查原始事件序号。
        """
        if timestamp is not None:
            for idx, e in enumerate(events):
                if (e.session_id == session_id
                        and e.timestamp_ms == timestamp
                        and (e.tool_name or "") == (tool_name or "")):
                    return idx
        # 降级：session_id + tool_name + 最近的 TOOL_CALL
        for idx, e in enumerate(events):
            if (e.session_id == session_id
                    and (e.tool_name or "") == (tool_name or "")
                    and e.is_tool_call()):
                return idx
        return -1

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

    def _run_l0_l6(self, access: dict,
                   events: list, dp: DataPack) -> dict:
        """对单次知识访问执行 L0-L6 判定。

        返回 dict 含 l0_origin~l6_used + cause_code。
        """
        task_run_id = dp.task_run_id
        event_idx = access.get("event_idx", 0)
        access_id = f"{dp.evaluation_id}_{task_run_id}_{event_idx}"
        source_system = access.get("source_system", "知识库")
        interaction = access.get("interaction", {})

        # L0: 来源标记（程序判定）
        l0_origin = self._determine_l0_origin(access, interaction, dp)

        # 提取推理上下文：知识访问前 agent 的行为上下文
        # 优先从 events 列表取 REASONING/TEXT（agent 推理文本），
        # 取不到时用 interaction 自身的 command 作为上下文
        reasoning_context = self._extract_reasoning_context(events, event_idx)
        if not reasoning_context:
            reasoning_context = str(interaction.get("command", "") or "")[:2000]

        # 提取查询内容
        query_content = str(interaction.get("command", "") or "")

        # 提取返回内容（从配对的 RESULT 事件获取）
        returned_content = self._get_output_preview(access, interaction)

        # 提取推理引用文本：知识访问后 agent 的行为上下文
        # 优先从 events 列表取 REASONING/TEXT，
        # 取不到时用 interaction 的 follow_up（后续工具调用摘要）作为上下文
        reasoning_ref = self._extract_reasoning_ref(events, event_idx)
        if not reasoning_ref:
            follow_up = interaction.get("follow_up")
            if follow_up:
                import json as _json
                reasoning_ref = _json.dumps(follow_up, ensure_ascii=False)[:3000]
            else:
                reasoning_ref = str(interaction.get("output", "") or "")[:3000]

        # 提取判定结论
        judgment_conclusion = self._get_judgment_conclusion(dp)

        # 获取漏洞类型（从 benchmark_item）
        vuln_type = self._get_vuln_type(dp)

        # ── L1: 需要知识？(LLM Prompt 2) ──
        l1_need = self._judge_l1(vuln_type, reasoning_context,
                                 dp, cancel_cb=None)

        if not l1_need:
            # L1=False → 全链短路，无断点
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin,
                l1_need_knowledge=False, l2_initiated=None, l3_query_accurate=None,
                l4_knowledge_exists=None, l5_retrieved=None, l6_used=None,
                l7_influenced=None, l7_method=None,
                effect_label=None, cause_code=None,
                query_content=query_content, returned_content=returned_content,
                reasoning_ref=reasoning_ref,
                judgment_conclusion=judgment_conclusion,
                evidence_json={"l1_reason": l1_need},
            )

        # ── L2: 发起访问？(程序判定) ──
        l2_initiated = access.get("is_kg", False) or access.get("is_mem", False)

        if not l2_initiated:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin,
                l1_need_knowledge=True, l2_initiated=False,
                l3_query_accurate=None, l4_knowledge_exists=None,
                l5_retrieved=None, l6_used=None,
                l7_influenced=None, l7_method=None,
                effect_label=None, cause_code="A",
                query_content=query_content, returned_content=returned_content,
                reasoning_ref=reasoning_ref,
                judgment_conclusion=judgment_conclusion,
                evidence_json={"breakpoint": "L2", "cause": "该查没查"},
            )

        # ── L3: 查询准确？(LLM Prompt 3) ──
        l3_accurate = self._judge_l3(query_content,
                                     reasoning_context, dp, cancel_cb=None)

        if not l3_accurate:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin,
                l1_need_knowledge=True, l2_initiated=True,
                l3_query_accurate=False, l4_knowledge_exists=None,
                l5_retrieved=None, l6_used=None,
                l7_influenced=None, l7_method=None,
                effect_label=None, cause_code="B",
                query_content=query_content, returned_content=returned_content,
                reasoning_ref=reasoning_ref,
                judgment_conclusion=judgment_conclusion,
                evidence_json={"breakpoint": "L3", "cause": "查询太泛"},
            )

        # ── L4: 知识存在？(程序判定，output_preview 非空) ──
        l4_exists = bool(returned_content and returned_content.strip()
                         and returned_content.strip() not in ("", "[]", "{}", "null"))

        if not l4_exists:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin,
                l1_need_knowledge=True, l2_initiated=True,
                l3_query_accurate=True, l4_knowledge_exists=False,
                l5_retrieved=None, l6_used=None,
                l7_influenced=None, l7_method=None,
                effect_label=None, cause_code="C",
                query_content=query_content, returned_content=returned_content,
                reasoning_ref=reasoning_ref,
                judgment_conclusion=judgment_conclusion,
                evidence_json={"breakpoint": "L4", "cause": "查了没得"},
            )

        # ── L5: 成功取回？(程序判定，无 error/timeout) ──
        l5_retrieved = not self._has_error(returned_content)

        if not l5_retrieved:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin,
                l1_need_knowledge=True, l2_initiated=True,
                l3_query_accurate=True, l4_knowledge_exists=True,
                l5_retrieved=False, l6_used=None,
                l7_influenced=None, l7_method=None,
                effect_label=None, cause_code="D",
                query_content=query_content, returned_content=returned_content,
                reasoning_ref=reasoning_ref,
                judgment_conclusion=judgment_conclusion,
                evidence_json={"breakpoint": "L5", "cause": "链路问题"},
            )

        # ── L6: 推理引用？(LLM Prompt 4) ──
        l6_used = self._judge_l6(returned_content,
                                  reasoning_ref, dp, cancel_cb=None)

        if not l6_used:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin,
                l1_need_knowledge=True, l2_initiated=True,
                l3_query_accurate=True, l4_knowledge_exists=True,
                l5_retrieved=True, l6_used=False,
                l7_influenced=None, l7_method=None,
                effect_label=None, cause_code="E",
                query_content=query_content, returned_content=returned_content,
                reasoning_ref=reasoning_ref,
                judgment_conclusion=judgment_conclusion,
                evidence_json={"breakpoint": "L6", "cause": "查到没用"},
            )

        # L6=True → L7 在 evidence_chain.py 中判定
        # 此处先写入 L0-L6 结果，L7 字段留空
        return self._make_record(
            access_id, dp, event_idx, source_system, l0_origin,
            l1_need_knowledge=True, l2_initiated=True,
            l3_query_accurate=True, l4_knowledge_exists=True,
            l5_retrieved=True, l6_used=True,
            l7_influenced=None, l7_method=None,
            effect_label=None, cause_code=None,
            query_content=query_content, returned_content=returned_content,
            reasoning_ref=reasoning_ref,
            judgment_conclusion=judgment_conclusion,
            evidence_json={"status": "pending_l7"},
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

    def _judge_l1(self, vuln_type: str,
                   reasoning_context: str, dp: DataPack,
                   cancel_cb=None) -> bool:
        """L1: 判断该场景是否需要知识支撑。

        优先用 LLM Prompt 2 判定。LLM 不可用时降级为规则。
        """
        if not self._llm_available():
            return self._judge_l1_rule()

        user_content = (
            f"漏洞类型: {vuln_type}\n\n"
            f"推理上下文:\n{reasoning_context[:2000]}\n\n"
            f"判断该场景是否需要外部知识支撑。"
        )
        messages = [
            {"role": "system", "content": _PROMPT2_SYSTEM},
            {"role": "user", "content": user_content},
        ]
        try:
            result = self._call_llm_json(messages, cancel_cb=cancel_cb,
                                         reasoning_effort="none")
            return bool(result.get("need_knowledge", False))
        except Exception as e:
            log("LIFECYCLE",
                f"L1 LLM failed, falling back to rule: {str(e)[:200]}",
                eval_id=dp.evaluation_id)
            return self._judge_l1_rule()

    def _judge_l1_rule(self) -> bool:
        """L1 降级规则：默认需要知识。

        不再依赖业务阶段判定——Agent 级别判定即可。
        """
        return True

    def _judge_l3(self, query_content: str,
                  reasoning_context: str, dp: DataPack,
                  cancel_cb=None) -> bool:
        """L3: 判断查询是否聚焦于当前任务。

        优先用 LLM Prompt 3。LLM 不可用时降级为查询非空即准确。
        """
        if not self._llm_available():
            return self._judge_l3_rule(query_content)

        user_content = (
            f"查询内容: {query_content[:1000]}\n\n"
            f"推理上下文:\n{reasoning_context[:2000]}\n\n"
            f"判断查询内容是否聚焦于当前任务。"
        )
        messages = [
            {"role": "system", "content": _PROMPT3_SYSTEM},
            {"role": "user", "content": user_content},
        ]
        try:
            result = self._call_llm_json(messages, cancel_cb=cancel_cb,
                                         reasoning_effort="none")
            return bool(result.get("query_accurate", False))
        except Exception as e:
            log("LIFECYCLE",
                f"L3 LLM failed, falling back to rule: {str(e)[:200]}",
                eval_id=dp.evaluation_id)
            return self._judge_l3_rule(query_content)

    def _judge_l3_rule(self, query_content: str) -> bool:
        """L3 降级规则：查询非空即准确。"""
        return bool(query_content and query_content.strip())

    def _judge_l6(self, returned_content: str,
                  reasoning_ref: str, dp: DataPack,
                  cancel_cb=None) -> bool:
        """L6: 判断推理文本是否引用了知识返回内容。

        优先用 LLM Prompt 4。LLM 不可用时降级为推理文本含知识关键词即引用。
        """
        if not self._llm_available():
            return self._judge_l6_rule(returned_content, reasoning_ref)

        user_content = (
            f"知识返回内容摘要:\n{returned_content[:2000]}\n\n"
            f"推理文本:\n{reasoning_ref[:3000]}\n\n"
            f"判断推理文本是否引用了知识返回的内容。"
        )
        messages = [
            {"role": "system", "content": _PROMPT4_SYSTEM},
            {"role": "user", "content": user_content},
        ]
        try:
            result = self._call_llm_json(messages, cancel_cb=cancel_cb,
                                         reasoning_effort="none")
            return bool(result.get("used", False))
        except Exception as e:
            log("LIFECYCLE",
                f"L6 LLM failed, falling back to rule: {str(e)[:200]}",
                eval_id=dp.evaluation_id)
            return self._judge_l6_rule(returned_content, reasoning_ref)

    def _judge_l6_rule(self, returned_content: str, reasoning_ref: str) -> bool:
        """L6 降级规则：推理文本含知识关键词即引用。

        从知识返回内容中提取关键词（函数名、模式名等），
        检查推理文本中是否包含这些关键词。
        """
        if not returned_content or not reasoning_ref:
            return False
        # 提取知识返回内容中的词（长度>3 的连续字母/数字串）
        keywords = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{3,}', returned_content)
        # 去重，取前 20 个
        seen = set()
        unique_keywords = []
        for kw in keywords:
            kl = kw.lower()
            if kl not in seen:
                seen.add(kl)
                unique_keywords.append(kw)
            if len(unique_keywords) >= 20:
                break
        # 在推理文本中搜索关键词
        reasoning_lower = reasoning_ref.lower()
        for kw in unique_keywords:
            if kw.lower() in reasoning_lower:
                return True
        return False

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

    def _get_vuln_type(self, dp: DataPack) -> str:
        """从 benchmark_item 获取漏洞类型。"""
        if dp.benchmark_item is None:
            return ""
        meta = getattr(dp.benchmark_item, "metadata", None) or {}
        return str(meta.get("vulnerability_type", "")
                  or meta.get("vuln_type", "")
                  or meta.get("type", ""))

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

    def _determine_cause_code(self, l1, l2, l3, l4, l5, l6) -> str | None:
        """根据 L1-L6 判定结果确定 cause_code。

        漏斗逻辑：从 L1 逐级向下，第一个 False 即为断点。
        L1=False → 全链短路，无断点，返回 None
        L2=False → A（该查没查）
        L3=False → B（查询太泛）
        L4=False → C（查了没得）
        L5=False → D（链路问题）
        L6=False → E（查到没用）
        全 True → None（L7 在 evidence_chain 中判定）
        """
        if not l1:
            return None  # L1=False: 不需要知识，无断点
        if not l2:
            return "A"  # 该查没查
        if not l3:
            return "B"  # 查询太泛
        if not l4:
            return "C"  # 查了没得
        if not l5:
            return "D"  # 链路问题
        if not l6:
            return "E"  # 查到没用
        return None  # L6=True, L7 在 evidence_chain 中判定

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
