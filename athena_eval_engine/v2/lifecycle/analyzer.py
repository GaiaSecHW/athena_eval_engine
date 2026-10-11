"""L0-L7 误报根因全链路分析器（§4.1）。

对每次知识访问，先标注其所属业务阶段，再在该阶段内逐级判定 L0-L7。
L0 标记知识的原始来源（provenance），不参与断链判定；
L1-L7 逐级判定断点，输出 cause_code（A-H）。

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
import threading
import time
from typing import Any

from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..infra import llm as llm_mod
from ..infra.parallel import iter_completed
from .case_filter import CaseFilter
from ..persistence.kad_repo import upsert_knowledge_access_details
from ...infrastructure.log_util import log, with_eval_ctx, get_eval_ctx

# ── Prompt 1-4 的 system prompt ──

_PROMPT1_SYSTEM = """你是漏洞挖掘过程分析员。判断每次知识访问发生在哪个业务阶段。

# 业务阶段定义

挖掘 Agent（agent_type=挖掘）的 5 个业务阶段：
1. 入口识别：确定攻击入口，识别用户可控的输入点（API 参数、请求体、URL 路径等）
2. 数据流追踪：从入口沿数据流追踪，分析数据如何在代码中传递和变换
3. 漏洞模式识别：判断数据流中是否存在已知的漏洞模式（如 SQL 注入、XSS、命令注入等）
4. Sink 点定位：定位漏洞最终触发位置（如数据库查询、命令执行、HTML 输出等）
5. 漏洞判定与上报：综合判断是否为漏洞，提交漏洞报告

验证 Agent（agent_type=验证）的 4 个业务阶段：
1. 漏洞理解：理解待验证漏洞的类型、入口和 sink 点信息
2. 代码定位：在目标代码中定位漏洞相关的代码位置
3. 验证执行：构造验证输入或分析代码路径，执行验证逻辑
4. 判定上报：综合验证结果，判定漏洞是否成立并上报

# 判断规则
- 仔细阅读每条知识访问对应的 REASONING/MESSAGE 事件文本，判断该时刻 Agent 正在执行哪个业务阶段
- 粗标注可能包含多个阶段，你需要将每次知识访问精确归入其中一个阶段
- 如果推理文本同时涉及多个阶段，选择最核心的那个阶段
- 如果推理文本内容太少无法判断，归入粗标注列表中的第一个阶段
- business_phase 必须是上述阶段名称之一，不能自创

只返回 JSON：
{
  "accesses": [
    {"event_idx": 数字, "business_phase": "阶段名称", "reason": "简要说明为什么归入该阶段"}
  ]
}
对每个知识访问的 event_idx 都返回判断结果。
"""

_PROMPT2_SYSTEM = """你是漏洞挖掘知识依赖分析员。判断某个业务阶段是否需要外部知识支撑才能完成。

# 知识的定义
知识包括：
- 漏洞模式知识：某类漏洞的特征、source/sink 模式、绕过手法
- 项目代码结构知识：组件依赖、模块关系、框架特性
- 历史挖掘经验：过往漏洞案例、常见误报模式

# 判断规则
- 如果该阶段的推理任务可以仅凭当前代码上下文完成（如直接读代码就能定位 sink 点），则不需要知识
- 如果该阶段的推理任务本质上需要了解某类漏洞的模式、项目的组件结构、或历史经验才能正确完成，则需要知识
- 挖掘 Agent 各阶段的典型知识需求：
  - 入口识别：需要了解项目框架的入口规范（如 SpringMVC 路由规则），通常需要知识
  - 数据流追踪：通常凭代码分析可完成，一般不需要知识
  - 漏洞模式识别：需要漏洞模式知识（如 SQL 注入的注入点特征），通常需要知识
  - Sink 点定位：需要了解漏洞类型对应的 sink 函数（如 executeQuery、Runtime.exec），通常需要知识
  - 漏洞判定与上报：需要确认漏洞模式和上报标准，有时需要知识
- 验证 Agent 各阶段的典型知识需求：
  - 漏洞理解：需要漏洞模式知识来理解待验证漏洞，通常需要知识
  - 代码定位：通常凭代码搜索可完成，一般不需要知识
  - 验证执行：需要漏洞验证方法知识（如构造 payload 的规则），通常需要知识
  - 判定上报：需要判定标准知识，有时需要知识
- 以上为典型情况，请结合实际推理上下文判断。如果推理文本显示 Agent 已经具备相关知识（如内联了模式描述），可能不需要外部知识

只返回 JSON：
{"need_knowledge": true/false, "reason": "简要说明该阶段是否需要知识支撑及原因"}
"""

_PROMPT3_SYSTEM = """你是知识查询质量评估员。判断 Agent 的知识查询内容是否聚焦于当前业务阶段的任务。

# 判断规则
- 查询内容应与当前业务阶段的任务直接相关
- 查询应包含足够的上下文信息（如漏洞类型、技术栈、具体代码位置等），而非泛泛的通用查询
- 查询准确（query_accurate=true）的条件：
  - 查询内容明确指向当前阶段需要解决的问题
  - 查询包含具体的技术上下文（如漏洞类型、框架名、函数名等）
  - 查询范围适中，不过宽也不过窄
- 查询不准确（query_accurate=false）的条件：
  - 查询内容与当前阶段任务无关或偏离主题
  - 查询过于宽泛（如只查 "SQL注入" 而无具体上下文）
  - 查询范围过宽，可能返回大量不相关结果
  - 查询内容存在明显错误或误导性描述

# 各阶段查询示例
- 漏洞模式识别阶段，准确查询："SQL注入 source sink 模式 Java SpringMVC"
- 漏洞模式识别阶段，不准确查询："所有漏洞类型"（过宽）
- Sink点定位阶段，准确查询："Java SQL注入 sink 函数 executeQuery prepareStatement"
- Sink点定位阶段，不准确查询："代码安全最佳实践"（偏离主题）

只返回 JSON：
{"query_accurate": true/false, "reason": "简要说明查询是否聚焦于当前阶段任务及原因"}
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

_MINING_AGENTS = {"turing", "argo", "secmate", "dataflow"}
_VERIFY_AGENTS = {"cvuln_verify", "webvuln_verify"}

_MINING_PHASES = {"入口识别", "数据流追踪", "漏洞模式识别", "Sink点定位", "漏洞判定与上报"}
_VERIFY_PHASES = {"漏洞理解", "代码定位", "验证执行", "判定上报"}

# 不产生知识访问的阶段标识符（跳过 L0-L7）
_SKIP_PHASE_IDENTIFIERS = {
    "reason", "preprocess", "explorer", "distiller", "noise-distiller", "report",
}

# L1 降级规则：不需要知识的阶段
_L1_RULE_NO_KNOWLEDGE_PHASES = {"数据流追踪", "代码定位"}

# L1 降级规则：需要知识的阶段
_L1_RULE_NEED_KNOWLEDGE_PHASES = {
    "入口识别", "漏洞模式识别", "Sink点定位", "漏洞判定与上报",
    "漏洞理解", "验证执行", "判定上报",
}

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
        2. 对每个有效 case，按 business_phase 分组知识访问
        3. 对跨阶段 session，用 LLM Prompt 1 细分到单一阶段
        4. 对每个阶段的知识访问，执行 L0-L6 漏斗判定
        5. L7 判定委托给 EvidenceChain（延迟 import）
        6. 写入 knowledge_access_detail 表

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

        for dp in valid_packs:
            if cancel_cb:
                cancel_cb()

            try:
                records = self._analyze_one_case(evaluation_id, dp, reports_dir, cancel_cb)
                all_records.extend(records)
            except Exception as e:
                log("LIFECYCLE",
                    f"analyze case {dp.task_run_id} failed: {str(e)[:300]}",
                    eval_id=evaluation_id)
                # 不跳过——向上抛出，遵循"禁止降级跳过"铁律
                raise

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

        # 标注业务阶段
        accesses = self._label_phases(evaluation_id, dp, accesses, events, cancel_cb)

        # 对每个访问执行 L0-L6
        records: list[dict] = []
        for acc in accesses:
            if cancel_cb:
                cancel_cb()

            # 跳过不产生知识访问的阶段
            phase = acc.get("business_phase")
            if phase is None:
                continue

            try:
                record = self._run_l0_l6(acc, phase, events, dp)
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

    def _label_phases(self, evaluation_id: str, dp: DataPack,
                      accesses: list[dict], events: list,
                      cancel_cb=None) -> list[dict]:
        """为每个知识访问标注业务阶段。

        策略：
        1. 用 _label_phase_for_access 获取每个访问的粗标注
        2. 如果是单一阶段，直接赋值
        3. 如果跨阶段（含 "+"），用 LLM Prompt 1 批量细分
        4. 不产生知识访问的标识符 → phase 设为 None（跳过）
        """
        phase_labels = dp.session_phase_labels or {}

        # 分离：需要 LLM 细分的 vs 直接赋值的
        need_llm: list[tuple[int, dict]] = []
        for i, acc in enumerate(accesses):
            phase = self._label_phase_for_access(acc, phase_labels)
            if phase is None:
                # 跳过（不产生知识访问 或 无标注）
                acc["business_phase"] = None
                continue

            if "+" in phase:
                # 跨阶段，需要 LLM 细分
                need_llm.append((i, acc))
            else:
                # 单一阶段
                acc["business_phase"] = phase.strip()

        # 批量 LLM 细分跨阶段的访问
        if need_llm:
            self._llm_label_phases(evaluation_id, dp, need_llm, events, cancel_cb)

        return accesses

    def _label_phase_for_access(self, access, session_phase_labels) -> str:
        """用 LLM Prompt 1 细分跨阶段 session 的知识访问到单一阶段。

        如果 session_phase_labels 已是单一阶段，直接返回。
        如果含 "+" 连接的跨阶段，返回含 "+" 的原始标注（由调用方批量 LLM 细分）。
        如果属于不产生知识访问的标识符，返回 None。

        实际的 LLM 细分在 _llm_label_phases 中批量执行。
        """
        session_id = access.get("session_id", "")
        coarse = session_phase_labels.get(session_id, "") if session_phase_labels else ""

        if not coarse:
            return None

        # 检查是否属于"不产生知识访问"的标识符
        if self._is_skip_phase(coarse):
            return None

        return coarse

    def _is_skip_phase(self, coarse_label: str) -> bool:
        """检查粗标注是否属于"不产生知识访问"的阶段。"""
        label = coarse_label.strip().lower()
        for skip in _SKIP_PHASE_IDENTIFIERS:
            if skip in label:
                return True
        return False

    def _llm_label_phases(self, evaluation_id: str, dp: DataPack,
                          need_llm: list[tuple[int, dict]],
                          events: list, cancel_cb=None):
        """用 LLM Prompt 1 批量细分跨阶段 session 的知识访问。

        将同一 case 的全部需 LLM 细分的访问一次性提交标注。
        """
        agent_type = dp.agent_type
        agent_category = "挖掘" if agent_type in _MINING_AGENTS else "验证"

        # 构建事件序列文本（取知识访问前后的 REASONING/MESSAGE 事件）
        access_indices = [acc.get("event_idx", -1) for _, acc in need_llm]
        event_sequence = self._build_event_sequence(events, access_indices)

        # 收集每个需 LLM 细分的访问的粗标注
        coarse_phases_set = set()
        for _, acc in need_llm:
            session_id = acc.get("session_id", "")
            coarse = (dp.session_phase_labels or {}).get(session_id, "")
            if coarse:
                coarse_phases_set.add(coarse)
        coarse_phases = " + ".join(sorted(coarse_phases_set))

        user_content = (
            f"Agent 类型: {agent_category}\n\n"
            f"第二层粗标注结果: {coarse_phases}\n\n"
            f"事件序列（按时间序）:\n{event_sequence}\n\n"
            f"知识访问的 event_idx 列表: {access_indices}\n\n"
            f"请对每个知识访问判断其所属业务阶段。"
        )

        messages = [
            {"role": "system", "content": _PROMPT1_SYSTEM},
            {"role": "user", "content": user_content},
        ]

        try:
            result = self._call_llm_json(messages, cancel_cb=cancel_cb,
                                         reasoning_effort="none")
        except Exception as e:
            log("LIFECYCLE",
                f"Prompt 1 LLM failed, falling back to first phase in coarse label: {str(e)[:200]}",
                eval_id=evaluation_id)
            # 降级：取粗标注的第一个阶段
            for _, acc in need_llm:
                session_id = acc.get("session_id", "")
                coarse = (dp.session_phase_labels or {}).get(session_id, "")
                first_phase = coarse.split("+")[0].strip() if coarse else None
                acc["business_phase"] = first_phase
            return

        # 将 LLM 结果回填到 accesses
        phase_map: dict[int, str] = {}
        for item in (result.get("accesses") or []):
            ev_idx = item.get("event_idx")
            if ev_idx is not None:
                phase_map[ev_idx] = item.get("business_phase")

        for _, acc in need_llm:
            ev_idx = acc.get("event_idx", -1)
            phase = phase_map.get(ev_idx)
            if phase is None and result.get("accesses"):
                # 顺序匹配降级
                phase_map_list = result.get("accesses") or []
                for item in phase_map_list:
                    if item.get("event_idx") == ev_idx:
                        phase = item.get("business_phase")
                        break
            acc["business_phase"] = phase

    def _build_event_sequence(self, events: list,
                             access_indices: list[int],
                             context_window: int = 5) -> str:
        """构建事件序列文本，供 LLM Prompt 1 使用。

        对每个知识访问，取其前后 context_window 条 REASONING/MESSAGE 事件。
        """
        lines: list[str] = []
        access_set = set(access_indices)

        # 收集所有需要的事件序号（知识访问 + 前后上下文）
        needed_indices = set()
        for idx in access_indices:
            if idx < 0 or idx >= len(events):
                continue
            # 前后各 context_window 条
            for offset in range(-context_window, context_window + 1):
                target = idx + offset
                if 0 <= target < len(events):
                    needed_indices.add(target)

        for idx in sorted(needed_indices):
            e = events[idx]
            if e.event_type not in ("REASONING", "MESSAGE", "TEXT"):
                continue
            text = self._extract_event_text(e)
            if text:
                marker = " <<<知识访问" if idx in access_set else ""
                text_preview = text[:300]
                lines.append(f"[{idx}] {e.event_type}: {text_preview}{marker}")

        return "\n".join(lines) if lines else "(无可用事件)"

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

    def _run_l0_l6(self, access: dict, business_phase: str,
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

        # 提取推理上下文（该阶段附近的 REASONING/MESSAGE 文本）
        reasoning_context = self._extract_reasoning_context(events, event_idx)

        # 提取查询内容
        query_content = str(interaction.get("command", "") or "")

        # 提取返回内容（从配对的 RESULT 事件获取）
        returned_content = self._get_output_preview(access, interaction)

        # 提取推理引用文本（后续 REASONING 事件）
        reasoning_ref = self._extract_reasoning_ref(events, event_idx)

        # 提取判定结论
        judgment_conclusion = self._get_judgment_conclusion(dp)

        # 获取漏洞类型（从 benchmark_item）
        vuln_type = self._get_vuln_type(dp)

        # ── L1: 需要知识？(LLM Prompt 2) ──
        l1_need = self._judge_l1(business_phase, vuln_type, reasoning_context,
                                 dp, cancel_cb=None)

        if not l1_need:
            # L1=False → 全链短路，无断点
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin, business_phase,
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
                access_id, dp, event_idx, source_system, l0_origin, business_phase,
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
        l3_accurate = self._judge_l3(business_phase, query_content,
                                     reasoning_context, dp, cancel_cb=None)

        if not l3_accurate:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin, business_phase,
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
                access_id, dp, event_idx, source_system, l0_origin, business_phase,
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
                access_id, dp, event_idx, source_system, l0_origin, business_phase,
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
        l6_used = self._judge_l6(business_phase, returned_content,
                                  reasoning_ref, dp, cancel_cb=None)

        if not l6_used:
            return self._make_record(
                access_id, dp, event_idx, source_system, l0_origin, business_phase,
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
            access_id, dp, event_idx, source_system, l0_origin, business_phase,
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

    def _judge_l1(self, business_phase: str, vuln_type: str,
                   reasoning_context: str, dp: DataPack,
                   cancel_cb=None) -> bool:
        """L1: 判断该业务阶段是否需要知识支撑。

        优先用 LLM Prompt 2 判定。LLM 不可用时降级为规则。
        """
        if not self._llm_available():
            return self._judge_l1_rule(business_phase)

        user_content = (
            f"业务阶段: {business_phase}\n\n"
            f"漏洞类型: {vuln_type}\n\n"
            f"该阶段的推理上下文:\n{reasoning_context[:2000]}\n\n"
            f"判断该阶段是否需要外部知识支撑。"
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
            return self._judge_l1_rule(business_phase)

    def _judge_l1_rule(self, business_phase: str) -> bool:
        """L1 降级规则：按阶段判定是否需要知识。

        入口识别/漏洞模式识别/Sink点定位/漏洞判定与上报 → 需要知识
        数据流追踪 → 不需要知识
        """
        if business_phase in _L1_RULE_NEED_KNOWLEDGE_PHASES:
            return True
        if business_phase in _L1_RULE_NO_KNOWLEDGE_PHASES:
            return False
        # 未知阶段，默认需要知识
        return True

    def _judge_l3(self, business_phase: str, query_content: str,
                  reasoning_context: str, dp: DataPack,
                  cancel_cb=None) -> bool:
        """L3: 判断查询是否聚焦于该阶段的任务。

        优先用 LLM Prompt 3。LLM 不可用时降级为查询非空即准确。
        """
        if not self._llm_available():
            return self._judge_l3_rule(query_content)

        user_content = (
            f"业务阶段: {business_phase}\n\n"
            f"查询内容: {query_content[:1000]}\n\n"
            f"该阶段的推理上下文:\n{reasoning_context[:2000]}\n\n"
            f"判断查询内容是否聚焦于当前阶段的任务。"
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

    def _judge_l6(self, business_phase: str, returned_content: str,
                  reasoning_ref: str, dp: DataPack,
                  cancel_cb=None) -> bool:
        """L6: 判断推理文本是否引用了知识返回内容。

        优先用 LLM Prompt 4。LLM 不可用时降级为推理文本含知识关键词即引用。
        """
        if not self._llm_available():
            return self._judge_l6_rule(returned_content, reasoning_ref)

        user_content = (
            f"业务阶段: {business_phase}\n\n"
            f"知识返回内容摘要:\n{returned_content[:2000]}\n\n"
            f"该阶段的推理文本:\n{reasoning_ref[:3000]}\n\n"
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

        if self.llm is not None:
            # 注入的客户端
            if hasattr(self.llm, "chat_json"):
                return self.llm.chat_json(messages, temperature=0,
                                          reasoning_effort=reasoning_effort,
                                          cancel_cb=cancel_cb)
        # 使用模块级函数
        return llm_mod.chat_json(messages, temperature=0,
                                reasoning_effort=reasoning_effort,
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
                     source_system: str, l0_origin: str, business_phase: str,
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
            "business_phase": business_phase,
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
