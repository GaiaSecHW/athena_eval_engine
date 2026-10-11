"""改进建议生成模块（§4.7 Prompt 6）。

L0-L7 分析完成后，每个误报 case 有一到多个断点。每个断点含
business_phase（业务阶段）、break_level（L2-L7）、cause_code（A-H）。
本模块从断点出发，结合漏洞类型、Agent 类型和断点证据，用 LLM Prompt 6
生成结构化改进建议——每条建议含责任方、具体改进动作、预期收益和优先级，
直接可派单到对应团队。

LLM 不可用时，用 RULE_TABLE 确定性生成降级建议。
"""
from __future__ import annotations

import json

from ..infra import llm as llm_mod
from ..infra.parallel import iter_completed
from ...infrastructure.log_util import log

# ── Prompt 6 System Prompt（完整复制自 docs/llm-prompts.md）──

_PROMPT6_SYSTEM = """你是知识接入效果测评的改进建议生成器。你的任务是根据误报 case 的断点分析结果，生成具体的、可派单的改进建议。

# 背景

误报根因全链路分析（L0-L7）完成后，每个误报 case 有一到多个断点。每个断点标注了：
- business_phase：断点所在的业务阶段（如"入口识别"、"漏洞判定与上报"）
- break_level：断点在哪一级（L2-L7）
- cause_code：成因代码（A-H），对应不同责任方和改进方向

# 断点→成因映射

| 断点级别 | 成因代码 | 含义 |
|---------|---------|------|
| L2 断 | A | 该查没查——需要知识但未发起访问，召回意识不足 |
| L3 断 | B | 查询太泛——查询内容过于宽泛，没有聚焦到当前 case 的具体漏洞类型和技术栈 |
| L4 断 | C | 查了没得——知识库/记忆进化里没有，覆盖度不足 |
| L5 断 | D | 链路问题——工具失败/超时/解析错误 |
| L6 断 | E | 查到没用——召回了但推理没引用，死知识 |
| L7 断（未影响结论） | F | 用了没推动——引用了知识但没改变结论，无效知识 |
| L7 推动但方向错 | G | 导致误判——知识推动了判定，但方向错了，负向知识 |
| G 的根因 | H | 内容有误——知识本身有问题（过时/不适用），是 G 的根因 |

G 和 H 不是并列关系，是因果关系：H（内容有误）是根因，G（导致误判）是 H 的结果。

# 改进建议表（责任方与改进方向的确定性映射）

| 成因 | 断点位置 | 责任方 | 改进动作方向 | 预期收益方向 |
|------|---------|--------|------------|------------|
| A | 某阶段 L2 断 | Agent | 在该阶段增加知识触发点 | 提高该阶段知识访问率 |
| B | 某阶段 L3 断 | Agent | 改进该阶段查询模板 | 提高该阶段查询准确率 |
| C | 某阶段 L4 断 | 知识方 | 补充该阶段所需知识 | 提高该阶段知识存在率 |
| D | 某阶段 L5 断 | Agent + 知识方 | 修复工具/超时 | 提高该阶段召回成功率 |
| E | 某阶段 L6 断 | Agent | 改进该阶段推理引用 | 提高该阶段使用率 |
| F | 某阶段 L7 断 | Agent / 知识方 | 优化该阶段知识内容 | 提高该阶段行为影响率 |
| G | 某阶段 L7 负向 | 知识方 | 修正该阶段引用的知识 | 降低负向知识率 |
| H | 某阶段 G 的根因 | 知识方 | 更新该阶段知识内容 | 消除该阶段的知识误导 |

# 你的任务

对输入的每个断点，生成一条改进建议。你需要：

1. **确定责任方**：严格按改进建议表映射，不自行变更责任方归属
2. **生成具体改进动作**：结合漏洞类型、业务阶段和断点证据，写出具体的、可执行的改进动作——不要泛泛而谈"改进查询"或"补充知识"，要指出在什么阶段、针对什么漏洞类型、做什么具体操作
3. **生成预期收益**：按改进建议表的方向，结合具体漏洞类型和业务阶段补充量化描述
4. **判定优先级**：
   - high：成因 G/H（负向知识导致误判），或同一成因在多个 case 反复出现
   - medium：成因 A/C/D/E/F（影响知识有效性但不直接导致误判）
   - low：成因 B（查询质量问题，影响效率但不直接影响判定）

# 改进动作写作要求

- 结合具体漏洞类型（如 SQL注入、XSS、反序列化等）和业务阶段（如入口识别、漏洞判定与上报等）
- 指出具体操作：在什么时机、什么条件下、做什么动作
- 对 Agent 责任方：指出应在哪个阶段的什么推理步骤增加知识触发点、改进查询模板或改进引用方式
- 对知识方责任方：指出应补充/修正哪个漏洞类型的哪部分知识（如 source/sink 描述、框架防御机制、校验逻辑等）
- 对 Agent + 知识方责任方：分别说明各自需做的事
- 改进动作限 100 字以内，必须包含可执行的具体操作

# 输出约束

- 每个断点生成一条建议，不合并、不拆分
- 一个 case 有多个断点时输出多条建议
- cause_code 为 G 时，如果证据中提到了知识内容的具体问题（如过时、不适用），在 action 中指出具体问题
- cause_code 为 H 时，action 应指向知识内容的具体修正方向
- 如果断点的 evidence 为空或过于模糊无法生成具体建议，action 写"待补充断点证据后生成具体改进动作"，priority 降为 low

只返回 JSON，不要输出其他内容。"""

# ── 规则降级表（LLM 不可用时确定性生成，复制自 docs/llm-prompts.md Prompt 6）──

RULE_TABLE = {
    "A": {"responsibility": "Agent",          "action_tpl": "在{phase}阶段增加知识触发点",         "impact_tpl": "提高{phase}阶段知识访问率",   "priority": "medium"},
    "B": {"responsibility": "Agent",          "action_tpl": "改进{phase}阶段查询模板",             "impact_tpl": "提高{phase}阶段查询准确率",   "priority": "low"},
    "C": {"responsibility": "知识方",          "action_tpl": "补充{phase}阶段所需知识",             "impact_tpl": "提高{phase}阶段知识存在率",   "priority": "medium"},
    "D": {"responsibility": "Agent + 知识方", "action_tpl": "修复{phase}阶段工具/超时问题",         "impact_tpl": "提高{phase}阶段召回成功率",   "priority": "medium"},
    "E": {"responsibility": "Agent",          "action_tpl": "改进{phase}阶段推理引用",             "impact_tpl": "提高{phase}阶段使用率",       "priority": "medium"},
    "F": {"responsibility": "Agent / 知识方", "action_tpl": "优化{phase}阶段知识内容",             "impact_tpl": "提高{phase}阶段行为影响率",   "priority": "medium"},
    "G": {"responsibility": "知识方",          "action_tpl": "修正{phase}阶段引用的知识",           "impact_tpl": "降低负向知识率",             "priority": "high"},
    "H": {"responsibility": "知识方",          "action_tpl": "更新{phase}阶段知识内容",             "impact_tpl": "消除{phase}阶段的知识误导",   "priority": "high"},
}


class SuggestionGenerator:
    """从断点生成结构化改进建议。

    输入：causal_chain_result（因果链分析结果，含 per_case_breakpoints）
    输出：改进建议列表，每条含 business_phase、cause_code、responsibility、
          action、expected_impact、priority。

    LLM 调用随 case 并行，受 llm.get_max_concurrency() 门控。
    LLM 不可用时用 RULE_TABLE 确定性生成降级建议。
    """

    def __init__(self, llm_client=None):
        """初始化建议生成器。

        Args:
            llm_client: 可选的 LLM 客户端（需有 chat_json 方法）。
                        为 None 时使用模块级 llm_mod.chat_json。
        """
        self.llm = llm_client

    def generate(self, evaluation_id: str, causal_chain_result: dict,
                 cancel_cb=None) -> list[dict]:
        """从断点生成结构化改进建议。

        遍历 causal_chain_result 中的 per_case_breakpoints，对每个 case 的
        断点列表调用 LLM Prompt 6 生成建议。LLM 不可用时降级为规则表生成。

        Args:
            evaluation_id: 评测 ID。
            causal_chain_result: 因果链分析结果，需含 per_case_breakpoints 列表。
                                 每个 case 结构：
                                 {"case_id": ..., "vuln_type": ...,
                                  "agent_type": ..., "breakpoints": [...]}
            cancel_cb: 取消检查回调，被取消时抛异常中止。

        Returns:
            改进建议列表，每条：
            {
                "business_phase": "...",
                "cause_code": "A"-"H",
                "responsibility": "Agent"|"知识方"|"Agent + 知识方"|"Agent / 知识方",
                "action": "具体改进动作（100字以内）",
                "expected_impact": "预期收益",
                "priority": "high"|"medium"|"low"
            }
        """
        per_case = causal_chain_result.get("per_case_breakpoints", [])
        if not per_case:
            log("SUGGESTION",
                f"no breakpoints in causal_chain_result for eval={evaluation_id}",
                eval_id=evaluation_id)
            return []

        log("SUGGESTION",
            f"generate: {len(per_case)} cases with breakpoints for eval={evaluation_id}",
            eval_id=evaluation_id)

        # LLM 不可用时全部走规则降级
        if not self._llm_available():
            log("SUGGESTION",
                f"LLM unavailable, all {len(per_case)} cases degraded to rule table",
                eval_id=evaluation_id)
            all_suggestions: list[dict] = []
            for case_data in per_case:
                if cancel_cb:
                    cancel_cb()
                case_id = case_data.get("case_id", "")
                vuln_type = case_data.get("vuln_type", "")
                agent_type = case_data.get("agent_type", "")
                breakpoints = case_data.get("breakpoints", [])
                for bp in breakpoints:
                    suggestion = self._rule_degradation(bp)
                    all_suggestions.append(suggestion)
            log("SUGGESTION",
                f"generate done (rule degradation): {len(all_suggestions)} suggestions",
                eval_id=evaluation_id)
            return all_suggestions

        # 构建全部 case 的 LLM 调用任务
        tasks = []
        for case_data in per_case:
            case_id = case_data.get("case_id", "")
            vuln_type = case_data.get("vuln_type", "")
            agent_type = case_data.get("agent_type", "")
            breakpoints = case_data.get("breakpoints", [])
            if not breakpoints:
                continue
            tasks.append({
                "case_id": case_id,
                "vuln_type": vuln_type,
                "agent_type": agent_type,
                "breakpoints": breakpoints,
            })

        if not tasks:
            log("SUGGESTION",
                f"no valid tasks (all cases have empty breakpoints) for eval={evaluation_id}",
                eval_id=evaluation_id)
            return []

        # 逐个提交 LLM 调用，受 llm_max_concurrency 全局门控
        # cancel_cb 穿透到 LLM 内循环
        futures = llm_mod.submit_llm_batch(
            self._call_llm_for_case,
            tasks,
            args_fn=lambda t: (t["case_id"], t["vuln_type"], t["agent_type"],
                               t["breakpoints"]),
            kwargs_fn=lambda t: {"cancel_cb": cancel_cb},
            cancel_cb=cancel_cb,
        )

        # 等待全部完成，按提交顺序对应
        results: list[list[dict] | None] = [None] * len(futures)
        for fut, _ in iter_completed(futures, cancel_cb=cancel_cb):
            # 找到对应的 index（submit_llm_batch 返回顺序与 tasks 对应）
            for i, f in enumerate(futures):
                if f is fut:
                    try:
                        results[i] = fut.result()
                    except Exception as e:
                        log("SUGGESTION",
                            f"LLM call failed for case {tasks[i].get('case_id', '')}: "
                            f"{str(e)[:200]}",
                            eval_id=evaluation_id)
                        results[i] = None  # 后续走降级
                    break

        # 将结果合并；LLM 失败的 case 走规则降级
        all_suggestions = []
        degraded_count = 0
        for i, result in enumerate(results):
            if result is None:
                # LLM 调用失败，降级
                task = tasks[i]
                for bp in task["breakpoints"]:
                    all_suggestions.append(self._rule_degradation(bp))
                    degraded_count += 1
                continue

            # 校验 LLM 返回的建议数与断点数一致
            suggestions = result if isinstance(result, list) else []
            all_suggestions.extend(suggestions)

        log("SUGGESTION",
            f"generate done: {len(all_suggestions)} suggestions "
            f"({degraded_count} degraded) for eval={evaluation_id}",
            eval_id=evaluation_id)

        return all_suggestions

    def _call_llm_for_case(self, case_id: str, vuln_type: str,
                           agent_type: str, breakpoints: list[dict],
                           cancel_cb=None) -> list[dict]:
        """对单个 case 的断点调用 LLM Prompt 6 生成建议。

        构建 user 输入（填入 case_id, vuln_type, agent_type, breakpoints），
        调用 chat_json 获取 LLM 生成的改进建议列表。

        Args:
            case_id: case 标识符。
            vuln_type: 漏洞类型（如 SQL注入、XSS）。
            agent_type: Agent 类型（如 turing, argo, secmate）。
            breakpoints: 断点列表，每个断点含 business_phase、break_level、
                         cause_code、evidence。
            cancel_cb: 取消回调，穿透到 LLM 内循环。

        Returns:
            改进建议列表（每条含 business_phase, cause_code, responsibility,
            action, expected_impact, priority）。
        """
        # 构建 user 输入 JSON
        input_data = {
            "case_id": case_id,
            "vuln_type": vuln_type,
            "agent_type": agent_type,
            "breakpoints": breakpoints,
        }
        input_json = json.dumps(input_data, ensure_ascii=False, indent=2)

        _JSON_TEMPLATE = (
            '{\n'
            '  "suggestions": [\n'
            '    {\n'
            '      "business_phase": "<断点所在的业务阶段，原样回填>",\n'
            '      "cause_code": "<成因代码 A-H，原样回填>",\n'
            '      "responsibility": "<责任方：Agent | 知识方 | Agent + 知识方 | Agent / 知识方>",\n'
            '      "action": "<100字以内具体改进动作>",\n'
            '      "expected_impact": "<预期收益，结合具体漏洞类型和业务阶段>",\n'
            '      "priority": "<high | medium | low>"\n'
            '    }\n'
            '  ]\n'
            '}'
        )
        user_content = (
            f"以下是误报 case 的断点分析结果，请为每个断点生成一条改进建议。\n\n"
            f"输入数据：\n{input_json}\n\n"
            f"对每个断点生成一条改进建议，返回 JSON：\n{_JSON_TEMPLATE}"
        )

        messages = [
            {"role": "system", "content": _PROMPT6_SYSTEM},
            {"role": "user", "content": user_content},
        ]

        try:
            if self.llm is not None and hasattr(self.llm, "chat_json"):
                result = self.llm.chat_json(
                    messages,
                    temperature=0,
                    reasoning_effort="none",
                    cancel_cb=cancel_cb,
                )
            else:
                result = llm_mod.chat_json(
                    messages,
                    temperature=0,
                    reasoning_effort="none",
                    cancel_cb=cancel_cb,
                )
        except Exception as e:
            log("SUGGESTION",
                f"_call_llm_for_case LLM failed for case={case_id}: {str(e)[:300]}")
            raise

        # chat_json 返回的是 parsed dict，结构为 {"suggestions": [...]}
        if isinstance(result, dict):
            suggestions = result.get("suggestions", [])
        elif isinstance(result, list):
            # 某些 LLM 可能直接返回列表
            suggestions = result
        else:
            log("SUGGESTION",
                f"unexpected LLM result type {type(result)} for case={case_id}")
            suggestions = []

        # 校验并规范化每条建议
        normalized: list[dict] = []
        for s in suggestions:
            if not isinstance(s, dict):
                continue
            cause_code = str(s.get("cause_code", "")).strip()
            # 校验 cause_code 在 A-H 范围内
            if cause_code not in RULE_TABLE:
                log("SUGGESTION",
                    f"invalid cause_code '{cause_code}' in suggestion for case={case_id}, "
                    f"skipping")
                continue
            normalized.append({
                "business_phase": str(s.get("business_phase", "")),
                "cause_code": cause_code,
                "responsibility": str(s.get("responsibility",
                                           RULE_TABLE[cause_code]["responsibility"])),
                "action": str(s.get("action", "")),
                "expected_impact": str(s.get("expected_impact", "")),
                "priority": str(s.get("priority",
                                       RULE_TABLE[cause_code]["priority"])),
            })

        # 如果 LLM 返回的建议数与断点数不匹配，对缺失的断点走降级
        if len(normalized) < len(breakpoints):
            covered_phases = {s["business_phase"] for s in normalized}
            for bp in breakpoints:
                phase = bp.get("business_phase", "")
                cause = bp.get("cause_code", "")
                # 粗略匹配：同 phase + 同 cause_code 的断点已有建议
                if (phase in covered_phases and
                        any(s["cause_code"] == cause for s in normalized
                            if s["business_phase"] == phase)):
                    continue
                normalized.append(self._rule_degradation(bp))
                log("SUGGESTION",
                    f"missing suggestion for bp phase={phase} cause={cause} "
                    f"in case={case_id}, degraded to rule table")

        return normalized

    def _rule_degradation(self, breakpoint: dict) -> dict:
        """LLM 不可用时用规则表确定性生成降级建议。

        规则降级表（从 docs/llm-prompts.md Prompt 6 复制）：
        - action 用模板填入 business_phase 名称
        - expected_impact 用方向性描述
        - 不含 LLM 生成的具体细节
        - 责任方和优先级严格按规则表

        Args:
            breakpoint: 断点 dict，需含 cause_code 和 business_phase。

        Returns:
            降级建议 dict。
        """
        cause_code = str(breakpoint.get("cause_code", "")).strip()
        phase = str(breakpoint.get("business_phase", "")).strip()

        # 未知 cause_code 时用安全默认值
        if cause_code not in RULE_TABLE:
            log("SUGGESTION",
                f"unknown cause_code '{cause_code}' in rule degradation, "
                f"using default")
            return {
                "business_phase": phase,
                "cause_code": cause_code,
                "responsibility": "Agent",
                "action": "待补充断点证据后生成具体改进动作",
                "expected_impact": "待确认",
                "priority": "low",
            }

        rule = RULE_TABLE[cause_code]
        action = rule["action_tpl"].format(phase=phase)
        expected_impact = rule["impact_tpl"].format(phase=phase)

        return {
            "business_phase": phase,
            "cause_code": cause_code,
            "responsibility": rule["responsibility"],
            "action": action,
            "expected_impact": expected_impact,
            "priority": rule["priority"],
        }

    # ── 工具方法 ──

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
