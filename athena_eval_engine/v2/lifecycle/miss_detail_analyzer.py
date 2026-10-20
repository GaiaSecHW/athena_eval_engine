"""漏报细分成因分析器 — 用 LLM 判定 sink_found_no_report 的具体漏报成因。

sink_found_no_report（sink 精确命中但未上报漏洞）只是第一层分类，
内部成因多样：调用链中断、知识误导、模型幻觉、验证遗漏等。
本模块把精确命中的 session 事件上下文交给 LLM，判定细分漏报成因。

细分漏报成因分类（miss_sub_category）：
- chain_break:     sink→source 调用链中断（只看到 sink 函数没追踪到入口/数据流不可达）
- params_uncontrollable: 参数可控性误判（认为用户输入不可达 sink）
- knowledge_mislead: 知识/记忆误导（知识内容错误、过时、不适用）
- hallucination:   模型幻觉（虚构不存在的防护措施/代码逻辑）
- logic_jump:      逻辑跳跃（看到局部代码就下结论）
- evidence_ignored: 忽略关键证据（sink 代码里有明显漏洞点但被忽略）
- verify_dimension_missing: 验证维度遗漏（没验证接口可达性/防护机制）
- verify_standard_too_strict: 判定标准过严（要求完整 POC 才上报）
- context_loss:    上下文压缩丢失（分析到关键点时上下文被压缩）
- vuln_confusion:  多漏洞混淆（报错对象或合并报告）
- other:           其他（自行总结）
"""
from __future__ import annotations

from ..infra import llm as llm_mod
from ..infra.token_counter import count_tokens
from ...infrastructure.log_util import log
from ..core.raw_event import RawEvent

# 细分漏报成因 → 描述
MISS_SUB_CATEGORIES = {
    "chain_break": "sink→source 调用链中断",
    "params_uncontrollable": "参数可控性误判",
    "knowledge_mislead": "知识/记忆误导",
    "hallucination": "模型幻觉",
    "logic_jump": "逻辑跳跃",
    "evidence_ignored": "忽略关键证据",
    "verify_dimension_missing": "验证维度遗漏",
    "verify_standard_too_strict": "判定标准过严",
    "context_loss": "上下文压缩丢失",
    "vuln_confusion": "多漏洞混淆",
    "other": "其他",
}

# 细分漏报成因的 LLM 输入 token 预算——
# 精确命中 session 事件可能巨大（110+ session），超 LLM 上下文（400K tokens）
# 用 count_tokens 预计算，动态适配 session 数量
_DETAIL_MAX_TOKENS = 60_000     # 给细分漏报成因的最大上下文（远小于 400K 主限制）
_DETAIL_RESERVE_TOKENS = 8_000  # 预留给 system prompt + 输出 + 格式

# 每个成因 → 责任方
MISS_SUB_RESPONSIBILITY = {
    "chain_break": "agent",
    "params_uncontrollable": "agent",
    "knowledge_mislead": "knowledge",
    "hallucination": "agent",
    "logic_jump": "agent",
    "evidence_ignored": "agent",
    "verify_dimension_missing": "agent",
    "verify_standard_too_strict": "agent",
    "context_loss": "agent",
    "vuln_confusion": "agent",
    "other": "agent",
}

_PROMPT_SYSTEM = """你是漏洞漏报成因分析专家。给你一条漏报漏洞（基线标注为真漏洞，但 agent 实际未上报）的上下文。

agent 在 trace 中**确实读到过 sink 点**（漏洞的最终触发位置——函数/行号级命中），但最终没有上报这个漏洞。请分析为什么。

你会收到：
- 漏洞标题：基线漏洞标题
- 漏洞描述：基线的漏洞描述（含 sink 点位置）
- sink 信息：LLM 从描述提取的 sink 文件、函数、行号
- 精确命中 session 的事件：agent 分析过程中读到 sink 点前后的事件序列
  （含推理文本、工具调用、工具返回、知识/记忆访问）

# 任务

分析 agent 为什么读到 sink 点却没上报漏洞，判定**最可能的细分漏报成因**。
注意：可能有多个因素，但请选**最主要的一个**作为主成因。

常见漏报成因（参考，不限于此）：
- chain_break: agent 只看到 sink 函数本身，没有向上追踪到 source 入口
  （HTTP 接口/参数），无法确认数据流可达 → 调用链中断
- params_uncontrollable: agent 误判用户输入不可达 sink（实际可控）
- knowledge_mislead: agent 访问了知识/记忆，但返回内容错误/过时/不适用，
  误导了判定（如误以为该框架默认过滤、该接口内网不可达）
- hallucination: agent 推理中虚构了代码中不存在的防护措施或逻辑
- logic_jump: agent 看到局部代码就下结论，没有完整分析数据流
- evidence_ignored: sink 代码里明显有注入/越权点但 agent 忽略或未识别
- verify_dimension_missing: agent 没验证接口可达性/防护机制/认证权限等维度
- verify_standard_too_strict: agent 要求完整 POC 或明确数据流证据才上报
- context_loss: 分析到 sink 关键点时上下文被压缩，后续推理丢失关键信息
- vuln_confusion: session 内分析多个漏洞，报错对象或报告归并错误
- other: 其他原因（自行总结）

# 事实依据要求

- evidence 必须引用 session 事件中的实际内容（推理文本、工具调用、知识返回），
  禁止推测
- 如果无法从事件中确认成因，miss_sub_category 填 "other"，reason 说明
  "无法从 session 中确认"

# 输出格式

只返回 JSON：
{
  "miss_sub_category": "chain_break|params_uncontrollable|knowledge_mislead|hallucination|logic_jump|evidence_ignored|verify_dimension_missing|verify_standard_too_strict|context_loss|vuln_confusion|other",
  "reason": "详细漏报原因分析，300字以内",
  "evidence": "session 事件中的具体事实依据",
  "confidence": 0.0-1.0,
  "key_events": ["关键事件1", "关键事件2"]  # 佐证成因的关键事件简述
}
"""


def _format_session_events(session_id: str, events: list[RawEvent]) -> str:
    """格式化 session 的事件为文本（复用 root_cause_analyzer 风格）。"""
    if not events:
        return f"（session {session_id} 无事件）"

    lines = []
    for ev in events:
        et = ev.event_type or "UNKNOWN"
        tool = ev.tool_name or ""
        if et == "REASONING":
            text = _extract_text(ev.output_json)
            if text:
                lines.append(f"[推理] {text}")
        elif et == "TEXT":
            text = _extract_text(ev.output_json)
            if text:
                lines.append(f"[文本] {text}")
        elif et == "TOOL_CALL":
            text = _extract_text(ev.input_json)
            kg_flag = ""
            if ev.is_kg_interaction:
                kg_flag = " [知识库访问]"
            elif ev.is_memory_interaction:
                kg_flag = " [记忆访问]"
            lines.append(f"[工具调用] {tool}{kg_flag}: {text}")
        elif et == "TOOL_RESULT":
            text = _extract_text(ev.output_json)
            kg_flag = ""
            if ev.is_kg_interaction:
                kg_flag = " [知识库返回]"
            elif ev.is_memory_interaction:
                kg_flag = " [记忆返回]"
            lines.append(f"[工具返回] {tool}{kg_flag}: {text}")
        elif et == "SESSION_START":
            lines.append(f"[会话开始] session={session_id}")

    return "\n".join(lines) if lines else f"（session {session_id} 无有效事件）"


def _extract_text(obj) -> str:
    """从 input_json/output_json 提取文本。"""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for key in ("content", "text", "message", "reasoning",
                     "command", "thinking", "description", "title",
                     "result", "output"):
            val = obj.get(key)
            if isinstance(val, str):
                return val
        # 兜底：递归找第一个字符串值
        for v in obj.values():
            if isinstance(v, str):
                return v
        try:
            import json
            return json.dumps(obj, ensure_ascii=False)
        except Exception:
            return str(obj)
    if isinstance(obj, list):
        try:
            import json
            return json.dumps(obj, ensure_ascii=False)
        except Exception:
            return str(obj)
    return str(obj)


class MissDetailAnalyzer:
    """漏报细分成因分析器 — 用 LLM 判定 sink_found_no_report 的具体成因。"""

    def analyze(
        self,
        evaluation_id: str,
        case: dict,
        session_events: dict[str, list[RawEvent]],
        cancel_cb=None,
    ) -> dict:
        """分析单个 sink_found_no_report case 的细分漏报成因。

        Args:
            evaluation_id: 评测 ID
            case: fn_miss 分析结果中的单个 case（sink_found_no_report），
                  含 case_id/vuln_title/sink_info/precise_sessions/hit_events
            session_events: {session_id: [RawEvent, ...]} 全部 session 事件索引
            cancel_cb: 取消回调

        Returns:
            {
                "miss_sub_category": str,
                "miss_sub_category_label": str,  # 中文描述
                "responsibility": str,           # agent/knowledge
                "reason": str,                   # 详细漏报原因
                "evidence": str,                 # 事实依据
                "confidence": float,
                "key_events": [str],
            }
        """
        cid = case.get("case_id", "")
        vuln_title = case.get("vuln_title", "")
        sink_info = case.get("sink_info", {}) or {}
        precise_sessions = case.get("precise_sessions", {}) or {}

        # 收集精确命中 session 的事件
        # 用 token 预计算动态适配体积：从 token 最少的 session 开始取，
        # 直到塞满上下文预算（避免超 LLM 上下文；也避免硬编码限制 session 数）
        session_texts: list[str] = []
        for at, sids in precise_sessions.items():
            for sid in sids:
                events = session_events.get(sid, [])
                text = _format_session_events(sid, events)
                if text and text not in session_texts:
                    session_texts.append(text)

        # 按 token 排序（小→大），从小的开始取，塞满预算
        session_texts.sort(key=lambda t: count_tokens(t))
        budget = _DETAIL_MAX_TOKENS - _DETAIL_RESERVE_TOKENS
        selected: list[str] = []
        used_tokens = 0
        for text in session_texts:
            t = count_tokens(text)
            if used_tokens + t > budget and selected:
                break
            selected.append(text)
            used_tokens += t
        session_texts = selected

        if not session_texts:
            log("MISS_DETAIL",
                f"case {cid}: 无精确命中 session 事件，跳过细分成因",
                eval_id=evaluation_id)
            return {
                "miss_sub_category": "other",
                "miss_sub_category_label": "其他",
                "responsibility": "agent",
                "reason": "无法从 session 中确认细分漏报成因（无事件上下文）",
                "evidence": "",
                "confidence": 0.0,
                "key_events": [],
            }

        user_content = (
            f"漏洞标题：{vuln_title}\n"
            f"漏洞描述：{case.get('description', '')}\n"
            f"sink 信息：{_sink_info_to_text(sink_info)}\n\n"
            f"精确命中 session 事件（agent 读到过 sink 点）：\n"
            f"{chr(10).join(session_texts)}"
        )

        messages = [
            {"role": "system", "content": _PROMPT_SYSTEM},
            {"role": "user", "content": user_content},
        ]

        try:
            kwargs = {"temperature": 0, "reasoning_effort": "none"}
            if cancel_cb:
                kwargs["cancel_cb"] = cancel_cb
            result = llm_mod.chat_json(messages, **kwargs)
        except Exception as e:
            log("MISS_DETAIL",
                f"case {cid} LLM 细分漏报成因失败: {e}",
                eval_id=evaluation_id)
            return {
                "miss_sub_category": "other",
                "miss_sub_category_label": "其他",
                "responsibility": "agent",
                "reason": f"LLM 分析失败: {str(e)[:100]}",
                "evidence": "",
                "confidence": 0.0,
                "key_events": [],
            }

        sub_category = result.get("miss_sub_category") or "other"
        if sub_category not in MISS_SUB_CATEGORIES:
            sub_category = "other"
        label = MISS_SUB_CATEGORIES.get(sub_category, sub_category)
        responsibility = MISS_SUB_RESPONSIBILITY.get(sub_category, "agent")
        reason = result.get("reason", "")
        evidence = result.get("evidence", "")
        confidence = float(result.get("confidence") or 0)
        key_events = result.get("key_events") or []

        log("MISS_DETAIL",
            f"case {cid}: sub_category={sub_category} ({label}), "
            f"conf={confidence:.2f}",
            eval_id=evaluation_id)

        return {
            "miss_sub_category": sub_category,
            "miss_sub_category_label": label,
            "responsibility": responsibility,
            "reason": reason,
            "evidence": evidence,
            "confidence": confidence,
            "key_events": key_events,
        }


def _sink_info_to_text(sink_info: dict) -> str:
    """将 sink_info 转为 LLM 可读文本。"""
    parts = []
    files = sink_info.get("sink_files") or []
    funcs = sink_info.get("sink_functions") or []
    lines = sink_info.get("sink_lines") or []
    desc = sink_info.get("sink_description") or ""
    if files:
        parts.append(f"文件: {', '.join(files)}")
    if funcs:
        parts.append(f"函数: {', '.join(funcs)}")
    if lines:
        parts.append(f"行号: {', '.join(lines)}")
    if desc:
        parts.append(f"描述: {desc}")
    return "; ".join(parts) if parts else "（无）"
