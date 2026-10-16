"""误报根因分析器 — 挖掘链 + 验证链各自独立压缩，最后合并输出。

对每个 FP case：
  1. 挖掘 agent session 链 → 每个 session 独立压缩 → 各自摘要 + L0-L7
  2. 验证 agent session 链 → 每个 session 独立压缩 → 各自摘要 + L0-L7
  3. 挖掘链所有 session 摘要合并 → LLM 合并压缩 → 最终根因 + 修复建议
  4. 验证链所有 session 摘要合并 → LLM 合并压缩 → 最终根因 + 修复建议

两步独立，各自有各自的 session 链、压缩过程、根因和修复建议。
session 链直接用 PARSING 阶段建好的 session_graph（parent_map），不重新构建。

独立压缩（不滚动）：
  session1 → LLM 压缩 → 摘要1 + L0-L7
  session2 → LLM 压缩 → 摘要2 + L0-L7
  ...
  sessionN → LLM 压缩 → 摘要N + L0-L7

合并压缩：
  摘要1 + 摘要2 + ... + 摘要N → LLM → 最终根因 + 修复建议 + L0-L7

不截断，不丢信息。压缩去掉冗余，保留逻辑链路。
"""
from __future__ import annotations

import json
from collections import defaultdict

from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..infra import llm as llm_mod
from ...infrastructure.log_util import log

# ── 挖掘 agent 类型（DataPack 级别）──
_MINING_AGENT_TYPES = {"turing", "argo", "secmate", "dataflow"}
# ── 验证 agent 类型（DataPack 级别）──
_VERIFY_AGENT_TYPES = {"cvuln_verify", "webvuln_verify"}
# ── Turing 平台：验证 session 的 agent 名（多版本命名）──
_TURING_VERIFY_AGENTS = {"vuln-hunt-validate", "web-validate"}

# ── 系统 prompt（固定）──

_SYSTEM_PROMPT = """你是漏洞误报根因分析专家。你将收到一条误报漏洞的某个 session（漏洞挖掘或验证过程中的一个环节），以及人工标注的误报原因。

# 任务

## 压缩模式
将收到的 session 内容压缩为结构化摘要，保留以下信息，丢弃冗余文本：
- 推理逻辑：agent 的分析思路、判断依据
- 工具调用：调了什么工具、参数是什么、返回了什么
- 知识访问：查了知识库什么内容、返回了什么、是否被引用
- 判定结论：agent 对漏洞的判定结果

**重点保留**：知识与记忆访问的总结与影响——agent 查了什么知识/记忆、返回了什么内容、这些内容是否影响了 agent 的推理和判定。

同时，对这个 session 里的每次知识访问，执行 L0-L7 逐级判定。

# 知识库与记忆访问的识别

session 文本中，评测引擎已在工具调用和工具返回的文本里标记了知识访问行为：
- `[知识库访问]`：agent 通过 athena_ask MCP 工具、bash athena CLI、或 vuln_hunt_submit_knowledge 访问知识库（Athena）
- `[知识库返回]`：知识库返回的内容
- `[记忆访问]`：agent 通过 mem.sh CLI 或 cat 读 wiki .md 文件访问记忆（Memory/Wiki）
- `[记忆返回]`：记忆返回的内容

这些标记是评测引擎预处理的结果，代表 agent 实际发生了知识/记忆访问行为。
没有标记的工具调用不是知识访问（如代码搜索、文件读写、shell 命令等）。

**知识库**：Athena 知识库，存储漏洞挖掘模式、误报判别方法等结构化知识，agent 通过 athena_ask 查询。
**记忆**：Wiki/记忆模块，存储经验总结、最佳实践等 .md 文件，agent 通过 mem.sh 或 cat 读取。

在 L0-L7 判定中：
- L0 来源：从标记判断是"知识库"还是"记忆"
- L2 发起访问：有 `[知识库访问]` 或 `[记忆访问]` 标记即为 true

# L0-L7 知识访问全链路判定规则

对 session 里的每次知识访问（带 `[知识库访问]`/`[记忆访问]` 标记的工具调用），逐级判定：

| 级别 | 追问 | 判定方法 | 断了是什么成因 | 责任方 |
|------|------|---------|---------------|--------|
| L0 | 知识来源？ | 从知识返回内容的来源标记判断 | —（不产生断链） | — |
| L1 | 需要知识？ | 推理任务是否需要外部知识支撑 | —（不产生断链） | — |
| L2 | 发起访问？ | agent 是否实际调用了知识库/记忆工具 | A 该查没查 | Agent |
| L3 | 查询准确？ | 查询内容是否聚焦当前任务（含具体漏洞类型/框架名/函数名等） | B 查询太泛/不聚焦 | Agent |
| L4 | 知识存在？ | 知识库是否有对应知识（返回内容非空且相关） | C 查了没得 | 知识方 |
| L5 | 成功取回？ | 返回内容是否有效（无 error/timeout/exception） | D 链路问题 | Agent + 知识方 |
| L6 | 被使用？ | agent 推理文本是否引用了知识返回内容 | E 查到没用 | Agent |
| L7 | 影响结论？ | 知识是否影响了判定结论 | F 用了没推动 / G 导致误判 | F: Agent/知识方, G: 知识方 |

判定规则：
- 逐级判定，不通过的级别即为断点，后续级别填 null
- L7 三种结果：positive（正确+一致=正向）、negative（错误+一致=负向，知识方向对但内容有误/过时）、null（不一致=中性，知识未影响结论）
- 如果 session 中没有知识访问行为，L1-L7 全部填 null，breakpoint=null，cause_code=null
- 如果 L1=false（不需要知识），后续级别全部 null，breakpoint=null，cause_code=null

# 输出格式

压缩模式返回 JSON：
{
  "summary": "结构化摘要，3000字以内。必须包含知识与记忆访问的总结与影响",
  "key_findings": ["关键发现1", "关键发现2"],
  "l0_l7": [
    {
      "l0_source": "来源标记（如无则空字符串）",
      "l1_need": true/false/null,
      "l2_initiated": true/false/null,
      "l3_accurate": true/false/null,
      "l4_exists": true/false/null,
      "l5_retrieved": true/false/null,
      "l6_used": true/false/null,
      "l7_influenced": "positive/negative/null",
      "breakpoint": "L2/L3/L4/L5/L6/L7/null",
      "cause_code": "A/B/C/D/E/F/G/null",
      "query_content": "查询内容摘要",
      "returned_content": "返回内容摘要"
    }
  ]
}

只返回 JSON，不要任何额外文字。"""


_MERGE_PROMPT = """你是漏洞误报根因分析专家。你将收到一条误报漏洞的多个 session 的独立压缩摘要，以及人工标注的误报原因。

# 任务

## 合并模式
将多个 session 的压缩摘要合并为最终结论。你需要：

1. 误报根因：为什么 agent 会误报这个漏洞？你已知人工标注的误报原因（在用户消息中给出），
   需要分析 agent 在 session 链中的哪个环节出了问题，导致没有发现人工标注的误报原因。
   从以下维度分析：
   - 知识访问问题：该查没查 / 查了但查询不准 / 知识错误 / 查到没用
   - 推理问题：逻辑跳跃 / 忽略关键证据 / 错误关联
   - 验证维度遗漏：agent 验证了哪些维度，遗漏了哪些维度（如接口实际网络可达性、
     防护机制实践有效性、部署环境约束等代码层面看不到的因素）
   - 验证逻辑不充分：验证条件错误 / 验证覆盖不足
2. 修复建议：针对根因，给出可执行的修复方案

# 输出格式

合并模式返回 JSON：
{
  "summary": "合并后的最终摘要，3000字以内",
  "root_cause": {
    "category": "knowledge_gap|query_inaccurate|knowledge_error|reasoning_flaw|verification_dimension_missing|verification_insufficient",
    "description": "根因描述，500字以内",
    "human_confirmation_reason": "人工标注的误报原因（从用户消息中提取）"
  },
  "fix_suggestion": "修复建议，300字以内",
  "l0_l7": [
    {
      "l0_source": "来源标记",
      "l1_need": true/false/null,
      "l2_initiated": true/false/null,
      "l3_accurate": true/false/null,
      "l4_exists": true/false/null,
      "l5_retrieved": true/false/null,
      "l6_used": true/false/null,
      "l7_influenced": "positive/negative/null",
      "breakpoint": "L2/L3/L4/L5/L6/L7/null",
      "cause_code": "A/B/C/D/E/F/G/null",
      "query_content": "查询内容摘要",
      "returned_content": "返回内容摘要"
    }
  ]
}

只返回 JSON，不要任何额外文字。"""


class RootCauseAnalyzer:
    """误报根因分析器 — 挖掘链 + 验证链各自独立压缩，最后合并输出。"""

    def analyze(
        self,
        evaluation_id: str,
        fp_cases: list[dict],
        data_packs: list[DataPack],
        cancel_cb=None,
        project_id: str = "",
    ) -> list[dict]:
        """对每个 FP case 的挖掘链和验证链各自做独立压缩 + 合并输出根因分析。

        Args:
            evaluation_id: 评测 ID
            fp_cases: case_matching 结果中 outcome=FP 的 case 列表，
                      每项含 case_id, verify_sessions, vulnerability_type, description
            data_packs: DataPack 列表
            cancel_cb: 取消回调
            project_id: 项目 ID（知识库主动验证用，空则跳过 Athena API 查询）

        Returns:
            分析结果列表，每项含：
            - case_id, vulnerability_type, description
            - mining: {session_chain, root_cause, fix_suggestion, compressed_summaries, l0_l7_breakpoints, l4_independent_verification}
            - verification: {session_chain, root_cause, fix_suggestion, compressed_summaries, l0_l7_breakpoints, l4_independent_verification}
        """
        # 构建 session_id → events 索引
        session_events: dict[str, list[RawEvent]] = defaultdict(list)
        # 构建 session_id → 角色（"mining" / "verify"）索引，合并全部 parent_map
        sid_role: dict[str, str] = {}
        all_parent_map: dict[str, str] = {}
        all_sessions: dict[str, dict] = {}
        for dp in data_packs:
            sg = dp.session_graph or {}
            sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
            parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}
            for sid, sdata in sessions.items():
                all_sessions[sid] = sdata
                # 判断角色：先看 session 的 agent 字段，再看 DataPack.agent_type
                session_agent = (sdata or {}).get("agent", "")
                if session_agent in _TURING_VERIFY_AGENTS:
                    sid_role[sid] = "verify"
                elif dp.agent_type in _VERIFY_AGENT_TYPES:
                    sid_role[sid] = "verify"
                elif dp.agent_type in _MINING_AGENT_TYPES:
                    sid_role[sid] = "mining"
            for sid, pid in parent_map.items():
                if sid in sessions:
                    all_parent_map[sid] = pid
            for ev in (dp.events or []):
                sid = ev.session_id or ""
                if sid:
                    session_events[sid].append(ev)

        results: list[dict] = []
        for case in fp_cases:
            if cancel_cb:
                cancel_cb()

            case_id = case.get("case_id", "")
            vuln_type = case.get("vulnerability_type", "")
            desc = case.get("description", "")
            verify_sids = case.get("verify_sessions", [])
            fp_reason = case.get("human_confirmation_summary", "")

            # 从 verify_sessions 沿 parent_map 追溯到根节点，
            # 用 PARSING 阶段已建好的调用关系，不重新构建
            case_chain = self._trace_chain(
                verify_sids, all_parent_map, all_sessions)

            # 按角色拆分为挖掘链和验证链
            mining_chain = [sid for sid in case_chain
                            if sid_role.get(sid) == "mining"]
            verify_chain = [sid for sid in case_chain
                            if sid_role.get(sid) == "verify"]

            log("ROOT_CAUSE",
                f"case {case_id}: 开始分析 (vuln_type={vuln_type})",
                eval_id=evaluation_id)

            # 第一步：挖掘 session 链滚动压缩
            mining_result = self._analyze_chain(
                evaluation_id, case_id, "mining",
                mining_chain, session_events,
                vuln_type, desc, fp_reason, cancel_cb,
                project_id=project_id,
            )

            # 第二步：验证 session 链滚动压缩
            verification_result = self._analyze_chain(
                evaluation_id, case_id, "verification",
                verify_chain, session_events,
                vuln_type, desc, fp_reason, cancel_cb,
                project_id=project_id,
            )

            results.append({
                "case_id": case_id,
                "vulnerability_type": vuln_type,
                "description": desc,
                "human_confirmation_summary": fp_reason,
                "mining": mining_result,
                "verification": verification_result,
            })

        return results

    @staticmethod
    def _trace_chain(
        verify_sids: list[str],
        parent_map: dict[str, str],
        sessions: dict[str, dict],
    ) -> list[str]:
        """从 verify_sessions 沿 parent_map 追溯到根节点，返回拓扑序（根→叶子）。

        直接用 PARSING 阶段建好的 parent_map 调用关系。
        """
        if not verify_sids:
            return []

        # 从每个 verify session 向上追溯，收集链上全部 session_id
        chain_set: set[str] = set()
        for vsid in verify_sids:
            cur = vsid
            while cur and cur in sessions and cur not in chain_set:
                chain_set.add(cur)
                cur = parent_map.get(cur, "")

        if not chain_set:
            return []

        # 拓扑排序：根→叶子
        children: dict[str, list[str]] = defaultdict(list)
        roots: list[str] = []
        for sid in chain_set:
            pid = parent_map.get(sid, "")
            if pid in chain_set:
                children[pid].append(sid)
            else:
                roots.append(sid)

        ordered: list[str] = []
        queue = sorted(roots)
        visited: set[str] = set()
        while queue:
            sid = queue.pop(0)
            if sid in visited:
                continue
            visited.add(sid)
            ordered.append(sid)
            for child in sorted(children.get(sid, [])):
                queue.append(child)

        return ordered

    def _analyze_chain(
        self,
        evaluation_id: str,
        case_id: str,
        chain_type: str,
        chain: list[str],
        session_events: dict[str, list[RawEvent]],
        vuln_type: str,
        desc: str,
        fp_reason: str = "",
        cancel_cb=None,
        project_id: str = "",
    ) -> dict:
        """对一条 session 链做独立压缩 + 合并输出。

        每个 session 独立调 LLM 压缩（不传递前一个摘要），
        收集所有摘要后合并调一次 LLM 输出最终根因。

        chain: 已排好序的 session_id 列表（根→叶子）。
        chain_type: "mining" 或 "verification"，仅用于日志。
        fp_reason: 人工标注的误报原因，传给 LLM 做根因分析。
        project_id: 项目 ID，用于知识库主动验证 L4。
        """
        if not chain:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 无 session，跳过",
                eval_id=evaluation_id)
            return {
                "session_chain": [],
                "root_cause": {
                    "category": "no_session",
                    "description": f"无 {chain_type} session",
                },
                "fix_suggestion": "",
                "compressed_summaries": [],
                "l0_l7_breakpoints": [],
            }

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} session 链 {len(chain)} 个 session",
            eval_id=evaluation_id)

        # ── 第一步：每个 session 独立压缩 ──
        compressed_summaries: list[dict] = []
        all_breakpoints: list[dict] = []

        for i, sid in enumerate(chain):
            if cancel_cb:
                cancel_cb()

            events = session_events.get(sid, [])
            session_text = self._format_session_events(sid, events)

            user_content = (
                f"漏洞类型：{vuln_type}\n"
                f"漏洞描述：{desc}\n"
                f"人工标注的误报原因：{fp_reason or '（未给出）'}\n\n"
                f"Session {i+1}/{len(chain)} (session_id={sid}):\n"
                f"{session_text}"
            )

            messages = [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ]

            try:
                result = llm_mod.chat_json(
                    messages,
                    temperature=0,
                    cancel_cb=cancel_cb,
                )
            except Exception as e:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} session {i+1}/{len(chain)} "
                    f"LLM 压缩失败: {str(e)[:200]}",
                    eval_id=evaluation_id)
                result = {
                    "summary": session_text[:3000] if session_text else "",
                    "key_findings": [],
                    "l0_l7": [],
                }

            summary = result.get("summary", "")
            l0_l7 = result.get("l0_l7") or []

            compressed_summaries.append({
                "session_id": sid,
                "step": i + 1,
                "summary": summary,
                "key_findings": result.get("key_findings") or [],
                "l0_l7": l0_l7,
            })

            # 收集断点
            for kp in l0_l7:
                if isinstance(kp, dict) and kp.get("breakpoint"):
                    all_breakpoints.append({
                        "session_id": sid,
                        **kp,
                    })

            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} session {i+1}/{len(chain)} "
                f"独立压缩完成 (summary {len(summary)} 字, "
                f"{len(l0_l7)} 条知识访问)",
                eval_id=evaluation_id)

        # ── 第二步：合并所有 session 摘要，输出最终根因 ──
        merge_user_content = self._build_merge_prompt(
            chain_type, vuln_type, desc, fp_reason,
            compressed_summaries,
        )

        merge_messages = [
            {"role": "system", "content": _MERGE_PROMPT},
            {"role": "user", "content": merge_user_content},
        ]

        try:
            merge_result = llm_mod.chat_json(
                merge_messages,
                temperature=0,
                cancel_cb=cancel_cb,
            )
        except Exception as e:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 合并压缩失败: {str(e)[:200]}",
                eval_id=evaluation_id)
            merge_result = {
                "summary": " | ".join(
                    s.get("summary", "") for s in compressed_summaries),
                "root_cause": {
                    "category": "llm_error",
                    "description": f"合并压缩 LLM 调用失败: {str(e)[:200]}",
                },
                "fix_suggestion": "",
                "l0_l7": [],
            }

        merge_summary = merge_result.get("summary", "")
        merge_root_cause = merge_result.get("root_cause", {
            "category": "unknown",
            "description": "无最终分析结果",
        })
        merge_fix = merge_result.get("fix_suggestion", "")
        merge_l0_l7 = merge_result.get("l0_l7") or []

        # 合并后的 L0-L7 断点也收集
        for kp in merge_l0_l7:
            if isinstance(kp, dict) and kp.get("breakpoint"):
                all_breakpoints.append({
                    "session_id": "merge",
                    **kp,
                })

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} 合并压缩完成 "
            f"(summary {len(merge_summary)} 字, "
            f"root_cause={merge_root_cause.get('category', '?')})",
            eval_id=evaluation_id)

        # ── L4 独立验证 ──
        l4_verification = self._verify_l4_independently(
            case_id, chain_type, vuln_type, fp_reason,
            all_breakpoints, project_id, cancel_cb,
        )

        return {
            "session_chain": chain,
            "root_cause": merge_root_cause,
            "fix_suggestion": merge_fix,
            "compressed_summaries": compressed_summaries,
            "merge_summary": merge_summary,
            "l0_l7_breakpoints": all_breakpoints,
            "l4_independent_verification": l4_verification,
        }

    @staticmethod
    def _build_merge_prompt(
        chain_type: str,
        vuln_type: str,
        desc: str,
        fp_reason: str,
        compressed_summaries: list[dict],
    ) -> str:
        """构建合并压缩的用户消息。"""
        parts = [
            f"漏洞类型：{vuln_type}",
            f"漏洞描述：{desc}",
            f"人工标注的误报原因：{fp_reason or '（未给出）'}",
            f"\n以下是 {chain_type} 链中 {len(compressed_summaries)} 个 session "
            f"的独立压缩摘要：\n",
        ]

        for s in compressed_summaries:
            parts.append(
                f"--- Session {s['step']} (session_id={s['session_id']}) ---"
            )
            parts.append(s.get("summary", ""))
            if s.get("key_findings"):
                parts.append(
                    f"关键发现: {'; '.join(s['key_findings'])}")
            if s.get("l0_l7"):
                parts.append(f"L0-L7 判定: {json.dumps(s['l0_l7'], ensure_ascii=False)}")
            parts.append("")

        parts.append(
            "请基于以上所有 session 的独立压缩摘要，合并分析并输出最终结论。"
        )
        return "\n".join(parts)

    def _verify_l4_independently(
        self,
        case_id: str,
        chain_type: str,
        vuln_type: str,
        fp_reason: str,
        all_breakpoints: list[dict],
        project_id: str,
        cancel_cb=None,
    ) -> dict | None:
        """L4 独立验证：当 L2 断点存在时，主动搜索知识库验证知识是否存在。

        只在有 L2 断点（agent 该查没查）时触发。
        """
        has_l2_break = any(
            bp.get("breakpoint") == "L2" for bp in all_breakpoints
        )
        if not has_l2_break:
            return None

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} 检测到 L2 断点，"
            f"启动知识库主动验证 L4 (project_id={project_id})")

        try:
            from .knowledge_verifier import KnowledgeVerifier
            verifier = KnowledgeVerifier()
            result = verifier.verify(
                vuln_type=vuln_type,
                fp_reason=fp_reason,
                project_id=project_id,
                cancel_cb=cancel_cb,
            )
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 独立验证完成: "
                f"l4={result.get('l4_knowledge_exists')}, "
                f"candidates={result.get('candidate_files', 0)}")
            return result
        except Exception as e:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 独立验证失败: {str(e)[:200]}")
            return {
                "l4_knowledge_exists": None,
                "matched_files": [],
                "summary": f"验证失败: {str(e)[:200]}",
                "kb_searched": {"athena_api": bool(project_id),
                                "wiki_nfs": True},
                "candidate_files": 0,
                "error": str(e)[:500],
            }

    def _format_session_events(
        self, session_id: str, events: list[RawEvent],
    ) -> str:
        """格式化 session 的全部事件为文本。"""
        if not events:
            return f"（session {session_id} 无事件）"

        lines = []
        for ev in events:
            et = ev.event_type or "UNKNOWN"
            ts = ev.timestamp_ms or 0
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
                # 标记知识访问
                kg_flag = ""
                if ev.is_kg_interaction:
                    kg_flag = " [知识库访问]"
                elif ev.is_memory_interaction:
                    kg_flag = " [记忆访问]"
                lines.append(f"[工具调用] {tool}{kg_flag}: {text}")
            elif et == "TOOL_RESULT":
                text = _extract_text(ev.output_json)
                # 标记知识访问返回
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
                     "command", "thinking", "description", "title", "result"):
            val = obj.get(key)
            if val and isinstance(val, str):
                return val
        return json.dumps(obj, ensure_ascii=False)
    return str(obj)
