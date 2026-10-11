"""L7 方向一致性 + 知识正确性判定（§4.1 Prompt 5）。

对 L6 已通过的知识访问，用 LLM Prompt 5（reasoning_effort=high）判定：
1. 知识正确性（knowledge_correct）：知识内容与基线漏洞信息对比
2. 方向一致性（direction_consistent）：知识方向与判定结论方向是否一致
3. 是否影响结论（influenced）：知识是否推动了判定

效果标签和成因代码由程序侧推导，LLM 不直接输出。
"""
from __future__ import annotations

from typing import Any

from ..infra import llm as llm_mod
from ..infra.concurrency import get as get_concurrency
from ..infra.parallel import iter_completed
from ..core.task_run import BenchmarkItem
from ...infrastructure.log_util import log, with_eval_ctx, get_eval_ctx

# ── 默认值 ──

L7_CONFIDENCE_THRESHOLD = 0.6  # 默认值，运行时可从 system_config 覆盖

# ── Prompt 5 System Prompt（完整复制自 docs/llm-prompts.md）──

_PROMPT5_SYSTEM = """你是知识影响效果判定员。判断知识是否影响了判定结论，知识内容是否正确，知识方向是否与判定结论一致。

# 你收到的信息
1. knowledge_content：知识返回的完整内容
2. reasoning_reference：推理文本中引用知识的片段
3. judgment_conclusion：Agent 的判定结论（如 "确认漏洞" / "排除误报"）
4. baseline_vuln_info：基线漏洞信息（含漏洞类型、source、sink、文件、描述），作为正确性的对照基准

# 判定维度

## 维度一：知识正确性（knowledge_correct）
对比知识内容与基线漏洞信息，判断知识是否正确：
- correct=true：知识描述的漏洞模式、sink 函数、攻击路径等与基线漏洞信息一致，知识是准确且适用的
- correct=false：知识内容存在以下问题之一：
  - 知识描述的漏洞模式与基线漏洞类型不符（如知识描述 XSS 模式但基线是 SQL 注入）
  - 知识指向的 sink 函数与基线 sink 不匹配
  - 知识内容过时（如描述的函数已在新版本中修复）
  - 知识内容不适用于当前项目的技术栈或代码结构

## 维度二：方向一致性（direction_consistent）
判断知识方向（指向漏洞存在 / 指向非漏洞）与判定结论方向是否一致：
- knowledge_direction：知识内容整体指向漏洞存在还是不存在
  - 如果知识描述了漏洞模式并确认当前代码符合该模式，知识方向为"指向漏洞"
  - 如果知识描述了安全实践并确认当前代码符合安全标准，知识方向为"指向非漏洞"
  - 如果知识是中性的描述性信息（如代码结构说明），不指向任何方向
- judgment_direction：判定结论的方向
  - "确认漏洞" → 指向漏洞
  - "排除误报" / "排除漏洞" → 指向非漏洞
- direction_consistent=true：知识方向与判定结论方向一致（都指向漏洞或都指向非漏洞）
- direction_consistent=false：知识方向与判定结论方向相反

## 维度三：置信度（confidence）
你对上述判定的置信度，0.0-1.0：
- 0.9-1.0：知识内容和基线信息都非常清晰，判定无歧义
- 0.7-0.9：有少量模糊点但总体判断清晰
- 0.6-0.7：存在一些不确定性，但倾向性明显
- <0.6：信息不足或矛盾，无法可靠判断

# 综合效果判定规则（由程序根据以下 LLM 输出推导，LLM 不直接输出效果标签）
- knowledge_correct=true + direction_consistent=true → POSITIVE（正向）
- knowledge_correct=false + direction_consistent=true → NEGATIVE（负向），成因 G/H（知识错误导致误判）
- direction_consistent=false → NEUTRAL（中性），成因 F（知识未推动结论或方向偏离）
- confidence < 0.6 → 标记 NULL（证据不足，不做效果判定）

# reason 写作要求（500字以内）
第一句给出核心结论：知识是否正确、方向是否一致。
然后分两个维度说明判断依据：
1. 知识正确性：知识内容与基线漏洞信息的具体对比（如 sink 函数是否匹配、漏洞模式是否一致）
2. 方向一致性：知识指向什么方向、判定结论是什么方向、两者是否一致
必须引用知识内容和基线漏洞信息中的具体内容作为证据，不要泛泛而谈。

只返回 JSON：
{
  "knowledge_correct": true/false,
  "direction_consistent": true/false,
  "confidence": 0.0-1.0,
  "reason": "500字以内中文，结论先行，分维度说明判断依据"
}
"""


class EvidenceChain:
    """L7 方向一致性 + 知识正确性判定器。

    被 LifecycleAnalyzer 在 L0-L6 漏斗通过后调用，对每次知识访问执行 L7 判定。
    LLM 不可用时降级为规则判定（confidence=0.0 触发置信度不足逻辑）。
    """

    def __init__(self, llm_client=None):
        """初始化。

        Args:
            llm_client: LLM 客户端模块（v2 infra.llm），None 时直接使用模块级函数。
                        主要用于测试注入 mock。
        """
        self.llm = llm_client
        self._confidence_threshold = L7_CONFIDENCE_THRESHOLD

    # ── 主入口 ──

    def judge_l7(self, evaluation_id: str, records: list[dict],
                 dp, reports_dir: str, cancel_cb=None) -> list[dict]:
        """对 L6 已通过的记录执行 L7 判定，原地更新 records。

        被 LifecycleAnalyzer.analyze() 调用，签名与 analyzer 的调用点匹配：
            ec = EvidenceChain(llm_client=self.llm)
            records = ec.judge_l7(evaluation_id, records, dp, reports_dir, cancel_cb)

        只处理 l6_used=True 且 l7_influenced=None 的记录（L0-L6 漏斗全通过）。
        其他记录（已有断点或已判定）跳过。

        Args:
            evaluation_id: 评测 ID
            records: knowledge_access_detail 记录列表（L0-L6 已填充）
            dp: DataPack，提供 benchmark_item 等基线信息
            reports_dir: 报告目录（暂未使用，预留）
            cancel_cb: 取消回调，穿透到 LLM 内循环

        Returns:
            更新后的 records（同一列表引用，原地修改）
        """
        # 提取基线漏洞信息（整个 case 共享一份）
        baseline_vuln_info = self._get_baseline_vuln_info(dp.benchmark_item)

        # 筛选需要 L7 判定的记录
        pending = [r for r in records
                   if r.get("l6_used") is True
                   and r.get("l7_influenced") is None]

        if not pending:
            return records

        log("L7",
            f"judge_l7: {len(pending)} records pending L7 "
            f"(total {len(records)}, baseline_vuln_type={baseline_vuln_info.get('vuln_type', '')})",
            eval_id=evaluation_id)

        # LLM 不可用时降级处理
        if not self._llm_available():
            for r in pending:
                self._apply_degradation(r, baseline_vuln_info)
            log("L7",
                f"LLM unavailable, degraded {len(pending)} records "
                f"(confidence=0.0, all defaults)",
                eval_id=evaluation_id)
            return records

        # 构建全部 LLM 调用任务
        tasks = []
        for r in pending:
            knowledge_content = r.get("returned_content") or ""
            reasoning_ref = r.get("reasoning_ref") or ""
            judgment_conclusion = r.get("judgment_conclusion") or ""

            tasks.append({
                "record": r,
                "knowledge_content": knowledge_content,
                "reasoning_ref": reasoning_ref,
                "judgment_conclusion": judgment_conclusion,
                "baseline_vuln_info": baseline_vuln_info,
            })

        # 逐个提交 LLM 调用，受 llm_max_concurrency 全局门控
        # cancel_cb 穿透到 LLM 内循环
        def _do_judge(task):
            return self._call_llm_l7(
                task["knowledge_content"],
                task["reasoning_ref"],
                task["judgment_conclusion"],
                task["baseline_vuln_info"],
                cancel_cb=cancel_cb,
            )

        futures = llm_mod.submit_llm_batch(
            _do_judge,
            tasks,
            cancel_cb=cancel_cb,
        )

        # 等待全部完成，按提交顺序对应
        results = [None] * len(futures)
        for i, fut in enumerate(futures):
            try:
                results[i] = fut.result()
            except Exception as e:
                log("L7",
                    f"LLM call failed for record {pending[i].get('access_id', '')}: "
                    f"{str(e)[:200]}",
                    eval_id=evaluation_id)
                results[i] = None  # 后续走降级

        # 将 LLM 结果写入 records
        for r, result in zip(pending, results):
            if result is None:
                # LLM 调用失败，降级
                self._apply_degradation(r, baseline_vuln_info)
                continue

            knowledge_correct = result.get("knowledge_correct", True)
            direction_consistent = result.get("direction_consistent", True)
            confidence = float(result.get("confidence", 0.0) or 0.0)
            reason = result.get("reason", "")

            # 置信度不足检查
            if confidence < self._confidence_threshold:
                r["l7_influenced"] = None
                r["l7_method"] = "EVIDENCE_CHAIN"
                r["effect_label"] = None
                r["cause_code"] = None
                r["evidence_json"] = {
                    "status": "l7_low_confidence",
                    "knowledge_correct": knowledge_correct,
                    "direction_consistent": direction_consistent,
                    "confidence": confidence,
                    "reason": reason,
                    "threshold": self._confidence_threshold,
                }
                continue

            # 推导 influenced：LLM 不直接输出，由程序判定
            # 知识被引用（L6=True）且方向一致 → 推断为影响了结论
            influenced = self._derive_influenced(
                knowledge_correct, direction_consistent, confidence)

            # 推导效果标签和成因代码
            effect_label, cause_code = self._derive_effect_and_cause(
                knowledge_correct, direction_consistent, confidence, influenced)

            r["l7_influenced"] = influenced
            r["l7_method"] = "EVIDENCE_CHAIN"
            r["effect_label"] = effect_label
            r["cause_code"] = cause_code
            r["evidence_json"] = {
                "knowledge_correct": knowledge_correct,
                "direction_consistent": direction_consistent,
                "confidence": confidence,
                "influenced": influenced,
                "reason": reason,
            }

        # 统计结果
        stats = {}
        for r in pending:
            label = r.get("effect_label") or "NULL"
            stats[label] = stats.get(label, 0) + 1
        log("L7",
            f"judge_l7 done: {len(pending)} records, results={stats}",
            eval_id=evaluation_id)

        return records

    # ── 效果标签和成因代码推导 ──

    def _derive_effect_and_cause(self, knowledge_correct: bool,
                                 direction_consistent: bool,
                                 confidence: float,
                                 influenced: bool) -> tuple[str | None, str | None]:
        """根据 LLM 输出推导效果标签和成因代码。

        推导规则：
        - confidence < threshold → effect_label=None, cause_code=None（置信度不足，不判定）
        - influenced=False → effect_label=NEUTRAL, cause_code=F（用了没推动）
        - influenced=True, correct=True, consistent=True → POSITIVE, cause_code=None（无断点）
        - influenced=True, correct=False, consistent=True → NEGATIVE, cause_code=G+H（负向知识，内容有误导致误判）
        - influenced=True, consistent=False → NEUTRAL, cause_code=F（方向不一致但非负向）

        Args:
            knowledge_correct: 知识是否正确
            direction_consistent: 方向是否一致
            confidence: 置信度
            influenced: 知识是否影响结论

        Returns:
            (effect_label, cause_code)
            effect_label: "POSITIVE" / "NEGATIVE" / "NEUTRAL" / None
            cause_code: "F" / "G" / "H" / None
        """
        # 置信度不足
        if confidence < self._confidence_threshold:
            return None, None

        # 未影响结论
        if not influenced:
            return "NEUTRAL", "F"

        # 影响了结论
        if direction_consistent:
            if knowledge_correct:
                # 正向：知识正确且方向一致
                return "POSITIVE", None
            else:
                # 负向：知识错误但方向一致（知识推动了错误方向判定）
                # G（导致误判）+ H（内容有误，G 的根因）
                return "NEGATIVE", "G"
        else:
            # 方向不一致但影响了结论 → 中性
            return "NEUTRAL", "F"

    def _derive_influenced(self, knowledge_correct: bool,
                           direction_consistent: bool,
                           confidence: float) -> bool:
        """推导知识是否影响了结论。

        LLM 不直接输出 influenced，由程序根据以下逻辑判定：
        - 知识被引用（L6=True，已由调用点保证）
        - direction_consistent=True 且 confidence >= threshold → 推断知识影响了结论
        - direction_consistent=False → 知识方向与结论方向相反，未推动结论
        - knowledge_correct=False 且 direction_consistent=True → 知识推动了判定（负向影响）

        简化规则：direction_consistent=True → influenced=True（知识方向与结论一致=推动了）
                  direction_consistent=False → influenced=False（方向不一致=未推动）

        Args:
            knowledge_correct: 知识是否正确
            direction_consistent: 方向是否一致
            confidence: 置信度

        Returns:
            bool: 知识是否影响了结论
        """
        if confidence < self._confidence_threshold:
            return True  # 置信度不足时默认有影响（触发后续推导）
        return direction_consistent

    # ── 基线漏洞信息提取 ──

    def _get_baseline_vuln_info(self, benchmark_item) -> dict:
        """从 BenchmarkItem 提取基线漏洞信息。

        参考 docs/l7-baseline-data-source.md：
        - vuln_type: metadata["vulnerability_type"]
        - description: metadata["description"]
        - file: metadata.get("source_file")  # 实际存的是 sink 点文件
        - sink: metadata.get("source_function") or metadata.get("locator")
        - source: None（缺失，标注为"不可用"）

        Args:
            benchmark_item: BenchmarkItem 或 None

        Returns:
            dict with keys: vuln_type, description, file, sink, source
        """
        if benchmark_item is None:
            return {
                "vuln_type": "",
                "description": "",
                "file": "",
                "sink": "",
                "source": None,  # 缺失
            }

        meta = getattr(benchmark_item, "metadata", None) or {}

        vuln_type = str(meta.get("vulnerability_type", "")
                        or meta.get("vuln_type", "")
                        or meta.get("type", ""))

        description = str(meta.get("description", "") or "")

        # source_file 实质是 sink 点文件（命名歧义，见 l7-baseline-data-source.md §4.2）
        file = str(meta.get("source_file", "") or "")

        # sink: source_function（sink 点函数名）或 locator（完整 sink 位置）
        sink = str(meta.get("source_function", "")
                   or meta.get("locator", "")
                   or "")

        # source（注入入口）—— 现有数据源不含结构化 source 字段
        source = meta.get("source_entry") or meta.get("source")
        if not source:
            source = None  # 标注为"不可用"

        return {
            "vuln_type": vuln_type,
            "description": description,
            "file": file,
            "sink": sink,
            "source": source,
        }

    # ── LLM 调用 ──

    def _call_llm_l7(self, knowledge_content: str, reasoning_ref: str,
                     judgment_conclusion: str, baseline_vuln_info: dict,
                     cancel_cb=None) -> dict:
        """调用 LLM Prompt 5 判定 L7。

        使用 reasoning_effort=high 进行深度推理。
        cancel_cb 穿透到 LLM 内循环。

        Args:
            knowledge_content: 知识返回内容
            reasoning_ref: 推理引用片段
            judgment_conclusion: 判定结论
            baseline_vuln_info: 基线漏洞信息 dict
            cancel_cb: 取消回调

        Returns:
            dict: {knowledge_correct, direction_consistent, confidence, reason}
        """
        # 构建 user 输入（模板来自 docs/llm-prompts.md Prompt 5）
        baseline_source = baseline_vuln_info.get("source")
        if baseline_source is None:
            baseline_source_str = "（基线无结构化 source 信息，请从描述中推断）"
        else:
            baseline_source_str = str(baseline_source)

        user_content = (
            f"知识返回内容:\n"
            f"{knowledge_content}\n\n"
            f"推理引用片段:\n"
            f"{reasoning_ref}\n\n"
            f"判定结论: {judgment_conclusion}\n\n"
            f"基线漏洞信息:\n"
            f"漏洞类型: {baseline_vuln_info.get('vuln_type', '')}\n"
            f"Source: {baseline_source_str}\n"
            f"Sink: {baseline_vuln_info.get('sink', '')}\n"
            f"文件: {baseline_vuln_info.get('file', '')}\n"
            f"描述: {baseline_vuln_info.get('description', '')}\n\n"
            f"判断知识是否正确、方向是否一致，给出置信度。"
        )

        messages = [
            {"role": "system", "content": _PROMPT5_SYSTEM},
            {"role": "user", "content": user_content},
        ]

        if self.llm is not None and hasattr(self.llm, "chat_json"):
            return self.llm.chat_json(
                messages, temperature=0,
                reasoning_effort="high",
                cancel_cb=cancel_cb,
            )

        return llm_mod.chat_json(
            messages, temperature=0,
            reasoning_effort="high",
            cancel_cb=cancel_cb,
        )

    # ── 降级处理 ──

    def _apply_degradation(self, record: dict, baseline_vuln_info: dict) -> None:
        """LLM 不可用时对单条记录执行降级。

        降级规则（任务规范）：
        - knowledge_correct 降级为 True（无法判定时默认正确）
        - direction_consistent 降级为 True
        - confidence = 0.0（触发置信度不足逻辑）
        - influenced 降级为 True（假设知识有影响）

        结果：confidence=0.0 < threshold(0.6) → effect_label=None, cause_code=None
        标记 l7_method=EVIDENCE_CHAIN 表示已尝试判定但证据不足。
        """
        knowledge_correct = True
        direction_consistent = True
        confidence = 0.0
        influenced = True

        effect_label, cause_code = self._derive_effect_and_cause(
            knowledge_correct, direction_consistent, confidence, influenced)

        record["l7_influenced"] = None  # confidence < threshold → 不判定
        record["l7_method"] = "EVIDENCE_CHAIN"
        record["effect_label"] = effect_label  # None（置信度不足）
        record["cause_code"] = cause_code  # None（置信度不足）
        record["evidence_json"] = {
            "status": "l7_degraded",
            "knowledge_correct": knowledge_correct,
            "direction_consistent": direction_consistent,
            "confidence": confidence,
            "influenced": influenced,
            "reason": "LLM 不可用，降级判定。confidence=0.0 触发置信度不足逻辑。",
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
