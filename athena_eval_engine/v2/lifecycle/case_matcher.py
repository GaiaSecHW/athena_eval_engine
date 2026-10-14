"""Case 匹配器 — 用 LLM 将原始数据 case 与基线 case 做语义匹配。

开发态下原始数据和基线是不同项目的数据，case_id 不相同，
需要用 LLM 判断哪些 case 描述的是同一个漏洞。

匹配策略：
1. 用本地 tokenizer 精确计算 token 数
2. 按 token 上限动态分批，每批放尽可能多的基线 case
3. 每条原始数据 case 对每批基线 case 做一次 LLM 调用
4. LLM 返回匹配结果（same_vuln + confidence + reason）
"""
from __future__ import annotations

from ..infra import llm as llm_mod
from ..infra.token_counter import count_tokens, fit_batch_by_token
from ...infrastructure.log_util import log

# 模型最大上下文 token 数 — 优先用 LLM 运行时收集的值，否则默认 128K
_DEFAULT_MAX_CONTEXT = 128_000
# 预留给 system prompt + 输出 + 格式的 token 数
_RESERVE_TOKENS = 8192

_PROMPT_SYSTEM = """你是漏洞匹配判定器。给你一条待判定的漏洞和一批参考漏洞，请判断待判定漏洞和哪些参考漏洞是同一个漏洞。

每个漏洞包含：
- title：漏洞标题
- description：漏洞描述（可能很长）
- vuln_type：漏洞类型

判断维度：
1. 代码位置：漏洞出现在哪个代码文件里（严格匹配）
2. 触发入口：漏洞通过哪个接口或功能触发（宽松匹配，写法不同但指向同一接口视为相同）
3. 漏洞类型：属于什么类别（宽松匹配，说法不同但同一类问题视为相同）

注意：两边的标题和描述可能写法不同，但说的可能是同一个问题。请仔细阅读全部内容综合判断，不要只看标题字面不一样就认为不是同一个。

对每个参考漏洞，返回判断结果。index 是参考漏洞在列表中的序号（从0开始）。

只返回 JSON：
{
  "matches": [
    {"index": 0, "same_vuln": true/false, "confidence": 0.0-1.0, "reason": "简要说明"},
    {"index": 1, "same_vuln": true/false, "confidence": 0.0-1.0, "reason": "简要说明"},
    ...
  ]
}
"""


def _case_to_text(c: dict) -> str:
    """将 case 转为 LLM 可读的文本。"""
    title = c.get("title") or c.get("vulnerability_type") or ""
    desc = c.get("description") or ""
    # description 可能很长，截取前 2000 字符
    if len(desc) > 2000:
        desc = desc[:2000] + "...(截断)"
    vt = c.get("vulnerability_type") or c.get("vuln_type") or ""
    return f"标题: {title}\n类型: {vt}\n描述: {desc}"


def match_cases(
    raw_cases: list[dict],
    baseline_cases: list[dict],
    evaluation_id: str,
    cancel_cb=None,
) -> list[dict]:
    """将原始数据 case 与基线 case 做 LLM 语义匹配。

    Args:
        raw_cases: 原始数据 case 列表（引擎上报）
        baseline_cases: 基线 case 列表（标准答案）
        evaluation_id: 评测 ID
        cancel_cb: 取消回调

    Returns:
        匹配结果列表，每条：
        {
            "raw_case_id": "...",
            "raw_title": "...",
            "matched_baseline_case_id": "..." or None,
            "matched_baseline_index": int or None,
            "confidence": float,
            "reason": "...",
        }
    """
    if not raw_cases or not baseline_cases:
        return []

    # 获取模型最大上下文 token 数（优先用运行时收集的值）
    max_ctx = llm_mod.get_max_context_tokens() or _DEFAULT_MAX_CONTEXT

    # 基线 case 文本
    baseline_texts = [_case_to_text(c) for c in baseline_cases]

    # 动态分批：按 token 上限决定每批放多少条基线 case
    batches = fit_batch_by_token(
        baseline_texts,
        max_tokens=max_ctx,
        reserve_tokens=_RESERVE_TOKENS,
    )

    log("MATCH", f"基线 {len(baseline_cases)} 条分 {len(batches)} 批 "
          f"(每批 {len(batches[0]) if batches else 0}~"
          f"{max(len(b) for b in batches) if batches else 0} 条) "
          f"原始数据 {len(raw_cases)} 条 → "
          f"预计 {len(raw_cases) * len(batches)} 次 LLM 调用",
        eval_id=evaluation_id)

    # 对每条原始数据 case，对每批基线做 LLM 匹配
    # 用 LLM gate 控制并发
    def _do_match(args: tuple) -> dict:
        raw_idx, batch_idx = args
        raw_case = raw_cases[raw_idx]
        batch_indices = batches[batch_idx]
        raw_text = _case_to_text(raw_case)

        # 构造基线列表（只含本批的 case）
        baseline_items = []
        for bi in batch_indices:
            baseline_items.append(f"[{len(baseline_items)}] {baseline_texts[bi]}")

        user_content = (
            f"待判定漏洞:\n{raw_text}\n\n"
            f"参考漏洞列表:\n" + "\n---\n".join(baseline_items) + "\n\n"
            f"对每个参考漏洞判断是否同一个漏洞。"
        )

        messages = [
            {"role": "system", "content": _PROMPT_SYSTEM},
            {"role": "user", "content": user_content},
        ]

        try:
            result = llm_mod.chat_json(messages, temperature=0, reasoning_effort="none")
            matches = result.get("matches", [])

            # 找到 same_vuln=true 且 confidence 最高的
            best_match = None
            best_conf = 0.0
            for m in matches:
                if m.get("same_vuln"):
                    conf = float(m.get("confidence", 0))
                    if conf > best_conf:
                        best_conf = conf
                        local_idx = int(m.get("index", -1))
                        if 0 <= local_idx < len(batch_indices):
                            best_match = {
                                "raw_case_id": raw_case.get("case_id")
                                    or raw_case.get("id") or "",
                                "raw_title": raw_case.get("title")
                                    or raw_case.get("vulnerability_type") or "",
                                "matched_baseline_case_id": baseline_cases[
                                    batch_indices[local_idx]
                                ].get("case_id")
                                    or baseline_cases[
                                        batch_indices[local_idx]
                                    ].get("id") or "",
                                "matched_baseline_index": batch_indices[local_idx],
                                "confidence": conf,
                                "reason": m.get("reason", ""),
                                "batch": batch_idx,
                            }
            return best_match or {
                "raw_case_id": raw_case.get("case_id")
                    or raw_case.get("id") or "",
                "raw_title": raw_case.get("title")
                    or raw_case.get("vulnerability_type") or "",
                "matched_baseline_case_id": None,
                "matched_baseline_index": None,
                "confidence": 0.0,
                "reason": "无匹配",
                "batch": batch_idx,
            }
        except Exception as e:
            log("MATCH", f"LLM 匹配失败 raw={raw_case.get('case_id')} "
                  f"batch={batch_idx}: {str(e)[:200]}",
                eval_id=evaluation_id)
            return {
                "raw_case_id": raw_case.get("case_id")
                    or raw_case.get("id") or "",
                "raw_title": raw_case.get("title")
                    or raw_case.get("vulnerability_type") or "",
                "matched_baseline_case_id": None,
                "matched_baseline_index": None,
                "confidence": 0.0,
                "reason": f"LLM 调用失败: {str(e)[:100]}",
                "batch": batch_idx,
            }

    # 生成所有 (raw_idx, batch_idx) 组合
    tasks = [
        (ri, bi)
        for ri in range(len(raw_cases))
        for bi in range(len(batches))
    ]

    # 用 LLM gate 并发提交
    futures = llm_mod.submit_llm_batch(_do_match, tasks, cancel_cb=cancel_cb)

    # 收集结果：每条原始数据 case 取所有批次中 confidence 最高的匹配
    best_by_raw: dict[int, dict] = {}
    for fut in futures:
        try:
            result = fut.result()
            if result is None:
                continue
            # 从 result 找到 raw_idx
            raw_case_id = result.get("raw_case_id", "")
            # 找 raw_idx
            raw_idx = None
            for ri, rc in enumerate(raw_cases):
                if (rc.get("case_id") or rc.get("id") or "") == raw_case_id:
                    raw_idx = ri
                    break
            if raw_idx is None:
                continue

            existing = best_by_raw.get(raw_idx)
            if existing is None or result["confidence"] > existing["confidence"]:
                best_by_raw[raw_idx] = result
        except Exception as e:
            log("MATCH", f"收集匹配结果失败: {str(e)[:200]}",
                eval_id=evaluation_id)

    # 按原始数据顺序输出
    results = []
    for ri in range(len(raw_cases)):
        if ri in best_by_raw:
            results.append(best_by_raw[ri])
        else:
            rc = raw_cases[ri]
            results.append({
                "raw_case_id": rc.get("case_id") or rc.get("id") or "",
                "raw_title": rc.get("title")
                    or rc.get("vulnerability_type") or "",
                "matched_baseline_case_id": None,
                "matched_baseline_index": None,
                "confidence": 0.0,
                "reason": "未执行匹配",
            })

    matched = sum(1 for r in results if r.get("matched_baseline_case_id"))
    log("MATCH", f"匹配完成: {matched}/{len(results)} 条原始数据找到匹配",
        eval_id=evaluation_id)

    return results
