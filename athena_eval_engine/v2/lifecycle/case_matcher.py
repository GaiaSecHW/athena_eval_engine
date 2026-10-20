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
- vuln_title：漏洞标题

判断标准：以漏洞的原始描述为核心依据，判断两边描述的是不是同一个漏洞。只要描述的漏洞本质相同就视为同一个，不要求代码位置完全一致。

具体来说：
1. 漏洞本质：描述的是不是同一个安全漏洞（如同一接口的同一类问题，或同一攻击路径的同一漏洞）
2. 触发入口：漏洞通过哪个接口或功能触发（宽松匹配，写法不同但指向同一接口视为相同）
3. 漏洞类型：属于什么类别（宽松匹配，说法不同但同一类问题视为相同）
4. 代码位置：作为辅助参考，不要求严格匹配。同一漏洞可能在不同的源文件中被描述（如一个描述入口控制器、另一个描述底层工具类），只要描述的是同一漏洞链即可

注意：两边的标题和描述可能写法不同，但说的可能是同一个问题。请仔细阅读全部内容综合判断，不要只看标题字面不一样或源文件不同就认为不是同一个。

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
    title = c.get("title") or c.get("vuln_title") or ""
    desc = c.get("description") or ""
    vt = c.get("vuln_type") or ""
    sf = c.get("source_file") or ""
    parts = [f"标题: {title}"]
    if vt:
        parts.append(f"类型: {vt}")
    if sf:
        parts.append(f"源文件: {sf}")
    parts.append(f"描述: {desc}")
    return "\n".join(parts)


def match_cases(
    raw_cases: list[dict],
    baseline_cases: list[dict],
    evaluation_id: str,
    cancel_cb=None,
    progress_cb=None,
) -> list[dict]:
    """将原始数据 case 与基线 case 做 LLM 语义匹配。

    Args:
        raw_cases: 原始数据 case 列表（引擎上报）
        baseline_cases: 基线 case 列表（标准答案）
        evaluation_id: 评测 ID
        cancel_cb: 取消回调
        progress_cb: 进度回调，签名 progress_cb(done: int, total: int, matched: int)

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
        """单次 LLM 调用：1 条原始数据 × 1 批基线。

        返回 raw_idx 和本批所有 same_vuln=true 的候选匹配（按 confidence 降序）。
        不只返回 best_match — 保留全部候选，供去重阶段回填次优匹配。
        """
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

        raw_case_id = raw_case.get("case_id") or raw_case.get("id") or ""
        raw_title = raw_case.get("title") or raw_case.get("vuln_title") or ""

        try:
            result = llm_mod.chat_json(messages, temperature=0, reasoning_effort="none")
            matches = result.get("matches", [])

            # 收集本批所有 same_vuln=true 的候选（按 confidence 降序）
            candidates = []
            for m in matches:
                if m.get("same_vuln"):
                    conf = float(m.get("confidence", 0))
                    local_idx = int(m.get("index", -1))
                    if 0 <= local_idx < len(batch_indices):
                        candidates.append({
                            "matched_baseline_case_id": baseline_cases[
                                batch_indices[local_idx]
                            ].get("case_id")
                                or baseline_cases[
                                    batch_indices[local_idx]
                                ].get("id") or "",
                            "matched_baseline_title": baseline_cases[
                                batch_indices[local_idx]
                            ].get("title")
                                or baseline_cases[
                                    batch_indices[local_idx]
                                ].get("vuln_title") or "",
                            "matched_baseline_index": batch_indices[local_idx],
                            "confidence": conf,
                            "reason": m.get("reason", ""),
                        })
            candidates.sort(key=lambda x: x["confidence"], reverse=True)
            return {
                "raw_idx": raw_idx,
                "raw_case_id": raw_case_id,
                "raw_title": raw_title,
                "candidates": candidates,
                "batch": batch_idx,
            }
        except Exception as e:
            log("MATCH", f"LLM 匹配失败 raw={raw_case_id} "
                  f"batch={batch_idx}: {str(e)[:200]}",
                eval_id=evaluation_id)
            return {
                "raw_idx": raw_idx,
                "raw_case_id": raw_case_id,
                "raw_title": raw_title,
                "candidates": [],
                "batch": batch_idx,
                "error": str(e)[:200],
            }

    # 生成所有 (raw_idx, batch_idx) 组合
    tasks = [
        (ri, bi)
        for ri in range(len(raw_cases))
        for bi in range(len(batches))
    ]

    # 用 LLM gate 并发提交
    futures = llm_mod.submit_llm_batch(_do_match, tasks, cancel_cb=cancel_cb)

    # 收集结果：每条原始数据 case 汇总所有批次的候选匹配
    # candidates_by_raw[raw_idx] = [candidate, ...]（跨批次合并，按 confidence 降序）
    candidates_by_raw: dict[int, list[dict]] = {}
    raw_meta: dict[int, dict] = {}  # raw_idx → {raw_case_id, raw_title}
    done_count = 0
    total_count = len(futures)
    for fut in futures:
        try:
            result = fut.result()
            done_count += 1
            if result is None:
                continue
            raw_idx = result.get("raw_idx")
            if raw_idx is None:
                # 兼容：从 raw_case_id 反查
                raw_case_id = result.get("raw_case_id", "")
                for ri, rc in enumerate(raw_cases):
                    if (rc.get("case_id") or rc.get("id") or "") == raw_case_id:
                        raw_idx = ri
                        break
            if raw_idx is None:
                continue

            raw_meta.setdefault(raw_idx, {
                "raw_case_id": result.get("raw_case_id", ""),
                "raw_title": result.get("raw_title", ""),
            })
            candidates_by_raw.setdefault(raw_idx, []).extend(
                result.get("candidates", [])
            )

            if progress_cb and done_count % 10 == 0:
                matched_count = sum(
                    1 for ri, cands in candidates_by_raw.items() if cands
                )
                progress_cb(done_count, total_count, matched_count)
        except Exception as e:
            log("MATCH", f"收集匹配结果失败: {str(e)[:200]}",
                eval_id=evaluation_id)

    # 每条原始数据的候选按 confidence 降序排序
    for ri in candidates_by_raw:
        candidates_by_raw[ri].sort(key=lambda x: x["confidence"], reverse=True)

    if progress_cb:
        matched_count = sum(1 for cands in candidates_by_raw.values() if cands)
        progress_cb(done_count, total_count, matched_count)

    # ── 去重 + 回填 ──
    # 一个基线 case 只能被一条原始 case 匹配。
    # 多条原始 case 匹配到同一个基线时，只保留 confidence 最高的；
    # 被踢掉的原始 case 从自己的候选列表里取下一个未被占用的基线（回填）。
    #
    # 算法：按每条原始数据的最高候选 confidence 降序处理，
    #       高 confidence 的原始数据先占用基线，
    #       低 confidence 的原始数据如果撞了就回填到自己的次优候选。
    occupied_baselines: set[str] = set()
    # 处理顺序：有候选的按最高 confidence 降序，无候选的排最后
    raw_order = sorted(
        range(len(raw_cases)),
        key=lambda ri: (
            -(candidates_by_raw.get(ri, [{}])[0].get("confidence", 0)
              if candidates_by_raw.get(ri) else 0),
        ),
    )

    # 按 raw_idx → result 映射，最后按原始顺序输出
    result_by_raw: dict[int, dict] = {}

    for ri in raw_order:
        meta = raw_meta.get(ri, {})
        rc = raw_cases[ri]
        raw_case_id = meta.get("raw_case_id") or rc.get("case_id") or rc.get("id") or ""
        raw_title = meta.get("raw_title") or rc.get("title") or rc.get("vuln_title") or ""

        cands = candidates_by_raw.get(ri, [])
        chosen = None
        reason = "无匹配"
        for cand in cands:
            bid = cand.get("matched_baseline_case_id", "")
            if not bid:
                continue
            if bid in occupied_baselines:
                continue  # 该基线已被占用，尝试下一个候选
            chosen = cand
            occupied_baselines.add(bid)
            reason = cand.get("reason", "")
            break

        if chosen:
            result_by_raw[ri] = {
                "raw_case_id": raw_case_id,
                "raw_title": raw_title,
                "matched_baseline_case_id": chosen.get("matched_baseline_case_id"),
                "matched_baseline_title": chosen.get("matched_baseline_title"),
                "matched_baseline_index": chosen.get("matched_baseline_index"),
                "confidence": chosen.get("confidence", 0.0),
                "reason": reason,
            }
        else:
            # 所有候选都被占用或无候选
            skipped = [c.get("matched_baseline_case_id", "") for c in cands
                       if c.get("matched_baseline_case_id")]
            if skipped:
                reason = f"候选基线 {','.join(skipped[:3])} 均已被占用"
            result_by_raw[ri] = {
                "raw_case_id": raw_case_id,
                "raw_title": raw_title,
                "matched_baseline_case_id": None,
                "matched_baseline_title": None,
                "matched_baseline_index": None,
                "confidence": 0.0,
                "reason": reason,
            }

    # 按原始数据顺序输出
    results = [result_by_raw[ri] for ri in range(len(raw_cases))]

    # 去重统计：回填了多少条
    backfilled = 0
    for ri, cands in candidates_by_raw.items():
        if not cands:
            continue
        # 如果最终匹配的不是第一个候选，说明发生了回填
        r = result_by_raw.get(ri, {})
        if r.get("matched_baseline_case_id") and r["matched_baseline_case_id"] != cands[0].get("matched_baseline_case_id"):
            backfilled += 1

    if backfilled > 0:
        log("MATCH", f"去重回填: {backfilled} 条原始数据使用了次优候选",
            eval_id=evaluation_id)

    matched = sum(1 for r in results if r.get("matched_baseline_case_id"))
    log("MATCH", f"匹配完成: {matched}/{len(results)} 条原始数据找到匹配",
        eval_id=evaluation_id)

    return results
