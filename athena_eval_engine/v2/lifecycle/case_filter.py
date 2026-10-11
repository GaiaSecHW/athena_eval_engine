"""有效 case 筛选模块（§4.4）。

从漏洞中心人工确认数据出发，筛选需要分析的 case。

漏洞中心基线已有两类人工确认 case：
- confirmation_status=vulnerable → expected_label=VULNERABLE（有漏洞）
- confirmation_status=not_vulnerable → expected_label=NON_VULNERABLE（非漏洞）

FP（误报）判定：
- 基线 expected_label=NON_VULNERABLE
- 在 trace findings 中找到对应 finding 且 validation_result=CONFIRMED
- → agent 误报了漏洞

FN（漏报）判定：
- 基线 expected_label=VULNERABLE
- 将基线漏洞与告警中心数据对比
- 告警中心有匹配 → agent 上报了该漏洞，不是漏报
- 告警中心无匹配 → agent 漏报了该漏洞
- 对漏报的 case，提取 sink 点，用 LLM 匹配在 trace 中找对应 session

"对应"的匹配方式取决于基线来源（benchmark_source）：
1. vuln_center（漏洞中心）：纯代码匹配
   - finding_id（case_id）直接匹配
   - 标题（vulnerability_type）+ 内容（description）文本匹配
2. vbench_zip（V-Bench 测评集）：LLM 匹配
   - 复用 v1 fpr_analysis.py 的两阶段 LLM 匹配（标题预筛 → 1vs1 详细对比）
   - 因为测评集 case 结构与 trace finding 结构不同，无法用标题/内容直接匹配

FN 的 trace 匹配始终用 LLM 匹配（因为漏报意味着 trace 里没有 finding，
只能用 sink 点信息去 trace 里定位对应的 session）。

按 eval_mode 筛选：
- runtime（运行态）：只分析 FP
- dev（开发态）：分析 FP + FN

找不到对应 trace 的 case 在返回结果中标记，供报告告警。
"""
from __future__ import annotations

import re
from collections import defaultdict

from ..core.data_pack import DataPack
from ..infra import llm as llm_mod
from ..infra.parallel import iter_completed
from ...infrastructure.log_util import log, with_eval_ctx, get_eval_ctx


class CaseFilter:
    """从漏洞中心基线出发，筛选 FP/FN case 对应的 DataPack。"""

    def filter_valid_cases(
        self, evaluation_id: str, data_packs: list,
        eval_mode: str = "dev",
        benchmark_source: str = "vbench_zip",
        alert_center_data: dict | None = None,
    ) -> list:
        """筛选需要分析的 DataPack。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表
            eval_mode: "dev"（开发态，FP+FN）| "runtime"（运行态，只 FP）
            benchmark_source: "vuln_center"（漏洞中心，纯代码匹配）|
                              "vbench_zip"（V-Bench 测评集，LLM 匹配）
            alert_center_data: 告警中心数据，用于 FN 判定

        Returns:
            需要分析的 DataPack 列表
        """
        # 收集所有 DataPack 的 findings，构建匹配索引
        all_findings: list[dict] = []
        for dp in data_packs:
            for f in (dp.findings or []):
                f["_task_run_id"] = dp.task_run_id
                f["_task_id"] = dp.task_id
                all_findings.append(f)

        # 按 task_id 分组 DataPack（一个 task 可能有挖掘+验证多个 agent）
        groups: dict[str, list[DataPack]] = defaultdict(list)
        for dp in data_packs:
            groups[dp.task_id].append(dp)

        # 从 DataPack 的 benchmark_item.metadata 收集所有基线 case
        # metadata = case_details[bid]，含 expected_label, vulnerability_type, description, source_file 等
        seen_case_ids: set[str] = set()
        baseline_cases: list[dict] = []
        for dp in data_packs:
            bm = dp.benchmark_item
            if bm is None or bm.metadata is None:
                continue
            cid = bm.benchmark_item_id or ""
            if cid in seen_case_ids:
                continue
            seen_case_ids.add(cid)
            md = bm.metadata
            baseline_cases.append({
                "case_id": cid,
                "expected_label": md.get("expected_label", ""),
                "title": md.get("vulnerability_type", ""),
                "description": md.get("description", ""),
                "source_file": md.get("source_file", ""),
                "source_line": md.get("source_line", ""),
                "source_function": md.get("source_function", ""),
            })

        # ── FP 筛选：基线 NON_VULNERABLE → 在 trace findings 中匹配 ──
        fp_cases = [bc for bc in baseline_cases
                    if bc["expected_label"] == "NON_VULNERABLE"]
        # 构建基线 case → finding 的匹配映射
        if benchmark_source == "vuln_center":
            fp_finding_map = self._match_by_code(
                evaluation_id, fp_cases, all_findings)
        else:
            fp_finding_map = self._match_by_llm(
                evaluation_id, fp_cases, all_findings)

        # ── FN 筛选（仅 dev 模式）：基线 VULNERABLE → 与告警中心对比 ──
        fn_cases = []
        if eval_mode == "dev":
            fn_cases = [bc for bc in baseline_cases
                        if bc["expected_label"] == "VULNERABLE"]

        # 基线漏洞与告警中心对比，找出漏报 case
        fn_baseline_cases = self._find_fn_cases(
            evaluation_id, fn_cases, alert_center_data, benchmark_source)

        # 对漏报 case，提取 sink，用 LLM 匹配在 trace 中找对应 session
        # 漏报意味着 trace 里没有 finding，只能用 sink 点信息定位 session
        fn_finding_map = self._match_fn_to_trace(
            evaluation_id, fn_baseline_cases, all_findings)

        # ── 组装有效 DataPack ──
        valid_packs: list[DataPack] = []
        unmatched_cases: list[dict] = []

        # 处理 FP
        for bc in fp_cases:
            cid = bc["case_id"]
            title = bc["title"]

            matched_finding = fp_finding_map.get(cid)

            if matched_finding is None:
                unmatched_cases.append({
                    "case_id": cid,
                    "expected_label": "NON_VULNERABLE",
                    "title": title,
                    "reason": "FP: no matching finding in trace",
                })
                log("CASE_FILTER",
                    f"unmatched FP case {cid}: no finding in trace "
                    f"(title={title[:60]})",
                    eval_id=evaluation_id)
                continue

            vr = matched_finding.get("validation_result", "")
            task_id = matched_finding.get("_task_id", "")

            if vr == "CONFIRMED":
                # FP: agent 误报了漏洞
                packs = self._get_packs_with_knowledge(groups, task_id)
                if packs:
                    log("CASE_FILTER",
                        f"keep case {cid}: FP (vr={vr}, "
                        f"task={task_id}, {len(packs)} packs)",
                        eval_id=evaluation_id)
                    valid_packs.extend(packs)
                else:
                    unmatched_cases.append({
                        "case_id": cid,
                        "expected_label": "NON_VULNERABLE",
                        "title": title,
                        "reason": "FP but no knowledge access in trace",
                    })
            else:
                log("CASE_FILTER",
                    f"skip case {cid}: NON_VULNERABLE but vr={vr} "
                    f"(not CONFIRMED, not FP)",
                    eval_id=evaluation_id)

        # 处理 FN
        for bc in fn_baseline_cases:
            cid = bc["case_id"]
            title = bc["title"]

            matched_finding = fn_finding_map.get(cid)

            if matched_finding is None:
                unmatched_cases.append({
                    "case_id": cid,
                    "expected_label": "VULNERABLE",
                    "title": title,
                    "reason": "FN: no matching trace session by sink",
                })
                log("CASE_FILTER",
                    f"unmatched FN case {cid}: no trace session "
                    f"by sink (title={title[:60]})",
                    eval_id=evaluation_id)
                continue

            task_id = matched_finding.get("_task_id", "")

            # FN: agent 漏报了漏洞，保留该 task 下有知识访问的 DataPack
            packs = self._get_packs_with_knowledge(groups, task_id)
            if packs:
                log("CASE_FILTER",
                    f"keep case {cid}: FN (task={task_id}, "
                    f"{len(packs)} packs)",
                    eval_id=evaluation_id)
                valid_packs.extend(packs)
            else:
                unmatched_cases.append({
                    "case_id": cid,
                    "expected_label": "VULNERABLE",
                    "title": title,
                    "reason": "FN but no knowledge access in trace",
                })

        log("CASE_FILTER",
            f"filtered {len(valid_packs)}/{len(data_packs)} packs "
            f"from {len(baseline_cases)} baseline cases "
            f"(mode={eval_mode}, source={benchmark_source}, "
            f"fp_cases={len(fp_cases)}, fn_cases={len(fn_baseline_cases)}, "
            f"unmatched={len(unmatched_cases)})",
            eval_id=evaluation_id)

        # 将 unmatched_cases 存到类属性，供报告读取
        self.unmatched_cases = unmatched_cases

        return valid_packs

    # ── FN 判定：基线漏洞 vs 告警中心 ──

    def _find_fn_cases(
        self,
        evaluation_id: str,
        vuln_baseline_cases: list[dict],
        alert_center_data: dict | None,
        benchmark_source: str,
    ) -> list[dict]:
        """从基线漏洞 case 中找出漏报 case。

        将基线漏洞与告警中心数据对比：
        - 告警中心有匹配 → agent 上报了该漏洞，不是漏报
        - 告警中心无匹配 → agent 漏报了该漏洞

        匹配方式与 FP 相同：vuln_center 用纯代码，vbench_zip 用 LLM。
        """
        if not vuln_baseline_cases:
            return []

        ac_cases = []
        if alert_center_data:
            ac_cases = alert_center_data.get("cases", [])

        if not ac_cases:
            # 告警中心无数据 → 所有基线漏洞都是漏报
            log("CASE_FILTER",
                f"no alert center data: all {len(vuln_baseline_cases)} "
                f"baseline vuln cases are FN",
                eval_id=evaluation_id)
            return list(vuln_baseline_cases)

        # 基线漏洞与告警中心匹配
        if benchmark_source == "vuln_center":
            matched_map = self._match_by_code(
                evaluation_id, vuln_baseline_cases, ac_cases)
        else:
            matched_map = self._match_by_llm(
                evaluation_id, vuln_baseline_cases, ac_cases)

        # 没匹配上的基线漏洞 = 漏报
        fn_cases = [bc for bc in vuln_baseline_cases
                    if bc["case_id"] not in matched_map]

        log("CASE_FILTER",
            f"FN detection: {len(vuln_baseline_cases)} baseline vulns vs "
            f"{len(ac_cases)} AC cases → {len(fn_cases)} FN "
            f"(matched={len(vuln_baseline_cases) - len(fn_cases)})",
            eval_id=evaluation_id)

        return fn_cases

    def _match_fn_to_trace(
        self,
        evaluation_id: str,
        fn_cases: list[dict],
        all_findings: list[dict],
    ) -> dict[str, dict]:
        """对漏报 case，用 LLM 匹配在 trace 中找对应 session。

        漏报意味着 agent 没上报 finding，trace 里没有对应的 finding。
        用基线的 sink 点信息（source_file / source_function），
        通过 LLM 匹配在 trace findings 中找最接近的 session。

        始终用 LLM 匹配，因为 sink 点信息与 trace session 的对应关系
        无法用纯代码判定。

        Returns:
            {case_id: matched_finding_dict}
        """
        if not fn_cases:
            return {}

        if not all_findings:
            log("CASE_FILTER",
                f"FN trace match: no findings in trace, "
                f"{len(fn_cases)} FN cases unmatched",
                eval_id=evaluation_id)
            return {}

        # 漏报 case 在 trace 里没有 finding，但可能在 trace 的其他事件中
        # 有知识访问。用 LLM 匹配找最接近的 finding（按 sink 点），
        # 然后通过该 finding 的 task_id 定位到有知识访问的 DataPack。
        fn_finding_map = self._match_by_llm(
            evaluation_id, fn_cases, all_findings)

        # 对没匹配上的 FN case，尝试用 sink 路径直接匹配
        unmatched_fn = [bc for bc in fn_cases
                        if bc["case_id"] not in fn_finding_map]
        if unmatched_fn:
            for bc in unmatched_fn:
                sink = bc.get("source_file", "")
                func = bc.get("source_function", "")
                if sink:
                    # 用 sink 路径在 findings 中找 source/sink 路径匹配的
                    for f in all_findings:
                        f_sink = str(f.get("sink") or f.get("source") or "")
                        if f_sink and _verify_sink(sink, f_sink) is True:
                            fn_finding_map[bc["case_id"]] = f
                            log("CASE_FILTER",
                                f"FN sink match: case {bc['case_id']} ← "
                                f"finding by sink path",
                                eval_id=evaluation_id)
                            break

        log("CASE_FILTER",
            f"FN trace match: {len(fn_cases)} FN cases, "
            f"{len(fn_finding_map)} matched to trace",
            eval_id=evaluation_id)

        return fn_finding_map

    # ── 纯代码匹配（漏洞中心）──

    @staticmethod
    def _match_by_code(
        evaluation_id: str,
        baseline_cases: list[dict],
        all_findings: list[dict],
    ) -> dict[str, dict]:
        """纯代码匹配：finding_id / 标题 / 内容。

        适用于漏洞中心基线（case_id 与 trace finding 有直接对应关系）。

        Returns:
            {case_id: matched_finding_dict}
        """
        result: dict[str, dict] = {}
        for bc in baseline_cases:
            cid = bc["case_id"]
            title = bc["title"]
            desc = bc["description"]
            matched = CaseFilter._match_finding(cid, title, desc, all_findings)
            if matched is not None:
                result[cid] = matched
        return result

    @staticmethod
    def _match_finding(case_id: str, title: str, description: str,
                       all_findings: list[dict]) -> dict | None:
        """在 findings 列表中找到与基线 case 对应的 finding。

        匹配优先级：
        1. finding_id / case_id 直接匹配
        2. 标题（vulnerability_type / title）匹配
        3. 内容（description）文本匹配
        """
        # 1. finding_id 直接匹配
        for f in all_findings:
            fid = str(f.get("finding_id") or f.get("display_id")
                      or f.get("id") or "")
            if fid and fid == case_id:
                return f

        # 2. 标题匹配
        if title:
            title_lower = title.lower().strip()
            for f in all_findings:
                f_title = str(
                    f.get("title") or f.get("vuln_type") or ""
                ).lower().strip()
                if f_title and f_title == title_lower:
                    return f
                # 部分匹配（标题包含关系）
                if f_title and title_lower and (
                    title_lower in f_title or f_title in title_lower
                ):
                    return f

        # 3. 内容匹配（description 关键词）
        if description:
            # 取 description 前 200 字做关键词匹配
            desc_sample = description[:200].lower()
            for f in all_findings:
                f_desc = str(f.get("description") or "").lower()
                if f_desc and desc_sample and desc_sample in f_desc:
                    return f

        return None

    # ── LLM 匹配（V-Bench 测评集 / FN trace 定位）──

    def _match_by_llm(
        self,
        evaluation_id: str,
        baseline_cases: list[dict],
        all_findings: list[dict],
    ) -> dict[str, dict]:
        """LLM 匹配：两阶段（标题预筛 → 1vs1 详细对比）。

        适用于 V-Bench 测评集基线（case 与 trace finding 结构不同，
        无法用标题/内容直接匹配），以及 FN trace 定位（漏报 case
        需要用 sink 点信息在 trace 中找对应 session）。

        复用 v1 fpr_analysis.py / ai_matcher.py 的匹配方法：
        - Phase 1: 每个基线 case 用 LLM 从全部 findings 中预筛候选
        - Phase 2: 对候选 1vs1 LLM 详细对比，程序校验 sink 路径
        - 冲突解决：一个 finding 只能匹配一个基线 case（1:1 分配）

        Returns:
            {case_id: matched_finding_dict}
        """
        if not baseline_cases or not all_findings:
            log("CASE_FILTER",
                f"LLM match skipped: {len(baseline_cases)} baseline_cases, "
                f"{len(all_findings)} findings",
                eval_id=evaluation_id)
            return {}

        log("CASE_FILTER",
            f"LLM match: {len(baseline_cases)} baseline_cases × "
            f"{len(all_findings)} findings",
            eval_id=evaluation_id)

        # 构建精简描述
        baseline_list = []
        for bc in baseline_cases:
            baseline_list.append({
                "case_id": bc["case_id"],
                "title": bc["title"],
                "description": bc["description"],
                "source_file": bc["source_file"],
            })
        finding_list = []
        for f in all_findings:
            finding_list.append({
                "title": f.get("title") or f.get("vuln_type") or "",
                "vuln_type": f.get("vuln_type", ""),
                "description": f.get("description") or "",
                "source": f.get("source") or "",
                "sink": f.get("sink") or "",
            })

        # Phase 1: 标题预筛（每基线 1 次 LLM）
        prefilter_candidates = self._llm_prefilter(
            evaluation_id, baseline_list, finding_list)

        # Phase 2: 1vs1 详细对比
        pair_results = self._llm_detail_match(
            evaluation_id, baseline_list, finding_list,
            prefilter_candidates)

        # 冲突解决：按基线顺序分配，先到先得（1:1）
        available_finding_indices = set(range(len(all_findings)))
        result: dict[str, dict] = {}

        for bi, bc in enumerate(baseline_cases):
            candidates = prefilter_candidates.get(
                bi, list(range(len(all_findings))))
            candidates = [fi for fi in candidates
                          if fi in available_finding_indices]

            best_fi = None
            best_score = 0.0
            for fi in candidates:
                score = pair_results.get((bi, fi), 0.0)
                if score > best_score:
                    best_score = score
                    best_fi = fi

            if best_fi is not None and best_score >= 0.5:
                available_finding_indices.discard(best_fi)
                matched_finding = all_findings[best_fi]
                result[bc["case_id"]] = matched_finding
                log("CASE_FILTER",
                    f"LLM MATCHED case {bc['case_id']} ← "
                    f"finding[{best_fi}] (score={best_score:.2f})",
                    eval_id=evaluation_id)

        return result

    def _llm_prefilter(
        self,
        evaluation_id: str,
        baseline_list: list[dict],
        finding_list: list[dict],
    ) -> dict[int, list[int]]:
        """Phase 1: 每个基线 case 用 LLM 预筛候选 finding。

        返回 {baseline_idx: [finding_idx, ...]}
        """
        _PREFILTER_LIMIT = 50
        prefilter_sys = (
            "下面是一些代码安全漏洞的标题和描述。"
            "请从标题和描述分析哪些漏洞报告跟该基线案例可能是同一个漏洞。"
            "宁可多选不要遗漏。"
            "将可能匹配的漏洞的 ID 原样返回，便于核对。"
            "只返回 JSON：{\"possible_ids\": [\"ID1\", \"ID2\"]}。"
            "无匹配返回空数组 []。"
        )

        def _prefilter_one(bi: int) -> tuple[int, list[int]]:
            bl = baseline_list[bi]
            id_to_idx: dict[str, int] = {}
            bl_desc = (bl.get("description", "") or "")[:500]
            lines = [
                f"基线案例标题：{bl.get('title', '')}",
                f"基线案例描述：{bl_desc}",
                "",
                "以下是要比较的漏洞报告：",
            ]
            for i, f in enumerate(finding_list[:_PREFILTER_LIMIT]):
                fid = str(i)
                id_to_idx[fid] = i
                f_title = f.get("title", "")
                f_desc = (f.get("description", "") or "")[:500]
                lines.append(f"[{fid}] {f_title}\n描述：{f_desc}")
            user_msg = "\n".join(lines)
            prompt = [
                {"role": "system", "content": prefilter_sys},
                {"role": "user", "content": user_msg},
            ]
            result = llm_mod.chat_json(prompt, temperature=0,
                                        reasoning_effort="none")
            indices = []
            if isinstance(result, dict):
                raw_ids = result.get("possible_ids", [])
                indices = [id_to_idx[x] for x in raw_ids
                           if isinstance(x, str) and x in id_to_idx]
            return bi, indices

        prefilter_candidates: dict[int, list[int]] = {}
        items = list(range(len(baseline_list)))

        try:
            futures = llm_mod.submit_llm_batch(
                with_eval_ctx(_prefilter_one), items)
            for fut, bi in zip(futures, items):
                try:
                    _, indices = fut.result()
                    if not indices:
                        indices = list(range(len(finding_list)))
                        log("CASE_FILTER",
                            f"prefilter 0 candidates (bl{bi}): fallback all",
                            eval_id=evaluation_id)
                    prefilter_candidates[bi] = indices
                except Exception as e:
                    prefilter_candidates[bi] = list(range(len(finding_list)))
                    log("CASE_FILTER",
                        f"prefilter FAILED (bl{bi}): {e}, fallback all",
                        eval_id=evaluation_id)
        except Exception:
            for bi in items:
                prefilter_candidates.setdefault(
                    bi, list(range(len(finding_list))))

        total_cand = sum(len(v) for v in prefilter_candidates.values())
        log("CASE_FILTER",
            f"prefilter: {len(baseline_list)} baseline_cases, "
            f"{total_cand} candidates "
            f"(avg {total_cand / max(len(baseline_list), 1):.1f}/case)",
            eval_id=evaluation_id)

        return prefilter_candidates

    def _llm_detail_match(
        self,
        evaluation_id: str,
        baseline_list: list[dict],
        finding_list: list[dict],
        prefilter_candidates: dict[int, list[int]],
    ) -> dict[tuple[int, int], float]:
        """Phase 2: 1vs1 LLM 详细对比 + 程序校验 sink。

        返回 {(baseline_idx, finding_idx): score}
        """
        _sys_prompt = (
            "你是漏洞匹配判定器。给你一个参考漏洞和一个待判定的漏洞，"
            "每个漏洞有标题、描述和代码文件路径，请从三个方面判断它们是不是同一个漏洞：\n"
            "1. 代码位置：漏洞出现在哪个代码文件里\n"
            "2. 触发入口：漏洞是通过哪个接口或功能触发的\n"
            "3. 漏洞类型：属于什么类别的问题（如SQL注入、命令注入、越权、IDOR、SSRF等）\n\n"
            "注意：两边的标题和描述可能写法不同，但说的可能是同一个问题。"
            "请仔细阅读全部内容，结合具体细节综合判断，"
            "不要只看标题字面不一样就认为不是同一个。\n\n"
            "先从标题和描述中提取各自的三个方面信息，代码文件路径作为参考，"
            "再逐一判断是否相同。\n"
            "判断标准：\n"
            "- 代码位置要求严格：文件路径必须明确对应，不同文件就是不同漏洞\n"
            "- 触发入口可以宽松：写法不同但指向同一个接口或功能的，视为相同\n"
            "- 漏洞类型可以宽松：说法不同但属于同一类问题的，视为相同\n\n"
            "desc_similarity是描述相似度（0.0-1.0），"
            "表示两边描述讲的是同一个问题的程度。\n\n"
            '只返回JSON：\n'
            '{\n'
            '  "baseline": {"sink": "...", "source": "...", "vuln_type": "..."},\n'
            '  "candidate": {"sink": "...", "source": "...", "vuln_type": "..."},\n'
            '  "same_sink": true/false,\n'
            '  "same_source": true/false,\n'
            '  "same_vuln_type": true/false,\n'
            '  "desc_similarity": 0.0-1.0,\n'
            '  "reason": "简要说明每个方面的判断理由"\n'
            '}'
        )

        # 收集所有 (baseline_idx, finding_idx) 对
        all_pairs: list[tuple[int, int]] = []
        for bi in range(len(baseline_list)):
            candidates = prefilter_candidates.get(
                bi, list(range(len(finding_list))))
            for fi in candidates:
                all_pairs.append((bi, fi))

        log("CASE_FILTER",
            f"detail_match: {len(all_pairs)} pairs to check",
            eval_id=evaluation_id)

        def _check_pair(pair: tuple[int, int]) -> tuple[int, int, float]:
            bi, fi = pair
            bl = baseline_list[bi]
            f = finding_list[fi]

            bl_desc = f"标题: {bl.get('title', '')}\n描述: {bl.get('description', '')}"
            bl_sink = bl.get("source_file", "")
            if bl_sink:
                bl_desc += f"\n代码文件: {bl_sink}"

            f_desc = f"标题: {f.get('title', '')}\n描述: {f.get('description', '')}"
            f_sink = f.get("sink", "") or f.get("source", "")
            if f_sink:
                f_desc += f"\n代码文件: {f_sink}"

            prompt = [
                {"role": "system", "content": _sys_prompt},
                {"role": "user", "content": (
                    f"参考漏洞:\n{bl_desc}\n\n"
                    f"待判定漏洞:\n{f_desc}\n\n"
                    f"提取三个方面信息并判断是否同一个漏洞。"
                )},
            ]
            try:
                result = llm_mod.chat_json(prompt, temperature=0,
                                            reasoning_effort="none")
                same_sink = _parse_bool(result.get("same_sink", False))
                same_source = _parse_bool(result.get("same_source", False))
                same_vuln_type = _parse_bool(result.get("same_vuln_type", False))
                desc_sim = result.get("desc_similarity")
                try:
                    desc_sim = float(desc_sim) if desc_sim is not None else 0.0
                except (ValueError, TypeError):
                    desc_sim = 0.0

                # 程序校验 sink 路径
                sink_check = _verify_sink(bl_sink, f_sink)
                if sink_check is False and same_sink:
                    same_sink = False
                elif sink_check is True and not same_sink:
                    same_sink = True

                # 匹配条件：vuln_type 必须为 true，且满足以下之一：
                # 1. sink 与 source 至少一个为 true，且描述相似度 >= 0.5
                # 2. sink 与 source 都为 false，但描述相似度 >= 0.6
                is_same = same_vuln_type and (
                    ((same_sink or same_source) and desc_sim >= 0.5) or
                    ((not same_sink and not same_source) and desc_sim >= 0.6)
                )
                return bi, fi, desc_sim if is_same else 0.0
            except Exception as e:
                log("CASE_FILTER",
                    f"LLM detail FAILED (bl{bi},f{fi}): {e}",
                    eval_id=evaluation_id)
                return bi, fi, 0.0

        pair_results: dict[tuple[int, int], float] = {}
        if all_pairs:
            try:
                futures = llm_mod.submit_llm_batch(
                    with_eval_ctx(_check_pair), all_pairs)
                for fut, pair in zip(futures, all_pairs):
                    try:
                        bi, fi, score = fut.result()
                        pair_results[(bi, fi)] = score
                    except Exception as e:
                        pair_results[pair] = 0.0
                        log("CASE_FILTER",
                            f"LLM detail result failed: {e}",
                            eval_id=evaluation_id)
            except Exception:
                for pair in all_pairs:
                    pair_results[pair] = 0.0

        return pair_results

    # ── 工具方法 ──

    @staticmethod
    def _get_packs_with_knowledge(groups: dict[str, list[DataPack]],
                                  task_id: str) -> list[DataPack]:
        """获取 task 下有知识访问记录的 DataPack。"""
        packs = groups.get(task_id, [])
        result = []
        for dp in packs:
            kf = dp.knowledge_fact
            if kf is None:
                continue
            if getattr(kf, "access", False) or getattr(kf, "memory_access", False):
                result.append(dp)
        return result


# ── 模块级工具函数（与 v1 fpr_analysis.py / ai_matcher.py 保持一致）──


def _norm_path(path: str) -> str:
    """归一化源文件路径用于比对。"""
    if not path:
        return ""
    path = path.strip()
    path = re.sub(r':\d+(-\d+)?$', '', path)
    path = re.sub(r':[^/]+$', '', path)  # 去掉 :function_name
    m = re.search(r'com/huawei/(.+)', path)
    if m:
        return m.group(1).lower().strip()
    m = re.search(r'/src/(.+)', path)
    if m:
        return m.group(1).lower().strip()
    return path.lower().strip("/")


def _verify_sink(baseline_sink: str, finding_sink: str) -> bool | None:
    """代码校验 sink 路径是否一致。返回 True/False，None=无法确定。"""
    bl = _norm_path(baseline_sink)
    fl = _norm_path(finding_sink)
    if not bl or not fl:
        return None
    if bl == fl:
        return True
    if bl in fl or fl in bl:
        return True
    bl_parts = bl.split("/")
    fl_parts = fl.split("/")
    for n in (3, 2):
        if len(bl_parts) >= n and len(fl_parts) >= n:
            if bl_parts[-n:] == fl_parts[-n:]:
                return True
    broad = {"controller", "service", "impl", "common", "config", "utils",
             "fintech", "huawei", "src", "com", "app", "main", "java",
             "sdk", "api", "core", "biz", "ws", "restful"}
    common = set(bl_parts) & set(fl_parts) - broad
    if not common:
        return False
    return None


def _parse_bool(val) -> bool:
    """解析 LLM 返回的 bool 值。"""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower().strip() == "true"
    return False
