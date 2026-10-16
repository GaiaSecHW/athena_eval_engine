"""有效 case 筛选模块（§4.4）。

从漏洞中心人工确认数据出发，筛选需要分析的 case。

漏洞中心基线已有两类人工确认 case：
- confirmation_status=vulnerable → expected_label=VULNERABLE（有漏洞）
- confirmation_status=not_vulnerable → expected_label=NON_VULNERABLE（误报）
- 排除 false_positive_group=non_fp（非误报，不参与分析）

FN（漏报）判定：
- 基线 expected_label=VULNERABLE
- 将基线漏洞与告警中心数据对比
- 告警中心有匹配 → agent 上报了该漏洞，不是漏报
- 告警中心无匹配 → agent 漏报了该漏洞

"对应"的匹配方式取决于基线来源（benchmark_source）：
1. vuln_center（漏洞中心）：纯代码匹配
   - case_id 直接匹配
   - 标题（vulnerability_type）+ 内容（description）文本匹配
2. vbench_zip（V-Bench 测评集）：LLM 匹配
   - 两阶段 LLM 匹配（标题预筛 → 1vs1 详细对比）
   - 因为测评集 case 结构与告警中心 case 结构不同，无法用标题/内容直接匹配

按 eval_mode 筛选：
- runtime（运行态）：基线含 VULNERABLE + NON_VULNERABLE（已排除 non_fp）
- dev（开发态）：分析 FN

找不到对应 trace 的 case 在返回结果中标记，供报告告警。
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from ..core.data_pack import DataPack
from ..infra import llm as llm_mod
from ..infra.parallel import iter_completed
from ...infrastructure.log_util import log, with_eval_ctx, get_eval_ctx


def _parse_locator(locator: str) -> tuple[str, str, str]:
    """解析 locator 字符串，返回 (source_file, source_function, source_line)。

    locator 格式可能为：
    - path/to/file.c                        (仅文件路径)
    - path/to/file.c:func_name              (文件+函数)
    - path/to/file.c:func_name:414          (文件+函数+行号)
    - path/to/file.c:func_name:414-420      (文件+函数+行号区间)
    - path/to/file.c:414                    (文件+行号)
    - path/to/file.c:414-420                (文件+行号区间)
    """
    if not locator:
        return "", "", ""

    def _is_line(s: str) -> bool:
        if s.isdigit():
            return True
        if "-" in s:
            nums = s.split("-")
            return len(nums) == 2 and all(n.isdigit() for n in nums)
        return False

    def _extract_line(s: str) -> str:
        return s.split("-")[0] if "-" in s and s.split("-")[0].isdigit() else (s if s.isdigit() else "")

    parts = locator.rsplit(":", 2)
    if len(parts) == 1:
        return parts[0], "", ""
    if len(parts) == 2:
        if _is_line(parts[1]):
            return parts[0], "", _extract_line(parts[1])
        return parts[0], parts[1], ""
    # 3 段：path:func:line
    source_file, source_function, source_line = parts
    if _is_line(source_line):
        return source_file, source_function, _extract_line(source_line)
    return source_file, source_function, ""


def _to_str(value) -> str:
    """将任意值转为字符串。dict/list 用 json.dumps，其他用 str()。"""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _normalize_ac_description(c: dict) -> str:
    """从告警中心 case 提取描述文本。

    告警中心字段类型不确定——raw_report_summary 可能是 dict 而非 str，
    每个字段取值后统一 _to_str 转换，避免 join 崩溃。
    """
    parts = []
    summary = c.get("summary")
    if summary:
        parts.append(_to_str(summary))
    raw_report = c.get("raw_report_summary")
    if raw_report:
        parts.append(_to_str(raw_report))
    display = c.get("display_summary")
    if display:
        parts.append(_to_str(display))
    return "\n".join(parts) if parts else ""


class CaseFilter:
    """从漏洞中心基线出发，筛选 FP/FN case 对应的 DataPack。"""

    def filter_valid_cases(
        self, evaluation_id: str, data_packs: list,
        eval_mode: str = "dev",
        benchmark_source: str = "vbench_zip",
        alert_center_data: dict | None = None,
        case_details: dict | None = None,
        case_session_matches: list[dict] | None = None,
    ) -> list:
        """筛选需要分析的 DataPack。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表
            eval_mode: "dev"（开发态，FP+FN）| "runtime"（运行态，只 FP）
            benchmark_source: "vuln_center"（漏洞中心，纯代码匹配）|
                              "vbench_zip"（V-Bench 测评集，LLM 匹配）
            alert_center_data: 告警中心数据，用于 FP/FN 判定
            case_details: 基线 case 详情 dict（case_id → metadata），
                          由 orchestrator._ingest() 返回的完整基线数据。
            case_session_matches: case_session_matcher 的匹配结果，
                          用于 FP case 的 DataPack 筛选

        Returns:
            需要分析的 DataPack 列表
        """
        # 按 task_id 分组 DataPack（一个 task 可能有挖掘+验证多个 agent）
        groups: dict[str, list[DataPack]] = defaultdict(list)
        for dp in data_packs:
            groups[dp.task_id].append(dp)

        # 收集基线 case：优先从 case_details（完整 33 条），回退到 data_packs
        baseline_cases: list[dict] = []
        if case_details:
            for cid, md in case_details.items():
                baseline_cases.append({
                    "case_id": cid,
                    "expected_label": md.get("expected_label", ""),
                    "title": md.get("vulnerability_type", ""),
                    "description": md.get("description", ""),
                    "source_file": md.get("source_file", ""),
                    "source_line": md.get("source_line", ""),
                    "source_function": md.get("source_function", ""),
                })
        else:
            # 回退：从 data_packs 的 benchmark_item.metadata 收集
            seen_case_ids: set[str] = set()
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

        # 归一化告警中心 case 为与基线同构的字典
        ac_cases: list[dict] = []
        if alert_center_data:
            for c in alert_center_data.get("cases", []):
                subject = c.get("subject") or {}
                locator = subject.get("locator") or ""
                source_file, source_function, source_line = (
                    _parse_locator(locator)
                )
                ac_cases.append({
                    "case_id": c.get("id") or "",
                    "title": c.get("title") or subject.get("type") or "",
                    "description": _normalize_ac_description(c),
                    "source_file": source_file,
                    "source_function": source_function,
                    "source_line": source_line,
                    "validation_result": c.get("validation_result") or "",
                })

        # ── FN 筛选：基线 VULNERABLE → 与告警中心对比 ──
        fn_cases = [bc for bc in baseline_cases
                    if bc["expected_label"] == "VULNERABLE"]

        # 基线漏洞与告警中心匹配
        # 告警中心有匹配 → agent 上报了该漏洞，不是漏报
        # 告警中心无匹配 → agent 漏报了该漏洞
        if benchmark_source == "vuln_center":
            fn_match_map = self._match_by_code(
                evaluation_id, fn_cases, ac_cases)
        else:
            fn_match_map = self._match_by_llm(
                evaluation_id, fn_cases, ac_cases)

        # ── 组装有效 DataPack ──
        valid_packs: list[DataPack] = []
        unmatched_cases: list[dict] = []

        # 处理 FN
        fn_baseline_cases = [bc for bc in fn_cases
                             if bc["case_id"] not in fn_match_map]

        for bc in fn_baseline_cases:
            cid = bc["case_id"]
            title = bc["title"]

            unmatched_cases.append({
                "case_id": cid,
                "expected_label": "VULNERABLE",
                "title": title,
                "reason": "FN: no matching case in alert center",
            })
            log("CASE_FILTER",
                f"FN case {cid}: no alert center match "
                f"(title={title[:60]})",
                eval_id=evaluation_id)
            # FN case 需要分析所有 task 的知识访问
            for task_id, packs in groups.items():
                kp = self._get_packs_with_knowledge(groups, task_id)
                if kp:
                    log("CASE_FILTER",
                        f"keep case {cid}: FN (task={task_id}, "
                        f"{len(kp)} packs)",
                        eval_id=evaluation_id)
                    valid_packs.extend(kp)
                    break

        # ── FP 筛选：基线 NON_VULNERABLE → 从 case_session_matches 拿 verify_sessions ──
        fp_matches = [m for m in (case_session_matches or [])
                      if m.get("outcome") == "FP"]
        for m in fp_matches:
            cid = m.get("case_id", "")
            verify_sids = m.get("verify_sessions", [])
            if not verify_sids:
                continue

            # 找到包含 verify_sessions 的 DataPack
            # 一个 verify session 可能跨多个 DataPack（挖掘+验证）
            case_packs: list[DataPack] = []
            seen_packs: set[int] = set()
            for dp in data_packs:
                sg = dp.session_graph or {}
                sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
                parent_map = sg.get("parent_map", {}) if isinstance(sg, dict) else {}

                # 检查这个 DataPack 是否包含 verify_sessions 或其祖先 session
                # 沿 parent_map 追溯：verify_session → root
                chain_sids: set[str] = set()
                for vsid in verify_sids:
                    cur = vsid
                    while cur and cur in sessions and cur not in chain_sids:
                        chain_sids.add(cur)
                        cur = parent_map.get(cur, "")

                # 这个 DataPack 的 sessions 与 case 链有交集
                if chain_sids & set(sessions.keys()):
                    if id(dp) not in seen_packs:
                        seen_packs.add(id(dp))
                        case_packs.append(dp)

            # 只保留有知识访问的 DataPack
            kp = [dp for dp in case_packs
                  if dp.knowledge_fact is not None
                  and (getattr(dp.knowledge_fact, "access", False)
                       or getattr(dp.knowledge_fact, "memory_access", False))]

            if kp:
                log("CASE_FILTER",
                    f"FP case {cid}: {len(kp)} packs with knowledge "
                    f"(verify_sessions={verify_sids})",
                    eval_id=evaluation_id)
                valid_packs.extend(kp)
            else:
                log("CASE_FILTER",
                    f"FP case {cid}: no packs with knowledge access "
                    f"(verify_sessions={verify_sids})",
                    eval_id=evaluation_id)

        log("CASE_FILTER",
            f"filtered {len(valid_packs)}/{len(data_packs)} packs "
            f"from {len(baseline_cases)} baseline cases "
            f"(mode={eval_mode}, source={benchmark_source}, "
            f"fn_cases={len(fn_baseline_cases)}, "
            f"fp_cases={len(fp_matches)}, "
            f"unmatched={len(unmatched_cases)})",
            eval_id=evaluation_id)

        # 将 unmatched_cases 存到类属性，供报告读取
        self.unmatched_cases = unmatched_cases

        return valid_packs

    # ── 纯代码匹配（漏洞中心）──

    @staticmethod
    def _match_by_code(
        evaluation_id: str,
        baseline_cases: list[dict],
        ac_cases: list[dict],
    ) -> dict[str, dict]:
        """纯代码匹配：case_id / 标题 / 内容。

        适用于漏洞中心基线（case_id 与告警中心 case 有直接对应关系）。

        Returns:
            {case_id: matched_ac_case_dict}
        """
        result: dict[str, dict] = {}
        for bc in baseline_cases:
            cid = bc["case_id"]
            title = bc["title"]
            desc = bc["description"]
            matched = CaseFilter._match_case(cid, title, desc, ac_cases)
            if matched is not None:
                result[cid] = matched
        return result

    @staticmethod
    def _match_case(case_id: str, title: str, description: str,
                    ac_cases: list[dict]) -> dict | None:
        """在告警中心 case 列表中找到与基线 case 对应的记录。

        匹配优先级：
        1. case_id 直接匹配
        2. 标题匹配
        3. 内容匹配
        """
        # 1. case_id 直接匹配
        for c in ac_cases:
            ac_id = str(c.get("case_id") or "")
            if ac_id and ac_id == case_id:
                return c

        # 2. 标题匹配
        if title:
            title_lower = title.lower().strip()
            for c in ac_cases:
                c_title = str(c.get("title") or "").lower().strip()
                if c_title and c_title == title_lower:
                    return c
                # 部分匹配（标题包含关系）
                if c_title and title_lower and (
                    title_lower in c_title or c_title in title_lower
                ):
                    return c

        # 3. 内容匹配（description 关键词）
        if description:
            desc_sample = description.lower()
            for c in ac_cases:
                c_desc = str(c.get("description") or "").lower()
                if c_desc and desc_sample and desc_sample in c_desc:
                    return c

        return None

    # ── LLM 匹配（V-Bench 测评集）──

    def _match_by_llm(
        self,
        evaluation_id: str,
        baseline_cases: list[dict],
        ac_cases: list[dict],
    ) -> dict[str, dict]:
        """LLM 匹配：两阶段（标题预筛 → 1vs1 详细对比）。

        适用于 V-Bench 测评集基线（case 与告警中心 case 结构不同，
        无法用标题/内容直接匹配）。

        Returns:
            {case_id: matched_ac_case_dict}
        """
        if not baseline_cases or not ac_cases:
            log("CASE_FILTER",
                f"LLM match skipped: {len(baseline_cases)} baseline_cases, "
                f"{len(ac_cases)} ac_cases",
                eval_id=evaluation_id)
            return {}

        log("CASE_FILTER",
            f"LLM match: {len(baseline_cases)} baseline_cases × "
            f"{len(ac_cases)} ac_cases",
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
        ac_list = []
        for c in ac_cases:
            ac_list.append({
                "case_id": c.get("case_id", ""),
                "title": c.get("title", ""),
                "description": c.get("description") or "",
                "source_file": c.get("source_file", ""),
            })

        # Phase 1: 标题预筛（每基线 1 次 LLM）
        prefilter_candidates = self._llm_prefilter(
            evaluation_id, baseline_list, ac_list)

        # Phase 2: 1vs1 详细对比
        pair_results = self._llm_detail_match(
            evaluation_id, baseline_list, ac_list,
            prefilter_candidates)

        # 冲突解决：按基线顺序分配，先到先得（1:1）
        available_ac_indices = set(range(len(ac_cases)))
        result: dict[str, dict] = {}

        for bi, bc in enumerate(baseline_cases):
            candidates = prefilter_candidates.get(
                bi, list(range(len(ac_cases))))
            candidates = [fi for fi in candidates
                          if fi in available_ac_indices]

            best_fi = None
            best_score = 0.0
            for fi in candidates:
                score = pair_results.get((bi, fi), 0.0)
                if score > best_score:
                    best_score = score
                    best_fi = fi

            if best_fi is not None and best_score >= 0.5:
                available_ac_indices.discard(best_fi)
                matched_ac = ac_cases[best_fi]
                result[bc["case_id"]] = matched_ac
                log("CASE_FILTER",
                    f"LLM MATCHED case {bc['case_id']} ← "
                    f"ac[{best_fi}] (score={best_score:.2f})",
                    eval_id=evaluation_id)

        return result

    def _llm_prefilter(
        self,
        evaluation_id: str,
        baseline_list: list[dict],
        ac_list: list[dict],
    ) -> dict[int, list[int]]:
        """Phase 1: 每个基线 case 用 LLM 预筛候选告警中心 case。

        返回 {baseline_idx: [ac_idx, ...]}
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
            bl_desc = bl.get("description", "") or ""
            lines = [
                f"基线案例标题：{bl.get('title', '')}",
                f"基线案例描述：{bl_desc}",
                "",
                "以下是要比较的漏洞报告：",
            ]
            for i, c in enumerate(ac_list[:_PREFILTER_LIMIT]):
                fid = str(i)
                id_to_idx[fid] = i
                c_title = c.get("title", "")
                c_desc = c.get("description", "") or ""
                lines.append(f"[{fid}] {c_title}\n描述：{c_desc}")
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
                        indices = list(range(len(ac_list)))
                        log("CASE_FILTER",
                            f"prefilter 0 candidates (bl{bi}): fallback all",
                            eval_id=evaluation_id)
                    prefilter_candidates[bi] = indices
                except Exception as e:
                    prefilter_candidates[bi] = list(range(len(ac_list)))
                    log("CASE_FILTER",
                        f"prefilter FAILED (bl{bi}): {e}, fallback all",
                        eval_id=evaluation_id)
        except Exception:
            for bi in items:
                prefilter_candidates.setdefault(
                    bi, list(range(len(ac_list))))

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
        ac_list: list[dict],
        prefilter_candidates: dict[int, list[int]],
    ) -> dict[tuple[int, int], float]:
        """Phase 2: 1vs1 LLM 详细对比 + 程序校验 sink。

        返回 {(baseline_idx, ac_idx): score}
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
            '  "baseline": {"source_file": "...", "vuln_type": "..."},\n'
            '  "candidate": {"source_file": "...", "vuln_type": "..."},\n'
            '  "same_source": true/false,\n'
            '  "same_vuln_type": true/false,\n'
            '  "desc_similarity": 0.0-1.0,\n'
            '  "reason": "简要说明每个方面的判断理由"\n'
            '}'
        )

        # 收集所有 (baseline_idx, ac_idx) 对
        all_pairs: list[tuple[int, int]] = []
        for bi in range(len(baseline_list)):
            candidates = prefilter_candidates.get(
                bi, list(range(len(ac_list))))
            for fi in candidates:
                all_pairs.append((bi, fi))

        log("CASE_FILTER",
            f"detail_match: {len(all_pairs)} pairs to check",
            eval_id=evaluation_id)

        def _check_pair(pair: tuple[int, int]) -> tuple[int, int, float]:
            bi, fi = pair
            bl = baseline_list[bi]
            c = ac_list[fi]

            bl_desc = f"标题: {bl.get('title', '')}\n描述: {bl.get('description', '')}"
            bl_src = bl.get("source_file", "")
            if bl_src:
                bl_desc += f"\n代码文件: {bl_src}"

            c_desc = f"标题: {c.get('title', '')}\n描述: {c.get('description', '')}"
            c_src = c.get("source_file", "")
            if c_src:
                c_desc += f"\n代码文件: {c_src}"

            prompt = [
                {"role": "system", "content": _sys_prompt},
                {"role": "user", "content": (
                    f"参考漏洞:\n{bl_desc}\n\n"
                    f"待判定漏洞:\n{c_desc}\n\n"
                    f"提取三个方面信息并判断是否同一个漏洞。"
                )},
            ]
            try:
                result = llm_mod.chat_json(prompt, temperature=0,
                                            reasoning_effort="none")
                same_source = _parse_bool(result.get("same_source", False))
                same_vuln_type = _parse_bool(result.get("same_vuln_type", False))
                desc_sim = result.get("desc_similarity")
                try:
                    desc_sim = float(desc_sim) if desc_sim is not None else 0.0
                except (ValueError, TypeError):
                    desc_sim = 0.0

                # 程序校验 source 路径
                src_check = _verify_path(bl_src, c_src)
                if src_check is False and same_source:
                    same_source = False
                elif src_check is True and not same_source:
                    same_source = True

                # 匹配条件：vuln_type 必须为 true，且满足以下之一：
                # 1. source 为 true，且描述相似度 >= 0.5
                # 2. source 为 false，但描述相似度 >= 0.6
                is_same = same_vuln_type and (
                    (same_source and desc_sim >= 0.5) or
                    ((not same_source) and desc_sim >= 0.6)
                )
                return bi, fi, desc_sim if is_same else 0.0
            except Exception as e:
                log("CASE_FILTER",
                    f"LLM detail FAILED (bl{bi},ac{fi}): {e}",
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


# ── 模块级工具函数 ──


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


def _verify_path(baseline_path: str, ac_path: str) -> bool | None:
    """代码校验文件路径是否一致。返回 True/False，None=无法确定。"""
    bl = _norm_path(baseline_path)
    fl = _norm_path(ac_path)
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
