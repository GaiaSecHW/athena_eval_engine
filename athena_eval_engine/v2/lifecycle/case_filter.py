"""有效 case 筛选模块（§4.4）。

从漏洞中心人工确认数据出发，筛选需要分析的 case。

漏洞中心基线已有两类人工确认 case：
- confirmation_status=vulnerable → expected_label=VULNERABLE（有漏洞）
- confirmation_status=not_vulnerable → expected_label=NON_VULNERABLE（非漏洞）

case 类型判定（纯代码，不需要 LLM）：
- FP（误报）：expected_label=NON_VULNERABLE + trace 里有对应 finding 且 validation_result=CONFIRMED
- FN（漏报）：expected_label=VULNERABLE + trace 里无对应 finding 或 validation_result=FALSE_POSITIVE

"对应"的匹配方式：
1. finding_id（case_id）直接匹配
2. 标题（vulnerability_type）+ 内容（description）文本匹配

按 eval_mode 筛选：
- runtime（运行态）：只分析 FP
- dev（开发态）：分析 FP + FN

找不到对应 trace 的 case 在返回结果中标记，供报告告警。
"""
from __future__ import annotations

import re
from collections import defaultdict

from ..core.data_pack import DataPack
from ...infrastructure.log_util import log


class CaseFilter:
    """从漏洞中心基线出发，筛选 FP/FN case 对应的 DataPack。"""

    def filter_valid_cases(
        self, evaluation_id: str, data_packs: list,
        eval_mode: str = "dev",
    ) -> list:
        """筛选需要分析的 DataPack。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表
            eval_mode: "dev"（开发态，FP+FN）| "runtime"（运行态，只 FP）

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

        valid_packs: list[DataPack] = []
        unmatched_cases: list[dict] = []  # 找不到对应 trace 的 case

        for bc in baseline_cases:
            cid = bc["case_id"]
            gt = bc["expected_label"]
            title = bc["title"]
            desc = bc["description"]

            # 在 all_findings 中找对应的 finding
            matched_finding = self._match_finding(cid, title, desc, all_findings)

            if matched_finding is None:
                # 找不到对应 trace → 记录告警
                unmatched_cases.append({
                    "case_id": cid,
                    "expected_label": gt,
                    "title": title,
                    "reason": "no matching finding in trace",
                })
                log("CASE_FILTER",
                    f"unmatched case {cid}: no finding in trace "
                    f"(gt={gt}, title={title[:60]})",
                    eval_id=evaluation_id)
                continue

            vr = matched_finding.get("validation_result", "")
            task_id = matched_finding.get("_task_id", "")

            # 判定 case 类型
            is_fp = self._is_fp(gt, vr)
            is_fn = self._is_fn(gt, vr)

            if is_fp:
                # FP：保留该 task 下有知识访问的 DataPack
                packs = self._get_packs_with_knowledge(groups, task_id)
                if packs:
                    log("CASE_FILTER",
                        f"keep case {cid}: FP (gt={gt}, vr={vr}, "
                        f"task={task_id}, {len(packs)} packs)",
                        eval_id=evaluation_id)
                    valid_packs.extend(packs)
                else:
                    unmatched_cases.append({
                        "case_id": cid,
                        "expected_label": gt,
                        "title": title,
                        "reason": "FP but no knowledge access in trace",
                    })
            elif is_fn and eval_mode == "dev":
                # FN：保留该 task 下有知识访问的 DataPack
                packs = self._get_packs_with_knowledge(groups, task_id)
                if packs:
                    log("CASE_FILTER",
                        f"keep case {cid}: FN (gt={gt}, vr={vr}, "
                        f"task={task_id}, {len(packs)} packs)",
                        eval_id=evaluation_id)
                    valid_packs.extend(packs)
                else:
                    unmatched_cases.append({
                        "case_id": cid,
                        "expected_label": gt,
                        "title": title,
                        "reason": "FN but no knowledge access in trace",
                    })
            else:
                log("CASE_FILTER",
                    f"skip case {cid}: not FP/FN "
                    f"(gt={gt}, vr={vr}, mode={eval_mode})",
                    eval_id=evaluation_id)

        log("CASE_FILTER",
            f"filtered {len(valid_packs)}/{len(data_packs)} packs "
            f"from {len(baseline_cases)} baseline cases "
            f"(mode={eval_mode}, unmatched={len(unmatched_cases)})",
            eval_id=evaluation_id)

        # 将 unmatched_cases 存到类属性，供报告读取
        self.unmatched_cases = unmatched_cases

        return valid_packs

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
            fid = str(f.get("finding_id") or f.get("display_id") or "")
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

    @staticmethod
    def _is_fp(gt: str, validation_result: str) -> bool:
        """FP = 基线标注非漏洞 + agent 确认了漏洞。

        expected_label=NON_VULNERABLE + validation_result=CONFIRMED
        → agent 误报了漏洞
        """
        return gt == "NON_VULNERABLE" and validation_result == "CONFIRMED"

    @staticmethod
    def _is_fn(gt: str, validation_result: str) -> bool:
        """FN = 基线标注有漏洞 + agent 没确认。

        expected_label=VULNERABLE + validation_result != CONFIRMED
        （FALSE_POSITIVE / None / UNCERTAIN）
        """
        return gt == "VULNERABLE" and validation_result != "CONFIRMED"

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
