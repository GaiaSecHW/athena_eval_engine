"""有效 case 筛选模块（§4.4）。

按 eval_mode 筛选需要分析的 case：

- runtime（运行态）：只分析 FP case（人工标注误报）
  FP = expected_label=NON_VULNERABLE + validation_result=CONFIRMED
  （agent 报了漏洞，但基线标注为非漏洞）

- dev（开发态）：分析 FP + FN case（误报 + 漏报）
  FP = 同上
  FN = expected_label=VULNERABLE + agent 未报或报 FALSE_POSITIVE
  FN 的 case 需通过 sink-point 匹配确认 agent 接触过漏洞文件

前置条件（所有 case 都需满足）：
1. outcome_fact 不为 None
2. knowledge_fact 不为 None 且有知识访问记录
3. benchmark_item 不为 None
"""
from __future__ import annotations

import re

from ..core.data_pack import DataPack
from ..infra.database import connect
from ...infrastructure.log_util import log


class CaseFilter:
    """按 eval_mode 筛选需要分析的 case。

    筛选逻辑：
    1. 所有 case 需满足前置条件（outcome/knowledge/benchmark 非空）
    2. 按 eval_mode 过滤 case 类型：
       - runtime：只保留 FP
       - dev：保留 FP + FN
    3. FP 通过 validation_result=CONFIRMED 识别
    4. FN 通过 sink-point 匹配确认 agent 接触过漏洞文件
    """

    def filter_valid_cases(
        self, evaluation_id: str, data_packs: list,
        eval_mode: str = "dev",
    ) -> list:
        """从 data_packs 中筛选需要分析的 case。

        Args:
            evaluation_id: 评测 ID
            data_packs: DataPack 列表
            eval_mode: "dev"（开发态，FP+FN）| "runtime"（运行态，只 FP）

        Returns:
            需要分析的 DataPack 列表
        """
        valid_packs: list[DataPack] = []

        for dp in data_packs:
            # ── 前置条件 ──
            if dp.outcome_fact is None:
                log("CASE_FILTER", f"skip {dp.task_run_id}: no outcome_fact",
                    eval_id=evaluation_id)
                continue

            if dp.knowledge_fact is None:
                log("CASE_FILTER", f"skip {dp.task_run_id}: no knowledge_fact",
                    eval_id=evaluation_id)
                continue

            kf = dp.knowledge_fact
            has_knowledge_access = (
                getattr(kf, "access", False)
                or getattr(kf, "memory_access", False)
            )
            if not has_knowledge_access:
                log("CASE_FILTER",
                    f"skip {dp.task_run_id}: no knowledge access record",
                    eval_id=evaluation_id)
                continue

            if dp.benchmark_item is None:
                log("CASE_FILTER", f"skip {dp.task_run_id}: no benchmark_item",
                    eval_id=evaluation_id)
                continue

            # ── 按 eval_mode 筛选 case 类型 ──
            of = dp.outcome_fact
            gt = str(of.gt_label) if of.gt_label else ""
            vr = of.validation_result or ""
            is_fp = self._is_fp(gt, vr)
            is_fn = self._is_fn(dp, gt, vr, evaluation_id)

            if is_fp:
                log("CASE_FILTER",
                    f"keep {dp.task_run_id}: FP case (gt={gt}, vr={vr})",
                    eval_id=evaluation_id)
                valid_packs.append(dp)
            elif is_fn and eval_mode == "dev":
                log("CASE_FILTER",
                    f"keep {dp.task_run_id}: FN case (gt={gt}, vr={vr})",
                    eval_id=evaluation_id)
                valid_packs.append(dp)
            else:
                log("CASE_FILTER",
                    f"skip {dp.task_run_id}: not FP/FN "
                    f"(gt={gt}, vr={vr}, mode={eval_mode})",
                    eval_id=evaluation_id)

        log("CASE_FILTER",
            f"filtered {len(valid_packs)}/{len(data_packs)} valid cases "
            f"(mode={eval_mode})",
            eval_id=evaluation_id)
        return valid_packs

    @staticmethod
    def _is_fp(gt: str, validation_result: str) -> bool:
        """FP = 基线标注非漏洞 + agent 确认了漏洞。

        expected_label=NON_VULNERABLE + validation_result=CONFIRMED
        → agent 误报了漏洞
        """
        return gt == "NON_VULNERABLE" and validation_result == "CONFIRMED"

    @staticmethod
    def _is_fn(dp: DataPack, gt: str, validation_result: str,
              evaluation_id: str) -> bool:
        """FN = 基线标注有漏洞 + agent 没报或报了 FALSE_POSITIVE。

        需通过 sink-point 匹配确认 agent 接触过漏洞文件，
        才能判断为漏报（而非完全不相关的 case）。

        expected_label=VULNERABLE + (validation_result 为 FALSE_POSITIVE/None)
        + sink-point 匹配到 agent 读取过漏洞文件
        """
        if gt != "VULNERABLE":
            return False
        # agent 报了漏洞且确认 → TP，不是 FN
        if validation_result == "CONFIRMED":
            return False

        # agent 没报 (NO_FINDING/None) 或报了 FALSE_POSITIVE → 可能是 FN
        # 需通过 sink-point 匹配确认 agent 接触过漏洞文件
        bm = dp.benchmark_item
        if bm is None or bm.metadata is None:
            return False

        md = bm.metadata
        source_file = md.get("source_file", "")
        source_line = md.get("source_line", "")
        source_function = md.get("source_function", "")

        if not source_file:
            # 无 sink 信息，无法确认关联性，不作为 FN
            return False

        # 检查 agent 是否读取过漏洞文件（sink-point 匹配）
        file_reads = _build_file_read_index(dp.events or [])
        sink_sessions = _find_sink_sessions(
            file_reads, source_file, source_line, source_function,
        )
        if sink_sessions:
            log("CASE_FILTER",
                f"FN confirmed: {dp.task_run_id} touched sink "
                f"file={_basename(source_file)} sessions={sink_sessions}",
                eval_id=evaluation_id)
            return True

        return False


# ── sink-point 匹配（从 workers/sink_matcher.py 复用逻辑）──


def _basename(path: str) -> str:
    """跨平台 basename。"""
    if not path:
        return ""
    parts = re.split(r'[/\\]', path)
    return parts[-1] if parts else path


def _build_file_read_index(events: list) -> list[dict]:
    """从 trace 事件中提取所有文件读取操作。

    覆盖 read 工具和 bash 工具（cat/grep/head/tail/sed）。
    返回: [{file_path, basename, offset, limit, content, session_id, timestamp}, ...]
    """
    # 构建 call_id → TOOL_RESULT 映射
    result_by_call_id: dict[str, str] = {}
    for e in events:
        if e.event_type == "TOOL_RESULT" and e.call_id:
            output = e.output_json
            if isinstance(output, str):
                result_by_call_id[e.call_id] = output
            elif output is not None:
                result_by_call_id[e.call_id] = str(output)

    reads: list[dict] = []
    for e in events:
        if e.event_type != "TOOL_CALL":
            continue
        tool = e.tool_name or ""
        inp = e.input_json or {}
        content = result_by_call_id.get(e.call_id, "") if e.call_id else ""

        if tool == "read":
            fp = str(inp.get("file_path") or inp.get("filePath") or inp.get("path") or "")
            if not fp:
                continue
            offset = inp.get("offset")
            limit = inp.get("limit")
            reads.append({
                "file_path": fp,
                "basename": _basename(fp),
                "offset": int(offset) if offset is not None and str(offset).isdigit() else None,
                "limit": int(limit) if limit is not None and str(limit).isdigit() else None,
                "content": content,
                "session_id": e.session_id,
                "timestamp": e.timestamp_ms or 0,
            })
        elif tool == "bash":
            cmd = str(inp.get("command") or "")
            if not cmd:
                continue
            for match in re.findall(r'[\w\-./]+\.[a-zA-Z]{1,6}', cmd):
                basename = _basename(match)
                if not basename or len(basename) >= 80 or basename.startswith('.'):
                    continue
                reads.append({
                    "file_path": match,
                    "basename": basename,
                    "offset": None,
                    "limit": None,
                    "content": content,
                    "session_id": e.session_id,
                    "timestamp": e.timestamp_ms or 0,
                })

    return reads


def _find_sink_sessions(file_reads: list[dict], source_file: str,
                        source_line: str, source_function: str) -> list[str]:
    """检查文件读取是否覆盖了基线的 sink 点。

    匹配条件：文件名一致 AND（行号在 read 范围内 OR 行号在返回内容里 OR 方法名在返回内容里）
    返回命中的 session_id 列表（去重）。
    """
    if not source_file:
        return []

    target_basename = _basename(source_file)
    has_line = bool(source_line)
    has_func = bool(source_function)

    # 无行号也无方法名 → 文件名匹配即可
    if not has_line and not has_func:
        matched = set()
        for r in file_reads:
            if r["basename"] == target_basename:
                matched.add(r["session_id"])
        return list(matched)

    target_line = None
    if has_line:
        try:
            target_line = int(source_line)
        except ValueError:
            target_line = None

    matched = set()
    for r in file_reads:
        if r["basename"] != target_basename:
            continue
        if target_line is not None:
            if r["offset"] is not None and r["limit"] is not None:
                if r["offset"] <= target_line <= r["offset"] + r["limit"]:
                    matched.add(r["session_id"])
                    continue
            if re.search(r'(?:^|\n)' + str(target_line) + r'\b', r["content"]):
                matched.add(r["session_id"])
                continue
        if has_func and re.search(r'\b' + re.escape(source_function) + r'\b', r["content"]):
            matched.add(r["session_id"])
            continue

    return list(matched)
