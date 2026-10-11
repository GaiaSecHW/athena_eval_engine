"""回归验证模块（§5.5 产出闭环 + §6.1 Case 重放协议）。

从漏洞中心或重放 Trace 读取重放后的判定结论，对比原始误报判定，
判定知识改进后误报是否消除。

核心流程：
1. 对每个原始 FP case，从漏洞中心 Chimera 按 case_id 查询重放后的 verdict
   （或从 replay_trace_dir 解析重放 Trace 提取 verdict）
2. 对比原始判定（FP）与重放判定（TN/FP/TP）
3. 统计消除率：FP→TN = 已消除，FP→FP = 未消除，FP→TP = 异常

消除率 NA 契约：total_fp=0 时返回 elimination_rate=None + reason_code="NO_FP_CASES"。

延迟 import vuln_center_client：该模块属于老代码 infrastructure 层，
v2 模块不在启动时硬依赖它，仅在实际查询时才加载。
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable

from ...infrastructure.log_util import log

# ── 延迟 import：漏洞中心客户端（老代码 infrastructure 层）──

try:
    from ...infrastructure.vuln_center_client import (
        search_vuln_cases as _search_vuln_cases,
        list_vuln_cases as _list_vuln_cases,
    )
except ImportError:
    _search_vuln_cases = None
    _list_vuln_cases = None


# ── verdict 常量 ──────────────────────────────────────────

# 重放判定结果（本模块输出）
REPLAY_TRUE_NEGATIVE = "TRUE_NEGATIVE"
REPLAY_FALSE_POSITIVE = "FALSE_POSITIVE"
REPLAY_TRUE_POSITIVE = "TRUE_POSITIVE"

# 原始判定值（original_fp_cases 中的 original_verdict 字段）
_ORIGINAL_FP = "FALSE_POSITIVE"

# 漏洞中心 confirmation_status → verdict 映射
_CONFIRM_STATUS_MAP = {
    "vulnerable": REPLAY_TRUE_POSITIVE,       # 人工确认是漏洞 → TP
    "not_vulnerable": REPLAY_TRUE_NEGATIVE,   # 人工确认非漏洞 → TN
}

# 告警中心 validation_result → verdict 映射
_VALIDATION_RESULT_MAP = {
    "vulnerable": REPLAY_TRUE_POSITIVE,        # 引擎判定是漏洞 → TP
    "not_vulnerable": REPLAY_TRUE_NEGATIVE,    # 引擎判定非漏洞 → TN
    "inconclusive": None,                      # 无法判定 → 未知
}


class ReplayVerifier:
    """回归验证器 — 对比原始误报判定与重放判定，判定误报是否消除。

    输入：原始 FP case 列表（含 case_id, vuln_type 等）+ 可选重放 trace 目录
    输出：消除统计 + 逐 case 结果

    verdict 来源优先级：
    1. replay_trace_dir 提供时，从重放 Trace 解析 verdict（按 replay=true 标记）
    2. replay_trace_dir 为 None 时，从漏洞中心 Chimera 按 case_id 查询 verdict
    """

    def __init__(self, project_id: str = "", llm_client: Any = None):
        """初始化回归验证器。

        Args:
            project_id: 项目 ID，用于漏洞中心 API 查询。
                        如果未提供，尝试从环境变量或 case 数据中获取。
            llm_client: 可选的 LLM 客户端（预留，当前实现不使用 LLM）。
        """
        self.project_id = project_id
        self.llm = llm_client

    def verify_replay(
        self,
        evaluation_id: str,
        original_fp_cases: list[dict],
        replay_trace_dir: str | None = None,
        cancel_cb: Callable[[], None] | None = None,
    ) -> dict:
        """回归验证：对比原始判定与重放判定，判定误报是否消除。

        Args:
            evaluation_id: 评测 ID。
            original_fp_cases: 原始误报 case 列表，每个 case 至少含::
                - case_id: case 标识符
                - vuln_type: 漏洞类型（可选，用于日志）
                - original_verdict: 原始判定（应为 FALSE_POSITIVE）
            replay_trace_dir: 重放 trace 目录（可选）。
                              提供时优先从该目录解析重放 trace 的 verdict；
                              为 None 时从漏洞中心查询。
            cancel_cb: 取消检查回调，被取消时抛异常中止。

        Returns:
            {
                "evaluation_id": "...",
                "total_fp": N,
                "eliminated": M,       # FP→TN 数量
                "not_eliminated": K,   # FP→FP 数量
                "anomaly": L,           # FP→TP 数量（异常）
                "elimination_rate": M/N or None,
                "reason_code": None or "NO_FP_CASES",
                "per_case_results": [...]
            }
        """
        total_fp = len(original_fp_cases)

        # NA 契约：零 FP case
        if total_fp == 0:
            log("REPLAY", f"no FP cases for eval={evaluation_id}, returning NA",
                eval_id=evaluation_id)
            return {
                "evaluation_id": evaluation_id,
                "total_fp": 0,
                "eliminated": 0,
                "not_eliminated": 0,
                "anomaly": 0,
                "elimination_rate": None,
                "reason_code": "NO_FP_CASES",
                "per_case_results": [],
            }

        log("REPLAY",
            f"verify_replay: {total_fp} FP cases for eval={evaluation_id}, "
            f"replay_trace_dir={'provided' if replay_trace_dir else 'None (query vuln center)'}",
            eval_id=evaluation_id)

        per_case_results: list[dict] = []
        eliminated = 0
        not_eliminated = 0
        anomaly = 0

        for i, case in enumerate(original_fp_cases):
            # 取消检查
            if cancel_cb:
                cancel_cb()

            case_id = case.get("case_id", "")
            vuln_type = case.get("vuln_type", "")
            original_verdict = case.get("original_verdict", _ORIGINAL_FP)

            if not case_id:
                log("REPLAY",
                    f"case at index {i} has no case_id, skipping",
                    eval_id=evaluation_id)
                continue

            # 获取重放判定
            replay_verdict = self._fetch_replay_verdict(
                case_id, replay_trace_dir=replay_trace_dir)

            # 判定 FP 是否消除
            elimination = self._determine_elimination(
                original_verdict, replay_verdict)

            if elimination["eliminated"]:
                eliminated += 1
            elif elimination["anomaly"]:
                anomaly += 1
            else:
                not_eliminated += 1

            per_case_results.append({
                "case_id": case_id,
                "vuln_type": vuln_type,
                "original_verdict": original_verdict,
                "replay_verdict": replay_verdict,
                "eliminated": elimination["eliminated"],
                "anomaly": elimination["anomaly"],
            })

            log("REPLAY",
                f"case={case_id} vuln_type={vuln_type} "
                f"original={original_verdict} replay={replay_verdict} "
                f"→ {'eliminated' if elimination['eliminated'] else 'anomaly' if elimination['anomaly'] else 'not_eliminated'}",
                eval_id=evaluation_id)

        elimination_rate = (
            eliminated / total_fp if total_fp > 0 else None
        )

        log("REPLAY",
            f"verify_replay done: total={total_fp} eliminated={eliminated} "
            f"not_eliminated={not_eliminated} anomaly={anomaly} "
            f"rate={elimination_rate:.1%}" if elimination_rate is not None
            else f"verify_replay done: total={total_fp} rate=None",
            eval_id=evaluation_id)

        return {
            "evaluation_id": evaluation_id,
            "total_fp": total_fp,
            "eliminated": eliminated,
            "not_eliminated": not_eliminated,
            "anomaly": anomaly,
            "elimination_rate": elimination_rate,
            "reason_code": None,
            "per_case_results": per_case_results,
        }

    def _fetch_replay_verdict(
        self,
        case_id: str,
        replay_trace_dir: str | None = None,
    ) -> str:
        """从漏洞中心或重放 Trace 读取重放后的判定结论。

        优先级：
        1. replay_trace_dir 提供时，从重放 Trace 解析 verdict（按 replay=true 标记）
        2. replay_trace_dir 为 None 时，从漏洞中心 Chimera 按 case_id 查询

        Args:
            case_id: case 标识符。
            replay_trace_dir: 重放 trace 目录（可选）。

        Returns:
            TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE
            如果无法获取重放判定，返回 FALSE_POSITIVE（保守降级：假定未消除）。
        """
        # 优先从重放 Trace 读取
        if replay_trace_dir:
            trace_verdict = self._extract_verdict_from_trace(
                case_id, replay_trace_dir)
            if trace_verdict:
                return trace_verdict
            # Trace 中未找到该 case 的重放记录，继续走漏洞中心查询
            log("REPLAY",
                f"case={case_id} not found in replay trace dir, "
                f"falling back to vuln center")

        # 从漏洞中心查询
        return self._query_vuln_center_verdict(case_id)

    def _extract_verdict_from_trace(
        self,
        case_id: str,
        replay_trace_dir: str,
    ) -> str | None:
        """从重放 Trace 目录解析指定 case 的重放判定结论。

        重放 Trace 中标记 replay=true，携带 original_case_id。
        扫描目录下的 JSONL 文件，查找匹配的 replay trace，
        从 trace 末尾的判定事件中提取 verdict。

        Args:
            case_id: 原始 case ID（用于匹配 original_case_id）。
            replay_trace_dir: 重放 trace 目录路径。

        Returns:
            TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE / None（未找到）
        """
        if not replay_trace_dir or not os.path.isdir(replay_trace_dir):
            return None

        # 扫描目录下所有 JSONL 文件，查找 replay=true 且 original_case_id 匹配的
        for root, _dirs, files in os.walk(replay_trace_dir):
            for fname in sorted(files):
                if not fname.endswith(".jsonl"):
                    continue
                fpath = os.path.join(root, fname)
                verdict = self._scan_jsonl_for_replay_verdict(
                    fpath, case_id)
                if verdict:
                    return verdict

        return None

    def _scan_jsonl_for_replay_verdict(
        self,
        fpath: str,
        case_id: str,
    ) -> str | None:
        """扫描单个 JSONL 文件，查找 replay 标记并提取 verdict。

        重放 trace 的事件结构因 Agent 不同而异，但共同特征：
        - 文件级或事件级有 replay=true 标记
        - 携带 original_case_id 指向原始 case
        - 末尾有判定事件（vulnerability_verify / verdict / confirmation 等）

        本方法采用宽松匹配策略：
        1. 先检查文件中是否有 replay=true 标记
        2. 再检查 original_case_id 是否匹配
        3. 最后从事件中提取 verdict 相关字段

        Args:
            fpath: JSONL 文件路径。
            case_id: 原始 case ID。

        Returns:
            verdict 字符串或 None。
        """
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            log("REPLAY",
                f"failed to read replay trace {fpath}: {str(e)[:200]}")
            return None

        is_replay = False
        matches_case = False
        # 从后往前找 verdict（最后的判定事件是最终结论）
        verdict_from_events: str | None = None

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(evt, dict):
                continue

            # 检查 replay 标记
            if evt.get("replay") is True or evt.get("is_replay") is True:
                is_replay = True

            # 检查 original_case_id 匹配
            orig_id = (
                evt.get("original_case_id")
                or evt.get("original_caseId")
                or _deep_get(evt, "metadata", "original_case_id")
                or _deep_get(evt, "meta", "original_case_id")
            )
            if orig_id and str(orig_id) == str(case_id):
                matches_case = True
            # 如果没有 original_case_id 字段，用文件名或 session 元数据匹配
            elif not orig_id and case_id in str(evt.get("session_id", "")):
                matches_case = True
            elif not orig_id and case_id in str(evt.get("case_id", "")):
                matches_case = True

            # 提取 verdict（从多种可能的字段中）
            v = _extract_verdict_from_event(evt)
            if v:
                verdict_from_events = v

        # 非 replay trace 或不匹配的 case，跳过
        if not is_replay and not matches_case:
            return None

        return verdict_from_events

    def _query_vuln_center_verdict(self, case_id: str) -> str:
        """从漏洞中心 Chimera 按 case_id 查询重放后的判定结论。

        复用 vuln_center_client.py 的查询逻辑：
        - 先用 search_vuln_cases 按 case_id 搜索
        - 从返回的 case 数据中提取 confirmation_status 或 validation_result
        - 映射为 TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE

        查询失败或无法判定时返回 FALSE_POSITIVE（保守降级：假定未消除），
        因为"无法确认消除"不等于"已消除"。

        Args:
            case_id: case 标识符。

        Returns:
            TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE
        """
        if _search_vuln_cases is None:
            log("REPLAY",
                f"vuln_center_client not available, "
                f"case={case_id} degraded to FALSE_POSITIVE")
            return REPLAY_FALSE_POSITIVE

        # 确定 project_id
        project_id = self.project_id
        if not project_id:
            # 尝试从环境变量获取
            project_id = os.environ.get("EVAL_PROJECT_ID", "")

        if not project_id:
            log("REPLAY",
                f"no project_id for case={case_id}, "
                f"cannot query vuln center, degraded to FALSE_POSITIVE")
            return REPLAY_FALSE_POSITIVE

        # 先从告警中心搜索（含 validation_result 引擎判定）
        try:
            items = _search_vuln_cases(
                project_id, case_id, scope="alert_center", page_size=5)
        except Exception as e:
            log("REPLAY",
                f"alert_center search failed for case={case_id}: "
                f"{str(e)[:200]}")
            items = []

        # 从告警中心结果中提取 verdict
        for item in items:
            if str(item.get("id", "")) != str(case_id):
                continue
            vr = item.get("validation_result")
            if vr and vr in _VALIDATION_RESULT_MAP:
                mapped = _VALIDATION_RESULT_MAP[vr]
                if mapped:
                    return mapped
            # 告警中心无 confirmation_status，继续查漏洞中心
            break

        # 从漏洞中心搜索（含 confirmation_status 人工确认状态）
        try:
            vuln_items = _search_vuln_cases(
                project_id, case_id, scope="vuln_center", page_size=5)
        except Exception as e:
            log("REPLAY",
                f"vuln_center search failed for case={case_id}: "
                f"{str(e)[:200]}")
            vuln_items = []

        for item in vuln_items:
            if str(item.get("id", "")) != str(case_id):
                continue
            cs = item.get("confirmation_status", "")
            if cs in _CONFIRM_STATUS_MAP:
                return _CONFIRM_STATUS_MAP[cs]
            break

        # 无法从漏洞中心获取重放判定，保守降级为 FP（假定未消除）
        log("REPLAY",
            f"no verdict found in vuln center for case={case_id}, "
            f"degraded to FALSE_POSITIVE (conservative)")
        return REPLAY_FALSE_POSITIVE

    def _determine_elimination(
        self,
        original_verdict: str,
        replay_verdict: str,
    ) -> dict:
        """判定 FP 是否消除。

        判定矩阵（§6.1）：
        | 原始判定 | 重放判定 | 判定结果 |
        | FP | TN | FP 已消除 |
        | FP | FP | FP 未消除 |
        | FP | TP | 异常（知识改进导致误判） |

        Args:
            original_verdict: 原始判定（FALSE_POSITIVE）。
            replay_verdict: 重放判定（TRUE_NEGATIVE / FALSE_POSITIVE / TRUE_POSITIVE）。

        Returns:
            {"eliminated": bool, "anomaly": bool}
        """
        if replay_verdict == REPLAY_TRUE_NEGATIVE:
            return {"eliminated": True, "anomaly": False}
        elif replay_verdict == REPLAY_TRUE_POSITIVE:
            # FP→TP：异常，知识改进引入了新问题（误报变漏报）
            return {"eliminated": False, "anomaly": True}
        else:
            # FP→FP：未消除
            return {"eliminated": False, "anomaly": False}


# ── 工具函数 ──────────────────────────────────────────────


def _deep_get(d: dict, *keys) -> Any:
    """从嵌套 dict 中按 key 路径取值，任一层不存在返回 None。"""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
        if cur is None:
            return None
    return cur


def _extract_verdict_from_event(evt: dict) -> str | None:
    """从单个 trace 事件中提取 verdict。

    不同 Agent 的 trace 格式不同，verdict 字段名各异。
    按优先级尝试多种可能的字段路径。

    Args:
        evt: 单个 trace 事件 dict。

    Returns:
        TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE / None
    """
    # 可能的 verdict 字段名（按优先级）
    _VERDICT_KEYS = [
        "verdict",
        "result",
        "verification_result",
        "vulnerability_verdict",
        "final_verdict",
        "conclusion",
    ]

    # 可能的 verdict 值 → 标准化映射
    _VALUE_MAP = {
        # 正面（是漏洞）
        "true_positive": REPLAY_TRUE_POSITIVE,
        "tp": REPLAY_TRUE_POSITIVE,
        "vulnerable": REPLAY_TRUE_POSITIVE,
        "confirmed": REPLAY_TRUE_POSITIVE,
        "positive": REPLAY_TRUE_POSITIVE,
        # 负面（非漏洞）
        "true_negative": REPLAY_TRUE_NEGATIVE,
        "tn": REPLAY_TRUE_NEGATIVE,
        "not_vulnerable": REPLAY_TRUE_NEGATIVE,
        "not_vulnerable ": REPLAY_TRUE_NEGATIVE,
        "safe": REPLAY_TRUE_NEGATIVE,
        "negative": REPLAY_TRUE_NEGATIVE,
        "not_confirmed": REPLAY_TRUE_NEGATIVE,
        "rejected": REPLAY_TRUE_NEGATIVE,
        # 误报
        "false_positive": REPLAY_FALSE_POSITIVE,
        "fp": REPLAY_FALSE_POSITIVE,
    }

    # 直接字段
    for key in _VERDICT_KEYS:
        val = evt.get(key)
        if val:
            mapped = _VALUE_MAP.get(str(val).strip().lower())
            if mapped:
                return mapped

    # 嵌套字段：metadata.verdict, result.verdict 等
    for parent_key in ("metadata", "meta", "result", "data", "payload"):
        parent = evt.get(parent_key)
        if not isinstance(parent, dict):
            continue
        for key in _VERDICT_KEYS:
            val = parent.get(key)
            if val:
                mapped = _VALUE_MAP.get(str(val).strip().lower())
                if mapped:
                    return mapped

    # 工具调用结果中的 verdict（如 vulnerability_verify 工具返回）
    tool_result = evt.get("tool_result") or evt.get("toolResult")
    if isinstance(tool_result, dict):
        for key in _VERDICT_KEYS:
            val = tool_result.get(key)
            if val:
                mapped = _VALUE_MAP.get(str(val).strip().lower())
                if mapped:
                    return mapped
    elif isinstance(tool_result, str):
        # tool_result 可能是 JSON 字符串
        try:
            tr_parsed = json.loads(tool_result)
            if isinstance(tr_parsed, dict):
                for key in _VERDICT_KEYS:
                    val = tr_parsed.get(key)
                    if val:
                        mapped = _VALUE_MAP.get(str(val).strip().lower())
                        if mapped:
                            return mapped
        except (json.JSONDecodeError, ValueError):
            pass

    # confirmation_status 字段（漏洞中心数据结构）
    cs = evt.get("confirmation_status")
    if cs and cs in _CONFIRM_STATUS_MAP:
        return _CONFIRM_STATUS_MAP[cs]

    # validation_result 字段（告警中心数据结构）
    vr = evt.get("validation_result")
    if vr and vr in _VALIDATION_RESULT_MAP:
        return _VALIDATION_RESULT_MAP[vr]

    return None
