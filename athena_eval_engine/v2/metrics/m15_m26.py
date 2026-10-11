"""Metric Engine — M15–M21 / M26（§4.5 / §8.2 / §8.3）。

生命周期过程指标 + 因果链指标。

每个函数接收 ``list[dict]`` 形式的 ``knowledge_access_detail`` 记录，
输出包含 ``metric_id`` / ``estimate`` / ``ci_lower`` / ``ci_upper`` /
``numerator`` / ``denominator`` / ``calculation_status`` / ``reason_code``
的 dict。

当分母为 0 或无数据时返回 ``calculation_status=NA`` + ``reason_code``，
NA 行不携带估计值（遵循 NA 契约）。

Wilson CI 复用 ``v2/metrics/engine.py`` 的 ``wilson()`` 函数。
"""
from __future__ import annotations

from .engine import wilson

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

CALCULATED = "OK"
NA = "NA"

# NA reason codes（§8.4）
_REASON_NO_DATA = "NO_DATA"
_REASON_NO_NEED_KNOWLEDGE = "NO_NEED_KNOWLEDGE"
_REASON_NO_INITIATED = "NO_INITIATED_ACCESS"
_REASON_NO_QUERY_ACCURATE = "NO_QUERY_ACCURATE_ACCESS"
_REASON_NO_EXISTS = "NO_EXISTS_ACCESS"
_REASON_NO_RETRIEVED = "NO_RETRIEVED_ACCESS"
_REASON_NO_USED = "NO_USED_ACCESS"
_REASON_NO_FP_CASE = "NO_FP_CASE"


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _na_result(metric_id: str, metric_name: str, reason: str) -> dict:
    """构造 NA 结果。NA 行不携带估计值。"""
    return {
        "metric_id": metric_id,
        "metric_name": metric_name,
        "estimate": None,
        "ci_lower": None,
        "ci_upper": None,
        "numerator": 0,
        "denominator": 0,
        "calculation_status": NA,
        "reason_code": reason,
    }


def _ok_result(metric_id: str, metric_name: str,
               numerator: int, denominator: int) -> dict:
    """构造 OK 结果（含 Wilson CI）。"""
    lo, hi = _wilson_ci(numerator, denominator)
    estimate = numerator / denominator
    return {
        "metric_id": metric_id,
        "metric_name": metric_name,
        "estimate": estimate,
        "ci_lower": lo,
        "ci_upper": hi,
        "numerator": numerator,
        "denominator": denominator,
        "calculation_status": CALCULATED,
        "reason_code": None,
    }


def _wilson_ci(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval（95% 置信区间）。

    复用 ``v2/metrics/engine.py`` 的 ``wilson()`` 函数。
    该函数返回 ``(ci_lower, ci_upper, status, reason_code)``，
    其中 status="NA" 时 ci_lower/ci_upper 为 None。
    本函数将 None 转为 0.0，以保持返回类型一致。
    """
    if total <= 0:
        return 0.0, 0.0
    lo, hi, status, _rc = wilson(successes, total, confidence=0.95)
    if lo is None or hi is None:
        return 0.0, 0.0
    return lo, hi


def _is_true(value) -> bool:
    """安全地判断一个值是否为 True。

    ``knowledge_access_detail`` 的布尔字段可能以 True/False/None 存储
    （MySQL BOOLEAN 通过 pymysql 返回 0/1/None）。
    """
    return value is True or value == 1


def _filter_valid(records: list[dict]) -> list[dict]:
    """过滤掉 ``business_phase`` 为 None 的记录。

    这些记录的 LLM 无法确定阶段，不参与生命周期统计（§4.1 NULL 处理）。
    """
    return [r for r in records if r.get("business_phase") is not None]


# ---------------------------------------------------------------------------
# M15–M21 生命周期过程指标
# ---------------------------------------------------------------------------

def calc_m15(access_details: list[dict]) -> dict:
    """M15: L1 知识需求率。

    分子：``l1_need_knowledge=True`` 的记录数
    分母：全部记录数（排除 ``business_phase`` 为 None 的跳过记录）

    返回::
        {
            "metric_id": "M15",
            "metric_name": "L1 知识需求率",
            "estimate": float,
            "ci_lower": float,
            "ci_upper": float,
            "numerator": int,
            "denominator": int,
            "calculation_status": "OK" | "NA",
            "reason_code": str | None
        }
    """
    metric_id = "M15"
    metric_name = "L1 知识需求率"

    if not access_details:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    valid = _filter_valid(access_details)
    denominator = len(valid)
    if denominator == 0:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    numerator = sum(1 for r in valid if _is_true(r.get("l1_need_knowledge")))
    return _ok_result(metric_id, metric_name, numerator, denominator)


def calc_m16(access_details: list[dict]) -> dict:
    """M16: L2 知识发起率。

    分子：``l2_initiated=True`` 的记录数
    分母：``l1_need_knowledge=True`` 的记录数
    """
    metric_id = "M16"
    metric_name = "L2 知识发起率"

    if not access_details:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    need_knowledge = [r for r in access_details if _is_true(r.get("l1_need_knowledge"))]
    denominator = len(need_knowledge)
    if denominator == 0:
        return _na_result(metric_id, metric_name, _REASON_NO_NEED_KNOWLEDGE)

    numerator = sum(1 for r in need_knowledge if _is_true(r.get("l2_initiated")))
    return _ok_result(metric_id, metric_name, numerator, denominator)


def calc_m17(access_details: list[dict]) -> dict:
    """M17: L3 查询准确率。

    分子：``l3_query_accurate=True`` 的记录数
    分母：``l2_initiated=True`` 的记录数
    """
    metric_id = "M17"
    metric_name = "L3 查询准确率"

    if not access_details:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    initiated = [r for r in access_details if _is_true(r.get("l2_initiated"))]
    denominator = len(initiated)
    if denominator == 0:
        return _na_result(metric_id, metric_name, _REASON_NO_INITIATED)

    numerator = sum(1 for r in initiated if _is_true(r.get("l3_query_accurate")))
    return _ok_result(metric_id, metric_name, numerator, denominator)


def calc_m18(access_details: list[dict]) -> dict:
    """M18: L4 知识存在率。

    分子：``l4_knowledge_exists=True`` 的记录数
    分母：``l3_query_accurate=True`` 的记录数
    """
    metric_id = "M18"
    metric_name = "L4 知识存在率"

    if not access_details:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    accurate = [r for r in access_details if _is_true(r.get("l3_query_accurate"))]
    denominator = len(accurate)
    if denominator == 0:
        return _na_result(metric_id, metric_name, _REASON_NO_QUERY_ACCURATE)

    numerator = sum(1 for r in accurate if _is_true(r.get("l4_knowledge_exists")))
    return _ok_result(metric_id, metric_name, numerator, denominator)


def calc_m19(access_details: list[dict]) -> dict:
    """M19: L5 召回成功率。

    分子：``l5_retrieved=True`` 的记录数
    分母：``l4_knowledge_exists=True`` 的记录数
    """
    metric_id = "M19"
    metric_name = "L5 召回成功率"

    if not access_details:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    exists = [r for r in access_details if _is_true(r.get("l4_knowledge_exists"))]
    denominator = len(exists)
    if denominator == 0:
        return _na_result(metric_id, metric_name, _REASON_NO_EXISTS)

    numerator = sum(1 for r in exists if _is_true(r.get("l5_retrieved")))
    return _ok_result(metric_id, metric_name, numerator, denominator)


def calc_m20(access_details: list[dict]) -> dict:
    """M20: L6 知识使用率。

    分子：``l6_used=True`` 的记录数
    分母：``l5_retrieved=True`` 的记录数
    """
    metric_id = "M20"
    metric_name = "L6 知识使用率"

    if not access_details:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    retrieved = [r for r in access_details if _is_true(r.get("l5_retrieved"))]
    denominator = len(retrieved)
    if denominator == 0:
        return _na_result(metric_id, metric_name, _REASON_NO_RETRIEVED)

    numerator = sum(1 for r in retrieved if _is_true(r.get("l6_used")))
    return _ok_result(metric_id, metric_name, numerator, denominator)


def calc_m21(access_details: list[dict]) -> dict:
    """M21: L7 知识影响率。

    分子：``l7_influenced=True`` 的记录数
    分母：``l6_used=True`` 的记录数
    """
    metric_id = "M21"
    metric_name = "L7 知识影响率"

    if not access_details:
        return _na_result(metric_id, metric_name, _REASON_NO_DATA)

    used = [r for r in access_details if _is_true(r.get("l6_used"))]
    denominator = len(used)
    if denominator == 0:
        return _na_result(metric_id, metric_name, _REASON_NO_USED)

    numerator = sum(1 for r in used if _is_true(r.get("l7_influenced")))
    return _ok_result(metric_id, metric_name, numerator, denominator)


# ---------------------------------------------------------------------------
# M26 阶段误报承担率
# ---------------------------------------------------------------------------

def calc_m26(access_details: list[dict]) -> dict:
    """M26: 阶段误报承担率。

    按 ``business_phase`` 分组，每个阶段计算：
    - 分子：该阶段有 ``cause_code``（不为 None）的 FP case 数
    - 分母：总 FP case 数

    "总 FP case 数" = 全部出现过 cause_code 的不同 case 数（跨所有阶段去重）。

    返回一个包含 ``per_phase`` 子结构的 dict，每个阶段一个 Wilson CI::

        {
            "metric_id": "M26",
            "metric_name": "阶段误报承担率",
            "calculation_status": "OK" | "NA",
            "reason_code": str | None,
            "total_fp_cases": int,
            "per_phase": {
                "入口识别": {
                    "estimate": float,
                    "ci_lower": float,
                    "ci_upper": float,
                    "numerator": int,
                    "denominator": int,
                    "calculation_status": "OK" | "NA",
                    "reason_code": str | None,
                },
                ...
            }
        }
    """
    metric_id = "M26"
    metric_name = "阶段误报承担率"

    if not access_details:
        result = _na_result(metric_id, metric_name, _REASON_NO_DATA)
        result["total_fp_cases"] = 0
        result["per_phase"] = {}
        return result

    # 收集所有有 cause_code 的记录，按 business_phase 分组
    # cause_code 不为 None 表示该阶段有断点
    phase_to_cases: dict[str, set] = {}
    all_fp_cases: set = set()

    for r in access_details:
        cause_code = r.get("cause_code")
        if cause_code is None:
            continue
        phase = r.get("business_phase")
        if phase is None:
            continue
        # case 标识用 task_run_id（同一 case 的不同阶段有不同的 task_run_id，
        # 但一个 task_run_id 对应一个 case 的一次运行）
        case_key = r.get("task_run_id") or r.get("access_id")
        if case_key is None:
            continue
        phase_to_cases.setdefault(phase, set()).add(case_key)
        all_fp_cases.add(case_key)

    total_fp_cases = len(all_fp_cases)

    if total_fp_cases == 0:
        result = _na_result(metric_id, metric_name, _REASON_NO_FP_CASE)
        result["total_fp_cases"] = 0
        result["per_phase"] = {}
        return result

    per_phase: dict[str, dict] = {}
    for phase, cases in sorted(phase_to_cases.items()):
        numerator = len(cases)
        denominator = total_fp_cases
        lo, hi = _wilson_ci(numerator, denominator)
        per_phase[phase] = {
            "estimate": numerator / denominator,
            "ci_lower": lo,
            "ci_upper": hi,
            "numerator": numerator,
            "denominator": denominator,
            "calculation_status": CALCULATED,
            "reason_code": None,
        }

    return {
        "metric_id": metric_id,
        "metric_name": metric_name,
        "estimate": None,  # M26 是多值指标，无单一 estimate
        "ci_lower": None,
        "ci_upper": None,
        "numerator": 0,
        "denominator": total_fp_cases,
        "calculation_status": CALCULATED,
        "reason_code": None,
        "total_fp_cases": total_fp_cases,
        "per_phase": per_phase,
    }


# ---------------------------------------------------------------------------
# 批量入口
# ---------------------------------------------------------------------------

def calc_all_lifecycle_metrics(access_details: list[dict]) -> list[dict]:
    """计算全部生命周期过程指标 M15–M21 + M26。

    参数:
        access_details: ``knowledge_access_detail`` 记录列表（dict）。

    返回:
        按 M15, M16, M17, M18, M19, M20, M21, M26 顺序排列的结果列表。
    """
    return [
        calc_m15(access_details),
        calc_m16(access_details),
        calc_m17(access_details),
        calc_m18(access_details),
        calc_m19(access_details),
        calc_m20(access_details),
        calc_m21(access_details),
        calc_m26(access_details),
    ]
