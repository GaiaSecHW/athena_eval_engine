"""Statistical Engine — Wilson CI（M5/M6/M11/M12）。

方案不含 No-KG 对照组，不需要配对 bootstrap / McNemar / Wilcoxon。
分母=0 → NA。
"""
from __future__ import annotations
import math
from scipy import stats as sp_stats


def wilson(success: int, total: int, confidence=0.95) -> tuple[float | None, float | None, str, str | None]:
    """Wilson CI（M5/M6/M11/M12）。total=0 → NA。"""
    if total <= 0:
        return None, None, "NA", "NO_VALID_DENOMINATOR"
    z = sp_stats.norm.ppf(1 - (1 - confidence) / 2)
    p = max(0.0, min(1.0, success / total))  # clamp，防止 success>total 导致 sqrt 负数
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(max(0.0, p * (1 - p) / total + z * z / (4 * total * total))) / denom
    return center - half, center + half, "CALCULATED", None
