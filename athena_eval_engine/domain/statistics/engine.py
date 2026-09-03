"""Statistical Engine（§9.4 / §9.11-9.14 / §13.10）。

- gt_stratified_paired_bootstrap：M1/M4，§9.4 + §13.10 max_attempts
- paired_bootstrap：M2/M3/M7/M8-M10
- mcnemar：B vs C 不对称（Exact if b+c<25；b+c=0 → NA）
- wilcoxon：M8-M10
- wilson：M5/M6
所有：分母=0 → NA；bootstrap valid<1000 → INSUFFICIENT_DATA → DB status=NA, reason=BOOTSTRAP_UNSTABLE。
"""
from __future__ import annotations
import math
from dataclasses import dataclass
import numpy as np
from scipy import stats as sp_stats


@dataclass
class BootstrapResult:
    estimate: float | None
    ci_lower: float | None
    ci_upper: float | None
    status: str  # CALCULATED / NA / INSUFFICIENT_DATA
    reason_code: str | None
    requested: int
    valid: int
    attempts: int
    seed: int | None


def _na(reason: str) -> BootstrapResult:
    return BootstrapResult(None, None, None, "NA", reason, 0, 0, 0, None)


def paired_bootstrap(population, estimator, *, B=2000, seed=None,
                     minimum_valid=1000, max_attempts_factor=10) -> BootstrapResult:
    """对 Task Pair 重采样（非分层），保留配对结构。M2/M3/M7/M8-M10。"""
    rng = np.random.default_rng(seed)
    n = len(population)
    if n == 0:
        return _na("NO_VALID_POPULATION")
    # 小样本（N<=5）跳过 Bootstrap，直接返回点估计
    if n <= 5:
        est = estimator(population)
        if est is None:
            return _na("UNDEFINED_ESTIMATE")
        return BootstrapResult(estimate=est, ci_lower=est, ci_upper=est,
                             status="CALCULATED", reason_code=None,
                             requested=0, valid=0, attempts=0, seed=seed)
    idx = np.arange(n)
    estimates = []
    max_attempts = max_attempts_factor * B
    attempts = 0
    while len(estimates) < B and attempts < max_attempts:
        attempts += 1
        sample_idx = rng.choice(idx, size=n, replace=True)
        sample = [population[i] for i in sample_idx]
        try:
            v = estimator(sample)
        except _UndefinedReplicate:
            continue
        if v is not None:
            estimates.append(v)
    if len(estimates) < minimum_valid:
        return BootstrapResult(estimator(population), None, None, "INSUFFICIENT_DATA",
                               "BOOTSTRAP_UNSTABLE", B, len(estimates), attempts, seed)
    est = estimator(population)
    arr = np.array(estimates)
    return BootstrapResult(
        estimate=est,
        ci_lower=float(np.percentile(arr, 2.5)),
        ci_upper=float(np.percentile(arr, 97.5)),
        status="CALCULATED", reason_code=None,
        requested=B, valid=len(estimates), attempts=attempts, seed=seed,
    )


def gt_stratified_paired_bootstrap(pairs, estimator, *, B=2000, seed=None,
                                    minimum_valid=1000, max_attempts_factor=10) -> BootstrapResult:
    """§9.4：按 benchmark GT 分层重采样。M1/M4。"""
    vuln = [p for p in pairs if getattr(p, "gt", None) == "VULNERABLE"]
    nonvuln = [p for p in pairs if getattr(p, "gt", None) == "NON_VULNERABLE"]
    if not vuln or not nonvuln:
        return _na("NO_STRATUM")  # 需两类 GT
    rng = np.random.default_rng(seed)
    estimates = []
    max_attempts = max_attempts_factor * B
    attempts = 0
    iv = np.arange(len(vuln)); inv = np.arange(len(nonvuln))
    while len(estimates) < B and attempts < max_attempts:
        attempts += 1
        sv = [vuln[i] for i in rng.choice(iv, size=len(vuln), replace=True)]
        sn = [nonvuln[i] for i in rng.choice(inv, size=len(nonvuln), replace=True)]
        try:
            v = estimator(sv + sn)
        except _UndefinedReplicate:
            continue
        if v is not None:
            estimates.append(v)
    if len(estimates) < minimum_valid:
        return BootstrapResult(None, None, None, "INSUFFICIENT_DATA", "BOOTSTRAP_UNSTABLE",
                               B, len(estimates), attempts, seed)
    est = estimator(pairs)
    arr = np.array(estimates)
    return BootstrapResult(est, float(np.percentile(arr, 2.5)), float(np.percentile(arr, 97.5)),
                           "CALCULATED", None, B, len(estimates), attempts, seed)


class _UndefinedReplicate(Exception):
    """replicate 分母=0 → skip（不塞 0）。"""
    pass


def wilson(success: int, total: int, confidence=0.95) -> tuple[float | None, float | None, str, str | None]:
    """Wilson CI（M5/M6）。total=0 → NA。"""
    if total <= 0:
        return None, None, "NA", "NO_VALID_DENOMINATOR"
    z = sp_stats.norm.ppf(1 - (1 - confidence) / 2)
    p = max(0.0, min(1.0, success / total))  # clamp，防止 success>total 导致 sqrt 负数
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(max(0.0, p * (1 - p) / total + z * z / (4 * total * total))) / denom
    return center - half, center + half, "CALCULATED", None


def mcnemar(b: int, c: int) -> dict:
    """§9.11/§9.13：B vs C 不对称。b+c=0 → NA(NO_DISCORDANT_PAIRS)；<25 Exact；≥25 χ² continuity-corrected。"""
    if b + c == 0:
        return {"status": "NA", "reason_code": "NO_DISCORDANT_PAIRS", "statistic": None, "p_value": None}
    if b + c < 25:
        # Exact: X ~ Binomial(b+c, 0.5)，双尾
        k = min(b, c)
        p = 2 * sp_stats.binom.cdf(k, b + c, 0.5)
        p = min(p, 1.0)
        return {"status": "CALCULATED", "reason_code": None, "statistic": float(k), "p_value": float(p),
                "method": "exact_mcnemar"}
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    p = 1 - sp_stats.chi2.cdf(chi2, df=1)
    return {"status": "CALCULATED", "reason_code": None, "statistic": float(chi2), "p_value": float(p),
            "method": "chi_square_continuity_corrected"}


def wilcoxon(differences) -> dict:
    """§9.12：Wilcoxon signed-rank。pairs<10 → NA。"""
    diffs = [d for d in differences if d is not None]
    if len(diffs) < 10:
        return {"status": "NA", "reason_code": "INSUFFICIENT_PAIRS", "statistic": None, "p_value": None}
    try:
        st, p = sp_stats.wilcoxon(diffs, zero_method="wilcox", alternative="two-sided", method="auto")
    except ValueError:
        return {"status": "NA", "reason_code": "ALL_ZERO_DIFFERENCES", "statistic": None, "p_value": None}
    return {"status": "CALCULATED", "reason_code": None, "statistic": float(st), "p_value": float(p)}
