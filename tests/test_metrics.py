"""Phase 4 测试 — Metric Engine + Statistical Engine（§9）。

验收（§1 R3）：
1. 合成已知效应数据 → 全部算对
2. 纯抖动空臂 → 效应量小、Δ≈0
3. 分母为 0 → NA + reason，不输出 0
4. McNemar 检验 B vs C（不是 IR 显著性）
"""
from __future__ import annotations
import random
import pytest
import numpy as np

from athena_eval_engine.domain.metrics import (
    PairView, calc_m1, calc_m2_m3, calc_m4, calc_m5, calc_m6, calc_m7,
    calc_m8, calc_m9, calc_m10, run_all_metrics,
)


def _pv(gt, kg_ok, nogk_ok, *, jsd=None, dt=None, ds=None, dtm=None) -> PairView:
    return PairView(
        kg_success=kg_ok, nogk_success=nogk_ok, gt=gt,
        kg_outcome="SUCCESS" if kg_ok else "FAIL",
        nogk_outcome="SUCCESS" if nogk_ok else "FAIL",
        jsd=jsd, delta_token=dt, delta_steps=ds, delta_time=dtm,
    )


# ===== 1. 合成已知效应 =====
def test_known_effect_kg_recovers_half():
    """NoKG 全 FAIL，KG 救回一半 → IR=0.5, RR=0（无回归）, ΔBA 正。
    20 vuln + 20 nonvuln pairs：NoKG fail, KG success in 10 vuln + 10 nonvuln."""
    pairs = []
    for i in range(20):
        # C：NoKG fail, KG success（救回）
        pairs.append(_pv("VULNERABLE", True, False, jsd=0.2 + i*0.01, dt=500+i, ds=-1, dtm=-2000))
    for i in range(20):
        # A：NoKG success, KG success（保持）
        pairs.append(_pv("NON_VULNERABLE", True, True, jsd=0.05, dt=100, ds=0, dtm=-500))
    m1, s1 = calc_m1(pairs, seed=7)
    assert m1.estimate is not None and m1.estimate > 0, "ΔBA 应为正（KG 更好）"
    assert m1.calculation_status == "CALCULATED"
    assert m1.n == 40

    r = calc_m2_m3(pairs, seed=7)
    m2 = r["m2"]; m3 = r["m3"]
    # C=20, D=0 → IR = 20/20 = 1.0（NoKG 全 fail，KG 全 success 在 vuln 组）
    # 但 nonvuln 组 NoKG success → C/D 只数 NoKG=fail 的 pair。vuln 20 个 NoKG fail → C=20（KG success）。nonvuln NoKG success → A。
    assert m2.estimate == pytest.approx(1.0), "IR = C/(C+D) = 20/20 = 1.0"
    # A=20, B=0 → RR = 0/(20+0) = 0
    assert m3.estimate == pytest.approx(0.0), "RR = B/(A+B) = 0/20 = 0"
    # McNemar joint：B=0, C=20 → b+c=20<25 → Exact
    joint = [s for s in r["statistical"] if s.scope_type == "JOINT"][0]
    assert joint.joint_analysis_id == "J001"
    assert joint.related_metric_ids == ["M2", "M3"]
    assert joint.details["b"] == 0 and joint.details["c"] == 20

    m4, _ = calc_m4(pairs, seed=7)
    # ΔFNR：KG FNR < NoKG FNR → 负
    assert m4.estimate is not None and m4.estimate < 0, "ΔFNR 应为负（KG 漏报率降）"


def test_m5_m6_wilson():
    """M5 KAR + M6 KDR Wilson CI。"""
    m5, s5 = calc_m5(access_count=8, valid_kg_count=10)
    assert m5.estimate == pytest.approx(0.8)
    assert s5[0].ci_lower < 0.8 < s5[0].ci_upper
    m6, s6 = calc_m6(access_delivery_count=7, access_count=8)
    assert m6.estimate == pytest.approx(7 / 8)
    assert s6[0].ci_lower < 0.875 < s6[0].ci_upper


def test_m7_jsd_median_iqr():
    """M7 JSD median + IQR。"""
    pairs = [_pv("VULNERABLE", True, True, jsd=j) for j in [0.1, 0.2, 0.3, 0.4, 0.5]] * 4
    m7, s7 = calc_m7(pairs, seed=3)
    assert m7.estimate == pytest.approx(0.3), "median=0.3"
    assert m7.calculation_status == "CALCULATED"
    assert s7[0].ci_lower is not None


def test_m8_m10_delta_median_wilcoxon():
    """M8-M10 ΔToken/Steps/Time median + Wilcoxon。"""
    pairs = [_pv("VULNERABLE", True, False,
                 dt=1000 + i*100, ds=-2-i, dtm=-5000-i*100) for i in range(15)]
    for calc, field in [(calc_m8, "delta_token"), (calc_m9, "delta_steps"), (calc_m10, "delta_time")]:
        m, s = calc(pairs, seed=3)
        assert m.median is not None
        assert m.calculation_status == "CALCULATED"
        assert s[0].test_name == "wilcoxon_signed_rank"
        assert s[0].p_value is not None, f"{field}: Wilcoxon p-value"


# ===== 2. 纯抖动空臂（Δ≈0） =====
def test_null_effect_delta_near_zero():
    """纯抖动：KG≈NoKG，ΔBA/ΔFNR ≈ 0，CI 跨 0。"""
    rng = random.Random(0)
    pairs = []
    for i in range(60):
        ks = rng.random() > 0.5
        ns = rng.random() > 0.5
        gt = "VULNERABLE" if i % 2 == 0 else "NON_VULNERABLE"
        pairs.append(_pv(gt, ks, ns, jsd=rng.random()*0.05, dt=rng.gauss(0, 50),
                         ds=rng.gauss(0, 1), dtm=rng.gauss(0, 1000)))
    m1, s1 = calc_m1(pairs, seed=1)
    assert abs(m1.estimate) < 0.15, "空臂 ΔBA 应近 0"
    assert s1[0].ci_lower < 0 < s1[0].ci_upper or abs(m1.estimate) < 0.1, "CI 应跨 0 或近 0"


# ===== 3. 分母为 0 → NA =====
def test_denominator_zero_na():
    """分母=0 → NA + reason，不输出 0。"""
    # 无 NoKG=fail → IR NA（C+D=0）
    pairs = [_pv("VULNERABLE", True, True) for _ in range(20)]  # 全 A（双方 success）
    r = calc_m2_m3(pairs, seed=1)
    assert r["m2"].calculation_status == "NA"
    assert r["m2"].reason_code == "NO_VALID_DENOMINATOR"
    # 全 NoKG success → RR NA（A+B=0）需 NoKG success；这里全 A → RR B=0 → RR=0/(20)=0 not NA
    # 单独构造 B>0：NoKG success, KG fail
    pairs2 = [_pv("VULNERABLE", False, True) for _ in range(20)]  # 全 B
    r2 = calc_m2_m3(pairs2, seed=1)
    assert r2["m3"].estimate == pytest.approx(1.0), "RR = 20/20 = 1.0（全回归）"
    # McNemar B=20, C=0 → Exact
    joint = [s for s in r2["statistical"] if s.scope_type == "JOINT"][0]
    assert joint.details["b"] == 20 and joint.details["c"] == 0


def test_mcnemar_no_discordant_na():
    """b+c=0 → McNemar NA(NO_DISCORDANT_PAIRS)。"""
    pairs = [_pv("VULNERABLE", True, True) for _ in range(20)]  # 全 A → B=0,C=0
    r = calc_m2_m3(pairs, seed=1)
    joint = [s for s in r["statistical"] if s.scope_type == "JOINT"][0]
    assert joint.status == "NA"
    assert joint.reason_code == "NO_DISCORDANT_PAIRS"


def test_m5_zero_denominator_na():
    """M5 valid_kg_count=0 → NA。"""
    m, s = calc_m5(access_count=0, valid_kg_count=0)
    assert m.calculation_status == "NA"
    assert m.reason_code == "NO_VALID_DENOMINATOR"
    assert s[0].status == "NA"


def test_run_all_metrics_smoke():
    """run_all_metrics 冒烟：10 指标 + 统计结果全产出。"""
    pairs = [_pv("VULNERABLE", True, False, jsd=0.1, dt=500, ds=-2, dtm=-3000) for _ in range(15)]
    pairs += [_pv("NON_VULNERABLE", True, True, jsd=0.05, dt=100, ds=0, dtm=-500) for _ in range(15)]
    out = run_all_metrics(pairs, kg_access=25, kg_valid=30, kg_delivery=20, access=25, seed=5)
    assert len(out["metric_results"]) == 10
    # 至少 M1-M4, M7-M10 有 CI（StatisticalResult）；M5/M6 Wilson；joint 1 条
    joint = [s for s in out["statistical_results"] if s.scope_type == "JOINT"]
    assert len(joint) == 1 and joint[0].joint_analysis_id == "J001"
    # 所有 metric 有 n
    assert all(m.n is not None for m in out["metric_results"])
