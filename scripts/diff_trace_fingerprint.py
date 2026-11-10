"""对比两次评测的根因分析输入指纹。

回答一个问题：两次评测结论不同，是输入变了、提示词变了，还是模型判定波动？

每次分析都会把实际喂给 LLM 的 session 文本写成内容寻址快照
（{eid}_trace_{case_id}_{chain}_{hash}.json），指纹同时记在
{eid}_dts_{case_id}.json 的 mining/verification.input_fingerprint 里。

用法：
  python scripts/diff_trace_fingerprint.py EV-A EV-B
  python scripts/diff_trace_fingerprint.py EV-A EV-B --reports-dir /app/reports
  python scripts/diff_trace_fingerprint.py EV-A EV-B --case case-xxx

退出码：0=输入与提示词一致；1=存在差异；2=文件缺失无法比较。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_CHAINS = ("mining", "verification")
_CHAIN_LABELS = {"mining": "挖掘链", "verification": "验证链"}


def _load_cases(reports_dir: str, evaluation_id: str) -> dict[str, dict]:
    """读取一次评测的全部 case 分析数据：{case_id: analysis_json}。"""
    cases: dict[str, dict] = {}
    pattern = os.path.join(reports_dir, f"{evaluation_id}_dts_*.json")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  读取失败 {os.path.basename(path)}: {e}")
            continue
        case_id = data.get("case_id") or os.path.basename(path).split(
            f"{evaluation_id}_dts_", 1)[-1].removesuffix(".json")
        cases[case_id] = data
    return cases


def _chain_fp(case_data: dict, chain: str) -> dict:
    return (case_data.get(chain) or {}).get("input_fingerprint") or {}


def _chain_cause(case_data: dict, chain: str) -> str:
    c = case_data.get(chain) or {}
    cause = c.get("primary_cause", "") or ""
    level = (c.get("root_cause") or {}).get("level", "")
    if cause and not level:
        try:
            from athena_eval_engine.v2.core.causal_levels import CAUSE_TO_LEVEL
            level = CAUSE_TO_LEVEL.get(cause, "")
        except Exception:
            level = ""
    return f"{cause or '-'}/{level or '-'}"


def _session_map(fp: dict) -> dict[str, str]:
    return {s.get("session_id", ""): s.get("sha256", "")
            for s in (fp.get("sessions") or []) if s.get("session_id")}


def _mark(same: bool) -> str:
    return "相同" if same else "不同"


def compare_chain(case_id: str, chain: str, a: dict, b: dict) -> tuple[bool, bool]:
    """比较一条链，返回 (输入/提示词是否一致, 链结论是否一致)。"""
    label = _CHAIN_LABELS.get(chain, chain)
    fa, fb = _chain_fp(a, chain), _chain_fp(b, chain)
    if not fa and not fb:
        print(f"  {label}: 两边都未提供输入指纹（旧版本数据）")
        return False, False
    if not fa or not fb:
        print(f"  {label}: 仅一边提供输入指纹，无法比较")
        return False, False

    ok = True
    ha, hb = fa.get("case_hash", ""), fb.get("case_hash", "")
    print(f"  {label}")
    print(f"    输入指纹  {ha[:12] or '-'} / {hb[:12] or '-'}  {_mark(ha == hb)}")
    ok &= ha == hb
    pa, pb = fa.get("prompt_hash", ""), fb.get("prompt_hash", "")
    print(f"    提示词    {pa[:12] or '-'} / {pb[:12] or '-'}  {_mark(pa == pb)}")
    ok &= pa == pb
    ca, cb = _chain_cause(a, chain), _chain_cause(b, chain)
    cause_same = ca == cb
    print(f"    链结论    {ca} / {cb}  {_mark(cause_same)}")

    sa, sb = _session_map(fa), _session_map(fb)
    sessions_same = True
    for sid in list(sa) + [s for s in sb if s not in sa]:
        va, vb = sa.get(sid, ""), sb.get(sid, "")
        if not va or not vb:
            print(f"    session {sid[:8]}  只在一边出现")
            sessions_same = False
        else:
            same = va == vb
            print(f"    session {sid[:8]}  {va[:8]} / {vb[:8]}  {_mark(same)}")
            sessions_same &= same
    ok &= sessions_same
    if ha != hb and sessions_same:
        print("    注意：session 内容一致但链指纹不同——链内 session 顺序变了")
    return ok, cause_same


def main() -> int:
    ap = argparse.ArgumentParser(description="对比两次评测的根因分析输入指纹")
    ap.add_argument("eval_a")
    ap.add_argument("eval_b")
    ap.add_argument("--reports-dir", default="",
                    help="报告目录，默认取 EVAL_REPORTS_DIR 或 config.yaml")
    ap.add_argument("--case", default="", help="只比较指定 case_id")
    args = ap.parse_args()

    reports_dir = args.reports_dir
    if not reports_dir:
        try:
            from athena_eval_engine.config_loader import get_reports_dir
            reports_dir = get_reports_dir()
        except Exception:
            reports_dir = os.path.join(ROOT, "reports")

    print(f"报告目录: {reports_dir}")
    print(f"A = {args.eval_a}\nB = {args.eval_b}\n")

    a_cases = _load_cases(reports_dir, args.eval_a)
    b_cases = _load_cases(reports_dir, args.eval_b)
    if not a_cases or not b_cases:
        print(f"未找到分析数据：A={len(a_cases)} 个 case, B={len(b_cases)} 个 case")
        return 2

    case_ids = sorted(set(a_cases) & set(b_cases))
    if args.case:
        case_ids = [c for c in case_ids if c == args.case]
    if not case_ids:
        print("两个评测没有共同的 case")
        return 2

    all_same = True
    all_causes_same = True
    for case_id in case_ids:
        print(f"case {case_id}")
        for chain in _CHAINS:
            ok, cause_same = compare_chain(
                case_id, chain, a_cases[case_id], b_cases[case_id])
            all_same &= ok
            all_causes_same &= cause_same
        print()

    print("===== 结论 =====")
    if not all_same:
        print("存在输入或提示词差异：先定位差异来源（输入变了查采集/解析，"
              "提示词变了查版本），不要当成模型不稳定。")
        return 1
    if all_causes_same:
        print("输入、提示词、链结论全部一致：这一轮完全可复现。")
        return 0
    print("输入与提示词完全一致，但链结论不同：属于模型判定波动，"
          "应收敛提示词或补程序兜底，而不是查数据。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
