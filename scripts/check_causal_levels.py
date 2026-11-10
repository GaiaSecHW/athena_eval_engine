"""术语单一来源一致性检查。

保证 A-K、L1-L8 在 Python 常量、UI config.js、prompt 三处含义一致。
运行：python scripts/check_causal_levels.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from athena_eval_engine.v2.core.causal_levels import (  # noqa: E402
    ALL_CAUSES,
    ALL_LEVELS,
    CAUSE_DESCRIPTIONS,
    CAUSE_EVIDENCE,
    CAUSE_LABELS,
    CAUSE_LEVEL_RANK,
    CAUSE_TO_CATEGORY,
    CAUSE_TO_LEVEL,
    CAUSE_TO_RESPONSIBILITY,
    LEVEL_QUESTIONS,
    LEVEL_RANK,
)

errors: list[str] = []

codes = set(ALL_CAUSES)
if codes != set("ABCDEFGHIJK"):
    errors.append(f"ALL_CAUSES 不是 A-K: {sorted(codes)}")
if "L" in codes:
    errors.append("存在 cause_code L，旧注释必须清理")

for name, mapping in {
    "CAUSE_TO_LEVEL": CAUSE_TO_LEVEL,
    "CAUSE_LEVEL_RANK": CAUSE_LEVEL_RANK,
    "CAUSE_LABELS": CAUSE_LABELS,
    "CAUSE_DESCRIPTIONS": CAUSE_DESCRIPTIONS,
    "CAUSE_TO_RESPONSIBILITY": CAUSE_TO_RESPONSIBILITY,
    "CAUSE_TO_CATEGORY": CAUSE_TO_CATEGORY,
    "CAUSE_EVIDENCE": CAUSE_EVIDENCE,
}.items():
    if set(mapping) != codes:
        errors.append(f"{name} 的 key 与 ALL_CAUSES 不一致")

for code, level in CAUSE_TO_LEVEL.items():
    if level not in ALL_LEVELS:
        errors.append(f"{code} → {level} 不在 ALL_LEVELS")
    elif CAUSE_LEVEL_RANK[code] != LEVEL_RANK[level]:
        errors.append(f"{code} 的排序权重与 {level} 不一致")

if set(LEVEL_QUESTIONS) != set(ALL_LEVELS) | {"L1"}:
    errors.append("LEVEL_QUESTIONS 必须覆盖 L1-L8")

# UI 标签与 Python 标签一致
cfg = (ROOT / "athena_eval_engine/static/lib/config.js").read_text(encoding="utf-8")
match = re.search(r"const DTS_CAUSE_LABELS\s*=\s*\{(.*?)\};", cfg, re.S)
if not match:
    errors.append("config.js 中未找到 DTS_CAUSE_LABELS")
else:
    ui_labels: dict[str, str] = {}
    for code, text in re.findall(r'"([A-K])"\s*:\s*"([^"]*)"', match.group(1)):
        inner = re.search(r"\(([^)]*)\)", text)
        ui_labels[code] = inner.group(1) if inner else text
    if ui_labels != CAUSE_LABELS:
        errors.append(f"UI 标签与 Python 不一致: {ui_labels}")

# prompt 必须包含标准标签
prompt_src = (ROOT / "athena_eval_engine/v2/lifecycle/root_cause_analyzer.py").read_text(
    encoding="utf-8")
for code, label in CAUSE_LABELS.items():
    if label not in prompt_src:
        errors.append(f"prompt 中缺少 {code} 的标准标签 {label!r}")

if errors:
    print("FAILED")
    for e in errors:
        print(" -", e)
    raise SystemExit(1)

print("OK: A-K / L1-L8 在 Python、UI、prompt 三处一致")
