"""独立 FPR 验证：规则匹配（源文件 + 漏洞标题关键词），不依赖 LLM。

匹配标准与 LLM 版本一致：漏洞位置、攻击入口、漏洞类型、漏洞原理。
"""
import json, re
from collections import defaultdict

# Load baseline
with open("baseline_data.json", encoding="utf-8") as f:
    baseline = json.load(f)

# Load alert center
import os
ac_path = os.environ.get("ALERT_CENTER_PATH", "/tmp/alert_center.json")
# Try Windows path
if not os.path.exists(ac_path):
    ac_path = r"C:\Users\W00867~1\AppData\Local\Temp\alert_center.json"
with open(ac_path, encoding="utf-8") as f:
    ac_data = json.load(f)
findings = ac_data.get("items", [])

print(f"Baseline: {len(baseline)} 条 (VULNERABLE={sum(1 for b in baseline if b['label']=='VULNERABLE')}, NON_VULNERABLE={sum(1 for b in baseline if b['label']=='NON_VULNERABLE')})")
print(f"Findings: {len(findings)} 条 (vulnerable={sum(1 for c in findings if c.get('validation_result')=='vulnerable')}, not_vulnerable={sum(1 for c in findings if c.get('validation_result')=='not_vulnerable')})")

# --- Step 1: Extract matching features ---

def normalize_path(path: str) -> str:
    """Normalize a file path for comparison."""
    if not path:
        return ""
    # Remove leading prefixes like "src/", "source/src/", etc.
    path = path.strip()
    # Get the meaningful part of the path
    # Remove common prefixes
    for prefix in ["src/com/huawei/", "source/src/com/huawei/", "src/main/java/com/huawei/"]:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    # Also handle "xxx-app/src/com/huawei/" pattern
    m = re.search(r'/src/com/huawei/', path)
    if m:
        path = path[m.end():]
    # Remove line numbers
    path = re.sub(r':\d+(-\d+)?$', '', path)
    path = re.sub(r':.*$', '', path)  # Remove function names after :
    path = path.lower().strip("/")
    return path

def extract_keywords(title: str) -> set:
    """Extract meaningful keywords from a vulnerability title."""
    # Remove common filler words
    stop_words = {"的", "了", "和", "与", "或", "在", "存在", "导致", "漏洞", "接口", "可", "造成",
                  "a", "an", "the", "in", "of", "for", "to", "is", "with", "by", "on", "at",
                  "post", "get", "put", "delete", "http", "https", "api", "v1", "v2"}
    # Split by non-alphanumeric (keep Chinese chars)
    tokens = re.findall(r'[\u4e00-\u9fff]+|[a-zA-Z][a-zA-Z0-9]+', title.lower())
    keywords = set()
    for token in tokens:
        if token not in stop_words and len(token) > 1:
            keywords.add(token)
    return keywords

# --- Step 2: Score matching ---

def score_match(finding: dict, bl_item: dict) -> float:
    """Score how well a finding matches a baseline item. 0 = no match, higher = better."""
    score = 0.0

    # 1. Source file matching (strongest signal)
    bl_file = normalize_path(bl_item.get("source_file", ""))
    subject = finding.get("subject", {}) or {}
    finding_locator = subject.get("locator", "") or ""
    finding_file = normalize_path(finding_locator)

    if bl_file and finding_file:
        # Exact match
        if bl_file == finding_file:
            score += 0.5
        # One contains the other
        elif bl_file in finding_file or finding_file in bl_file:
            score += 0.4
        # Same filename (last component)
        elif bl_file.split("/")[-1] == finding_file.split("/")[-1]:
            score += 0.3
        # Share a significant path segment (at least 2 dirs)
        else:
            bl_parts = bl_file.split("/")
            f_parts = finding_file.split("/")
            # Check if last 2-3 path components match
            for n in (3, 2):
                if len(bl_parts) >= n and len(f_parts) >= n:
                    if bl_parts[-n:] == f_parts[-n:]:
                        score += 0.25
                        break

    # 2. Title/vulnerability type keyword matching
    bl_title = bl_item.get("vuln_type", "")
    finding_title = finding.get("title", "")

    bl_kw = extract_keywords(bl_title)
    f_kw = extract_keywords(finding_title)

    if bl_kw and f_kw:
        overlap = bl_kw & f_kw
        union = bl_kw | f_kw
        jaccard = len(overlap) / len(union) if union else 0
        score += jaccard * 0.3

        # Bonus for specific high-value keyword matches
        high_value_kw = {"sftp", "ssrf", "sql", "注入", "越权", "idora", "idor", "session",
                        "劫持", "正则", "regex", "命令", "command", "权限", "白名单",
                        "下载", "删除", "读取", "明文", "凭据", "密码", "sdp", "ussd"}
        hv_overlap = overlap & high_value_kw
        score += len(hv_overlap) * 0.05

    # 3. API endpoint matching
    bl_desc = bl_item.get("description", "")
    # Extract API paths from description and title
    bl_apis = set(re.findall(r'/(?:api|fintech|apaas|supergateway|orgportal|spportal|omportal|http|transaction|saving)[/\w{}.-]*', bl_desc + bl_title, re.IGNORECASE))
    f_apis = set(re.findall(r'/(?:api|fintech|apaas|supergateway|orgportal|spportal|omportal|http|transaction|saving)[/\w{}.-]*', finding_title + finding.get("summary", ""), re.IGNORECASE))

    if bl_apis and f_apis:
        api_overlap = bl_apis & f_apis
        if api_overlap:
            score += 0.15

    return score

# --- Step 3: Run matching with 1:1 constraint ---

# Score all pairs
all_scores = []  # (score, bl_idx, finding_idx)
for bl_idx, bl in enumerate(baseline):
    for f_idx, finding in enumerate(findings):
        s = score_match(finding, bl)
        if s > 0.15:  # threshold for considering a match
            all_scores.append((s, bl_idx, f_idx))

# Sort by score descending
all_scores.sort(key=lambda x: x[0], reverse=True)

# Greedy 1:1 assignment
matched_baseline = {}  # bl_idx -> (f_idx, score)
matched_findings = {}  # f_idx -> (bl_idx, score)

for score, bl_idx, f_idx in all_scores:
    if bl_idx in matched_baseline or f_idx in matched_findings:
        continue
    matched_baseline[bl_idx] = (f_idx, score)
    matched_findings[f_idx] = (bl_idx, score)

# --- Step 4: Calculate FPR ---

matched_count = len(matched_findings)
fp_count = 0
tp_count = 0

for f_idx, (bl_idx, score) in matched_findings.items():
    bl_label = baseline[bl_idx]["label"]
    if bl_label == "NON_VULNERABLE":
        fp_count += 1
    else:
        tp_count += 1

fpr = fp_count / matched_count if matched_count > 0 else 0

print(f"\n=== 独立 FPR 计算结果 ===")
print(f"总 findings: {len(findings)}")
print(f"总 baseline: {len(baseline)}")
print(f"匹配数: {matched_count}")
print(f"  真正 (TP, baseline=VULNERABLE): {tp_count}")
print(f"  误报 (FP, baseline=NON_VULNERABLE): {fp_count}")
print(f"FPR = {fp_count}/{matched_count} = {fpr:.1%}")
print(f"\n匹配阈值: 0.15 (score > 0.15 才考虑)")

# Show all matches
print(f"\n=== 匹配明细 ===")
for f_idx in sorted(matched_findings.keys()):
    bl_idx, score = matched_findings[f_idx]
    finding = findings[f_idx]
    bl = baseline[bl_idx]
    bl_label = bl["label"]
    is_fp = "❌ FP" if bl_label == "NON_VULNERABLE" else "✅ TP"
    print(f"\n[{f_idx+1}] {is_fp} score={score:.3f}")
    print(f"  Finding: {finding.get('title','')[:70]}")
    print(f"  Finding locator: {(finding.get('subject',{}) or {}).get('locator','')[:70]}")
    print(f"  Baseline [{bl_label}]: {bl['vuln_type'][:70]}")
    print(f"  Baseline file: {bl['source_file'][:70]}")

# Show unmatched findings count
unmatched = len(findings) - matched_count
print(f"\n未匹配 findings: {unmatched}")

# Show unmatched baselines
unmatched_bl = [i for i in range(len(baseline)) if i not in matched_baseline]
print(f"未匹配 baseline: {len(unmatched_bl)}")
for i in unmatched_bl:
    print(f"  [{baseline[i]['label']}] {baseline[i]['vuln_type'][:60]}  |  {baseline[i]['source_file'][:50]}")
