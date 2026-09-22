"""独立 FPR 验证 v2：更全面的规则匹配 + 所有候选匹配输出。

匹配维度：源文件路径、API 端点、漏洞类型关键词、漏洞标题相似度。
"""
import json, re, os
from collections import defaultdict

# Load baseline
with open("baseline_data.json", encoding="utf-8") as f:
    baseline = json.load(f)

# Load alert center
ac_path = r"C:\Users\W00867~1\AppData\Local\Temp\alert_center.json"
with open(ac_path, encoding="utf-8") as f:
    ac_data = json.load(f)
findings = ac_data.get("items", [])

print(f"Baseline: {len(baseline)} 条 (VUL={sum(1 for b in baseline if b['label']=='VULNERABLE')}, NV={sum(1 for b in baseline if b['label']=='NON_VULNERABLE')})")
print(f"Findings: {len(findings)} 条 (vul={sum(1 for c in findings if c.get('validation_result')=='vulnerable')}, nv={sum(1 for c in findings if c.get('validation_result')=='not_vulnerable')})")

# --- Feature extraction ---

def norm_path(path: str) -> str:
    if not path:
        return ""
    path = path.strip()
    # Remove line numbers and function names
    path = re.sub(r':\d+(-\d+)?$', '', path)
    path = re.sub(r':[^/]+$', '', path)  # Remove :function_name
    # Extract the meaningful path (after /com/huawei/)
    m = re.search(r'com/huawei/(.+)', path)
    if m:
        return m.group(1).lower().strip()
    m = re.search(r'/src/(.+)', path)
    if m:
        return m.group(1).lower().strip()
    return path.lower().strip("/")

def extract_apis(text: str) -> set:
    """Extract API endpoint paths."""
    apis = set()
    # Match patterns like POST /api/..., GET /fintech/..., etc.
    for m in re.finditer(r'(?:POST|GET|PUT|DELETE)\s+(/[/\w{}.-]+)', text, re.IGNORECASE):
        apis.add(m.group(1).lower().rstrip("/"))
    # Also match bare paths
    for m in re.finditer(r'(/(?:api|fintech|apaas|supergateway|orgportal|spportal|omportal|http|transaction|saving|omserver|riskControl|v1|v2)[/\w{}.-]+)', text, re.IGNORECASE):
        apis.add(m.group(1).lower().rstrip("/"))
    return apis

def extract_keywords(text: str) -> set:
    """Extract meaningful keywords."""
    stop = {"的","了","和","与","或","在","存在","导致","漏洞","接口","可","造成",
            "a","an","the","in","of","for","to","is","with","by","on","at","as",
            "post","get","put","delete","http","https","api","v1","v2","存在","导致","可造成"}
    tokens = re.findall(r'[\u4e00-\u9fff]+|[a-zA-Z][a-zA-Z0-9]+', text.lower())
    return {t for t in tokens if t not in stop and len(t) > 1}

def get_finding_features(finding: dict) -> dict:
    subject = finding.get("subject", {}) or {}
    locator = subject.get("locator", "") or ""
    title = finding.get("title", "") or ""
    summary = finding.get("summary", "") or ""
    display = finding.get("display_summary", "") or ""
    if isinstance(display, dict):
        display = json.dumps(display, ensure_ascii=False)
    if not isinstance(display, str):
        display = str(display)
    raw_report = finding.get("raw_report_summary", "") or ""
    if isinstance(raw_report, dict):
        raw_report = json.dumps(raw_report, ensure_ascii=False)
    if not isinstance(raw_report, str):
        raw_report = str(raw_report)

    all_text = " ".join([str(title), str(summary), display, raw_report])

    return {
        "path": norm_path(locator),
        "locator_raw": locator,
        "apis": extract_apis(all_text),
        "keywords": extract_keywords(title + " " + summary),
        "title": title,
        "summary": summary[:200],
        "vr": finding.get("validation_result", ""),
    }

def get_baseline_features(bl: dict) -> dict:
    desc = bl.get("description", "") or ""
    title = bl.get("vuln_type", "") or ""
    return {
        "path": norm_path(bl.get("source_file", "")),
        "apis": extract_apis(desc + " " + title),
        "keywords": extract_keywords(title + " " + desc[:200]),
        "title": title,
        "desc": desc[:200],
        "label": bl["label"],
    }

# Pre-compute features
bl_features = [get_baseline_features(b) for b in baseline]
f_features = [get_finding_features(f) for f in findings]

# --- Scoring ---

def score_pair(fi: int, bi: int) -> float:
    """Score a finding-baseline pair. Returns 0-1."""
    ff = f_features[fi]
    bf = bl_features[bi]
    score = 0.0
    reasons = []

    # 1. Source file path matching (strongest)
    if ff["path"] and bf["path"]:
        if ff["path"] == bf["path"]:
            score += 0.45
            reasons.append("path:exact")
        elif ff["path"] in bf["path"] or bf["path"] in ff["path"]:
            score += 0.35
            reasons.append("path:contains")
        else:
            # Check last 2-3 path segments
            f_parts = ff["path"].split("/")
            b_parts = bf["path"].split("/")
            for n in (3, 2):
                if len(f_parts) >= n and len(b_parts) >= n:
                    if f_parts[-n:] == b_parts[-n:]:
                        score += 0.25
                        reasons.append(f"path:last{n}")
                        break
            else:
                # Check if they share a significant directory (exclude very common segments)
                common = set(f_parts) & set(b_parts)
                # Exclude overly broad segments that appear in most paths
                broad = {"controller", "service", "impl", "common", "config", "utils",
                         "fintech", "huawei", "src", "com", "app", "main", "java",
                         "sdk", "api", "core", "biz", "ws", "restful"}
                significant = {p for p in common if len(p) > 3 and p not in broad}
                # Need at least 2 significant shared segments to count
                if len(significant) >= 2:
                    score += 0.15
                    reasons.append(f"path:shared_dir:{significant}")

    # 2. API endpoint matching
    if ff["apis"] and bf["apis"]:
        overlap = ff["apis"] & bf["apis"]
        if overlap:
            score += 0.25
            reasons.append(f"api:{overlap}")

    # 3. Keyword matching
    if ff["keywords"] and bf["keywords"]:
        overlap = ff["keywords"] & bf["keywords"]
        union = ff["keywords"] | bf["keywords"]
        jaccard = len(overlap) / len(union) if union else 0
        score += jaccard * 0.2
        if overlap:
            reasons.append(f"kw:{overlap}")

    # 4. High-value keyword matches (bonus)
    hv_kw = {"sftp", "ssrf", "sql", "注入", "越权", "idor", "session", "劫持", "正则", "regex",
             "命令", "command", "权限", "白名单", "下载", "删除", "读取", "明文", "凭据",
             "密码", "sdp", "ussd", "mass", "assignment", "批量赋值", "租户", "隔离",
             "日志", "注入", "远程", "rce", "k8s", "master"}
    hv_overlap = ff["keywords"] & bf["keywords"] & hv_kw
    score += len(hv_overlap) * 0.03
    if hv_overlap:
        reasons.append(f"hv:{hv_overlap}")

    return min(score, 1.0), reasons

# --- Run matching ---

# Score all pairs above threshold
THRESHOLD = 0.10
all_scores = []
for fi in range(len(findings)):
    for bi in range(len(baseline)):
        s, reasons = score_pair(fi, bi)
        if s >= THRESHOLD:
            all_scores.append((s, fi, bi, reasons))

all_scores.sort(key=lambda x: x[0], reverse=True)

# Greedy 1:1 assignment
matched_f = {}  # fi -> (bi, score, reasons)
matched_b = {}  # bi -> (fi, score)

for s, fi, bi, reasons in all_scores:
    if fi in matched_f or bi in matched_b:
        continue
    matched_f[fi] = (bi, s, reasons)
    matched_b[bi] = (fi, s)

# Calculate FPR
matched_count = len(matched_f)
fp = 0
tp = 0
for fi, (bi, s, reasons) in matched_f.items():
    if baseline[bi]["label"] == "NON_VULNERABLE":
        fp += 1
    else:
        tp += 1

fpr = fp / matched_count if matched_count > 0 else 0

print(f"\n=== 独立 FPR v2 (threshold={THRESHOLD}) ===")
print(f"匹配: {matched_count}/{len(findings)}")
print(f"  TP={tp}, FP={fp}")
print(f"FPR = {fp}/{matched_count} = {fpr:.1%}")

# Show all matches sorted by finding index
print(f"\n=== 匹配明细 ({matched_count} 条) ===")
for fi in sorted(matched_f.keys()):
    bi, s, reasons = matched_f[fi]
    bl = baseline[bi]
    finding = findings[fi]
    is_fp = "❌ FP" if bl["label"] == "NON_VULNERABLE" else "✅ TP"
    print(f"\n[F{fi+1:3d}] {is_fp} score={s:.3f} reasons={','.join(reasons[:3])}")
    print(f"  Finding: {finding.get('title','')[:75]}")
    print(f"  F-locator: {(finding.get('subject',{}) or {}).get('locator','')[:75]}")
    print(f"  Baseline[{bl['label'][:3]}]: {bl['vuln_type'][:75]}")
    print(f"  B-file: {bl['source_file'][:75]}")

# Also show top unmatched candidates (high score but lost 1:1)
print(f"\n=== 未匹配但高分候选 (top 20) ===")
unmatched_candidates = [(s, fi, bi, reasons) for s, fi, bi, reasons in all_scores
                        if fi not in matched_f and bi not in matched_b]
for s, fi, bi, reasons in unmatched_candidates[:20]:
    bl = baseline[bi]
    finding = findings[fi]
    is_fp = "FP?" if bl["label"] == "NON_VULNERABLE" else "TP?"
    print(f"[F{fi+1:3d}→B{bi+1:2d}] {is_fp} score={s:.3f} | {finding.get('title','')[:50]} → {bl['vuln_type'][:50]}")

# Unmatched baselines
unmatched_bl = [i for i in range(len(baseline)) if i not in matched_b]
print(f"\n未匹配 baseline: {len(unmatched_bl)}/{len(baseline)}")
for i in unmatched_bl:
    print(f"  [{baseline[i]['label'][:3]}] {baseline[i]['vuln_type'][:60]} | {baseline[i]['source_file'][:50]}")
