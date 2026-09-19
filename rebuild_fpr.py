"""重新跑 FPR 分析 + 更新报告 JSON 中的 M13 指标。
不重跑整个 pipeline，只重跑 REPORTING 阶段的 FPR 分析部分。

用法: python rebuild_fpr.py <evaluation_id>
"""
import sys
import json
import os
import pymysql

# 设置环境变量（pod 里已有，本地开发用）
os.environ.setdefault("EVAL_MYSQL_HOST", "eval-engine-mysql")
os.environ.setdefault("EVAL_MYSQL_USER", "root")
os.environ.setdefault("EVAL_MYSQL_PASSWORD", "Icsl_eval")
os.environ.setdefault("EVAL_MYSQL_DATABASE", "athena_eval")

EVAL_ID = sys.argv[1] if len(sys.argv) > 1 else "EV-20260917120111-7242"
REPORTS_DIR = os.environ.get("EVAL_REPORTS_DIR", "/app/reports")
REPORT_PATH = os.path.join(REPORTS_DIR, f"{EVAL_ID}.json")

print(f"=== 重建 FPR 分析: {EVAL_ID} ===")

# Step 1: 从 DB 获取 entries 和 case_details
print("\n[1] 从 DB 获取 entries 和 case_details...")
conn = pymysql.connect(
    host=os.environ["EVAL_MYSQL_HOST"],
    user=os.environ["EVAL_MYSQL_USER"],
    password=os.environ["EVAL_MYSQL_PASSWORD"],
    database=os.environ["EVAL_MYSQL_DATABASE"],
    charset="utf8mb4",
    autocommit=True,
)
cur = conn.cursor(pymysql.cursors.DictCursor)

# entries
cur.execute(
    "SELECT JSON_EXTRACT(config_json, '$.manifest.entries') as entries "
    "FROM evaluation_snapshot WHERE evaluation_id=%s", (EVAL_ID,))
row = cur.fetchone()
entries = json.loads(row["entries"]) if row and row["entries"] else []
print(f"  entries: {len(entries)} 条")
for e in entries:
    print(f"    condition={e.get('condition')}, category={e.get('category')}, "
          f"project_id={e.get('project_id')}, task_id_actual={e.get('task_id_actual')}")

# benchmark_set_id
cur.execute("SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s", (EVAL_ID,))
row = cur.fetchone()
bsid = row["benchmark_set_id"] if row else None
print(f"  benchmark_set_id: {bsid}")

# case_details from benchmark_item
cur.execute(
    "SELECT benchmark_item_id, expected_label, metadata_json "
    "FROM benchmark_item WHERE benchmark_set_id=%s", (bsid,))
rows = cur.fetchall()
conn.close()

case_details = {}
for r in rows:
    cid = r["benchmark_item_id"]
    meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
    desc = meta.get("description", "") or meta.get("vulnerability_type", "")
    case_details[cid] = {
        "description": desc,
        "vulnerability_type": meta.get("vulnerability_type", ""),
        "target_finding_id": meta.get("target_finding_id", ""),
        "expected_label": r["expected_label"],
        "source_file": meta.get("source_file", ""),
        "source_function": meta.get("source_function", ""),
        "source_line": meta.get("source_line", ""),
    }
print(f"  case_details: {len(case_details)} 条")
_vuln = sum(1 for c in case_details.values() if c["expected_label"] == "VULNERABLE")
_nonvuln = sum(1 for c in case_details.values() if c["expected_label"] == "NON_VULNERABLE")
print(f"    VULNERABLE={_vuln}, NON_VULNERABLE={_nonvuln}")

# Step 2: 加载现有报告
print(f"\n[2] 加载报告: {REPORT_PATH}")
with open(REPORT_PATH, "r", encoding="utf-8") as f:
    report = json.load(f)
print(f"  报告加载成功, top-level keys: {list(report.keys())[:10]}")

# Step 3: 重跑 FPR 分析
print("\n[3] 重跑 FPR 分析...")
from athena_eval_engine.application.fpr_analysis import run_fpr_analysis, derive_fpr_from_subset
from athena_eval_engine.infrastructure.vuln_center_client import list_vuln_cases

_e2e_fpr_kg = None
_e2e_fpr_nogk = None
_ac_fpr_kg = None
_ac_fpr_nogk = None
_vc_ids_kg = set()
_vc_ids_nogk = set()

def _extract_source_task_id(entry):
    return entry.get("task_id_actual") or ""

for cond_label, cond_val in (("KG", "KG"), ("NOGK", "NOGK")):
    _mining_entry = next((e for e in entries
                          if e.get("category", "") != "verify"
                          and e.get("condition") == cond_val
                          and e.get("project_id")), None)
    if not _mining_entry:
        print(f"  ({cond_label}): 无 mining entry，跳过")
        continue
    _fpr_pid = _mining_entry["project_id"]
    _fpr_tid = _extract_source_task_id(_mining_entry) or _mining_entry.get("task_id", "")
    print(f"  ({cond_label}): project={_fpr_pid}, task={_fpr_tid}")

    try:
        _ac_result = run_fpr_analysis(_fpr_pid, _fpr_tid,
                                       source="alert_center", case_details=case_details)
    except Exception as e:
        print(f"  ({cond_label}): FPR 分析失败: {e}")
        _ac_result = None

    if _ac_result:
        print(f"  ({cond_label}): 告警中心 FPR={_ac_result['fpr']:.1%} "
              f"(匹配 {_ac_result['matched']}/{_ac_result['total_findings']})")
        # 派生漏洞中心 FPR
        _vc_ids = set()
        try:
            _vc_cases = list_vuln_cases(project_id=_fpr_pid, source_task_id=_fpr_tid)
            _vc_ids = {c.get("id", "") for c in _vc_cases if c.get("id")}
            if _vc_ids:
                _vc_result = derive_fpr_from_subset(_ac_result, _vc_ids)
                print(f"  ({cond_label}): 漏洞中心 FPR={_vc_result['fpr']:.1%} "
                      f"(匹配 {_vc_result['matched']}/{_vc_result['total_findings']})")
            else:
                _vc_result = None
                print(f"  ({cond_label}): 漏洞中心 case ID 为空")
        except Exception as e:
            print(f"  ({cond_label}): 派生漏洞中心 FPR 失败: {e}")
            _vc_result = None

        if cond_val == "KG":
            _ac_fpr_kg = _ac_result
            _e2e_fpr_kg = _vc_result
            _vc_ids_kg = _vc_ids
        else:
            _ac_fpr_nogk = _ac_result
            _e2e_fpr_nogk = _vc_result
            _vc_ids_nogk = _vc_ids
    else:
        print(f"  ({cond_label}): 告警中心无数据")

# Step 3b: 持久化 FPR 匹配结果到文件（供后续环节使用）
_fpr_match_data = {}
if _ac_fpr_kg:
    _fpr_match_data["kg"] = {**_ac_fpr_kg, "vc_ids": list(_vc_ids_kg)}
if _ac_fpr_nogk:
    _fpr_match_data["nogk"] = {**_ac_fpr_nogk, "vc_ids": list(_vc_ids_nogk)}
if _fpr_match_data:
    _fpr_match_path = os.path.join(REPORTS_DIR, f"{EVAL_ID}_fpr_match.json")
    try:
        with open(_fpr_match_path, "w", encoding="utf-8") as _f:
            json.dump(_fpr_match_data, _f, ensure_ascii=False)
        print(f"\n[3b] FPR 匹配结果已写入: {_fpr_match_path}")
    except Exception as _e:
        print(f"\n[3b] ⚠ FPR 匹配结果写入失败: {_e}")

# Step 4: 更新 M13 指标
print("\n[4] 更新 M13 指标...")

def _update_m13_fpr(m13, fpr_kg_result, fpr_nogk_result, label=""):
    if not m13:
        return
    if not fpr_kg_result and not fpr_nogk_result:
        m13["estimate"] = None
        m13["calculation_status"] = "NA"
        m13["reason_code"] = "FPR_ANALYSIS_FAILED"
        m13["ci_lower"] = None
        m13["ci_upper"] = None
        m = m13.get("method", {})
        m.clear()
        m["formula"] = "误报率 = 误报数 / (误报数 + 真正数)"
        print(f"  M13 ({label}): NA (FPR_ANALYSIS_FAILED)")
        return
    fpr_kg = fpr_kg_result["fpr"] if fpr_kg_result else None
    fpr_nogk = fpr_nogk_result["fpr"] if fpr_nogk_result else None
    tp_kg = fpr_kg_result["tp"] if fpr_kg_result else 0
    fp_kg = fpr_kg_result["fp"] if fpr_kg_result else 0
    tp_n = fpr_nogk_result["tp"] if fpr_nogk_result else 0
    fp_n = fpr_nogk_result["fp"] if fpr_nogk_result else 0
    n_kg = fpr_kg_result["total_findings"] if fpr_kg_result else 0
    n_n = fpr_nogk_result["total_findings"] if fpr_nogk_result else 0
    m13["estimate"] = fpr_kg if fpr_kg is not None else 0.0
    m13["calculation_status"] = "CALCULATED"
    m13["reason_code"] = None
    m = m13.get("method", {})
    m["fpr_kg"] = fpr_kg if fpr_kg is not None else 0.0
    m["fpr_nogk"] = fpr_nogk if fpr_nogk is not None else 0.0
    m["tp_kg"] = tp_kg
    m["fp_kg"] = fp_kg
    m["fn_kg"] = 0
    m["tn_kg"] = 0
    m["tp_n"] = tp_n
    m["fp_n"] = fp_n
    m["fn_n"] = 0
    m["tn_n"] = 0
    m["formula"] = "误报率 = 误报数 / (误报数 + 真正数)"
    m["formula_kg"] = f"KG: {fp_kg} / ({fp_kg} + {tp_kg}) = {fpr_kg:.4f}" if fpr_kg is not None else "KG: 无数据"
    m["formula_nogk"] = f"NOGK: {fp_n} / ({fp_n} + {tp_n}) = {fpr_nogk:.4f}" if fpr_nogk is not None else "NOGK: 无数据"
    m["uncertainty"] = None
    m13["n"] = n_kg
    m13["ci_lower"] = None
    m13["ci_upper"] = None
    print(f"  M13 ({label}): KG FPR={fpr_kg:.4f} (FP={fp_kg}, TP={tp_kg}, N={n_kg})"
          + (f", NOGK FPR={fpr_nogk:.4f} (FP={fp_n}, TP={tp_n}, N={n_n})" if fpr_nogk is not None else ", NOGK 无数据"))

# 顶层 M13
_update_m13_fpr(report.get("p0", {}).get("M13"), _ac_fpr_kg, _ac_fpr_nogk, label="顶层")

# 分组 M13
for mg in report.get("metric_groups", []):
    _cat = mg.get("category", "")
    if _cat == "mining":
        _update_m13_fpr(mg.get("p0", {}).get("M13"), _ac_fpr_kg, _ac_fpr_nogk, label=f"挖掘({mg.get('task_id','')})")
    elif _cat == "verify":
        _update_m13_fpr(mg.get("p0", {}).get("M13"), _e2e_fpr_kg, _e2e_fpr_nogk, label=f"验证({mg.get('task_id','')})")
    # 挂载 E2E FPR 数据到 verify 分组
    if _cat == "verify" and (_e2e_fpr_kg or _e2e_fpr_nogk):
        mg["e2e_fpr_kg"] = _e2e_fpr_kg
        mg["e2e_fpr_nogk"] = _e2e_fpr_nogk

# 添加 mining_fpr 分组（如果 FPR 有结果）
if _ac_fpr_kg or _ac_fpr_nogk:
    # 检查是否已存在 mining_fpr 分组
    _has_mining_fpr = any(mg.get("category") == "mining_fpr" for mg in report.get("metric_groups", []))
    if not _has_mining_fpr:
        report.setdefault("metric_groups", []).append({
            "task_id": "",
            "category": "mining_fpr",
            "label": "漏洞挖掘误报率",
            "agent_name": "",
            "p0": {}, "p1": {}, "p2": {},
            "diagnostic_hits": [],
            "case_results": [],
            "pair_count": 0,
            "e2e_fpr_kg": _ac_fpr_kg,
            "e2e_fpr_nogk": _ac_fpr_nogk,
        })
    else:
        for mg in report["metric_groups"]:
            if mg.get("category") == "mining_fpr":
                mg["e2e_fpr_kg"] = _ac_fpr_kg
                mg["e2e_fpr_nogk"] = _ac_fpr_nogk

# 更新 warnings（去掉 M13 NA 告警）
_warnings = report.get("warnings", [])
_new_warnings = [w for w in _warnings if "M13" not in w]
report["warnings"] = _new_warnings
if len(_warnings) != len(_new_warnings):
    print(f"\n  去掉 M13 NA 告警: {len(_warnings)} → {len(_new_warnings)} 条")

# Step 5: 写回报告 JSON
print(f"\n[5] 写回报告 JSON: {REPORT_PATH}")
rj = json.dumps(report, ensure_ascii=False, indent=2)
with open(REPORT_PATH, "w", encoding="utf-8") as f:
    f.write(rj)
print(f"  报告已更新 ({len(rj):,} 字节)")

# Step 6: 重新生成 HTML
print("\n[6] 重新生成静态 HTML...")
try:
    from athena_eval_engine.api.routes.evaluations import render_static_report
    render_static_report(EVAL_ID)
    print("  HTML 生成成功")
except Exception as e:
    print(f"  HTML 生成失败: {e}")

print(f"\n=== 完成 ===")
