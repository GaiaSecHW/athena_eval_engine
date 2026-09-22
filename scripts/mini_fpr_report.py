#!/usr/bin/env python3
"""Mini FPR 报告生成器 — 只含误报率 + 告警中心数据与基线匹配明细。

用法:
    python mini_fpr_report.py <evaluation_id>

输出:
    {evaluation_id}_mini.html  (当前目录)

数据流:
    DB evaluation_snapshot → manifest/entries → case_details(基线)
    → vuln_center_client.list_alert_center_cases → findings(告警中心)
    → run_fpr_analysis → LLM 匹配 + FPR 计算
    → 自包含 HTML (误报率卡片 + 匹配明细表格 + 筛选)
"""
import sys
import os
import json
import re

# 确保能 import athena_eval_engine
_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_HERE)  # athena_eval_engine 的父目录
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from athena_eval_engine.infrastructure.database import connect
from athena_eval_engine.infrastructure import vuln_center_client
from athena_eval_engine.application.fpr_analysis import run_fpr_analysis
from athena_eval_engine.infrastructure.log_util import log, set_eval_ctx
from athena_eval_engine.infrastructure import llm as _llm_mod
from athena_eval_engine.infrastructure.concurrency import set_val as _conc_set, get_keys as _conc_keys


def _load_db_config():
    """从 DB system_config 表加载系统参数到当前进程内存。

    独立脚本进程不走 uvicorn startup，需要手动加载 DB 配置才能用
    运行时并发参数（而非 concurrency.py 默认值）。
    """
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT config_key, config_value FROM system_config")
            rows = cur.fetchall()
        finally:
            conn.close()
    except Exception as e:
        log("MINI-FPR", f"从 DB 加载系统参数失败（用默认值）: {e}")
        return

    _cfg_keys = _conc_keys()
    for key, value in rows:
        if key in _cfg_keys:
            _conc_set(key, int(value))
        elif key == "llm_max_concurrency":
            _llm_mod.set_max_concurrency(int(value))
        elif key == "reasoning_effort":
            _llm_mod.set_runtime_config(reasoning_effort=value)
    log("MINI-FPR", f"从 DB 加载 {len(rows)} 项系统参数，llm_max_concurrency={_llm_mod.get_max_concurrency()}")


def _extract_source_task_id(entry: dict) -> str:
    src = entry.get("source_uri", "") or ""
    m = re.search(r'/tasks/([^/]+)', src)
    return m.group(1) if m else ""


def load_eval_config(evaluation_id: str):
    """从 DB 读评测配置，返回 (manifest, bsid, entries, case_details)。"""
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT config_json FROM evaluation_snapshot WHERE evaluation_id=%s",
                    (evaluation_id,))
        row = cur.fetchone()
        if not row:
            print(f"ERROR: evaluation {evaluation_id} not found")
            sys.exit(1)
        cfg = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        manifest = cfg.get("manifest", {})
        entries = manifest.get("entries", [])
        cur.execute("SELECT benchmark_set_id FROM evaluation WHERE evaluation_id=%s",
                    (evaluation_id,))
        eval_row = cur.fetchone()
        bsid = eval_row[0] if eval_row else "BS001"
    finally:
        conn.close()

    # 重建 case_details
    _bm_source = manifest.get("benchmark_source", "vbench_zip")
    _vc_task_id = manifest.get("vc_source_task_id")
    case_details = {}
    if _bm_source == "vuln_center" and not _vc_task_id:
        for e in entries:
            tid_actual = e.get("task_id_actual") or _extract_source_task_id(e) or e.get("task_id")
            if tid_actual:
                _vc_task_id = tid_actual
                break
    try:
        if _bm_source == "vuln_center":
            bm = vuln_center_client.get_vuln_center_benchmark(bsid, _vc_task_id)
            if not (bm.get("cases") or []) and _vc_task_id:
                bm = vuln_center_client.get_vuln_center_benchmark(bsid, None)
            for c in (bm.get("cases") or []):
                cid = c.get("case_id") or c.get("id") or ""
                if cid:
                    case_details[cid] = {
                        "description": c.get("description") or "",
                        "vulnerability_type": c.get("vulnerability_type") or "",
                        "target_finding_id": c.get("target_finding_id") or "",
                        "expected_label": c.get("expected_label") or "VULNERABLE",
                        "source_file": c.get("source_file") or "",
                        "source_function": c.get("source_function") or "",
                        "source_line": c.get("source_line") or "",
                        "locator": c.get("locator") or "",
                    }
        else:
            from athena_eval_engine.infrastructure.vbench_client import get_benchmark
            bm = get_benchmark(bsid)
            for c in (bm.get("cases") or []):
                cid = c.get("case_id") or c.get("id") or ""
                if cid:
                    findings = c.get("findings") or []
                    desc = " ".join(f.get("explanation", "") for f in findings if f.get("explanation")) \
                           or c.get("description", "") or c.get("vulnerability_type", "") or ""
                    case_details[cid] = {
                        "description": desc,
                        "vulnerability_type": c.get("vulnerability_type") or c.get("category") or "",
                        "target_finding_id": c.get("target_finding_id") or "",
                        "expected_label": c.get("expected_label") or "VULNERABLE",
                        "source_file": c.get("source_file") or "",
                        "source_function": c.get("source_function") or "",
                        "source_line": c.get("source_line") or "",
                    }
    except Exception as e:
        log("MINI-FPR", f"取基线数据失败: {e}")
    return manifest, bsid, entries, case_details


def run_fpr_for_cond(entries, case_details, cond_label, cond_val):
    """对 KG 或 NOGK 运行告警中心 FPR 分析。"""
    _mining_entry = next((e for e in entries
                          if e.get("category", "") != "verify"
                          and e.get("condition") == cond_val
                          and e.get("project_id")), None)
    if not _mining_entry:
        log("MINI-FPR", f"({cond_label}) 无 mining entry，跳过")
        return None

    _fpr_pid = _mining_entry["project_id"]
    _fpr_tid = _extract_source_task_id(_mining_entry) or _mining_entry.get("task_id", "")
    if not _fpr_tid or _fpr_tid == _mining_entry.get("task_id"):
        _fpr_tid = _mining_entry.get("task_id", "")

    log("MINI-FPR", f"({cond_label}) 告警中心 FPR: project={_fpr_pid}, task={_fpr_tid}")
    try:
        result = run_fpr_analysis(_fpr_pid, _fpr_tid,
                                  source="alert_center", case_details=case_details)
    except Exception as e:
        log("MINI-FPR", f"({cond_label}) FPR 分析失败: {e}")
        return None
    return result


def generate_html(evaluation_id, kg_result, nogk_result):
    """生成自包含 HTML：误报率卡片 + 匹配明细表格 + 筛选。"""

    def _fpr_card(label, r):
        if not r or r.get("fpr") is None:
            return f'<div class="mcard"><div class="mc-label">{label}</div><div class="mc-val" style="color:var(--gray)">—</div></div>'
        fpr = r["fpr"]
        tp = r.get("tp", 0)
        fp = r.get("fp", 0)
        matched = r.get("matched", 0)
        total_f = r.get("total_findings", 0)
        total_bl = r.get("total_baseline", 0)
        pct = f"{fpr*100:.2f}%"
        color = "var(--red)" if fpr > 0.3 else ("var(--amber)" if fpr > 0 else "var(--green)")
        return f'''<div class="mcard">
          <div class="mc-label">{label}</div>
          <div class="mc-val" style="color:{color}">{pct}</div>
          <div class="mc-ci">误报={fp} / (误报+真正)={fp+tp} · 匹配={matched}/{total_f} · 基线={total_bl}</div>
        </div>'''

    # 合并 match_details
    all_details = []
    if kg_result and kg_result.get("match_details"):
        for d in kg_result["match_details"]:
            d2 = dict(d)
            d2["condition"] = "KG"
            all_details.append(d2)
    if nogk_result and nogk_result.get("match_details"):
        for d in nogk_result["match_details"]:
            d2 = dict(d)
            d2["condition"] = "No-KG"
            all_details.append(d2)

    rows_html = []
    for d in all_details:
        if d.get("is_fp"):
            verdict = "fp"
            badge = '<span class="badge badge-fp">误报</span>'
        elif d.get("match_status") == "已匹配":
            verdict = "tp"
            badge = '<span class="badge badge-tp">真正</span>'
        else:
            verdict = "unmatched"
            badge = '<span class="badge badge-unmatched">未匹配</span>'

        bl_label = d.get("bl_label", "")
        if bl_label == "VULNERABLE":
            bl_label_html = '<span style="color:var(--red);font-size:11px">漏洞</span>'
        elif bl_label == "NON_VULNERABLE":
            bl_label_html = '<span style="color:var(--gray);font-size:11px">非漏洞</span>'
        else:
            bl_label_html = "-"

        cond_badge = ('<span style="font-size:11px;font-weight:600;color:var(--acc)">KG</span>'
                      if d.get("condition") == "KG"
                      else '<span style="font-size:11px;font-weight:600;color:var(--gray)">No-KG</span>')

        def _esc(s):
            return str(s or "").replace("<", "&lt;").replace(">", "&gt;")

        match_key = "matched" if d.get("match_status") == "已匹配" else "unmatched"
        rows_html.append(
            f'<tr data-condition="{d.get("condition","")}" data-match="{match_key}" data-verdict="{verdict}">'
            f'<td>{d.get("seq","")}</td>'
            f'<td>{cond_badge}</td>'
            f'<td style="font-size:12px">{_esc(d.get("finding_id",""))}</td>'
            f'<td style="max-width:150px;word-break:break-all">{_esc(d.get("finding_title",""))}</td>'
            f'<td style="font-size:12px;color:var(--sub);max-width:300px;word-break:break-all">{_esc(d.get("finding_summary","")[:200])}</td>'
            f'<td>{d.get("match_status","")}</td>'
            f'<td style="font-size:12px">{_esc(d.get("bl_case_id",""))}</td>'
            f'<td style="max-width:150px;word-break:break-all">{_esc(d.get("bl_title",""))}</td>'
            f'<td>{bl_label_html}</td>'
            f'<td style="font-size:12px;color:var(--sub);max-width:300px">{_esc(d.get("reason",""))}</td>'
            f'<td>{badge}</td>'
            f'</tr>'
        )

    has_nogk = bool(nogk_result)
    filter_bar = f'''<div class="filter-bar">
      <span class="filter-label">筛选：</span>
      <div class="filter-group">
        <span class="filter-title">条件</span>
        <button class="fbtn active" data-filter="condition" data-val="ALL" onclick="fprFilter(this,'condition','ALL')">全部</button>
        <button class="fbtn" data-filter="condition" data-val="KG" onclick="fprFilter(this,'condition','KG')">KG</button>
        {"<button class=\"fbtn\" data-filter=\"condition\" data-val=\"No-KG\" onclick=\"fprFilter(this,'condition','No-KG')\">No-KG</button>" if has_nogk else ""}
      </div>
      <div class="filter-group">
        <span class="filter-title">匹配状态</span>
        <button class="fbtn active" data-filter="match" data-val="ALL" onclick="fprFilter(this,'match','ALL')">全部</button>
        <button class="fbtn" data-filter="match" data-val="matched" onclick="fprFilter(this,'match','matched')">已匹配</button>
        <button class="fbtn" data-filter="match" data-val="unmatched" onclick="fprFilter(this,'match','unmatched')">未匹配</button>
      </div>
      <div class="filter-group">
        <span class="filter-title">判定</span>
        <button class="fbtn active" data-filter="verdict" data-val="ALL" onclick="fprFilter(this,'verdict','ALL')">全部</button>
        <button class="fbtn" data-filter="verdict" data-val="tp" onclick="fprFilter(this,'verdict','tp')">真正</button>
        <button class="fbtn" data-filter="verdict" data-val="fp" onclick="fprFilter(this,'verdict','fp')">误报</button>
        <button class="fbtn" data-filter="verdict" data-val="unmatched" onclick="fprFilter(this,'verdict','unmatched')">未匹配</button>
      </div>
      <span class="filter-count">共 {len(all_details)} 条</span>
    </div>'''

    html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mini FPR Report — {evaluation_id}</title>
<style>
:root{{--bg:#f5f6f8;--panel:#fff;--p2:#f0f2f5;--bd:#e1e4e8;--txt:#1a1d23;--sub:#6b7280;--acc:#2563eb;--green:#16a34a;--red:#dc2626;--amber:#d97706;--gray:#9ca3af}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--txt);font-size:16px;line-height:1.6;padding:24px}}
h2{{font-size:20px;margin-bottom:16px}}
h3{{font-size:15px;color:var(--sub);text-transform:uppercase;letter-spacing:.6px;font-weight:600;margin-bottom:12px}}
.card{{background:var(--panel);border:1px solid var(--bd);border-radius:14px;padding:20px;margin-bottom:16px}}
.mcards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}}
.mcard{{background:var(--panel);border:1px solid var(--bd);border-radius:14px;padding:16px;text-align:center}}
.mc-label{{font-size:14px;color:var(--sub);margin-bottom:6px}}
.mc-val{{font-size:28px;font-weight:700;font-family:"SF Mono",Consolas,monospace}}
.mc-ci{{font-size:13px;color:var(--sub);margin-top:6px;font-family:"SF Mono",Consolas,monospace}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{color:var(--sub);font-weight:500;text-align:left;padding:8px;border-bottom:1px solid var(--bd);font-size:12px;text-transform:uppercase;letter-spacing:.4px}}
td{{padding:10px 8px;border-bottom:1px solid var(--bd);vertical-align:top}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}}
.badge-fp{{background:rgba(217,119,6,.18);color:var(--amber)}}
.badge-tp{{background:rgba(22,163,74,.18);color:var(--green)}}
.badge-unmatched{{background:var(--p2);color:var(--gray)}}
.filter-bar{{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin-bottom:12px;padding:8px 12px;background:var(--p2);border-radius:8px}}
.filter-label{{font-size:13px;font-weight:600;color:var(--sub)}}
.filter-group{{display:flex;gap:4px;align-items:center}}
.filter-title{{font-size:12px;color:var(--gray);margin-right:4px}}
.fbtn{{padding:2px 10px;border:1px solid var(--bd);border-radius:4px;background:var(--panel);color:var(--sub);font-size:12px;cursor:pointer}}
.fbtn.active{{border-color:var(--acc);background:var(--acc);color:#fff}}
.filter-count{{font-size:12px;color:var(--gray);margin-left:auto}}
.note{{font-size:12px;color:var(--gray);margin-top:8px;padding:8px 12px;background:var(--p2);border-radius:8px}}
</style>
</head>
<body>
<h2>误报率分析 — {evaluation_id}</h2>

<div class="card">
  <h3>误报率统计</h3>
  <div class="mcards">
    {_fpr_card("KG", kg_result)}
    {_fpr_card("No-KG", nogk_result) if has_nogk else ""}
  </div>
  <div class="note">
    计算公式：误报率 = 误报数 / (误报数 + 真正数)<br>
    误报 = 匹配到"非漏洞"基线的漏洞上报；真正 = 匹配到"漏洞"基线的漏洞上报；未匹配的漏洞不参与计算
  </div>
</div>

<div class="card" style="overflow-x:auto">
  <h3>告警中心匹配明细</h3>
  {filter_bar}
  <table>
    <thead><tr><th>#</th><th>条件</th><th>告警中心ID</th><th>标题</th><th>摘要</th><th>匹配状态</th><th>基线case_id</th><th>基线标题</th><th>基线标签</th><th>匹配理由</th><th>判定</th></tr></thead>
    <tbody>{"".join(rows_html)}</tbody>
  </table>
</div>

<script>
function fprFilter(btn,filterType,val){{
  var card=btn.closest('.card');
  card.querySelectorAll('[data-filter="'+filterType+'"]').forEach(function(b){{
    b.classList.remove('active');
    b.style.borderColor='var(--bd)';
    b.style.background='var(--panel)';
    b.style.color='var(--sub)';
  }});
  btn.classList.add('active');
  btn.style.borderColor='var(--acc)';
  btn.style.background='var(--acc)';
  btn.style.color='#fff';
  var active={{}};
  card.querySelectorAll('.fbtn.active').forEach(function(b){{
    active[b.getAttribute('data-filter')]=b.getAttribute('data-val');
  }});
  var count=0;
  card.querySelectorAll('tbody tr').forEach(function(row){{
    var show=true;
    for(var f in active){{
      if(active[f]!=='ALL'&&row.getAttribute('data-'+f)!==active[f]){{show=false;break;}}
    }}
    row.style.display=show?'':'none';
    if(show)count++;
  }});
  var countEl=card.querySelector('.filter-count');
  if(countEl)countEl.textContent='共 '+count+' 条';
}}
</script>
</body>
</html>'''
    return html


def main():
    if len(sys.argv) < 2:
        print("用法: python mini_fpr_report.py <evaluation_id>")
        sys.exit(1)

    evaluation_id = sys.argv[1]
    set_eval_ctx(evaluation_id)

    # 从 DB 加载系统参数（独立进程不走 uvicorn startup）
    _load_db_config()

    # 硬编码 LLM 并发=300，基线并发=300，batch 并发=30
    _llm_mod.set_max_concurrency(300)
    _conc_set("fpr_baseline_workers", 300)
    _conc_set("fpr_baseline_batch", 30)
    log("MINI-FPR", f"硬编码并发: llm=300, fpr_baseline_workers=300, fpr_baseline_batch=30")

    log("MINI-FPR", f"开始: {evaluation_id}")

    # 1. 读评测配置 + 重建基线
    manifest, bsid, entries, case_details = load_eval_config(evaluation_id)
    if not case_details:
        print("ERROR: case_details 为空，无法分析")
        sys.exit(1)
    log("MINI-FPR", f"配置加载完成: entries={len(entries)}, case_details={len(case_details)}, bsid={bsid}")

    # 2. KG + NOGK 并行跑告警中心 FPR
    from concurrent.futures import ThreadPoolExecutor, as_completed
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        futures = {
            pool.submit(run_fpr_for_cond, entries, case_details, "KG", "KG"): "KG",
            pool.submit(run_fpr_for_cond, entries, case_details, "NOGK", "NOGK"): "NOGK",
        }
        kg_result = None
        nogk_result = None
        for fut in as_completed(futures):
            cond = futures[fut]
            result = fut.result()
            if cond == "KG":
                kg_result = result
            else:
                nogk_result = result
            if result:
                log("MINI-FPR", f"({cond}) FPR={result['fpr']:.1%} 匹配={result['matched']} 误报={result['fp']} 真正={result['tp']}")
    finally:
        pool.shutdown(wait=True)

    if not kg_result and not nogk_result:
        print("ERROR: KG 和 NOGK 均无 FPR 结果")
        sys.exit(1)

    # 3. 生成 HTML
    html = generate_html(evaluation_id, kg_result, nogk_result)
    out_path = f"{evaluation_id}_mini.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    log("MINI-FPR", f"完成: {out_path} ({len(html):,} 字节)")
    print(f"OK: {out_path} ({len(html):,} 字节)")


if __name__ == "__main__":
    main()
