"""评测 API + 报告 API。

端点：
- GET /api/v2/evaluations/{eid}/report           — 基础报告段（指标 + 召回率/准确率 + 汇总）
- GET /api/v2/evaluations/{eid}/report/lifecycle  — 生命周期分析段
- GET /api/v2/evaluations/{eid}/report/status     — 各段报告就绪状态
- GET /api/v2/evaluations/{eid}                   — 评测详情（状态 + 元信息）
- GET /api/v2/evaluations/{eid}/debug/{step}      — 步骤中间数据明细（调试用）
- GET /api/v2/evaluations/{eid}/debug             — 调试页面（HTML）
"""
from __future__ import annotations

import json
import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/api/v2/evaluations", tags=["evaluations"])

# 报告目录（与老代码一致，环境变量优先）
REPORTS_DIR = os.environ.get("EVAL_REPORTS_DIR", "reports")


def _report_path(evaluation_id: str, suffix: str) -> str:
    """构造报告文件路径。suffix 不含路径分隔符，如 'lifecycle'。"""
    return os.path.join(REPORTS_DIR, f"{evaluation_id}_{suffix}.json")


def _read_report_segment(evaluation_id: str, suffix: str) -> dict:
    """读取报告段 JSON 文件，不存在时返回 404。"""
    path = _report_path(evaluation_id, suffix)
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail=f"{suffix} report not found for evaluation '{evaluation_id}'",
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.loads(f.read())


# ---------------------------------------------------------------------------
# 评测详情端点
# ---------------------------------------------------------------------------

@router.get("/{evaluation_id}")
def get_evaluation(evaluation_id: str):
    """返回评测状态 + 元信息（从 DB 读取，兼容 v1/v2）。"""
    import json as _json
    from ...infrastructure.database import connect

    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT e.evaluation_id, e.evaluation_name, e.evaluation_status, "
            "e.benchmark_set_id, e.created_at, e.started_at, e.finished_at, "
            "e.error_message, e.version, "
            "s.config_json "
            "FROM evaluation e "
            "LEFT JOIN evaluation_snapshot s ON e.evaluation_id = s.evaluation_id "
            "WHERE e.evaluation_id = %s",
            (evaluation_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"evaluation '{evaluation_id}' not found",
            )
        result = {
            "evaluation_id": row[0],
            "name": row[1] or row[0],
            "status": row[2],
            "benchmark_set_id": row[3],
            "created_at": row[4].isoformat() if row[4] else None,
            "started_at": row[5].isoformat() if row[5] else None,
            "finished_at": row[6].isoformat() if row[6] else None,
            "error_message": row[7],
            "version": row[8],
        }
        # 从 config_json 提取 manifest 信息
        if row[9]:
            cfg = _json.loads(row[9]) if isinstance(row[9], str) else row[9]
            manifest = cfg.get("manifest", {})
            result["benchmark_source"] = manifest.get("benchmark_source", "vuln_center")
            result["eval_mode"] = manifest.get("eval_mode", "dev")
            result["vc_source_project_name"] = manifest.get("vc_source_project_name", "")
            result["vc_source_task_name"] = manifest.get("vc_source_task_name", "")
            entries = manifest.get("entries", [])
            result["entries_info"] = [
                {
                    "condition": e.get("condition"),
                    "project_name": e.get("project_name", ""),
                    "task_name": e.get("task_name", ""),
                    "category": e.get("category", ""),
                }
                for e in entries
            ]
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 报告端点
# ---------------------------------------------------------------------------

@router.get("/{evaluation_id}/report")
def get_base_report(evaluation_id: str):
    """返回 {eid}.json 基础报告段（指标 + 汇总）。"""
    path = os.path.join(REPORTS_DIR, f"{evaluation_id}.json")
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail=f"base report not found for evaluation '{evaluation_id}'",
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.loads(f.read())


@router.get("/{evaluation_id}/report/lifecycle")
def get_lifecycle_report(evaluation_id: str):
    """返回 {eid}_lifecycle.json 报告段。"""
    return _read_report_segment(evaluation_id, "lifecycle")


@router.get("/{evaluation_id}/report/status")
def get_report_status(evaluation_id: str):
    """返回各段报告就绪状态。

    检查以下段文件是否存在：
    - base: {eid}.json
    - fpr: {eid}_fpr.json
    - kg: {eid}_kg.json
    - lifecycle: {eid}_lifecycle.json
    """
    segments = {
        "base": f"{evaluation_id}.json",
        "fpr": f"{evaluation_id}_fpr.json",
        "kg": f"{evaluation_id}_kg.json",
        "lifecycle": f"{evaluation_id}_lifecycle.json",
    }
    return {
        name: os.path.isfile(os.path.join(REPORTS_DIR, filename))
        for name, filename in segments.items()
    }


# ---------------------------------------------------------------------------
# 调试端点 — 步骤中间数据明细
# ---------------------------------------------------------------------------

# 已知步骤列表（按 pipeline 顺序）
_DEBUG_STEPS = ["ingesting", "parsing", "resolving", "calculating",
                "lifecycle", "causal_chain", "reporting"]


@router.get("/{evaluation_id}/debug")
def get_debug_page(evaluation_id: str):
    """调试页面：展示各步骤中间数据。"""
    # 检查哪些步骤有数据
    available = []
    for step in _DEBUG_STEPS:
        path = os.path.join(REPORTS_DIR, f"{evaluation_id}_debug_{step}.json")
        if os.path.isfile(path):
            available.append(step)

    steps_html = "".join(
        f'<button class="step-btn{" active" if i == 0 else ""}" '
        f'data-step="{step}">{step}</button>'
        for i, step in enumerate(available)
    )
    no_data = not available
    empty_msg = '<div class="empty">暂无调试数据。评测运行后此处显示各步骤中间数据。</div>' if no_data else ""

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>调试 — {evaluation_id}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
h1 {{ font-size: 18px; margin-bottom: 16px; color: #8be9fd; word-break: break-all; }}
.step-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
.step-btn {{ padding: 6px 14px; border: 1px solid #444; background: #2a2a4e; color: #aaa;
  border-radius: 4px; cursor: pointer; font-size: 13px; }}
.step-btn:hover {{ background: #3a3a5e; color: #fff; }}
.step-btn.active {{ background: #6c5ce7; color: #fff; border-color: #6c5ce7; }}
.content {{ background: #16213e; border: 1px solid #333; border-radius: 6px; padding: 16px;
  max-height: 75vh; overflow: auto; }}
.content pre {{ font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }}
.empty {{ color: #666; padding: 40px; text-align: center; }}
.stats {{ display: flex; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }}
.stat {{ background: #2a2a4e; padding: 8px 14px; border-radius: 4px; font-size: 13px; }}
.stat .num {{ font-size: 20px; font-weight: bold; color: #8be9fd; }}
.stat .label {{ color: #888; font-size: 11px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #333; color: #888; position: sticky; top: 0; background: #16213e; }}
td {{ padding: 4px 8px; border-bottom: 1px solid #222; vertical-align: top; }}
tr:hover {{ background: #1a1a3e; }}
.badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; }}
.badge-vulnerable {{ background: #e74c3c; color: #fff; }}
.badge-not_vulnerable {{ background: #27ae60; color: #fff; }}
.badge-pending {{ background: #f39c12; color: #fff; }}
.badge-inconclusive {{ background: #95a5a6; color: #fff; }}
.badge-VULNERABLE {{ background: #e74c3c; color: #fff; }}
.badge-NON_VULNERABLE {{ background: #27ae60; color: #fff; }}
</style>
</head>
<body>
<h1>调试 — {evaluation_id}</h1>
<div class="step-bar">{steps_html}</div>
{empty_msg}
<div class="content" id="content"></div>
<script>
const eid = "{evaluation_id}";
const available = {available!r};

async function loadStep(step) {{
  const resp = await fetch(`/api/v2/evaluations/${{eid}}/debug/${{step}}`);
  if (!resp.ok) {{ document.getElementById("content").innerHTML = "<p>加载失败</p>"; return; }}
  const data = await resp.json();
  render(step, data);
}}

function render(step, data) {{
  const el = document.getElementById("content");
  if (step === "ingesting") renderIngesting(el, data);
  else el.innerHTML = `<pre>${{JSON.stringify(data, null, 2)}}</pre>`;
}}

function renderIngesting(el, data) {{
  let html = "";

  // 配置信息
  html += `<div class="stats">`;
  html += `<div class="stat"><div class="num">${{data.benchmark_source}}</div><div class="label">benchmark_source</div></div>`;
  html += `<div class="stat"><div class="num">${{data.eval_mode}}</div><div class="label">eval_mode</div></div>`;
  html += `<div class="stat"><div class="num">${{data.raw_data?.total ?? 0}}</div><div class="label">原始数据</div></div>`;
  html += `<div class="stat"><div class="num">${{data.baseline?.total ?? 0}}</div><div class="label">基线数据</div></div>`;
  html += `</div>`;

  // 原始数据明细
  const raw = data.raw_data || {{}};
  html += `<h3 style="margin:16px 0 8px;color:#8be9fd;">原始数据（告警中心） — ${{raw.total ?? 0}} 条</h3>`;
  if (raw.cases?.length) {{
    html += `<table><thead><tr><th>case_id</th><th>title</th><th>validation_result</th><th>stage</th><th>false_positive_reason</th><th>project_id</th></tr></thead><tbody>`;
    for (const c of raw.cases) {{
      const vr = c.validation_result || "pending";
      html += `<tr><td>${{c.case_id ?? ""}}</td><td>${{c.title ?? ""}}</td>`
        + `<td><span class="badge badge-${{vr}}">${{vr}}</span></td>`
        + `<td>${{c.current_stage ?? ""}}</td>`
        + `<td>${{c.false_positive_reason ?? ""}}</td>`
        + `<td>${{c.project_id ?? ""}}</td></tr>`;
    }}
    html += `</tbody></table>`;
  }}

  // 基线数据明细
  const bl = data.baseline || {{}};
  html += `<h3 style="margin:16px 0 8px;color:#8be9fd;">基线数据 — ${{bl.total ?? 0}} 条</h3>`;
  if (bl.cases?.length) {{
    html += `<table><thead><tr><th>case_id</th><th>vulnerability_type</th><th>expected_label</th><th>source_file</th><th>false_positive_reason</th><th>false_positive_group</th></tr></thead><tbody>`;
    for (const c of bl.cases) {{
      const el2 = c.expected_label || "";
      html += `<tr><td>${{c.case_id ?? ""}}</td><td>${{c.vulnerability_type ?? ""}}</td>`
        + `<td><span class="badge badge-${{el2}}">${{el2}}</span></td>`
        + `<td>${{c.source_file ?? ""}}</td>`
        + `<td>${{c.false_positive_reason ?? ""}}</td>`
        + `<td>${{c.false_positive_group ?? ""}}</td></tr>`;
    }}
    html += `</tbody></table>`;
  }}

  el.innerHTML = html;
}}

// 默认加载第一个
if (available.length) loadStep(available[0]);

// 按钮点击
document.querySelectorAll(".step-btn").forEach(btn => {{
  btn.addEventListener("click", () => {{
    document.querySelectorAll(".step-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    loadStep(btn.dataset.step);
  }});
}});
</script>
</body>
</html>
""")


@router.get("/{evaluation_id}/debug/{step}")
def get_debug_step(evaluation_id: str, step: str):
    """返回某步骤的中间数据 JSON。"""
    path = os.path.join(REPORTS_DIR, f"{evaluation_id}_debug_{step}.json")
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail=f"debug data for step '{step}' not found",
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.loads(f.read())
