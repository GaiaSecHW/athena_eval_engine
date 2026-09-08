"""漏洞中心（Chimera，secflow-platform-vuln）数据读取 — V-Bench 测评集的原始数据源。

漏洞中心暴露 ``GET /api/vuln/cases``（bearer token 鉴权），返回 case 列表。
基线只取**人工确认**的 case：分两次查询——``confirmation_status=vulnerable`` 取确认漏洞，
``confirmation_status=not_vulnerable`` 取确认非漏洞。未判定的 case（inconclusive）
不作为基线（无明确 GT，不能算 TP/FP/FN/TN）。

本 client 在评测基线「漏洞中心数据」模式下替代 ``vbench_client.get_benchmark``，
归一成同构的 ``{cases: [{case_id, vulnerability_type, description, target_finding_id, expected_label}]}``。

description 渲染完全移植 V-Bench builder 的
``vbench_next/app/upstream/import_service.py:normalize_case_description``（6 段），
保证与现有 benchmark.zip 语义逐字一致，``ai_matcher`` LLM 匹配无感切换。
"""
from __future__ import annotations
import json
import urllib.parse
import urllib.request
from ..config_loader import VULN_CENTER_API_URL, PLATFORM_TOKEN


def _get(url: str, params: dict | None = None) -> dict | list:
    """带 bearer token 的 GET，返回 JSON。沿用 vbench_client 的 urllib 同步风格。"""
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {PLATFORM_TOKEN}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def list_vuln_cases(project_id: str, source_task_id: str | None = None,
                    confirmation_status: str | None = None,
                    page_size: int = 1000, max_pages: int = 100) -> list[dict]:
    """分页拉取漏洞中心 case。

    ``scope=vuln_center`` + ``project_id`` + 可选 ``source_task_ids`` 做项目/任务级过滤。
    ``confirmation_status`` 取 'vulnerable' 或 'not_vulnerable'，分别拉人工确认的漏洞/非漏洞。
    默认 page_size=1000 一次取完，超 1000 自动翻页兜底。
    """
    accumulated: list[dict] = []
    total: int | None = None
    for page in range(1, max_pages + 1):
        params: dict[str, str | int] = {
            "scope": "vuln_center",
            "project_id": project_id,
            "sort_field": "created_at",
            "sort_direction": "desc",
            "include_decision_reason": "false",
            "page": page,
            "page_size": page_size,
        }
        if source_task_id:
            params["source_task_ids"] = source_task_id
        if confirmation_status:
            params["confirmation_status"] = confirmation_status
        data = _get(VULN_CENTER_API_URL, params)
        items = data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        accumulated.extend(items)
        if total is None:
            total = data.get("total") if isinstance(data, dict) else None
        if not items:
            break
        if total is not None and len(accumulated) >= total:
            break
        if total is None and len(items) < page_size:
            break
    return accumulated


def _render_description_value(value) -> str:
    """移植 vbench_next import_service._render_description_value。"""
    if value is None or value == "":
        return "(not provided upstream)"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _join_present(*values) -> str | None:
    """移植 vbench_next import_service._join_present。"""
    rendered = [
        _render_description_value(v)
        for v in values
        if v is not None and v != ""
    ]
    return "\n".join(rendered) if rendered else None


def _normalize_case_description(case: dict) -> str:
    """移植 vbench_next/app/upstream/import_service.py:normalize_case_description。

    渲染 6 段有界语义段，不抬升 report claims 的可信度：
    1. Vulnerability title
    2. Human-confirmed black-box vulnerability（固定提示）
    3. Upstream summary
    4. Human confirmation notes
    5. Report claims requiring code verification
    6. POC or trigger-input evidence
    """
    confirmation = case.get("human_confirmation")
    latest_decision = case.get("latest_human_decision")
    fact_detail = (
        "The upstream human decision confirms that the vulnerability was "
        "reproduced through black-box observation. This confirms existence, "
        "not any reported code location or call path."
    )
    human_notes = _join_present(
        confirmation.get("summary") if confirmation else None,
        latest_decision.get("reason") if latest_decision else None,
    )
    subject = case.get("subject")
    report_claims = _join_present(
        case.get("raw_report_summary"),
        subject if subject is not None else None,
    )
    poc_detail = _join_present(
        "POC is evidence only and must not be executed",
        case.get("display_summary"),
        "Static POC material is referenced." if case.get("has_static_poc") else None,
        "Dynamic POC material is referenced." if case.get("has_dynamic_poc") else None,
    )
    sections = (
        ("Vulnerability title", case.get("title") or case.get("id")),
        ("Human-confirmed black-box vulnerability", fact_detail),
        ("Upstream summary", case.get("summary")),
        ("Human confirmation notes", human_notes),
        ("Report claims requiring code verification", report_claims),
        ("POC or trigger-input evidence", poc_detail),
    )
    return "\n\n".join(
        f"## {heading}\n{_render_description_value(value)}"
        for heading, value in sections
    )


def _extract_function_name(locator: str, subject_name: str) -> str:
    """从文件路径或 subject.name 中提取函数名/方法名。"""
    # 1) 文件名去扩展名就是函数名（如 devdrv_manager_ioctl.c → devdrv_manager_ioctl）
    import os as _os
    if locator:
        basename = _os.path.basename(locator)
        name = _os.path.splitext(basename)[0]
        if name and name not in ("main", "index", "init", "config"):
            return name
    # 2) 从 subject.name 开头提取函数名（到第一个空格/中文/标点）
    if subject_name:
        import re as _re
        m = _re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)', subject_name)
        if m:
            return m.group(1)
    return ""


def _case_to_benchmark(c: dict, expected_label: str) -> dict:
    """单条 case 归一成基线结构。"""
    subject = c.get("subject") or {}
    locator = subject.get("locator") or ""
    subj_name = subject.get("name") or ""
    func_name = _extract_function_name(locator, subj_name)
    return {
        "case_id": c.get("id") or "",
        "vulnerability_type": c.get("title") or subject.get("type") or "",
        "description": _normalize_case_description(c),
        "target_finding_id": (c.get("source_task") or {}).get("finding_id"),
        "expected_label": expected_label,
        "source_file": locator,            # 基线漏洞所在文件路径
        "source_function": func_name,      # 基线漏洞所在函数名/方法名
    }


def get_vuln_center_benchmark(project_id: str, source_task_id: str | None = None) -> dict:
    """返回与 ``vbench_client.get_benchmark`` 同构的基线结构。

    分两次查询：``confirmation_status=vulnerable`` 取确认漏洞（VULNERABLE），
    ``confirmation_status=not_vulnerable`` 取确认非漏洞（NOT_VULNERABLE）。
    未判定的 inconclusive case 不作为基线。expected_label 由查询过滤直接确定。
    """
    vuln_cases = list_vuln_cases(project_id, source_task_id, confirmation_status="vulnerable")
    not_vuln_cases = list_vuln_cases(project_id, source_task_id, confirmation_status="not_vulnerable")
    cases = [_case_to_benchmark(c, "VULNERABLE") for c in vuln_cases]
    cases += [_case_to_benchmark(c, "NOT_VULNERABLE") for c in not_vuln_cases]
    return {"benchmark_id": project_id, "name": None, "cases": cases}
