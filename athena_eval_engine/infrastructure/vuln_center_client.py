"""漏洞中心（Chimera，secflow-platform-vuln）数据读取 — V-Bench 测评集的原始数据源。

漏洞中心暴露 ``GET /api/vuln/cases``（bearer token 鉴权），返回 case 列表。
基线拉取**人工确认漏洞**（``confirmation_status=vulnerable``）和
**人工确认非漏洞**（``confirmation_status=not_vulnerable``）两类 case，
分别标记为 VULNERABLE 和 NON_VULNERABLE。

本 client 在评测基线「漏洞中心数据」模式下替代 ``vbench_client.get_benchmark``，
归一成同构的 ``{cases: [{case_id, vulnerability_type, description, target_finding_id, expected_label}]}``。

description 渲染完全移植 V-Bench builder 的
``vbench_next/app/upstream/import_service.py:normalize_case_description``（6 段），
保证与现有 benchmark.zip 语义逐字一致，``ai_matcher`` LLM 匹配无感切换。
"""
from __future__ import annotations
import json
import time
import urllib.parse
import urllib.request
from urllib.error import URLError
from ..config_loader import VULN_CENTER_API_URL, PLATFORM_TOKEN


def _get(url: str, params: dict | None = None, retries: int = 20,
         retry_delay: float = 5.0) -> dict | list:
    """带 bearer token 的 GET，返回 JSON。沿用 vbench_client 的 urllib 同步风格。

    内部 Service 短暂抖动时指数退避重试。
    """
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {PLATFORM_TOKEN}"})
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read().decode("utf-8"))
        except (URLError, TimeoutError, OSError) as e:
            last_err = e
            if attempt + 1 < retries:
                time.sleep(retry_delay)
    raise last_err


def list_vuln_cases(project_id: str, source_task_id: str | None = None,
                    confirmation_status: str | None = None,
                    page_size: int = 1000, max_pages: int = 100) -> list[dict]:
    """分页拉取漏洞中心 case。

    ``scope=vuln_center`` + ``project_id`` + 可选 ``source_task_ids`` 做项目/任务级过滤。
    ``confirmation_status`` 取 'vulnerable' 拉人工确认漏洞。基线只包含确认漏洞。
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


def list_alert_center_cases(project_id: str, source_task_id: str | None = None,
                            page_size: int = 1000, max_pages: int = 100) -> list[dict]:
    """分页拉取告警中心 case。

    ``scope=alert_center`` + ``project_id`` + 可选 ``source_task_ids`` 做项目/任务级过滤。
    返回全部提交的 case（不限 confirmation_status），含引擎判定字段：
    - ``validation_result``: vulnerable / not_vulnerable / inconclusive / None
    - ``current_stage``: receive / validation
    - ``current_status``: pending / completed
    - ``latest_engine_decision``: 引擎最新决策
    - ``confirm_terminal_status``: 引擎处理终态
    """
    accumulated: list[dict] = []
    total: int | None = None
    for page in range(1, max_pages + 1):
        params: dict[str, str | int] = {
            "scope": "alert_center",
            "project_id": project_id,
            "sort_field": "created_at",
            "sort_direction": "desc",
            "include_decision_reason": "false",
            "page": page,
            "page_size": page_size,
        }
        if source_task_id:
            params["source_task_ids"] = source_task_id
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


def get_alert_center_summary(project_id: str, source_task_id: str | None = None) -> dict:
    """返回告警中心 case 摘要，用于指标计算和报告展示。

    返回结构::

        {
            "total": N,                    # 告警中心收到漏洞总数
            "cases": [...],               # 全部 case 原始数据
            "by_verdict": {                # 按 validation_result 分类
                "vulnerable": [...],      # 是漏洞
                "not_vulnerable": [...],  # 不是漏洞
                "inconclusive": [...],    # 无法判定
                "pending": [...],         # 其他（研判中）— current_stage=receive 且无 validation_result
            },
            "counts": {
                "vulnerable": N,
                "not_vulnerable": N,
                "inconclusive": N,
                "pending": N,
            }
        }
    """
    cases = list_alert_center_cases(project_id, source_task_id)
    by_verdict: dict[str, list[dict]] = {
        "vulnerable": [],
        "not_vulnerable": [],
        "inconclusive": [],
        "pending": [],
    }
    for c in cases:
        vr = c.get("validation_result")
        stage = c.get("current_stage")
        if vr == "vulnerable":
            by_verdict["vulnerable"].append(c)
        elif vr == "not_vulnerable":
            by_verdict["not_vulnerable"].append(c)
        elif vr == "inconclusive":
            by_verdict["inconclusive"].append(c)
        elif not vr and stage == "receive":
            by_verdict["pending"].append(c)
        else:
            # 其他未覆盖的情况归入 pending
            by_verdict["pending"].append(c)
    counts = {k: len(v) for k, v in by_verdict.items()}
    return {
        "total": len(cases),
        "cases": cases,
        "by_verdict": by_verdict,
        "counts": counts,
    }


def search_vuln_cases(project_id: str, search_term: str, scope: str = "alert_center",
                      page_size: int = 20) -> list[dict]:
    """按 case ID 搜索 case。

    CVulnVerify 的 trace_case_ids 来自告警中心，默认 scope=alert_center。
    返回原始 case 列表，调用方自行提取所需字段。
    """
    params = {
        "scope": scope,
        "project_id": project_id,
        "search": search_term,
        "sort_field": "created_at",
        "sort_direction": "desc",
        "page": 1,
        "page_size": page_size,
    }
    data = _get(VULN_CENTER_API_URL, params)
    return data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])


def get_task_id_by_case_id(project_id: str, case_id: str) -> str | None:
    """通过 case ID 搜索告警中心，返回 source_task.task_id。"""
    items = search_vuln_cases(project_id, case_id, scope="alert_center", page_size=1)
    if not items:
        return None
    source_task = items[0].get("source_task") or {}
    return source_task.get("task_id")


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


def _parse_locator(locator: str) -> tuple[str, str, str]:
    """解析 locator 字符串，返回 (source_file, source_function, source_line)。

    locator 格式可能为：
    - path/to/file.c                        (仅文件路径)
    - path/to/file.c:func_name              (文件+函数)
    - path/to/file.c:func_name:414          (文件+函数+行号)
    - path/to/file.c:func_name:414-420      (文件+函数+行号区间)
    - path/to/file.c:414                    (文件+行号)
    - path/to/file.c:414-420                (文件+行号区间)
    """
    if not locator:
        return "", "", ""

    def _is_line(s: str) -> bool:
        if s.isdigit():
            return True
        if "-" in s:
            nums = s.split("-")
            return len(nums) == 2 and all(n.isdigit() for n in nums)
        return False

    def _extract_line(s: str) -> str:
        return s.split("-")[0] if "-" in s and s.split("-")[0].isdigit() else (s if s.isdigit() else "")

    parts = locator.rsplit(":", 2)
    if len(parts) == 1:
        return parts[0], "", ""
    if len(parts) == 2:
        if _is_line(parts[1]):
            return parts[0], "", _extract_line(parts[1])
        return parts[0], parts[1], ""
    # 3 段：path:func:line
    source_file, source_function, source_line = parts
    if _is_line(source_line):
        return source_file, source_function, _extract_line(source_line)
    return source_file, source_function, ""


def _case_to_benchmark(c: dict, expected_label: str) -> dict:
    """单条 case 归一成基线结构。"""
    subject = c.get("subject") or {}
    locator = subject.get("locator") or ""
    source_file, source_function, source_line = _parse_locator(locator)
    return {
        "case_id": c.get("id") or "",
        "vulnerability_type": c.get("title") or subject.get("type") or "",
        "description": _normalize_case_description(c),
        "target_finding_id": (c.get("source_task") or {}).get("finding_id"),
        "expected_label": expected_label,
        "source_file": source_file,
        "source_function": source_function,
        "source_line": source_line,
        "locator": locator,
    }


def get_vuln_center_benchmark(project_id: str, source_task_id: str | None = None,
                              fetch_non_vuln: bool = True) -> dict:
    """返回与 ``vbench_client.get_benchmark`` 同构的基线结构。

    拉取两类人工确认 case：
    - ``confirmation_status=vulnerable`` → expected_label=VULNERABLE
    - ``confirmation_status=not_vulnerable`` → expected_label=NON_VULNERABLE

    ``fetch_non_vuln=False`` 时跳过非漏洞 API 调用。
    """
    vuln_cases = list_vuln_cases(project_id, source_task_id, confirmation_status="vulnerable")
    cases = [_case_to_benchmark(c, "VULNERABLE") for c in vuln_cases]
    if fetch_non_vuln:
        nonvuln_cases = list_vuln_cases(project_id, source_task_id, confirmation_status="not_vulnerable")
        cases += [_case_to_benchmark(c, "NON_VULNERABLE") for c in nonvuln_cases]
    return {"benchmark_id": project_id, "name": None, "cases": cases}
