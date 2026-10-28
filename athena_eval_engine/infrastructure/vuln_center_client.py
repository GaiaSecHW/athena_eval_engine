"""漏洞中心（Chimera，secflow-platform-vuln）数据读取 — V-Bench 测评集的原始数据源。

漏洞中心暴露 ``GET /api/vuln/cases``（bearer token 鉴权），返回 case 列表。
基线拉取**人工确认漏洞**（``confirmation_status=vulnerable``）和
**人工确认非漏洞**（``confirmation_status=not_vulnerable``）两类 case，
分别标记为 VULNERABLE 和 NON_VULNERABLE。

本 client 在评测基线「漏洞中心数据」模式下替代 ``vbench_client.get_benchmark``，
归一成同构的 ``{cases: [{case_id, vuln_title, description, expected_label}]}``。

description 渲染完全移植 V-Bench builder 的
``vbench_next/app/upstream/import_service.py:normalize_case_description``（6 段），
保证与现有 benchmark.zip 语义逐字一致，``ai_matcher`` LLM 匹配无感切换。
"""
from __future__ import annotations
import json
import time
import urllib.parse
import urllib.request
from urllib.error import URLError, HTTPError
from ..config_loader import VULN_CENTER_API_URL, PLATFORM_TOKEN
from .log_util import log


def _get(url: str, params: dict | None = None, retries: int = 20,
         retry_delay: float = 5.0, timeout: float = 180) -> dict | list:
    """带 bearer token 的 GET，返回 JSON。沿用 vbench_client 的 urllib 同步风格。

    内部 Service 短暂抖动时指数退避重试。
    """
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {PLATFORM_TOKEN}"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            last_err = e
            log("VULN_CENTER", f"HTTP {e.code} 重试 {attempt+1}/{retries}: {url}")
            if attempt + 1 < retries:
                time.sleep(retry_delay)
        except (URLError, TimeoutError, OSError) as e:
            last_err = e
            log("VULN_CENTER", f"网络错误重试 {attempt+1}/{retries}: {url} → {e}")
            if attempt + 1 < retries:
                time.sleep(retry_delay)
    log("VULN_CENTER", f"❌ {retries} 次重试全部失败: {url} → {last_err}")
    raise last_err


def get_case_raw_report(case_id: str, report_id: str = "raw-intake") -> str:
    """获取 case 的原始漏洞报告内容。

    调用漏洞中心 API ``GET /api/vuln/cases/{case_id}/report?report_id=raw-intake``，
    返回 report 的 ``content`` 字段（Markdown 格式的完整漏洞报告）。

    失败时返回空字符串，不抛异常（原始报告是补充信息，不阻塞主流程）。
    """
    try:
        data = _get(
            f"{VULN_CENTER_API_URL}/{case_id}/report",
            params={"report_id": report_id},
            retries=3,
        )
        if isinstance(data, dict):
            return data.get("content") or ""
    except Exception as e:
        log("VULN_CENTER", f"获取原始报告失败 case={case_id}: {e}")
    return ""


def list_stats(project_id: str, source_task_id: str | None = None,
               confirmation_status: str | None = None,
               false_positive_group: str | None = None) -> dict:
    """获取漏洞中心 case 汇总统计（不拉全量，直接返回计数）。

    调用 ``GET /api/vuln/cases/ops/list-stats``：
    - 无过滤 → {total, confirmed, ruled_out, inconclusive}
    - confirmation_status=vulnerable → confirmed=确认漏洞数
    - confirmation_status=not_vulnerable → ruled_out=确认非漏洞数
    - false_positive_group=confirmed_fp → 确认误报数（total）

    Args:
        project_id: 项目 ID。
        source_task_id: 任务 ID（可选）。
        confirmation_status: vulnerable/not_vulnerable（可选）。
        false_positive_group: confirmed_fp/non_fp（可选）。

    Returns:
        汇总 dict（total/confirmed/ruled_out/inconclusive）。失败返回全 0。
    """
    params: dict = {"project_id": project_id, "scope": "vuln_center",
                    "sort_field": "created_at", "sort_direction": "desc"}
    if source_task_id:
        params["source_task_ids"] = source_task_id
    if confirmation_status:
        params["confirmation_status"] = confirmation_status
    if false_positive_group:
        params["false_positive_group"] = false_positive_group
    try:
        data = _get(
            f"{VULN_CENTER_API_URL}/ops/list-stats",
            params=params,
            retries=3,
            retry_delay=2.0,
            timeout=15,
        )
        if isinstance(data, dict):
            return {
                "total": data.get("total") or 0,
                "confirmed": data.get("confirmed") or 0,
                "ruled_out": data.get("ruled_out") or 0,
                "inconclusive": data.get("inconclusive") or 0,
            }
    except Exception as e:
        log("VULN_CENTER", f"list_stats 失败: {str(e)[:200]}")
    return {"total": 0, "confirmed": 0, "ruled_out": 0, "inconclusive": 0}


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
            "include_decision_reason": "true",
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
                            final_result: str | None = None,
                            page_size: int = 100, max_pages: int = 1000) -> list[dict]:
    """分页拉取告警中心 case。

    ``project_id`` + 可选 ``source_task_ids`` 做项目/任务级过滤。
    ``final_result`` 可选，传 ``vulnerable`` 只取引擎判定为漏洞的 case。
    不传则拉全量。

    拉取策略：先查总条数，再并行分页拉取。
    """
    from concurrent.futures import ThreadPoolExecutor

    def _build_params(page: int, ps: int) -> dict[str, str | int]:
        params: dict[str, str | int] = {
            "project_id": project_id,
            "sort_field": "created_at",
            "sort_direction": "desc",
            "page": page,
            "page_size": ps,
        }
        if source_task_id:
            params["source_task_ids"] = source_task_id
        if final_result:
            params["final_result"] = final_result
        return params

    # 先查总条数（page_size=1，只取 1 条拿 total）
    first_data = _get(VULN_CENTER_API_URL, _build_params(1, 1))
    total = first_data.get("total") if isinstance(first_data, dict) else None
    if not total:
        # 没有数据或 API 不返回 total，回退到串行翻页
        items = first_data.get("items", []) if isinstance(first_data, dict) else []
        accumulated = list(items)
        page = 2
        while page <= max_pages:
            data = _get(VULN_CENTER_API_URL, _build_params(page, page_size))
            items = data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            if not items:
                break
            accumulated.extend(items)
            if len(items) < page_size:
                break
            page += 1
        return accumulated

    # 算总页数
    import math
    num_pages = min(math.ceil(total / page_size), max_pages)
    log("VULN_CENTER", f"告警中心: total={total}, page_size={page_size}, "
          f"pages={num_pages}")

    # 并行拉取所有页
    def _fetch_page(page: int) -> list[dict]:
        data = _get(VULN_CENTER_API_URL, _build_params(page, page_size))
        return data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

    accumulated: list[dict] = []
    max_workers = min(num_pages, 10)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch_page, p): p for p in range(1, num_pages + 1)}
        for fut in futures:
            page = futures[fut]
            try:
                items = fut.result()
                accumulated.extend(items)
            except Exception as e:
                log("VULN_CENTER", f"拉取第 {page}/{num_pages} 页失败: {e}")

    # 按创建时间降序排序（并行拉取后顺序乱了）
    accumulated.sort(key=lambda c: c.get("created_at", ""), reverse=True)
    log("VULN_CENTER", f"告警中心拉取完成: {len(accumulated)}/{total} 条")
    return accumulated


def get_alert_center_summary(project_id: str, source_task_id: str | None = None,
                             final_result: str | None = None) -> dict:
    """返回告警中心 case 摘要，用于指标计算和报告展示。

    ``final_result`` 可选，传 ``vulnerable`` 只取引擎判定为漏洞的 case。

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
    cases = list_alert_center_cases(project_id, source_task_id, final_result=final_result)
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
    """构建漏洞描述：标题 + 概述 + 人工确认信息。

    直接使用告警中心返回的中文内容，不做英文模板包装。
    """
    parts: list[str] = []
    title = case.get("title") or case.get("id") or ""
    if title:
        parts.append(title)

    summary = case.get("summary") or ""
    if summary:
        parts.append(summary)

    ds = case.get("display_summary")
    if isinstance(ds, dict):
        subtitle = ds.get("subtitle") or ""
        if subtitle:
            parts.append(subtitle)

    confirmation = case.get("human_confirmation")
    if confirmation:
        hc_summary = confirmation.get("summary") or ""
        if hc_summary:
            parts.append(f"人工确认：{hc_summary}")

    latest_decision = case.get("latest_human_decision")
    if latest_decision:
        reason = latest_decision.get("reason") or ""
        if reason:
            parts.append(f"人工判定原因：{reason}")

    return "\n\n".join(parts) if parts else ""


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
    # 误报信息：类别（false_positive_reason）+ 人工写的具体原因（human_confirmation.summary）
    hc = c.get("human_confirmation") or {}
    return {
        "case_id": c.get("id") or "",
        "vuln_title": c.get("title") or "",
        "vuln_type": subject.get("type") or "",
        "description": _normalize_case_description(c),
        "expected_label": expected_label,
        "source_file": source_file,
        "source_function": source_function,
        "source_line": source_line,
        "locator": locator,
        "false_positive_group": c.get("false_positive_group") or "",
        "false_positive_reason": c.get("false_positive_reason") or "",
        "human_confirmation_summary": hc.get("summary") or "",
    }


def get_vuln_center_benchmark(project_id: str, source_task_id: str | None = None,
                              fetch_non_vuln: bool = True) -> dict:
    """返回与 ``vbench_client.get_benchmark`` 同构的基线结构。

    拉取两类人工确认 case：
    - ``confirmation_status=vulnerable`` → expected_label=VULNERABLE
    - ``confirmation_status=not_vulnerable`` → expected_label=NON_VULNERABLE

    ``fetch_non_vuln=False`` 时跳过非漏洞 API 调用。
    排除 ``false_positive_group=non_fp`` 的 case（非误报，不参与分析）。
    """
    vuln_cases = list_vuln_cases(project_id, source_task_id, confirmation_status="vulnerable")
    cases = [_case_to_benchmark(c, "VULNERABLE") for c in vuln_cases]
    log("VULN_CENTER", f"vulnerable cases: {len(vuln_cases)}")
    if fetch_non_vuln:
        nonvuln_cases = list_vuln_cases(project_id, source_task_id, confirmation_status="not_vulnerable")
        nonvuln_cases = [c for c in nonvuln_cases
                         if c.get("false_positive_group") != "non_fp"]
        cases += [_case_to_benchmark(c, "NON_VULNERABLE") for c in nonvuln_cases]
        log("VULN_CENTER", f"not_vulnerable cases: {len(nonvuln_cases)} (excluded non_fp)")

    # 拉取每个 case 的原始漏洞报告
    for c in cases:
        cid = c.get("case_id") or ""
        if cid:
            c["description"] = get_case_raw_report(cid) or c.get("description") or ""

    return {"benchmark_id": project_id, "name": None, "cases": cases}
