"""按 owner（agent / 责任方）汇总的评测日报。

Owner 两类：
- ``agent:<agent_type>``：某个 agent 的日报（含评测指标 + agent 责任的问题单）
- ``resp:<responsibility>``：知识库 / 外部数据源 / 评测流程的日报（只列问题单）

数据口径：
- 窗口：``since``（默认=该 owner 上次成功发送时间）到 ``until``（默认=now），UTC。
- 评测：``evaluation.finished_at`` 落在窗口内，状态 COMPLETED /
  COMPLETED_WITH_WARNINGS / FAILED。一个评测涉及多个 agent 时，会出现在
  每个 agent 的日报里（按 agent 视角统计）。
- 指标：读 ``{reports_dir}/{eid}.json`` 的 ``recall_precision``，
  窗口内各评测的 TP/FP/FN/TN 求和后重新计算 FPR / 准确率。
- 新增问题单：``dts_issue.created_at`` 落在窗口内。
- 未关闭问题单：``status NOT IN ('passed','not_issue')`` 的存量。
- 责任方过滤：``responsibility`` 是逗号分隔多值，用 FIND_IN_SET 精确匹配；
  agent 日报只列含 ``agent`` 责任的单，知识库/外部数据源/评测流程各自只列自己的。
- 多责任方问题单会同时出现在 agent 日报和对应责任方日报里。

日报只输出摘要 + 链接，完整内容由前端页面承载。
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

from ...config_loader import EVAL_PUBLIC_URL, get_reports_dir
from ..core.agents import (
    AGENT_DISPLAY_NAMES,
    AGENT_SHORT_LABELS,
    ALL_AGENT_SET,
    ALL_AGENT_TYPES,
)
from ..core.causal_levels import ALL_LEVELS
from ..infra.db_utils import db_query as _db_query

# trace_kind → agent_type（与 v2/parsers 的别名表保持一致）
_TRACE_KIND_TO_AGENT: dict[str, str] = {
    "turing": "turing",
    "argo": "argo",
    "secmate": "secmate",
    "cvuln_verify": "cvuln_verify",
    "webvulnverify": "webvuln_verify",
    "webvuln_verify": "webvuln_verify",
    "dataflow": "dataflow",
    "dataflow_vuln_scan": "dataflow",
}

_RESPONSIBILITY_LABELS: dict[str, str] = {
    "other": "其他责任（知识库/外部数据源/评测流程）",
    "knowledge": "知识库",
    "external_data_source": "外部数据源",
    "eval_process": "评测流程",
}

_OTHER_RESPONSIBILITIES = ("knowledge", "external_data_source", "eval_process")

_LEVEL_LABELS: dict[str, str] = {
    "L2": "发起访问",
    "L3": "查询聚焦",
    "L4": "知识存在",
    "L5": "成功取回",
    "L6": "引用内容",
    "L7": "影响结论",
    "L8": "其他维度",
}

_TERMINAL_OK = ("COMPLETED", "COMPLETED_WITH_WARNINGS")
_OPEN_ISSUE_EXCLUDED = ("passed", "not_issue")
_CHANNEL = "xiaoluban"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_dt(value: str | None) -> datetime | None:
    """解析 ISO 时间，统一成 UTC naive（DB 存储口径）。"""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _iso(dt: datetime | None) -> str:
    return dt.isoformat() + "Z" if dt else ""


def _fmt_local(dt: datetime | None) -> str:
    """UTC naive → 北京时间字符串。"""
    if not dt:
        return "-"
    local = dt + timedelta(hours=8)
    return local.strftime("%Y-%m-%d %H:%M")


def _pct(value) -> str:
    if value is None:
        return "NA"
    return f"{float(value) * 100:.1f}%"


def _split_owner_key(owner_key: str) -> tuple[str, str]:
    kind, _, key = str(owner_key or "").partition(":")
    return kind, key


def _agent_types_from_manifest(manifest: dict) -> set[str]:
    agents: set[str] = set()
    for entry in (manifest or {}).get("entries", []):
        kind = str(entry.get("trace_kind") or "").strip().lower()
        agent = _TRACE_KIND_TO_AGENT.get(kind)
        if agent:
            agents.add(agent)
    return agents


def _manifest_task_name(manifest: dict) -> str:
    names = []
    for entry in (manifest or {}).get("entries", []):
        name = str(entry.get("task_name") or "").strip()
        if name and name not in names:
            names.append(name)
    return "、".join(names)


def _read_eval_metrics(evaluation_id: str) -> dict:
    """从基础报告读取 recall_precision；失败/缺失返回空 dict。"""
    path = os.path.join(get_reports_dir(), f"{evaluation_id}.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("recall_precision") or {}
    except (OSError, ValueError):
        return {}


def _load_owners(owner_key: str | None = None) -> list[dict]:
    def _do(cur):
        sql = ("SELECT owner_key, owner_kind, display_name, owner_name, "
               "target_type, target_id, enabled FROM notify_owner_config")
        params: list = []
        if owner_key:
            sql += " WHERE owner_key=%s"
            params.append(owner_key)
        sql += " ORDER BY owner_kind, owner_key"
        cur.execute(sql, tuple(params))
        cols = ["owner_key", "owner_kind", "display_name", "owner_name",
                "target_type", "target_id", "enabled"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    return _db_query(_do)


def last_sent_at(owner_key: str, channel: str = _CHANNEL) -> datetime | None:
    """该 owner 上次成功发送的窗口结束时间（UTC naive）。"""
    def _do(cur):
        cur.execute(
            "SELECT MAX(window_end) FROM notification_log "
            "WHERE owner_key=%s AND channel=%s AND status='sent'",
            (owner_key, channel))
        row = cur.fetchone()
        return row[0] if row else None
    return _db_query(_do)


def record_send(owner_key: str, recipient: str, window_start: str,
                window_end: str, content_hash: str, status: str,
                error: str | None = None, channel: str = _CHANNEL) -> None:
    """写入一次发送记录（sent/failed）。"""
    start = _parse_dt(window_start) or _now_utc()
    end = _parse_dt(window_end) or _now_utc()

    def _do(cur):
        cur.execute(
            "INSERT INTO notification_log "
            "(owner_key, channel, recipient, window_start, window_end, "
            " content_hash, status, error) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (owner_key, channel, recipient, start, end,
             content_hash, status, error))
    _db_query(_do)


def _load_evaluations(since: datetime, until: datetime) -> list[dict]:
    def _do(cur):
        cur.execute(
            "SELECT e.evaluation_id, e.evaluation_name, e.evaluation_status, "
            "       e.finished_at, e.task_id, e.agent_name, e.error_message, "
            "       s.config_json "
            "FROM evaluation e "
            "LEFT JOIN evaluation_snapshot s "
            "  ON s.evaluation_id = e.evaluation_id "
            "WHERE e.finished_at >= %s AND e.finished_at <= %s "
            "  AND e.evaluation_status IN "
            "      ('COMPLETED','COMPLETED_WITH_WARNINGS','FAILED') "
            "ORDER BY e.finished_at DESC",
            (since, until))
        cols = ["evaluation_id", "evaluation_name", "evaluation_status",
                "finished_at", "task_id", "agent_name", "error_message",
                "config_json"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    return _db_query(_do)


def _issue_filter(owner_kind: str, owner_value: str) -> tuple[str, list]:
    """返回问题单的责任方过滤 SQL 片段与参数。"""
    if owner_kind == "agent":
        # 兼容历史行 responsibility 为空：空责任方默认按 agent 处理
        return ("(responsibility IS NULL OR responsibility = '' "
                "OR FIND_IN_SET('agent', responsibility) > 0) "
                "AND FIND_IN_SET(%s, agent_type) > 0", [owner_value])
    if owner_value == "other":
        # 知识库 / 外部数据源 / 评测流程合并为一个责任方
        return ("(" + " OR ".join(
            f"FIND_IN_SET('{r}', responsibility) > 0"
            for r in _OTHER_RESPONSIBILITIES) + ")", [])
    return "FIND_IN_SET(%s, responsibility) > 0", [owner_value]


def _load_new_issues(owner_kind: str, owner_value: str, since: datetime,
                     until: datetime) -> list[dict]:
    filter_sql, params = _issue_filter(owner_kind, owner_value)

    def _do(cur):
        cur.execute(
            "SELECT dts_id, case_id, vuln_title, agent_type, case_type, "
            "       cause_code, breakpoint_level, solution, status, "
            "       responsibility, created_at "
            "FROM dts_issue "
            f"WHERE created_at >= %s AND created_at <= %s AND {filter_sql} "
            "ORDER BY created_at DESC",
            (since, until, *params))
        cols = ["dts_id", "case_id", "vuln_title", "agent_type", "case_type",
                "cause_code", "breakpoint_level", "solution", "status",
                "responsibility", "created_at"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    return _db_query(_do)


def _load_open_issues(owner_kind: str, owner_value: str,
                      limit: int = 200) -> tuple[int, list[dict]]:
    filter_sql, params = _issue_filter(owner_kind, owner_value)
    placeholders = ",".join(["%s"] * len(_OPEN_ISSUE_EXCLUDED))

    def _do(cur):
        cur.execute(
            f"SELECT COUNT(*) FROM dts_issue "
            f"WHERE status NOT IN ({placeholders}) AND {filter_sql}",
            (*_OPEN_ISSUE_EXCLUDED, *params))
        total = cur.fetchone()[0]
        cur.execute(
            f"SELECT dts_id, case_id, vuln_title, agent_type, case_type, "
            f"       cause_code, breakpoint_level, status, responsibility, "
            f"       updated_at "
            f"FROM dts_issue "
            f"WHERE status NOT IN ({placeholders}) AND {filter_sql} "
            f"ORDER BY updated_at DESC LIMIT %s",
            (*_OPEN_ISSUE_EXCLUDED, *params, limit))
        cols = ["dts_id", "case_id", "vuln_title", "agent_type", "case_type",
                "cause_code", "breakpoint_level", "status", "responsibility",
                "updated_at"]
        return total, [dict(zip(cols, r)) for r in cur.fetchall()]
    return _db_query(_do)


def _issue_item(item: dict) -> dict:
    return {
        "dts_id": item["dts_id"],
        "case_id": item.get("case_id") or "",
        "vuln_title": item.get("vuln_title") or "",
        "agent_type": item.get("agent_type") or "",
        "case_type": item.get("case_type") or "",
        "cause_code": item.get("cause_code") or "",
        "breakpoint_level": item.get("breakpoint_level") or "",
        "status": item.get("status") or "",
        "solution": item.get("solution") or "",
        "responsibility": item.get("responsibility") or "",
        "url": f"{EVAL_PUBLIC_URL}/dts/{item['dts_id']}",
    }


def _build_agent_report(owner: dict, since: datetime, until: datetime,
                        evaluations: list[dict]) -> dict:
    agent_type = _split_owner_key(owner["owner_key"])[1]
    display_name = (owner.get("display_name")
                    or AGENT_DISPLAY_NAMES.get(agent_type, agent_type))

    agent_evals: list[dict] = []
    failed_evals: list[dict] = []
    tp = fp = fn = tn = 0
    for ev in evaluations:
        finished_at = ev.get("finished_at")
        if finished_at is not None and finished_at < since:
            continue
        manifest: dict = {}
        raw_cfg = ev.get("config_json")
        if raw_cfg:
            try:
                cfg = json.loads(raw_cfg) if isinstance(raw_cfg, str) else raw_cfg
                manifest = (cfg or {}).get("manifest", {}) or {}
            except (ValueError, TypeError):
                manifest = {}
        agents = _agent_types_from_manifest(manifest)
        if not agents:
            # 老快照可能没有 trace_kind：回退到 evaluation.agent_name
            fallback = str(ev.get("agent_name") or "").strip().lower()
            if fallback in ALL_AGENT_SET:
                agents = {fallback}
        if agent_type not in agents:
            continue

        task_name = _manifest_task_name(manifest)
        if ev["evaluation_status"] == "FAILED":
            failed_evals.append({
                "evaluation_id": ev["evaluation_id"],
                "name": ev.get("evaluation_name") or ev["evaluation_id"],
                "task_name": task_name,
                "error_message": ev.get("error_message") or "",
                "url": f"{EVAL_PUBLIC_URL}/evals/{ev['evaluation_id']}",
            })
            continue

        rp = _read_eval_metrics(ev["evaluation_id"])
        ev_tp = int(rp.get("tp_count") or 0)
        ev_fp = int(rp.get("fp_count") or 0)
        ev_fn = int(rp.get("fn_count") or 0)
        ev_tn = int(rp.get("tn_count") or 0)
        tp += ev_tp
        fp += ev_fp
        fn += ev_fn
        tn += ev_tn
        agent_evals.append({
            "evaluation_id": ev["evaluation_id"],
            "name": ev.get("evaluation_name") or ev["evaluation_id"],
            "status": ev["evaluation_status"],
            "finished_at": _iso(ev.get("finished_at")),
            "task_name": task_name,
            "tp": ev_tp, "fp": ev_fp, "fn": ev_fn, "tn": ev_tn,
            "fpr": round(ev_fp / (ev_tp + ev_fp), 4) if (ev_tp + ev_fp) > 0 else None,
            "precision": (round(ev_tp / (ev_tp + ev_fp), 4)
                          if (ev_tp + ev_fp) > 0 else None),
            "url": f"{EVAL_PUBLIC_URL}/evals/{ev['evaluation_id']}",
        })

    new_issues = _load_new_issues("agent", agent_type, since, until)
    open_total, open_issues = _load_open_issues("agent", agent_type)

    fpr = round(fp / (tp + fp), 4) if (tp + fp) > 0 else None
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None

    return {
        "owner_key": owner["owner_key"],
        "owner_kind": "agent",
        "agent_type": agent_type,
        "display_name": display_name,
        "owner_name": owner.get("owner_name") or "",
        "target_type": owner.get("target_type") or "user",
        "target_id": owner.get("target_id") or "",
        "enabled": bool(owner.get("enabled")),
        "window": {"start": _iso(since), "end": _iso(until)},
        "evaluations": {
            "total": len(agent_evals) + len(failed_evals),
            "completed": len(agent_evals),
            "failed": len(failed_evals),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "fpr": fpr, "precision": precision,
            "items": agent_evals,
            "failed_items": failed_evals,
        },
        "new_issues": [_issue_item(i) for i in new_issues],
        "open_issues": {
            "total": open_total,
            "items": [_issue_item(i) for i in open_issues],
        },
        "urls": {
            "eval_list": f"{EVAL_PUBLIC_URL}/evals",
            "issue_list": f"{EVAL_PUBLIC_URL}/dts?agent_type={agent_type}&status=open",
        },
    }


def _split_agent_types(agent_type: str) -> list[str]:
    parts = [p.strip() for p in str(agent_type or "").split(",") if p.strip()]
    return parts or ["unknown"]


def _build_responsibility_report(owner: dict, since: datetime,
                                 until: datetime) -> dict:
    responsibility = _split_owner_key(owner["owner_key"])[1]
    display_name = (owner.get("display_name")
                    or _RESPONSIBILITY_LABELS.get(responsibility, responsibility))

    new_issues = _load_new_issues("responsibility", responsibility, since, until)
    open_total, open_issues = _load_open_issues("responsibility", responsibility)

    order = {agent: idx for idx, agent in enumerate(ALL_AGENT_TYPES)}
    groups: dict[str, dict] = {}

    def _group(agent: str) -> dict:
        if agent not in groups:
            groups[agent] = {
                "agent_type": agent,
                "display_name": AGENT_DISPLAY_NAMES.get(agent, agent),
                "new_issues": [],
                "open_issues": {"total": 0, "items": []},
                "url": (f"{EVAL_PUBLIC_URL}/dts?responsibility={responsibility}"
                        f"&agent_type={agent}&status=open"),
            }
        return groups[agent]

    for item in new_issues:
        for agent in _split_agent_types(item.get("agent_type")):
            _group(agent)["new_issues"].append(_issue_item(item))
    for item in open_issues:
        for agent in _split_agent_types(item.get("agent_type")):
            g = _group(agent)
            g["open_issues"]["items"].append(_issue_item(item))
            g["open_issues"]["total"] += 1

    ordered = sorted(groups.values(),
                     key=lambda g: order.get(g["agent_type"], 99))

    return {
        "owner_key": owner["owner_key"],
        "owner_kind": "responsibility",
        "responsibility": responsibility,
        "display_name": display_name,
        "owner_name": owner.get("owner_name") or "",
        "target_type": owner.get("target_type") or "user",
        "target_id": owner.get("target_id") or "",
        "enabled": bool(owner.get("enabled")),
        "window": {"start": _iso(since), "end": _iso(until)},
        "groups": ordered,
        "totals": {"new": len(new_issues), "open": open_total},
        "urls": {
            "issue_list": (f"{EVAL_PUBLIC_URL}/dts?"
                           f"responsibility={responsibility}&status=open"),
        },
    }


def build_reports(owner_key: str | None = None,
                  since: str | None = None,
                  until: str | None = None,
                  force: bool = False) -> dict:
    """构建一个或多个 owner 的日报。

    ``since`` 不传时使用该 owner 上次成功发送的 ``window_end``；
    没有发送记录时回退到 ``until - 24h``。``force=True`` 时忽略发送记录。
    """
    until_dt = _parse_dt(until) or _now_utc()
    explicit_since = _parse_dt(since)
    owners = _load_owners(owner_key)

    windows: dict[str, datetime] = {}
    for owner in owners:
        key = owner["owner_key"]
        if explicit_since:
            windows[key] = explicit_since
        else:
            last = None if force else last_sent_at(key)
            windows[key] = last or (until_dt - timedelta(hours=24))

    # 一次拉取覆盖所有 agent 的最早窗口；agent 报告构建时再按自己的窗口过滤
    agent_windows = [w for k, w in windows.items()
                     if _split_owner_key(k)[0] == "agent"]
    if agent_windows:
        evaluations = _load_evaluations(min(agent_windows), until_dt)
    else:
        evaluations = []

    reports = []
    for owner in owners:
        kind = owner.get("owner_kind") or _split_owner_key(owner["owner_key"])[0]
        win_start = windows[owner["owner_key"]]
        if kind == "agent":
            reports.append(_build_agent_report(
                owner, win_start, until_dt, evaluations))
        else:
            reports.append(_build_responsibility_report(
                owner, win_start, until_dt))

    return {
        "generated_at": _iso(_now_utc()),
        "until": _iso(until_dt),
        "agents": reports,
    }


# ── 消息渲染（HTML span + emoji） ─────────────────────

def _span(text, color: str | None = None, bold: bool = False,
          size: int | None = None) -> str:
    styles = []
    if color:
        styles.append(f"color:{color}")
    if bold:
        styles.append("font-weight:bold")
    if size:
        styles.append(f"font-size:{size}px")
    return (f'<span style="{";".join(styles)}">{text}</span>'
            if styles else str(text))


def _env_prefix(report: dict) -> str:
    env = str(report.get("env_name") or "").strip()
    return f"【{env}】" if env else ""


def _compact_levels(items: list[dict]) -> str:
    """按 L2-L8 统计新增问题单，输出一行紧凑分布。"""
    counts = {level: 0 for level in ALL_LEVELS}
    unknown = 0
    for item in items:
        level = str(item.get("breakpoint_level") or "").strip().upper()
        if level in counts:
            counts[level] += 1
        else:
            unknown += 1
    parts = [f"{level} {_LEVEL_LABELS.get(level, '')}:{counts[level]} 条"
             for level in ALL_LEVELS if counts[level] > 0]
    if unknown:
        parts.append(f"未知:{unknown} 条")
    return "  ".join(parts)


def render_agent_text(report: dict) -> str:
    ev = report.get("evaluations") or {}
    new_issues = report.get("new_issues") or []
    open_issues = report.get("open_issues") or {}
    window = report.get("window") or {}
    short = AGENT_SHORT_LABELS.get(report.get("agent_type", ""),
                                   report.get("agent_type", ""))
    owner = report.get("owner_name") or "未配置负责人"
    start = _fmt_local(_parse_dt(window.get("start")))
    end = _fmt_local(_parse_dt(window.get("end")))
    urls = report.get("urls") or {}

    lines = [
        _span(f"🧪 {_env_prefix(report)}奇美拉测评日报 · {short}",
              color="#2563eb", bold=True, size=16),
        f"👤 负责人：{owner}",
        f"🕒 统计窗口：{start} ~ {end}",
    ]

    total = int(ev.get("total") or 0)
    completed = int(ev.get("completed") or 0)
    failed = int(ev.get("failed") or 0)
    failed_items = ev.get("failed_items") or []
    if total > 0:
        lines += ["", _span(f"📊 评测（{total} 个）", bold=True)]
        status_parts = []
        if completed > 0:
            status_parts.append(
                f"✅ 完成 {_span(completed, color='#16a34a', bold=True)}")
        if failed > 0:
            status_parts.append(
                f"❌ 失败 {_span(failed, color='#dc2626', bold=True)}")
        if status_parts:
            lines.append(" · ".join(status_parts))

        metric_parts = []
        for key, label, icon, color in (
                ("tp", "真阳性", "🎯", "#16a34a"),
                ("fp", "误报", "🚨", "#dc2626"),
                ("fn", "漏报", "🕳️", "#d97706"),
                ("tn", "真阴性", "✅", "#16a34a")):
            value = int(ev.get(key) or 0)
            if value > 0:
                metric_parts.append(
                    f"{icon} {label} {_span(value, color=color, bold=True)}")
        if metric_parts:
            lines.append(" · ".join(metric_parts))

        rate_parts = []
        for key, label, icon, color in (
                ("fpr", "误报率", "📉", "#d97706"),
                ("precision", "准确率", "📈", "#16a34a")):
            value = ev.get(key)
            if value is not None and float(value) != 0:
                rate_parts.append(
                    f"{icon} {label} {_span(_pct(value), color=color, bold=True)}")
        if rate_parts:
            lines.append(" · ".join(rate_parts))

        tasks = [e.get("task_name") for e in (ev.get("items") or [])
                 if e.get("task_name")]
        if tasks:
            lines.append("📁 任务：" + "、".join(dict.fromkeys(tasks)))

        if failed_items:
            ids = "、".join(
                f"{i.get('evaluation_id')}({i.get('task_name') or '-'})"
                for i in failed_items[:5])
            more = f" 等 {len(failed_items)} 个" if len(failed_items) > 5 else ""
            lines.append(f"❌ 失败评测：{ids}{more}")

    if new_issues:
        lines += ["", _span(f"🆕 新增问题单（{len(new_issues)}）", bold=True),
                  f"🧩 {_compact_levels(new_issues)}"]

    open_total = int(open_issues.get("total") or 0)
    if open_total > 0:
        lines += ["", _span(f"⚠️ 未关闭问题单（{open_total}）", bold=True)]

    if new_issues or open_total > 0:
        lines += ["", f"🔗 查看全部：{urls.get('issue_list', '')}"]

    return "\n".join(lines)


def render_responsibility_text(report: dict) -> str:
    window = report.get("window") or {}
    owner = report.get("owner_name") or "未配置负责人"
    start = _fmt_local(_parse_dt(window.get("start")))
    end = _fmt_local(_parse_dt(window.get("end")))
    totals = report.get("totals") or {}

    lines = [
        _span(f"🧪 {_env_prefix(report)}奇美拉测评日报 · "
              f"{report.get('display_name', '')}",
              color="#2563eb", bold=True, size=16),
        f"👤 负责人：{owner}",
        f"🕒 统计窗口：{start} ~ {end}",
    ]
    summary_parts = []
    if int(totals.get("new") or 0) > 0:
        summary_parts.append(f"新增 {totals['new']}")
    if int(totals.get("open") or 0) > 0:
        summary_parts.append(f"未关闭 {totals['open']}")
    if summary_parts:
        lines.append("📌 汇总：" + " · ".join(summary_parts))

    for group in report.get("groups") or []:
        new_items = group.get("new_issues") or []
        open_issues = group.get("open_issues") or {}
        open_total = int(open_issues.get("total") or 0)
        if not new_items and open_total == 0:
            continue
        header_parts = []
        if new_items:
            header_parts.append(f"新增 {len(new_items)}")
        if open_total > 0:
            header_parts.append(f"未关闭 {open_total}")
        lines += ["", _span(
            f"🤖 {group.get('display_name', group.get('agent_type'))}"
            f"（{' / '.join(header_parts)}）", bold=True)]
        if new_items:
            lines.append(f"🧩 {_compact_levels(new_items)}")
        group_url = group.get("url") or (report.get("urls") or {}).get("issue_list", "")
        if group_url:
            lines.append(f"🔗 查看全部：{group_url}")

    return "\n".join(lines)


def render_text(report: dict) -> str:
    if report.get("owner_kind") == "agent":
        return render_agent_text(report)
    return render_responsibility_text(report)


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
