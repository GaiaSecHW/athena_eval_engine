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
  窗口内各评测的 TP/FP/FN/TN 求和后展示计数。
- 误报率：**只展示回归后误报率**（FP 问题单 ``failed/(passed+failed)``），
  与首页看板同口径；评测报告里的单次 fpr/precision 不代表平台整体，不展示。
- 新增问题单：``dts_issue.created_at`` 落在窗口内。
- 未关闭问题单：``status NOT IN ('passed','not_issue','unattributable')`` 的存量
  （无法归因视为关闭——全部线索被否定+标注不全，等标注方补充后重新开启）。
- 责任方过滤：``responsibility`` 是逗号分隔多值，用 FIND_IN_SET 精确匹配；
  agent 日报只列含 ``agent`` 责任的单，知识库/外部数据源/评测流程各自只列自己的。
- 多责任方问题单会同时出现在 agent 日报和对应责任方日报里。

日报只输出摘要 + 链接，完整内容由前端页面承载。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone

from ...config_loader import EVAL_ENV_NAME, EVAL_PUBLIC_URL, get_reports_dir
from ..core.agents import (
    AGENT_DISPLAY_NAMES,
    AGENT_SHORT_LABELS,
    ALL_AGENT_SET,
)
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

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

_TERMINAL_OK = ("COMPLETED", "COMPLETED_WITH_WARNINGS")
# 未关闭问题单口径：排除已关闭状态。无法归因（unattributable）视为关闭
# （用户定稿）：全部线索被否定+标注不全，退出修复队列等标注方补充。
# 无回归关单（no_regression）同视为关闭（不经回归验证直接关闭）。
_OPEN_ISSUE_EXCLUDED = ("passed", "not_issue", "unattributable",
                        "no_regression")
_CHANNEL = "xiaoluban"
# 定期报告通道：独立于日报的发送记录（窗口/去重按周期，标题=日报/周报/月报）
_CHANNEL_REPORT = "xiaoluban-report"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


_public_url_cache: tuple[float, str] | None = None
_PUBLIC_URL_CACHE_SECONDS = 60.0


def get_public_url() -> str:
    """对外访问地址：system_config.notify_public_url → EVAL_PUBLIC_URL。"""
    global _public_url_cache
    now = time.monotonic()
    if (_public_url_cache
            and now - _public_url_cache[0] < _PUBLIC_URL_CACHE_SECONDS):
        return _public_url_cache[1]

    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='notify_public_url'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    value = (_db_query(_do) or EVAL_PUBLIC_URL).rstrip("/")
    _public_url_cache = (now, value)
    return value


def invalidate_public_url_cache() -> None:
    global _public_url_cache
    _public_url_cache = None


def get_env_name() -> str:
    """环境标识：system_config.notify_env_name → EVAL_ENV_NAME → 公网地址推断。"""
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='notify_env_name'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    value = _db_query(_do) or EVAL_ENV_NAME
    if value:
        return value
    url = get_public_url().lower()
    if "chimera-y" in url:
        return "yellow"
    if "chimera-g" in url:
        return "green"
    return ""


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


def _fmt_date_short(dt: datetime | None) -> str:
    """UTC naive → 北京时间短日期（M/D），WeLink 标题用。"""
    if not dt:
        return "-"
    local = dt + timedelta(hours=8)
    return local.strftime("%m/%d")


def _level_counts(items: list[dict]) -> str:
    """断点分布超紧凑形式：L2×12 L8×10（含义见问题单页图例）。"""
    counts: dict[str, int] = {}
    unknown = 0
    for item in items or []:
        level = str(item.get("breakpoint_level") or "").strip().upper()
        if level:
            counts[level] = counts.get(level, 0) + 1
        else:
            unknown += 1
    parts = [f"{lv}×{n}" for lv, n in sorted(counts.items())]
    if unknown:
        parts.append(f"?×{unknown}")
    return " ".join(parts)


def _pct(value) -> str:
    if value is None:
        return "NA"
    return f"{float(value) * 100:.1f}%"


# 「任务」= 奇美拉平台的扫描任务（project_task_summary 的任务行），
# 不是本引擎的评测任务。窗口口径：task_finished_at 在近 N 天内，
# 与 /eval/report 列表的任务结束时间同源。
_TASK_FINISHED_WINDOW_DAYS = 30


def _task_confirmation_stats(
        days: int = _TASK_FINISHED_WINDOW_DAYS,
        as_of: datetime | None = None) -> list[dict]:
    """近 N 天结束的平台任务：确认率/误报率统计，按确认率从低到高排序。

    确认率 = 人工已确认（确认漏洞 + 确认非漏洞 + 确认误报）/ 漏洞总数；
    误报率 = 确认误报 /（确认漏洞 + 确认误报）（与 /eval/report 同口径）；
    只统计 vuln_total > 0、task_finished_at 在窗口内的任务。
    as_of=None 锚定当前时刻；趋势对比传上期边界（滚动窗口锚点，
    任务须 fin <= as_of，不能用"未来"任务虚增对比基数）。
    """
    anchor = as_of or _now_utc()
    cutoff = anchor - timedelta(days=days)

    def _do(cur):
        cur.execute(
            "SELECT task_name, task_id, vuln_total, "
            "confirmed_vulnerable, confirmed_not_vulnerable, "
            "confirmed_fp, task_finished_at "
            "FROM project_task_summary "
            "WHERE task_id != ''"
        )
        return cur.fetchall()

    try:
        rows = _db_query(_do)
    except Exception:
        return []

    tasks: list[dict] = []
    for tname, tid, tot, vuln, nonvuln, fp, finished in rows:
        tot = int(tot or 0)
        if tot <= 0:
            continue
        try:
            fin = _parse_dt(finished)
        except (TypeError, ValueError):
            fin = None
        if fin is None or fin < cutoff or fin > anchor:
            continue
        vuln = int(vuln or 0)
        fp = int(fp or 0)
        confirmed_cnt = vuln + int(nonvuln or 0) + fp
        fpr_denom = vuln + fp
        tasks.append({
            "task_name": tname or tid,
            "total": tot,
            "confirmed": confirmed_cnt,
            "rate": confirmed_cnt / tot,
            "fpr": (fp / fpr_denom) if fpr_denom > 0 else None,
            "tp": vuln,
            "fp": fp,
        })
    tasks.sort(key=lambda t: (t["rate"], t["task_name"]))
    return tasks


def _confirmation_snapshot(as_of: datetime | None = None) -> dict:
    """近30天（锚点 as_of）结束任务的确认率/误报率聚合，供趋势对比。"""
    tasks = _task_confirmation_stats(as_of=as_of)
    total = sum(t["total"] for t in tasks)
    confirmed = sum(t["confirmed"] for t in tasks)
    tp = sum(t["tp"] for t in tasks)
    fp = sum(t["fp"] for t in tasks)
    return {
        "n_tasks": len(tasks),
        "rate": (confirmed / total) if total > 0 else None,
        "fpr": (fp / (tp + fp)) if (tp + fp) > 0 else None,
        "total": total,
        "confirmed": confirmed,
        "tasks": tasks,
    }


# 低确认率阈值（低于此值的任务计入"确认率偏低"计数）与
# 高误报率阈值（高于此值的任务列入重点关注清单）
_LOW_CONFIRM_RATE = 0.2
_HIGH_FPR_RATE = 0.7


def _render_confirmation_section(as_of: datetime | None = None) -> list[str]:
    """近30天结束任务的人工确认率区块（x 报必含内容）。

    确认率带与上期的对比（与误报率同一锚点口径：当前 vs 周期起点，
    `_task_confirmation_stats(as_of=...)` 滚动窗口，上期任务须
    fin <= as_of，不能用"未来"任务虚增对比基数）。
    """
    tasks = _task_confirmation_stats()
    total = sum(t["total"] for t in tasks)
    confirmed = sum(t["confirmed"] for t in tasks)
    if total <= 0:
        return ["📊 近30天无已结束任务（人工确认率暂无数据）"]
    # 上期确认率：同一滚动窗口锚定周期起点
    prev_tasks = _task_confirmation_stats(as_of=as_of) if as_of else []
    prev_total = sum(t["total"] for t in prev_tasks)
    prev_confirmed = sum(t["confirmed"] for t in prev_tasks)
    prev_rate = (prev_confirmed / prev_total) if prev_total > 0 else None
    rate = confirmed / total
    lines = [
        f"📊 一个月内结束任务 {len(tasks)} 个，人工确认率："
        f"{_span(_pct(rate), color='#16a34a', bold=True)}"
        f"{_pct_diff(rate, prev_rate)}"
        f"（已确认 {confirmed} / 漏洞总数 {total}）",
    ]
    low_confirm = [t for t in tasks if t["rate"] < _LOW_CONFIRM_RATE]
    if low_confirm:
        lines.append(
            f"🟡 确认率低于 {_pct(_LOW_CONFIRM_RATE)} 的任务："
            f"{_span(len(low_confirm), color='#d97706', bold=True)} 个")
    high_fpr = [t for t in tasks
                if t.get("fpr") is not None and t["fpr"] > _HIGH_FPR_RATE]
    if high_fpr:
        high_fpr.sort(key=lambda t: -(t["fpr"] or 0))
        parts = [
            f"{t['task_name']} "
            f"{_span(_pct(t['fpr']), color='#dc2626', bold=True)}"
            for t in high_fpr[:5]]
        more = (f" 等 {len(high_fpr)} 个" if len(high_fpr) > 5 else "")
        lines.append(
            f"🚨 误报率高于 {_pct(_HIGH_FPR_RATE)} 的任务（需重点关注）："
            + "、".join(parts) + more)
    return lines


def _pct_diff(cur, prev) -> str:
    """本期 vs 上期百分点差（含箭头；改善绿、恶化红、持平灰）。"""
    if cur is None or prev is None:
        return "（上期 暂无数据）"
    diff = (cur - prev) * 100
    if diff < -0.05:
        return (f"（上期 {_pct(prev)}，"
                f"{_span(f'↓{abs(diff):.1f} 个百分点', color='#16a34a', bold=True)}）")
    if diff > 0.05:
        return (f"（上期 {_pct(prev)}，"
                f"{_span(f'↑{diff:.1f} 个百分点', color='#dc2626', bold=True)}）")
    return f"（上期 {_pct(prev)}，持平）"


def _leader_window_stats(since: datetime, until: datetime) -> dict:
    """领导摘要的本期窗口统计：回归验证 / 根因分布（按 agent）/ 评测 / 未关闭。

    agent_type 是逗号分隔多值：每条按行汇总（总数不重复计），分 agent
    明细在 Python 侧拆分累计（多 agent 问题单计入每个 agent 的明细）。
    """
    def _split_agents(raw) -> list[str]:
        return [a.strip() for a in str(raw or "").split(",") if a.strip()]

    def _do(cur):
        out: dict = {
            "reg_passed": 0, "reg_failed": 0,
            "new_fp": 0, "new_fn": 0, "evals": 0, "eval_projects": 0,
            "open_by_agent": {},
            "closed_total": 0,     # 本期关闭（回归通过/无回归关单/无法归因）
            "closed_by_status": {},
            "closed_cum_by_status": {},  # 累计已关闭（同口径，不分窗口）
        }
        try:
            # 回归验证总量：join dts_issue 取 agent（仅总量统计）
            cur.execute(
                "SELECT i.agent_type, r.status, COUNT(*) "
                "FROM dts_regression_result r "
                "JOIN dts_issue i ON r.dts_id = i.dts_id "
                "WHERE r.submitted_at >= %s AND r.submitted_at <= %s "
                "GROUP BY i.agent_type, r.status",
                (since, until))
            for _at, st_, n in cur.fetchall():
                n = int(n or 0)
                if st_ == "passed":
                    out["reg_passed"] += n
                elif st_ == "failed":
                    out["reg_failed"] += n
        except Exception as e:
            log("REPORT", f"领导摘要-回归统计失败: {e}")
        try:
            # 本期新增问题单总量（按类型）
            cur.execute(
                "SELECT case_type, COUNT(*) FROM dts_issue "
                "WHERE created_at >= %s AND created_at <= %s "
                "GROUP BY case_type",
                (since, until))
            for ct, n in cur.fetchall():
                n = int(n or 0)
                if ct == "FN":
                    out["new_fn"] += n
                else:
                    out["new_fp"] += n
        except Exception as e:
            log("REPORT", f"领导摘要-新增问题单统计失败: {e}")
        try:
            # 完成评测数 + 涉及项目数（项目维度看本期测评覆盖面）
            cur.execute(
                "SELECT COUNT(*), "
                "COUNT(DISTINCT NULLIF(s.project_id, '')) "
                "FROM evaluation e "
                "LEFT JOIN evaluation_summary s "
                "ON s.evaluation_id = e.evaluation_id "
                "WHERE e.evaluation_status IN "
                "('COMPLETED','COMPLETED_WITH_WARNINGS') "
                "AND e.finished_at >= %s AND e.finished_at <= %s",
                (since, until))
            _row = cur.fetchone()
            out["evals"] = int((_row[0] if _row else 0) or 0)
            out["eval_projects"] = int((_row[1] if _row else 0) or 0)
        except Exception as e:
            log("REPORT", f"领导摘要-完成评测统计失败: {e}")
        try:
            cur.execute(
                "SELECT agent_type, COUNT(*) FROM dts_issue "
                "WHERE status NOT IN ('passed','not_issue','unattributable','no_regression') "
                "GROUP BY agent_type")
            for at, n in cur.fetchall():
                for a in _split_agents(at):
                    out["open_by_agent"][a] = (
                        out["open_by_agent"].get(a, 0) + int(n or 0))
        except Exception as e:
            log("REPORT", f"领导摘要-未关闭分布统计失败: {e}")
        try:
            # 本期关闭（问题修复情况）：进入关闭状态的条数，按状态分。
            # closed_at 由状态更新维护；历史数据为 NULL 时用 updated_at 兜底
            # （近似——老数据无法精确还原关闭时刻）。
            cur.execute(
                "SELECT status, COUNT(*) FROM dts_issue "
                "WHERE status IN ('passed','no_regression','unattributable') "
                "AND COALESCE(closed_at, updated_at) >= %s "
                "AND COALESCE(closed_at, updated_at) <= %s "
                "GROUP BY status",
                (since, until))
            for st_, n in cur.fetchall():
                n = int(n or 0)
                out["closed_total"] += n
                out["closed_by_status"][str(st_)] = n
        except Exception as e:
            log("REPORT", f"领导摘要-本期关闭统计失败: {e}")
        try:
            # 累计已关闭（不分窗口）：领导判断"修复盘子"的全局进度。
            # 无法归因同样是关闭的一种状态，按状态分列。
            cur.execute(
                "SELECT status, COUNT(*) FROM dts_issue "
                "WHERE status IN ('passed','no_regression','unattributable') "
                "GROUP BY status")
            for st_, n in cur.fetchall():
                out["closed_cum_by_status"][str(st_)] = int(n or 0)
        except Exception as e:
            log("REPORT", f"领导摘要-累计关闭统计失败: {e}")
        try:
            # 无法归因存量（视为关闭、等标注方补充——单独体现）
            cur.execute(
                "SELECT COUNT(*) FROM dts_issue "
                "WHERE status='unattributable'")
            out["unattributable"] = int(cur.fetchone()[0] or 0)
        except Exception as e:
            log("REPORT", f"领导摘要-无法归因统计失败: {e}")
        return out
    return _db_query(_do)


def render_leader_text(period_label: str, since: datetime, until: datetime,
                       public_url: str,
                       prev_as_of: datetime | None = None) -> str:
    """x 报正文（领导视角，单条消息）。

    按领导的问题链组织：误报率多高（趋势）→ 人工确认率/任务风险 →
    根因是什么 → 修复进展 → 谁欠账。

    prev_as_of：上期对比锚点 = **上一次成功发送报告的时间**（调用方
    从 notification_log 取）。不能用周期起点——日报的周期起点是今天
    0 点，滚动 30 天指标在 0 点和当前只差几小时，对比值≈同一份数据
    （曾误把当天废弃的那版发送当成"上期"）。无历史发送时传 None →
    显示「上期 暂无数据」。
    """
    env = get_env_name()
    env_prefix = f"【{env}】" if env else ""
    lines = [
        _span(f"🧪 {env_prefix}奇美拉测评{period_label}",
              color="#2563eb", bold=True, size=16),
        f"🕒 统计窗口：{_fmt_local(since)} ~ {_fmt_local(until)}",
    ]

    # ① 误报率 + 趋势（近30天滚动，本期锚点=现在，
    #    上期锚点=上次发送时间——真·上期报告的数据）
    cur_snap = _confirmation_snapshot()
    prev_snap = _confirmation_snapshot(as_of=prev_as_of) if prev_as_of else {}
    if cur_snap.get("fpr") is not None:
        lines.append(
            f"📉 采集项目误报率（近30天）："
            f"{_span(_pct(cur_snap['fpr']), color='#16a34a', bold=True)}"
            f"{_pct_diff(cur_snap['fpr'], prev_snap.get('fpr'))}")
    else:
        lines.append("📉 采集项目误报率（近30天）：暂无数据")

    # ② 人工确认率区块（必含：确认率+上期对比 / 低确认率计数 / 高误报率清单）
    #    上期锚点 = 上次发送时间（同上，真·上期报告口径）
    lines += _render_confirmation_section(prev_as_of)

    # ③ 总览：修复验证 + 完成评测
    st = _leader_window_stats(since, until)
    verified = st["reg_passed"] + st["reg_failed"]
    overview = []
    if verified > 0:
        overview.append(
            f"修复验证通过率 {_pct(st['reg_passed'] / verified)}"
            f"（通过 {st['reg_passed']} / 不通过 {st['reg_failed']}）")
    # 项目维度：本期新增测评的项目数（完成评测数不展示）
    try:
        _proj = int(st.get("eval_projects") or 0)
    except Exception:
        _proj = 0
    if _proj > 0:
        overview.append(f"新增测评项目 {_proj} 个")
    if overview:
        lines.append("🔄 " + " · ".join(overview))

    # 问题修复情况：本期新发现 / 修复关闭 / 未关闭存量变化（领导最关心的
    # "问题在收敛吗"）。恒定输出——本期无增减时也明示 0，不能整行消失。
    _CLOSED_LABELS = (("passed", "回归通过"),
                       ("no_regression", "无回归关单"),
                       ("unattributable", "无法归因"))
    new_total = st["new_fp"] + st["new_fn"]
    closed_total = int(st.get("closed_total") or 0)
    # 修复情况只讲"关闭"与"存量变化"；新发现是入口量，归按 Agent 块头
    line = f"🛠 问题修复情况：修复关闭 {closed_total} 条"
    if closed_total:
        detail = " · ".join(
            f"{label} {int((st.get('closed_by_status') or {}).get(key) or 0)} 条"
            for key, label in _CLOSED_LABELS
            if int((st.get("closed_by_status") or {}).get(key) or 0))
        if detail:
            line += f"（{detail}）"
    net = new_total - closed_total
    if net > 0:
        line += f"，未关闭存量增加 {net} 条"
    elif net < 0:
        line += f"，未关闭存量减少 {abs(net)} 条"
    else:
        line += "，未关闭存量持平"
    lines.append(line)
    # 历史累计已关闭（不分窗口）：无法归因同样是关闭的一种状态
    cum = st.get("closed_cum_by_status") or {}
    cum_total = sum(int(n or 0) for n in cum.values())
    if cum_total:
        cum_detail = " · ".join(
            f"{label} {int(cum.get(key) or 0)} 条"
            for key, label in _CLOSED_LABELS
            if int(cum.get(key) or 0))
        lines.append(
            f"📦 历史累计已关闭 {cum_total} 条"
            + (f"（{cum_detail}）" if cum_detail else ""))

    open_dist = st.get("open_by_agent") or {}
    if open_dist:
        top = sorted(open_dist.items(), key=lambda x: -x[1])
        segs = [f"{AGENT_SHORT_LABELS.get(a, a)} {n} 个"
                for a, n in top[:4]]
        more = f" 等 {len(top)} 项" if len(top) > 4 else ""
        lines.append("👥 未关闭问题单：" + " · ".join(segs) + more)
    # 无法归因存量（视为关闭但欠标注方补充——单独体现，有数据才显示）
    unattr = int(st.get("unattributable") or 0)
    if unattr > 0:
        lines.append(
            f"🚫 无法归因 {unattr} 条：全部线索被否定+标注不全，"
            f"待标注方补充后重新开启")
    lines.append(f"🔗 {public_url}/dts")
    return "\n".join(lines)


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


def _earliest_data_time() -> datetime | None:
    """库里最早的业务数据时间（UTC naive）。

    用于「从未发送过」的 owner：第一次日报应覆盖全部历史，而不是只发 24h。
    """
    def _do(cur):
        cur.execute(
            "SELECT MIN(finished_at) FROM evaluation "
            "WHERE evaluation_status IN "
            "('COMPLETED','COMPLETED_WITH_WARNINGS','FAILED')")
        ev = cur.fetchone()[0]
        cur.execute("SELECT MIN(created_at) FROM dts_issue")
        iss = cur.fetchone()[0]
        candidates = [x for x in (ev, iss) if x is not None]
        return min(candidates) if candidates else None
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


def _load_regression_stats(owner_kind: str, owner_value: str) -> dict:
    """回归验证后的误报率：FP 问题单中 failed / (passed + failed)。

    与首页看板「回归后误报率」同一口径。评测报告里的 fpr/precision 只反映
    单次评测的基线匹配结果，不代表平台整体，日报不再展示。
    """
    filter_sql, params = _issue_filter(owner_kind, owner_value)

    def _do(cur):
        cur.execute(
            "SELECT status, COUNT(*) FROM dts_issue "
            "WHERE case_type='FP' AND status IN ('passed','failed') "
            f"AND {filter_sql} GROUP BY status",
            tuple(params))
        counts = {row[0]: int(row[1]) for row in cur.fetchall()}
        passed = counts.get("passed", 0)
        failed = counts.get("failed", 0)
        denom = passed + failed
        return {
            "passed": passed,
            "failed": failed,
            "verified": denom,
            "post_fpr": (failed / denom) if denom > 0 else None,
        }
    return _db_query(_do)


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


def _issue_item(item: dict, public_url: str) -> dict:
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
        "url": f"{public_url}/dts/{item['dts_id']}",
    }


def _build_agent_report(owner: dict, since: datetime, until: datetime,
                        evaluations: list[dict], public_url: str) -> dict:
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
                "url": f"{public_url}/evals/{ev['evaluation_id']}",
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
            "url": f"{public_url}/evals/{ev['evaluation_id']}",
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
        # 回归后误报率（FP 问题单回归验证 failed/(passed+failed)）
        "regression": _load_regression_stats("agent", agent_type),
        "new_issues": [_issue_item(i, public_url) for i in new_issues],
        "open_issues": {
            "total": open_total,
            "items": [_issue_item(i, public_url) for i in open_issues],
        },
        "urls": {
            "eval_list": f"{public_url}/evals",
            "issue_list": f"{public_url}/dts?agent_type={agent_type}&status=open",
        },
    }


def _build_responsibility_report(owner: dict, since: datetime,
                                 until: datetime, public_url: str) -> dict:
    responsibility = _split_owner_key(owner["owner_key"])[1]
    display_name = (owner.get("display_name")
                    or _RESPONSIBILITY_LABELS.get(responsibility, responsibility))

    new_issues = _load_new_issues("responsibility", responsibility, since, until)
    open_total, open_issues = _load_open_issues("responsibility", responsibility)

    # 不再按 agent 细分组：责任方段只有一个负责人，按 agent 分组没有
    # 对应读者（各 agent 的视角由各 agent 段承载）——只呈现汇总 + 链接
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
        "new_issues": [_issue_item(i, public_url) for i in new_issues],
        "open_issues": {
            "total": open_total,
            "items": [_issue_item(i, public_url) for i in open_issues],
        },
        "totals": {"new": len(new_issues), "open": open_total},
        "urls": {
            "issue_list": (f"{public_url}/dts?"
                           f"responsibility={responsibility}&status=open"),
        },
    }


def build_reports(owner_key: str | None = None,
                  since: str | None = None,
                  until: str | None = None,
                  force: bool = False,
                  channel: str = _CHANNEL) -> dict:
    """构建一个或多个 owner 的日报/周报。

    统计窗口 = **上轮未发送的数据**（按 channel 分离跟踪）：
    - 有成功发送记录 → 从上次成功发送的 ``window_end`` 开始（只发增量）；
    - 从未发送过 → 所有历史数据都还没发过，从库里最早业务数据开始；
    - 显式传 ``since`` 时以调用方为准。
    ``force`` 仅影响发送去重（是否允许当天重发），不影响统计窗口。
    周报传 ``channel=_CHANNEL_WEEKLY``——窗口跟踪/发送记录与日报独立。
    """
    until_dt = _parse_dt(until) or _now_utc()
    explicit_since = _parse_dt(since)
    owners = _load_owners(owner_key)

    earliest: datetime | None = None
    windows: dict[str, datetime] = {}
    for owner in owners:
        key = owner["owner_key"]
        if explicit_since:
            windows[key] = explicit_since
            continue
        last = last_sent_at(key, channel)
        if last is not None:
            windows[key] = last
            continue
        if earliest is None:
            earliest = _earliest_data_time() or (until_dt - timedelta(hours=24))
        windows[key] = earliest

    # 一次拉取覆盖所有 agent 的最早窗口；agent 报告构建时再按自己的窗口过滤
    agent_windows = [w for k, w in windows.items()
                     if _split_owner_key(k)[0] == "agent"]
    if agent_windows:
        evaluations = _load_evaluations(min(agent_windows), until_dt)
    else:
        evaluations = []

    public_url = get_public_url()
    reports = []
    for owner in owners:
        kind = owner.get("owner_kind") or _split_owner_key(owner["owner_key"])[0]
        win_start = windows[owner["owner_key"]]
        if kind == "agent":
            reports.append(_build_agent_report(
                owner, win_start, until_dt, evaluations, public_url))
        else:
            reports.append(_build_responsibility_report(
                owner, win_start, until_dt, public_url))

    env_name = get_env_name()
    for report in reports:
        report["env_name"] = env_name

    return {
        "generated_at": _iso(_now_utc()),
        "until": _iso(until_dt),
        "env_name": env_name,
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
    """按 L2-L8 统计问题单，输出一行紧凑分布。"""
    return _level_counts(items)


def render_agent_text(report: dict, period_label: str = "日报",
                     header: bool = True) -> str:
    """owner 分节（WeLink 短消息形态：每分节 ≤4 行）。"""
    ev = report.get("evaluations") or {}
    new_issues = report.get("new_issues") or []
    open_issues = report.get("open_issues") or {}
    window = report.get("window") or {}
    short = AGENT_SHORT_LABELS.get(report.get("agent_type", ""),
                                   report.get("agent_type", ""))
    owner = report.get("owner_name") or "未配置负责人"
    urls = report.get("urls") or {}

    if header:
        s = _fmt_date_short(_parse_dt(window.get("start")))
        lines = [
            _span(f"🧪 {_env_prefix(report)}奇美拉测评{period_label} · {short}"
                  f"（{s}）", color="#2563eb", bold=True, size=16),
            f"👤 {owner}",
        ]
    else:
        lines = [_span(f"🧩 {short}（{owner}）", bold=True)]

    total = int(ev.get("total") or 0)
    if total > 0:
        # 一行评测指标：只展示结果（状态是过期信息，失败在列表页看）
        metric_parts = []
        for key, label in (("tp", "TP"), ("fp", "FP"),
                           ("fn", "FN"), ("tn", "TN")):
            value = int(ev.get(key) or 0)
            if value > 0:
                metric_parts.append(f"{label} {value}")
        reg = report.get("regression") or {}
        post_fpr = reg.get("post_fpr")
        tail = (f"｜回归后误报率 {_pct(post_fpr)}"
                if post_fpr is not None else "")
        lines.append(f"📊 评测 {total} 个：" + " · ".join(metric_parts) + tail)

    open_total = int(open_issues.get("total") or 0)
    if open_total > 0 or new_issues:
        label = f"⚠️ 未关闭 {open_total}"
        if new_issues:
            label += f"（+{len(new_issues)}）"
        levels = _level_counts(open_issues.get("items") or [])
        if levels:
            label += f"｜{levels}"
        lines.append(label)
    url = urls.get("issue_list", "")
    if url:
        lines.append(f"🔗 {url}")
    return "\n".join(lines)


def render_responsibility_text(report: dict,
                               period_label: str = "日报",
                               header: bool = True) -> str:
    """责任方分节（WeLink 短消息形态：≤3 行）。"""
    window = report.get("window") or {}
    owner = report.get("owner_name") or "未配置负责人"
    totals = report.get("totals") or {}

    if header:
        s = _fmt_date_short(_parse_dt(window.get("start")))
        lines = [
            _span(f"🧪 {_env_prefix(report)}奇美拉测评{period_label} · "
                  f"{report.get('display_name', '')}（{s}）",
                  color="#2563eb", bold=True, size=16),
            f"👤 {owner}",
        ]
    else:
        lines = [_span(f"🧩 {report.get('display_name', '')}（{owner}）",
                       bold=True)]
    open_total = int(totals.get("open") or 0)
    new_cnt = int(totals.get("new") or 0)
    if open_total > 0 or new_cnt > 0:
        label = f"⚠️ 未关闭 {open_total}"
        if new_cnt:
            label += f"（+{new_cnt}）"
        levels = _level_counts(
            (report.get("open_issues") or {}).get("items") or [])
        if levels:
            label += f"｜{levels}"
        lines.append(label)
    url = (report.get("urls") or {}).get("issue_list", "")
    if url:
        lines.append(f"🔗 {url}")
    return "\n".join(lines)


def render_text(report: dict, period_label: str = "日报",
                header: bool = True) -> str:
    if report.get("owner_kind") == "agent":
        return render_agent_text(report, period_label=period_label,
                                 header=header)
    return render_responsibility_text(report, period_label=period_label,
                                       header=header)


def render_combined_text(reports: list[dict],
                         period_label: str = "周报") -> str:
    """（已废弃：责任明细改为 per-owner 定向发送，不再合并成一条消息。）

    保留占位避免外部调用方 AttributeError；返回各分节拼接。
    """
    reports = [r for r in (reports or []) if r]
    return "\n".join(
        render_text(r, period_label=period_label, header=False)
        for r in reports if r)


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
