"""首页看板聚合接口。

GET /api/v2/dashboard/overview — 一次性返回首页看板所需全部指标：

- overall: 跨评测总体误报率/漏报率、回归后误报率/漏报率、TP/FP/FN/TN 合计
- cause_agent_matrix: A-K × agent 交叉表（问题单按 cause_code × agent_type 计数）
- agent_detail: 各 agent 维度明细（问题单数、FP 数、FN 数、误报率、
  回归验证数、回归后误报率）
- dts: 问题单全局统计（by_status / by_cause_code / by_agent_type / total）

数据来源：
- 总体误报率/漏报率：读取所有已完成评测的 {eid}.json 报告
  recall_precision 字段（sum(FP)/sum(TP+FP)、sum(FN)/sum(TP+FN)）
- 回归后误报率/漏报率：dts_issue 表 status 聚合
  （failed/(passed+failed)，按 case_type 区分 FP/FN）
- 交叉表/明细：dts_issue 表 GROUP BY
"""
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException

from ..infra.log_util import log
from ..infra.db_utils import db_query as _db_query

router = APIRouter(prefix="/api/v2/dashboard", tags=["dashboard"])

# 报告目录（统一从 config_loader 读取）
from ...config_loader import get_reports_dir
REPORTS_DIR = get_reports_dir()

# 报告文件读取并发度（I/O 密集，线程足够）
_IO_WORKERS = 8

# A-K 成因码
_ALL_CAUSE_CODES = list("ABCDEFGHIJK")

# 6 个 agent 类型（集中配置见 v2/core/agents.py）
from ..core.agents import ALL_AGENT_TYPES as _ALL_AGENT_TYPES


def _eval_status_counts() -> dict:
    """评测总数与各状态计数（首页 KPI 用，避免前端拉全量评测列表）。"""
    def _query(cur):
        cur.execute("SELECT evaluation_status, COUNT(*) FROM evaluation "
                    "GROUP BY evaluation_status")
        by_status = {row[0]: int(row[1]) for row in cur.fetchall()}
        return {"total": sum(by_status.values()), "by_status": by_status}
    return _db_query(_query)


def _completed_eids() -> list[str]:
    """已完成评测 ID 列表（三个聚合函数共用一次查询）。"""
    def _query(cur):
        cur.execute(
            "SELECT evaluation_id FROM evaluation "
            "WHERE evaluation_status IN ('COMPLETED','COMPLETED_WITH_WARNINGS')"
        )
        return [row[0] for row in cur.fetchall()]
    return _db_query(_query)


def _parallel_map(fn, items):
    """并发执行 fn(item)，按输入顺序返回结果。"""
    items = list(items)
    if not items:
        return []
    if len(items) == 1:
        return [fn(items[0])]
    with ThreadPoolExecutor(max_workers=min(_IO_WORKERS, len(items))) as pool:
        return list(pool.map(fn, items))


def _eval_mode_of(eid: str) -> str:
    """读取评测的 eval_mode（runtime/dev）。

    从 {eid}_debug_ingesting.json 的 eval_mode 字段读取；
    文件缺失时返回 ""（无法归类）。
    """
    path = os.path.join(REPORTS_DIR, f"{eid}_debug_ingesting.json")
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.loads(f.read())
        mode = d.get("eval_mode", "")
        return mode if mode in ("runtime", "dev") else ""
    except Exception:
        return ""


# evaluation_summary 列（顺序与 _normalize_summary 对应）
_SUMMARY_COLS = (
    "evaluation_id", "eval_mode", "tp_count", "fp_count", "fn_count", "tn_count",
    "recall_rate", "precision_rate", "fpr_rate",
    "agent_outcomes", "breakpoint_distribution",
)


def _json_obj(v) -> dict:
    """JSON 列可能是 str 或已解析的 dict。"""
    if not v:
        return {}
    if isinstance(v, dict):
        return v
    try:
        return json.loads(v) or {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _normalize_summary(row: dict) -> dict:
    """把 evaluation_summary 行归一成聚合用的结构。"""
    return {
        "eval_mode": row.get("eval_mode") or "unknown",
        "tp": int(row.get("tp_count") or 0),
        "fp": int(row.get("fp_count") or 0),
        "fn": int(row.get("fn_count") or 0),
        "tn": int(row.get("tn_count") or 0),
        "agent_outcomes": _json_obj(row.get("agent_outcomes")),
        "breakpoint_distribution": _json_obj(row.get("breakpoint_distribution")),
    }


def _load_summaries(eids: list[str]) -> dict[str, dict]:
    """从 evaluation_summary 读汇总；旧评测缺行时从报告文件回填（一次性）。"""
    if not eids:
        return {}
    cols = ", ".join(_SUMMARY_COLS)

    def _query(cur):
        ph = ",".join(["%s"] * len(eids))
        cur.execute(
            f"SELECT {cols} FROM evaluation_summary "
            f"WHERE evaluation_id IN ({ph})",
            tuple(eids),
        )
        return [dict(zip(_SUMMARY_COLS, r)) for r in cur.fetchall()]

    try:
        rows = _db_query(_query)
    except Exception as e:
        # 表未迁移/DB 异常：退回读文件，保证看板可用
        log("DASHBOARD", f"读取 evaluation_summary 失败，回退文件读取: {e}")
        return _backfill_summaries(eids, persist=False)
    out = {r["evaluation_id"]: _normalize_summary(r) for r in rows}
    missing = [eid for eid in eids if eid not in out]
    if missing:
        out.update(_backfill_summaries(missing))
    return out


def _backfill_summaries(eids: list[str], persist: bool = True) -> dict[str, dict]:
    """旧评测（FINALIZE 之前完成）没有索引行：读一次报告文件并回写。"""
    def _read_one(eid: str):
        mode = _eval_mode_of(eid) or "unknown"

        rp: dict = {}
        base_path = os.path.join(REPORTS_DIR, f"{eid}.json")
        if os.path.isfile(base_path):
            try:
                with open(base_path, "r", encoding="utf-8") as f:
                    rp = (json.load(f) or {}).get("recall_precision") or {}
            except Exception:
                rp = {}

        agent_outcomes: dict = {}
        cm_path = os.path.join(REPORTS_DIR, f"{eid}_debug_case_matching.json")
        if os.path.isfile(cm_path):
            try:
                with open(cm_path, "r", encoding="utf-8") as f:
                    cm = json.load(f) or {}
                agent_outcomes = cm.get("agent_outcomes") or {}
                if not agent_outcomes:
                    # 旧 dump 无 agent_outcomes：从 matches + parsing 反推
                    agent_outcomes = _agent_outcomes_from_matches(eid, cm)
            except Exception as e:
                log("DASHBOARD", f"回填 case_matching 失败 {eid}: {e}")

        bp: dict = {}
        lp = os.path.join(REPORTS_DIR, f"{eid}_lifecycle.json")
        if os.path.isfile(lp):
            try:
                with open(lp, "r", encoding="utf-8") as f:
                    bp = (json.load(f) or {}).get("breakpoint_distribution") or {}
            except Exception:
                bp = {}

        return eid, mode, rp, agent_outcomes, bp

    out: dict[str, dict] = {}
    upserts: list[tuple] = []
    for item in _parallel_map(_read_one, eids):
        if not item:
            continue
        eid, mode, rp, agent_outcomes, bp = item
        out[eid] = {
            "eval_mode": mode,
            "tp": int(rp.get("tp_count") or 0),
            "fp": int(rp.get("fp_count") or 0),
            "fn": int(rp.get("fn_count") or 0),
            "tn": int(rp.get("tn_count") or 0),
            "agent_outcomes": agent_outcomes,
            "breakpoint_distribution": bp,
        }
        upserts.append((
            eid, mode,
            out[eid]["tp"], out[eid]["fp"], out[eid]["fn"], out[eid]["tn"],
            rp.get("recall_rate"), rp.get("precision_rate"), rp.get("fpr_rate"),
            json.dumps(agent_outcomes, ensure_ascii=False),
            json.dumps(bp, ensure_ascii=False),
        ))

    if upserts and persist:
        def _write(cur):
            cur.executemany(
                "INSERT INTO evaluation_summary "
                "(evaluation_id, eval_mode, tp_count, fp_count, fn_count, tn_count, "
                " recall_rate, precision_rate, fpr_rate, agent_outcomes, "
                " breakpoint_distribution) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE "
                "eval_mode=VALUES(eval_mode), tp_count=VALUES(tp_count), "
                "fp_count=VALUES(fp_count), fn_count=VALUES(fn_count), "
                "tn_count=VALUES(tn_count), recall_rate=VALUES(recall_rate), "
                "precision_rate=VALUES(precision_rate), fpr_rate=VALUES(fpr_rate), "
                "agent_outcomes=VALUES(agent_outcomes), "
                "breakpoint_distribution=VALUES(breakpoint_distribution)",
                upserts,
            )
        try:
            _db_query(_write)
        except Exception as e:
            log("DASHBOARD", f"回填 evaluation_summary 失败: {e}")

    return out


def _agent_outcomes_from_matches(eid: str, cm: dict) -> dict:
    """旧 dump 无 agent_outcomes：从 matches + parsing 反推各 agent TP/FP。"""
    sid_to_agent: dict[str, str] = {}
    ps_path = os.path.join(REPORTS_DIR, f"{eid}_debug_parsing.json")
    if os.path.isfile(ps_path):
        try:
            with open(ps_path, "r", encoding="utf-8") as f:
                ps = json.load(f) or {}
            for pack in ps.get("data_packs", []):
                at = pack.get("agent_type", "")
                for s in (pack.get("sessions", []) or []):
                    sid = s.get("session_id", "")
                    if sid and at:
                        sid_to_agent[sid] = at
        except Exception as e:
            log("DASHBOARD", f"读取 parsing 失败 {eid}: {e}")

    stats: dict[str, dict] = {}
    for m in (cm.get("matches", []) or []):
        outcome = m.get("outcome", "")
        if outcome not in ("TP", "FP"):
            continue
        key = "tp" if outcome == "TP" else "fp"
        mining = m.get("mining_sessions", []) or []
        bumped = set()
        for sid in mining:
            agent = sid_to_agent.get(sid, "")
            if agent and agent not in bumped:
                bumped.add(agent)
                a = stats.setdefault(agent, {"tp": 0, "fp": 0, "fn": 0})
                a[key] = a.get(key, 0) + 1
    return stats


# 断点矩阵的 L 级别（L1 是前置判定，不是断点）
_BP_LEVELS = ["L2", "L3", "L4", "L5", "L6", "L7", "L8"]


def _aggregate_breakpoints(summaries: dict[str, dict]) -> dict:
    """汇总断点分布（agent × L2-L8），按 eval_mode 分组。

    数据来自 evaluation_summary.breakpoint_distribution，不读 lifecycle 文件。
    """
    def _empty() -> dict:
        return {a: {lv: 0 for lv in _BP_LEVELS} for a in _ALL_AGENT_TYPES}

    grouped: dict[str, dict] = {
        "runtime": _empty(), "dev": _empty(), "unknown": _empty(),
    }

    for s in summaries.values():
        mode = s.get("eval_mode") or "unknown"
        dist = s.get("breakpoint_distribution") or {}
        bucket = grouped.setdefault(mode, _empty())
        for agent, levels in dist.items():
            if not isinstance(levels, dict):
                continue
            if agent not in bucket:
                bucket[agent] = {lv: 0 for lv in _BP_LEVELS}
            for lv in _BP_LEVELS:
                bucket[agent][lv] += int(levels.get(lv) or 0)
    return grouped


def _aggregate_reports(summaries: dict[str, dict]) -> dict:
    """按 eval_mode 汇总 recall_precision（来自 evaluation_summary）。

    Returns:
        {
            "runtime": {"tp": N, "fp": N, "fn": N, "tn": N, "count": N},
            "dev": {...},
            "unknown": {...},
        }
    """
    grouped: dict[str, dict] = {
        "runtime": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0},
        "dev": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0},
        "unknown": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0},
    }

    for s in summaries.values():
        mode = s.get("eval_mode") or "unknown"
        bucket = grouped.setdefault(mode, {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0})
        bucket["tp"] += s.get("tp", 0)
        bucket["fp"] += s.get("fp", 0)
        # 运行态没有漏报基线：历史报告里即使有 FN 也不计入运行态统计
        bucket["fn"] += (0 if mode == "runtime" else s.get("fn", 0))
        bucket["tn"] += s.get("tn", 0)
        bucket["count"] += 1
    return grouped


def _aggregate_agent_fpr(summaries: dict[str, dict]) -> dict:
    """按 eval_mode 汇总各 agent 的 TP/FP/FN（来自 evaluation_summary）。

    口径：agent 误报率 = FP / (TP + FP)、漏报率 = FN / (TP + FN)。

    Returns:
        {
            "runtime": {"turing": {"tp": N, "fp": N, "fn": N}, ...},
            "dev": {...},
            "unknown": {...},
        }
    """
    grouped: dict[str, dict[str, dict]] = {
        "runtime": {}, "dev": {}, "unknown": {},
    }

    for s in summaries.values():
        mode = s.get("eval_mode") or "unknown"
        for agent, st in (s.get("agent_outcomes") or {}).items():
            if not isinstance(st, dict):
                continue
            tp = st.get("tp", 0) or 0
            fp = st.get("fp", 0) or 0
            # 运行态没有漏报基线：不统计 FN
            fn = 0 if mode == "runtime" else (st.get("fn", 0) or 0)
            bucket = grouped.setdefault(mode, {})
            a = bucket.setdefault(agent, {"tp": 0, "fp": 0, "fn": 0})
            a["tp"] += tp
            a["fp"] += fp
            a["fn"] += fn
    return grouped


def _query_dts_aggregate() -> dict:
    """从 dts_issue 表聚合：交叉矩阵、agent 明细、回归统计、全局统计。

    Returns:
        {
            "cause_agent_matrix": {"A": {"turing": N, ...}, ...},
            "agent_detail": [
                {"agent": str, "issues": N, "fp": N, "fn": N,
                 "reg_passed": N, "reg_failed": N},
            ],
            "post_stats": {"passed": N, "failed": N},   # 全局回归验证数
            "dts": {"by_status": {}, "by_cause_code": {}, "by_agent_type": {},
                    "by_case_type": {}, "total": N},
        }
    """
    def _do_query(cur):
        # 1. A-K × agent 交叉矩阵（agent_type 逗号分隔多值，拆开计数）
        cur.execute(
            "SELECT cause_code, agent_type, COUNT(*) FROM dts_issue "
            "WHERE cause_code IS NOT NULL AND cause_code != '' "
            "AND agent_type IS NOT NULL AND agent_type != '' "
            "GROUP BY cause_code, agent_type"
        )
        matrix: dict[str, dict[str, int]] = {c: {} for c in _ALL_CAUSE_CODES}
        for cause, agents, cnt in cur.fetchall():
            for at in str(agents).split(","):
                at = at.strip()
                if not at:
                    continue
                matrix.setdefault(cause, {})[at] = matrix.get(cause, {}).get(at, 0) + cnt

        # 2. agent 维度明细：agent_type × case_type × status
        cur.execute(
            "SELECT agent_type, case_type, status, COUNT(*) FROM dts_issue "
            "GROUP BY agent_type, case_type, status"
        )
        agent_agg: dict[str, dict] = {}
        for agents, case_type, status, cnt in cur.fetchall():
            for at in str(agents).split(","):
                at = at.strip()
                if not at:
                    continue
                a = agent_agg.setdefault(at, {"issues": 0, "fp": 0, "fn": 0,
                                              "reg_passed": 0, "reg_failed": 0})
                a["issues"] += cnt
                if case_type == "FP":
                    a["fp"] += cnt
                elif case_type == "FN":
                    a["fn"] += cnt
                if status == "passed":
                    a["reg_passed"] += cnt
                elif status == "failed":
                    a["reg_failed"] += cnt

        # 3. 全局回归验证统计（不区分 agent）
        cur.execute(
            "SELECT case_type, status, COUNT(*) FROM dts_issue "
            "GROUP BY case_type, status"
        )
        post: dict = {"FP": {"passed": 0, "failed": 0},
                      "FN": {"passed": 0, "failed": 0}}
        for case_type, status, cnt in cur.fetchall():
            bucket = post.setdefault(case_type or "FP", {"passed": 0, "failed": 0})
            if status == "passed":
                bucket["passed"] += cnt
            elif status == "failed":
                bucket["failed"] += cnt

        # 4. 全局统计（复用 get_dts_stats 口径）
        cur.execute("SELECT status, COUNT(*) FROM dts_issue GROUP BY status")
        by_status = {r[0]: r[1] for r in cur.fetchall()}
        cur.execute("SELECT cause_code, COUNT(*) FROM dts_issue GROUP BY cause_code")
        by_cause = {r[0]: r[1] for r in cur.fetchall()}
        cur.execute("SELECT agent_type, COUNT(*) FROM dts_issue GROUP BY agent_type")
        by_agent = {r[0]: r[1] for r in cur.fetchall()}
        cur.execute("SELECT case_type, COUNT(*) FROM dts_issue GROUP BY case_type")
        by_case_type = {r[0]: r[1] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM dts_issue")
        total = cur.fetchone()[0]

        agent_detail = sorted(
            ({"agent": at, **agg} for at, agg in agent_agg.items()),
            key=lambda x: -x["issues"],
        )
        return {
            "cause_agent_matrix": matrix,
            "agent_detail": agent_detail,
            "post_stats": post,
            "dts": {
                "by_status": by_status,
                "by_cause_code": by_cause,
                "by_agent_type": by_agent,
                "by_case_type": by_case_type,
                "total": total,
            },
        }

    try:
        return _db_query(_do_query)
    except Exception as e:
        log("DASHBOARD", f"DTS 聚合查询失败: {e}")
        raise HTTPException(status_code=500, detail=f"DTS 聚合查询失败: {e}")


@router.get("/overview")
def get_dashboard_overview():
    """首页看板聚合指标。

    Returns:
        {
            "overall": {
                "total_fpr": float | None,   # 总体误报率 sum(FP)/sum(TP+FP)
                "total_fnr": float | None,   # 总体漏报率 sum(FN)/sum(TP+FN)
                "post_fpr": float | None,    # 回归后误报率 failed/(passed+failed) 全局
                "post_fnr": float | None,    # 回归后漏报率（FN 问题单回归验证）
                "tp": int, "fp": int, "fn": int, "tn": int,
                "report_count": int,          # 参与聚合的评测数
            },
            "cause_agent_matrix": {...},
            "agent_detail": [...],
            "dts": {...},
            "updated_at": str,
        }
    """
    from datetime import datetime, timezone, timedelta

    # 已完成评测列表 + 汇总索引：一次查询拿到全部聚合输入，不读大报告文件
    try:
        eids = _completed_eids()
    except Exception as e:
        log("DASHBOARD", f"查询已完成评测失败: {e}")
        raise HTTPException(status_code=500, detail=f"查询已完成评测失败: {e}")
    summaries = _load_summaries(eids)

    # 1. 跨评测 fpr/fnr（按 eval_mode 分组：runtime/dev/unknown）
    reports = _aggregate_reports(summaries)
    overall_by_mode: dict[str, dict] = {}
    for mode in ("runtime", "dev", "unknown"):
        b = reports.get(mode, {}) or {}
        btp, bfp, bfn, btn = b.get("tp", 0), b.get("fp", 0), b.get("fn", 0), b.get("tn", 0)
        b_fpr = (bfp / (btp + bfp)) if (btp + bfp) > 0 else None
        b_fnr = (bfn / (btp + bfn)) if (btp + bfn) > 0 else None
        overall_by_mode[mode] = {
            "total_fpr": round(b_fpr, 4) if b_fpr is not None else None,
            "total_fnr": round(b_fnr, 4) if b_fnr is not None else None,
            "tp": btp, "fp": bfp, "fn": bfn, "tn": btn,
            "report_count": b.get("count", 0),
        }
    # 汇总（全部 mode 合并，兼容旧前端字段）
    tp = sum((reports.get(m, {}) or {}).get("tp", 0) for m in ("runtime", "dev", "unknown"))
    fp = sum((reports.get(m, {}) or {}).get("fp", 0) for m in ("runtime", "dev", "unknown"))
    fn = sum((reports.get(m, {}) or {}).get("fn", 0) for m in ("runtime", "dev", "unknown"))
    tn = sum((reports.get(m, {}) or {}).get("tn", 0) for m in ("runtime", "dev", "unknown"))
    total_fpr = (fp / (tp + fp)) if (tp + fp) > 0 else None
    total_fnr = (fn / (tp + fn)) if (tp + fn) > 0 else None

    # 2. DTS 聚合（回归后误报率/漏报率 + 交叉矩阵 + agent 明细）
    agg = _query_dts_aggregate()
    post = agg.get("post_stats") or {}

    fp_post = post.get("FP", {"passed": 0, "failed": 0})
    fn_post = post.get("FN", {"passed": 0, "failed": 0})
    fp_denom = fp_post.get("passed", 0) + fp_post.get("failed", 0)
    post_fpr = (fp_post.get("failed", 0) / fp_denom) if fp_denom > 0 else None
    fn_denom = fn_post.get("passed", 0) + fn_post.get("failed", 0)
    post_fnr = (fn_post.get("failed", 0) / fn_denom) if fn_denom > 0 else None
    for mode in ("runtime", "dev", "unknown"):
        overall_by_mode[mode]["post_fpr"] = post_fpr
        # 运行态没有漏报基线，不提供回归后漏报率
        overall_by_mode[mode]["post_fnr"] = None if mode == "runtime" else post_fnr

    # 3. agent 明细：按 eval_mode 分组（runtime/dev/unknown）
    agent_fpr_stats = _aggregate_agent_fpr(summaries)  # {mode: {agent: {tp, fp, fn}}}
    agent_detail_by_mode: dict[str, list] = {
        "runtime": [], "dev": [], "unknown": [],
    }

    def _build_agent_detail(stats: dict) -> list:
        """从 agent 统计构建明细列表（含 fpr/fnr）。"""
        out = []
        for agent, st in sorted(stats.items()):
            tp, fp, fn = st.get("tp", 0), st.get("fp", 0), st.get("fn", 0)
            denom = tp + fp
            a_fpr = (fp / denom) if denom > 0 else None
            fnr_denom = tp + fn
            a_fnr = (fn / fnr_denom) if fnr_denom > 0 else None
            out.append({
                "agent": agent,
                "issues": 0,
                "fp": fp,
                "tp": tp,
                "fn": fn,
                "fpr": round(a_fpr, 4) if a_fpr is not None else None,
                "fnr": round(a_fnr, 4) if a_fnr is not None else None,
                "reg_passed": 0,
                "reg_failed": 0,
                "post_fpr": None,
            })
        return out

    for mode in ("runtime", "dev", "unknown"):
        stats = agent_fpr_stats.get(mode, {}) or {}
        agent_detail_by_mode[mode] = _build_agent_detail(stats)

    now_cst = datetime.now(timezone(timedelta(hours=8)))
    try:
        eval_counts = _eval_status_counts()
    except Exception as e:
        log("DASHBOARD", f"查询评测状态计数失败: {e}")
        eval_counts = {"total": 0, "by_status": {}}
    return {
        "evaluations": eval_counts,
        "overall": {
            "runtime": overall_by_mode.get("runtime", {}),
            "dev": overall_by_mode.get("dev", {}),
            "unknown": overall_by_mode.get("unknown", {}),
            "total_fpr": round(total_fpr, 4) if total_fpr is not None else None,
            "total_fnr": round(total_fnr, 4) if total_fnr is not None else None,
            "post_fpr": post_fpr,
            "post_fnr": post_fnr,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "report_count": len(reports),
        },
        "agent_detail": agent_detail_by_mode,
        "cause_agent_matrix": agg.get("cause_agent_matrix", {}),
        "breakpoint_matrix": _aggregate_breakpoints(summaries),
        "dts": agg.get("dts", {}),
        "updated_at": now_cst.strftime("%Y-%m-%d %H:%M:%S"),
    }
