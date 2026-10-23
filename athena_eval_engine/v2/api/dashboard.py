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

from fastapi import APIRouter

from ...infrastructure.log_util import log
from ..persistence.dts_repo import _db_query

router = APIRouter(prefix="/api/v2/dashboard", tags=["dashboard"])

# 报告目录（与老代码一致，环境变量优先）
REPORTS_DIR = os.environ.get("EVAL_REPORTS_DIR", "reports")

# A-K 成因码
_ALL_CAUSE_CODES = list("ABCDEFGHIJK")

# 6 个 agent 类型（集中配置见 v2/core/agents.py）
from ..core.agents import ALL_AGENT_TYPES as _ALL_AGENT_TYPES


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


def _read_eval_reports() -> dict:
    """读取所有已完成评测的 {eid}.json 报告 recall_precision 数据，按 eval_mode 分组。

    从 evaluation 表查 COMPLETED / COMPLETED_WITH_WARNINGS 评测，
    逐个读报告文件（不存在跳过）。

    Returns:
        {
            "runtime": {"tp": N, "fp": N, "fn": N, "tn": N, "count": N},
            "dev": {"tp": N, "fp": N, "fn": N, "tn": N, "count": N},
            "unknown": {...},   # eval_mode 文件缺失的评测
        }
    """
    grouped: dict[str, dict] = {
        "runtime": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0},
        "dev": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0},
        "unknown": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0},
    }

    def _query(cur):
        cur.execute(
            "SELECT evaluation_id FROM evaluation "
            "WHERE evaluation_status IN ('COMPLETED','COMPLETED_WITH_WARNINGS')"
        )
        return [row[0] for row in cur.fetchall()]

    try:
        eids = _db_query(_query)
    except Exception as e:
        log("DASHBOARD", f"查询已完成评测失败: {str(e)[:200]}")
        return grouped

    for eid in eids:
        path = os.path.join(REPORTS_DIR, f"{eid}.json")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.loads(f.read())
            rp = data.get("recall_precision") or {}
            mode = _eval_mode_of(eid) or "unknown"
            bucket = grouped.setdefault(mode, {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "count": 0})
            bucket["tp"] += rp.get("tp_count") or 0
            bucket["fp"] += rp.get("fp_count") or 0
            bucket["fn"] += rp.get("fn_count") or 0
            bucket["tn"] += rp.get("tn_count") or 0
            bucket["count"] += 1
        except Exception as e:
            log("DASHBOARD", f"读取报告失败 {eid}: {str(e)[:200]}")
            continue
    return grouped


def _read_agent_fpr() -> dict:
    """反推各 agent 的 TP/FP/FN（来自完成评测的 case_matching + parsing），按 eval_mode 分组。

    口径与总体误报率一致：agent 误报率 = FP / (TP + FP)、漏报率 = FN / (TP + FN)。

    数据来源：
    - {eid}_debug_case_matching.json：每个 case 的 outcome + mining_sessions，
      以及新 dump 的 agent_outcomes 字段（含 TP/FP/FN）
    - {eid}_debug_parsing.json：session_id → agent_type 映射
    - {eid}_debug_ingesting.json：eval_mode（runtime/dev）

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

    def _bump(mode: str, agent: str, key: str):
        if not agent:
            return
        bucket = grouped.setdefault(mode, {})
        a = bucket.setdefault(agent, {"tp": 0, "fp": 0, "fn": 0})
        a[key] = a.get(key, 0) + 1

    # 复用已完成评测列表
    def _query(cur):
        cur.execute(
            "SELECT evaluation_id FROM evaluation "
            "WHERE evaluation_status IN ('COMPLETED','COMPLETED_WITH_WARNINGS')"
        )
        return [row[0] for row in cur.fetchall()]

    try:
        eids = _db_query(_query)
    except Exception as e:
        log("DASHBOARD", f"查询已完成评测失败(agent_fpr): {str(e)[:200]}")
        return grouped

    for eid in eids:
        mode = _eval_mode_of(eid) or "unknown"
        cm_path = os.path.join(REPORTS_DIR, f"{eid}_debug_case_matching.json")
        if not os.path.isfile(cm_path):
            continue
        try:
            with open(cm_path, "r", encoding="utf-8") as f:
                cm = json.loads(f.read())
        except Exception as e:
            log("DASHBOARD", f"读取 case_matching 失败 {eid}: {str(e)[:200]}")
            continue

        # 优先用 agent_outcomes（含 TP/FP/FN——新 dump 字段，直接统计各 agent）
        ao = cm.get("agent_outcomes", {}) or {}
        if ao:
            for agent, st in ao.items():
                tp = st.get("tp", 0) or 0
                fp = st.get("fp", 0) or 0
                fn = st.get("fn", 0) or 0
                bucket = grouped.setdefault(mode, {})
                a = bucket.setdefault(agent, {"tp": 0, "fp": 0, "fn": 0})
                a["tp"] += tp
                a["fp"] += fp
                a["fn"] += fn
            continue

        # 回退：旧 dump 无 agent_outcomes，从 matches（仅 FP/FN）+ parsing 反推
        # session_id → agent_type 映射（从 parsing 数据）
        sid_to_agent: dict[str, str] = {}
        ps_path = os.path.join(REPORTS_DIR, f"{eid}_debug_parsing.json")
        if os.path.isfile(ps_path):
            try:
                with open(ps_path, "r", encoding="utf-8") as f:
                    ps = json.loads(f.read())
                for pack in ps.get("data_packs", []):
                    at = pack.get("agent_type", "")
                    for s in (pack.get("sessions", []) or []):
                        sid = s.get("session_id", "")
                        if sid and at:
                            sid_to_agent[sid] = at
            except Exception as e:
                log("DASHBOARD", f"读取 parsing 失败 {eid}: {str(e)[:200]}")

        for m in (cm.get("matches", []) or []):
            outcome = m.get("outcome", "")
            if outcome not in ("TP", "FP"):
                continue
            key = "tp" if outcome == "TP" else "fp"
            mining = m.get("mining_sessions", []) or []
            if not mining:
                continue
            # 该 case 的挖掘 agent：取第一个 mining session 的 agent（
            # 多个 session 同 agent 时只算一次，避免重复计数）
            bumped = set()
            for sid in mining:
                agent = sid_to_agent.get(sid, "")
                if agent and agent not in bumped:
                    bumped.add(agent)
                    _bump(mode, agent, key)
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
        log("DASHBOARD", f"DTS 聚合查询失败: {str(e)[:200]}")
        return {
            "cause_agent_matrix": {c: {} for c in _ALL_CAUSE_CODES},
            "agent_detail": [],
            "post_stats": {},
            "dts": {"by_status": {}, "by_cause_code": {}, "by_agent_type": {},
                    "by_case_type": {}, "total": 0},
        }


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

    # 1. 跨评测 fpr/fnr（按 eval_mode 分组：runtime/dev/unknown）
    reports = _read_eval_reports()
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
        overall_by_mode[mode]["post_fnr"] = post_fnr

    # 3. agent 明细：按 eval_mode 分组（runtime/dev/unknown）
    agent_fpr_stats = _read_agent_fpr()  # {mode: {agent: {tp, fp, fn}}}
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
    return {
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
        "dts": agg.get("dts", {}),
        "updated_at": now_cst.strftime("%Y-%m-%d %H:%M:%S"),
    }
