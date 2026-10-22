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


def _read_eval_reports() -> list[dict]:
    """读取所有已完成评测的 {eid}.json 报告 recall_precision 数据。

    从 evaluation 表查 COMPLETED / COMPLETED_WITH_WARNINGS 评测，
    逐个读报告文件（不存在跳过），返回 [{eid, tp, fp, fn, tn, fpr_rate}]。
    """
    results: list[dict] = []

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
        return results

    for eid in eids:
        path = os.path.join(REPORTS_DIR, f"{eid}.json")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.loads(f.read())
            rp = data.get("recall_precision") or {}
            results.append({
                "evaluation_id": eid,
                "tp": rp.get("tp_count") or 0,
                "fp": rp.get("fp_count") or 0,
                "fn": rp.get("fn_count") or 0,
                "tn": rp.get("tn_count") or 0,
            })
        except Exception as e:
            log("DASHBOARD", f"读取报告失败 {eid}: {str(e)[:200]}")
            continue
    return results


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

    # 1. 跨评测 fpr/fnr
    reports = _read_eval_reports()
    tp = sum(r["tp"] for r in reports)
    fp = sum(r["fp"] for r in reports)
    fn = sum(r["fn"] for r in reports)
    tn = sum(r["tn"] for r in reports)

    fpr_denom = tp + fp
    total_fpr = (fp / fpr_denom) if fpr_denom > 0 else None
    fnr_denom = tp + fn
    total_fnr = (fn / fnr_denom) if fnr_denom > 0 else None

    # 2. DTS 聚合（回归后误报率/漏报率 + 交叉矩阵 + agent 明细）
    agg = _query_dts_aggregate()
    post = agg.get("post_stats") or {}

    fp_post = post.get("FP", {"passed": 0, "failed": 0})
    fn_post = post.get("FN", {"passed": 0, "failed": 0})
    fp_denom = fp_post.get("passed", 0) + fp_post.get("failed", 0)
    post_fpr = (fp_post.get("failed", 0) / fp_denom) if fp_denom > 0 else None
    fn_denom = fn_post.get("passed", 0) + fn_post.get("failed", 0)
    post_fnr = (fn_post.get("failed", 0) / fn_denom) if fn_denom > 0 else None

    # 3. agent 明细：补误报率/回归后误报率（只读已有数据，无数据为 None）
    agent_detail = []
    for a in agg.get("agent_detail", []):
        fpr_denom = a.get("fp", 0) + (a.get("issues", 0) - a.get("fp", 0) - a.get("fn", 0))
        # 误报率按 agent 上报数：FP / (TP+FP)，但 agent 级无 TP 直接数据。
        # 用问题单口径：FP / 全部问题单（含 FP+FN），近似 agent 误报占比。
        total_issues = a.get("issues", 0)
        a_fpr = (a.get("fp", 0) / total_issues) if total_issues > 0 else None
        reg_denom = a.get("reg_passed", 0) + a.get("reg_failed", 0)
        a_post_fpr = (a.get("reg_failed", 0) / reg_denom) if reg_denom > 0 else None
        agent_detail.append({
            "agent": a.get("agent", ""),
            "issues": a.get("issues", 0),
            "fp": a.get("fp", 0),
            "fn": a.get("fn", 0),
            "fpr": round(a_fpr, 4) if a_fpr is not None else None,
            "reg_passed": a.get("reg_passed", 0),
            "reg_failed": a.get("reg_failed", 0),
            "post_fpr": round(a_post_fpr, 4) if a_post_fpr is not None else None,
        })

    now_cst = datetime.now(timezone(timedelta(hours=8)))
    return {
        "overall": {
            "total_fpr": round(total_fpr, 4) if total_fpr is not None else None,
            "total_fnr": round(total_fnr, 4) if total_fnr is not None else None,
            "post_fpr": round(post_fpr, 4) if post_fpr is not None else None,
            "post_fnr": round(post_fnr, 4) if post_fnr is not None else None,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "report_count": len(reports),
        },
        "cause_agent_matrix": agg.get("cause_agent_matrix", {}),
        "agent_detail": agent_detail,
        "dts": agg.get("dts", {}),
        "updated_at": now_cst.strftime("%Y-%m-%d %H:%M:%S"),
    }
