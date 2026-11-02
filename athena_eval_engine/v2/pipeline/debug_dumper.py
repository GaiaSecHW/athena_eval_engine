"""Debug 数据 dump — 从 orchestrator 提取的辅助方法。

将各阶段中间数据 dump 到 {eid}_debug_{step}.json，供调试界面查看。
"""
from __future__ import annotations

import glob
import os

from ...infrastructure.log_util import log
from ..infra.json_utils import json_dump as _json_dump


def clear_debug_files(reports_dir: str, evaluation_id: str):
    """清除该评测的所有报告与 debug 数据文件（重跑时清理历史数据）。

    重跑必须全量重建报告——旧报告文件不删会导致：
    - REPORTING 阶段 ``_has_lifecycle_report`` 短路跳过组装，旧报告永不更新
    - 重跑中途失败时页面仍显示旧报告（状态 FAILED 但数据是旧的）

    删除范围：{eid}_debug_*.json、{eid}.json、{eid}_lifecycle.json、{eid}.html。

    注意：{eid}_dts_*.json（DTS 完整根因分析数据）不删除——
    generate_dts_issues 用 "w" 模式覆盖写入同名文件，重跑后 case 消失
    的旧文件保留可读（DB 行通过 UPSERT 保留，analysis_data_path 指向
    的文件需要存在）。
    """
    patterns = [
        f"{evaluation_id}_debug_*.json",
        f"{evaluation_id}.json",
        f"{evaluation_id}_lifecycle.json",
        f"{evaluation_id}.html",
    ]
    for pattern in patterns:
        for f in glob.glob(os.path.join(reports_dir, pattern)):
            try:
                os.remove(f)
            except Exception:
                pass


def dump_debug(reports_dir: str, evaluation_id: str, step: str, data: dict):
    """将步骤中间数据 dump 到 {eid}_debug_{step}.json。"""
    path = os.path.join(reports_dir, f"{evaluation_id}_debug_{step}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            _json_dump(data, f)
        log("DEBUG", f"dump {step}: {path}")
    except Exception as e:
        log("DEBUG", f"dump {step} 失败: {e}")


def calc_agent_outcomes(
    case_session_matches: list[dict],
    data_packs: list,
) -> dict:
    """从完整 case_session_matches 统计各 agent 的 TP/FP。

    case_session_matches 含全部 outcome（TP/FP/FN/TN），但 debug matches
    只 dump FP/FN。看板计算各 agent 误报率 FP/(TP+FP) 需要 TP，
    故在 dump 时单独统计 agent 级 outcome。

    Returns:
        {"turing": {"tp": N, "fp": N}, "argo": {...}, ...}
    """
    # session_id → agent_type 映射（从 data_packs 的 session_graph）
    sid_to_agent: dict[str, str] = {}
    for dp in data_packs:
        at = getattr(dp, "agent_type", "") or ""
        if not at:
            continue
        sg = getattr(dp, "session_graph", None) or {}
        sessions = sg.get("sessions", {}) if isinstance(sg, dict) else {}
        if isinstance(sessions, dict):
            for sid in sessions:
                if sid:
                    sid_to_agent[sid] = at

    agent_stats: dict[str, dict] = {}

    def _bump(agent: str, key: str):
        if not agent:
            return
        a = agent_stats.setdefault(agent, {"tp": 0, "fp": 0, "fn": 0})
        a[key] = a.get(key, 0) + 1

    for r in (case_session_matches or []):
        outcome = r.get("outcome", "")
        if outcome not in ("TP", "FP", "FN"):
            continue
        key = {"TP": "tp", "FP": "fp", "FN": "fn"}[outcome]
        # 该 case 的挖掘 agent：mining_sessions 涉及的 agent。
        # FN（漏报）时挖掘 session 可能为空（没上报），此时无法归因到
        # 具体 agent——跳过（漏报率分母只统计有挖掘 session 的 FN）。
        mining = r.get("mining_sessions", []) or []
        bumped = set()
        for sid in mining:
            agent = sid_to_agent.get(sid, "")
            if agent and agent not in bumped:
                bumped.add(agent)
                _bump(agent, key)
    return agent_stats


def summarize_data_pack(dp) -> dict:
    """将 DataPack 序列化为 debug 可展示的摘要（含 session 关系图）。"""
    sg = dp.session_graph or {}
    sessions = sg.get("sessions", {})
    edges = sg.get("edges", {})
    parent_map = sg.get("parent_map", {})

    # session 列表（含 agent、phase、parent + task 信息）
    session_list = []
    for sid, info in sessions.items():
        info_d = info if isinstance(info, dict) else {}
        session_list.append({
            "session_id": sid,
            "agent": info_d.get("agent", ""),
            "session_type": info_d.get("session_type", ""),
            "task_type": info_d.get("task_type", ""),
            "task_id": info_d.get("task_id", ""),
            "status": info_d.get("status", ""),
            "is_failed_task": info_d.get("is_failed_task", False),
            "parent_id": parent_map.get(sid, ""),
            "phase": (dp.session_phase_labels or {}).get(sid, ""),
        })

    # 边列表
    edge_list = []
    for src, targets in edges.items():
        if isinstance(targets, set):
            targets = sorted(targets)
        elif not isinstance(targets, list):
            targets = list(targets)
        for tgt in targets:
            edge_list.append({"from": src, "to": tgt})

    return {
        "task_run_id": dp.task_run_id,
        "task_id": dp.task_id,
        "agent_type": dp.agent_type,
        "condition": dp.condition,
        "session_count": len(sessions),
        "edge_count": len(edge_list),
        "event_count": len(dp.events or []),
        "sessions": session_list,
        "edges": edge_list,
        "fact_deps": sg.get("fact_deps", {}),
    }
