"""自动创建测评——确认率 100%、误报率 ≥30%、近 1.5 个月结束的任务自动发起运行态测评。

候选条件（project_task_summary 扫描，全部满足）：
- 人工确认率 = 100%（vuln_total > 0 且全部人工确认）；
- 误报率 ≥ 30%（confirmed_fp/(confirmed_vulnerable+confirmed_fp)，
  与平台任务详情手动启动门槛 fpr>=0.3 一致——自动创建的任务手动也能启动）；
- 任务结束时间在 1.5 个月（45 天）内；
- 任务在采集白名单内（project_task_summary 已按 SYNC_AGENT_ALLOWLIST 过滤）。

创建路径复用手动启动的 create_evaluation（v1 创建路由）：走全部
门禁——槽位唯一（每任务每模式一条）、源码存在、未过期；100% 确认率
豁免 2 天定稿窗口。幂等：已有同模式评测的任务被槽位门禁拒绝，
不会重复创建。

开关：system_config.auto_eval_enabled（'1' 开 / 空 或 '0' 关），默认关闭。
调度：随采集线程（project_task_sync）每次采集完成后触发一次；
run_once() 供手动执行。每次运行结果固化到 system_config.auto_eval_last_run。
"""
from __future__ import annotations

import json
import random
import threading
import time
from datetime import datetime, timedelta, timezone

from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

# 默认参数（system_config 可覆盖，UI 可配）
_DEFAULT_MIN_CONFIRM_RATE = 1.0    # 确认率阈值（>=，默认 100%）
_DEFAULT_MAX_FINISHED_DAYS = 45    # 任务结束窗口（天内，默认 1.5 个月）
_DEFAULT_MIN_FPR = 0.3            # 误报率门槛（>=，默认 30%）

# 配置键
_KEY_ENABLED = "auto_eval_enabled"
_KEY_MIN_CONFIRM_RATE = "auto_eval_min_confirm_rate"
_KEY_MAX_FINISHED_DAYS = "auto_eval_max_finished_days"
_KEY_MIN_FPR = "auto_eval_min_fpr"

_running = False
_run_guard = threading.Lock()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_config() -> dict:
    """读取自动创建测评配置：开关 + 确认率阈值 + 结束窗口天数。"""
    def _do(cur):
        cur.execute(
            f"SELECT config_key, config_value FROM system_config "
            f"WHERE config_key IN ('{_KEY_ENABLED}', "
            f"'{_KEY_MIN_CONFIRM_RATE}', '{_KEY_MAX_FINISHED_DAYS}', "
            f"'{_KEY_MIN_FPR}')")
        return {str(k): str(v or "").strip() for k, v in cur.fetchall()}
    try:
        cfg = _db_query(_do) or {}
    except Exception as e:
        log("AUTO_EVAL", f"读取配置失败: {e}")
        cfg = {}

    def _float(key: str, default: float, lo: float, hi: float) -> float:
        try:
            v = float(cfg.get(key) or default)
        except (TypeError, ValueError):
            v = default
        return min(max(v, lo), hi)

    rate = _float(_KEY_MIN_CONFIRM_RATE, _DEFAULT_MIN_CONFIRM_RATE, 0.0, 1.0)
    try:
        days = int(float(cfg.get(_KEY_MAX_FINISHED_DAYS)
                         or _DEFAULT_MAX_FINISHED_DAYS))
    except (TypeError, ValueError):
        days = _DEFAULT_MAX_FINISHED_DAYS
    days = min(max(days, 1), 365)
    fpr = _float(_KEY_MIN_FPR, _DEFAULT_MIN_FPR, 0.0, 1.0)
    return {
        "enabled": cfg.get(_KEY_ENABLED, "") == "1",
        "min_confirm_rate": rate,
        "max_finished_days": days,
        "min_fpr": fpr,
    }


def set_config(enabled: bool | None = None,
               min_confirm_rate: float | None = None,
               max_finished_days: int | None = None,
               min_fpr: float | None = None) -> dict:
    """写自动创建测评配置（只更新传入项），返回写后的完整配置。"""
    updates: list[tuple[str, str]] = []
    if enabled is not None:
        updates.append((_KEY_ENABLED, "1" if enabled else "0"))
    if min_confirm_rate is not None:
        rate = min(max(float(min_confirm_rate), 0.0), 1.0)
        updates.append((_KEY_MIN_CONFIRM_RATE, f"{rate}"))
    if max_finished_days is not None:
        days = min(max(int(max_finished_days), 1), 365)
        updates.append((_KEY_MAX_FINISHED_DAYS, str(days)))
    if min_fpr is not None:
        fpr = min(max(float(min_fpr), 0.0), 1.0)
        updates.append((_KEY_MIN_FPR, f"{fpr}"))

    def _do(cur):
        for key, value in updates:
            cur.execute(
                "INSERT INTO system_config (config_key, config_value) "
                "VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
                (key, value))
    _db_query(_do)
    log("AUTO_EVAL", f"更新配置: {updates}")
    return get_config()


def is_enabled() -> bool:
    return get_config()["enabled"]


def get_last_run() -> dict:
    """读取上次运行结果（system_config.auto_eval_last_run 固化的 JSON）。"""
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config "
            "WHERE config_key='auto_eval_last_run'")
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    try:
        raw = _db_query(_do)
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _record_last_run(summary: dict) -> None:
    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES ('auto_eval_last_run', %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (json.dumps(summary, ensure_ascii=False),))
    try:
        _db_query(_do)
    except Exception as e:
        log("AUTO_EVAL", f"固化运行结果失败: {e}")


def _gen_evaluation_id() -> str:
    """与前端 genId 同格式：EV-YYYYMMDDHHMMSS-XXXX（UTC+8）。"""
    d = datetime.now(timezone(timedelta(hours=8)))
    p = lambda n: str(n).zfill(2)
    return (f"EV-{d.year}{p(d.month)}{p(d.day)}"
            f"{p(d.hour)}{p(d.minute)}{p(d.second)}"
            f"-{random.randint(1000, 9999)}")


def _load_candidates(min_confirm_rate: float, max_finished_days: int,
                      min_fpr: float) -> list[dict]:
    """扫描候选：确认率 ≥ 阈值、误报率 ≥ 阈值、结束 N 天内、白名单（表已过滤）。"""
    cutoff = (_now_utc() - timedelta(days=max_finished_days)) \
        .strftime("%Y-%m-%d 00:00:00")

    def _do(cur):
        cur.execute(
            "SELECT project_id, task_id, task_name "
            "FROM project_task_summary "
            "WHERE task_id != '' AND vuln_total > 0 "
            "AND confirm_rate >= %s "
            "AND (confirmed_vulnerable + confirmed_fp) > 0 "
            "AND confirmed_fp / (confirmed_vulnerable + confirmed_fp) >= %s "
            "AND task_finished_at >= %s "
            "ORDER BY project_id, task_id",
            (min_confirm_rate, min_fpr, cutoff))
        cols = ["project_id", "task_id", "task_name"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    return _db_query(_do)


def run_once(force: bool = False) -> dict:
    """执行一次自动创建：扫描候选 → 逐个走创建门禁 → 固化结果。

    幂等：候选任务若已有同模式评测，创建门禁拒绝（计入 skipped）。
    Returns:
        {"at": ..., "enabled": bool, "candidates": n,
         "created": n, "created_ids": [...], "skipped": n,
         "skip_reasons": {task_id: 原因, ...}}
    """
    global _running
    with _run_guard:
        if _running:
            return {"status": "running"}
        _running = True
    try:
        summary = _run_once_inner(force=force)
        _record_last_run(summary)
        return summary
    finally:
        with _run_guard:
            _running = False


def _run_once_inner(force: bool) -> dict:
    from fastapi import HTTPException

    started = _now_utc().strftime("%Y-%m-%d %H:%M:%S")
    if not force and not is_enabled():
        summary = {"at": started, "enabled": False, "skipped_run": "disabled"}
        return summary

    # 延迟 import：复用手动启动的创建路由（走全部门禁 + 后台提交）
    from ...api.routes.evaluations import create_evaluation

    config = get_config()
    candidates = _load_candidates(
        min_confirm_rate=config["min_confirm_rate"],
        max_finished_days=config["max_finished_days"],
        min_fpr=config["min_fpr"])
    created: list[str] = []
    skip_reasons: dict[str, str] = {}

    class _AutoReq:
        """与前端 startEval 同构的创建请求（运行态）。"""
        evaluation_name: str
        kg_project_id: str
        kg_task_id: str
        benchmark_source = "vuln_center"
        benchmark_set_id: str
        vc_source_task_id: str
        eval_mode = "runtime"

    for cand in candidates:
        req = _AutoReq()
        req.evaluation_id = _gen_evaluation_id()
        req.evaluation_name = cand["task_name"] or cand["task_id"]
        req.kg_project_id = cand["project_id"]
        req.kg_task_id = cand["task_id"]
        req.benchmark_set_id = cand["project_id"]
        req.vc_source_task_id = cand["task_id"]
        try:
            create_evaluation(req)
            created.append(req.evaluation_id)
            log("AUTO_EVAL",
                f"自动创建成功: {cand['task_id'][:40]} -> {req.evaluation_id}")
        except HTTPException as e:
            detail = str(e.detail)[:120]
            skip_reasons[cand["task_id"]] = detail
            log("AUTO_EVAL",
                f"自动创建跳过: {cand['task_id'][:40]}: {detail}")
        except Exception as e:
            skip_reasons[cand["task_id"]] = str(e)[:120]
            log("AUTO_EVAL",
                f"自动创建失败: {cand['task_id'][:40]}: {e}")

    summary = {
        "at": started,
        "enabled": True,
        "config": {
            "min_confirm_rate": config["min_confirm_rate"],
            "max_finished_days": config["max_finished_days"],
            "min_fpr": config["min_fpr"],
        },
        "candidates": len(candidates),
        "created": len(created),
        # 只留前 20 个，防固化值过大
        "created_ids": created[:20],
        "skipped": len(skip_reasons),
        "skip_reasons": dict(list(skip_reasons.items())[:20]),
    }
    # 手动触发（force）同时执行「标注变化增量重跑」——system 页的
    # 「立即执行一轮」按钮承诺同一开关控制该能力。定时采集路径由
    # project_task_sync 单独调用 retrigger，此处仅 force=True 时执行，
    # 避免同一轮重复触发。
    if force:
        try:
            from .annotation_retrigger import run_after_sync as run_retrigger
            summary["retrigger"] = run_retrigger(force=True)
        except Exception as e:
            summary["retrigger"] = {"error": str(e)[:200]}
            log("AUTO_EVAL", f"标注变化增量重跑异常: {e}")

    log("AUTO_EVAL", f"运行完成: 候选 {summary['candidates']}, "
                     f"创建 {summary['created']}, 跳过 {summary['skipped']}")
    return summary


def run_after_sync() -> None:
    """采集线程每轮采集完成后调用：开关开启则自动创建一轮。"""
    if not is_enabled():
        return
    try:
        run_once()
    except Exception as e:
        log("AUTO_EVAL", f"自动创建异常: {e}")


def trigger_async() -> dict:
    """手动触发一次（异步线程），返回启动状态。

    并发防护只由 run_once 入口的 _running 门禁承担——此处不再预置
    _running（曾导致双重加锁：预置 True 后 worker 调 run_once 被
    入口门禁直接拒绝，手动触发变成空操作，无日志无记录）。
    """
    if _running:
        return {"status": "running"}

    def _worker():
        try:
            run_once(force=True)
        except Exception as e:
            log("AUTO_EVAL", f"手动自动创建异常: {e}")

    threading.Thread(target=_worker, name="auto-eval-manual",
                     daemon=True).start()
    return {"status": "started"}
