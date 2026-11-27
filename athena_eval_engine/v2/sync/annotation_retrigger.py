"""标注变化自动触发增量测评。

测评自动化的补充块：评测完成后人工标注又发生了变化（FINALIZE 固化的
baseline 计数 ≠ 当前 project_task_summary 计数）→ 随采集轮（06/12/17）
主动重跑该评测。重跑是**增量**的：per-case 根因缓存按标注指纹匹配——
标注未变的 case 复用既有结论，只有标注变化的 case 重新 LLM 分析。

与自动创建测评共用开关 ``auto_eval_enabled``。

去重：``system_config.annotation_retrigger_state`` 记录每个评测已触发
的标注签名——同一标注状态只触发一次（避免每轮采集重复重跑）；重跑
完成 FINALIZE 会写回新 baseline，与当前计数一致后自然不再判定为变化。
同一任务同模式已有运行中的评测时跳过（避免并发写冲突）。

调用：project_task_sync.schedule_loop 在每轮采集完成后调用 run_after_sync()。
"""
from __future__ import annotations

import json

from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log

_STATE_KEY = "annotation_retrigger_state"
_MAX_PER_ROUND = 10          # 单轮最多触发的评测数（防雪崩）
_TERMINAL = ("COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED")


def _load_state() -> dict:
    def _do(cur):
        cur.execute(
            "SELECT config_value FROM system_config WHERE config_key=%s",
            (_STATE_KEY,))
        row = cur.fetchone()
        return (row[0] or "") if row else ""
    try:
        raw = _db_query(_do) or ""
    except Exception:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _save_state(state: dict) -> None:
    def _do(cur):
        cur.execute(
            "INSERT INTO system_config (config_key, config_value) "
            "VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            (_STATE_KEY, json.dumps(state, ensure_ascii=False)))
        cur.execute("SELECT 1")
    _db_query(_do)


def _changed_evaluations() -> list[dict]:
    """已完成的评测中，标注计数相对 FINALIZE 基线发生变化的全量列表。

    口径与评测列表「标注已变化」一致：baseline 四项计数（vuln_total/
    confirmed_vulnerable/confirmed_fp/confirmed_not_vulnerable）与当前
    project_task_summary 同任务计数**不一致**才算变化；baseline 任一项
    为 NULL（老数据，未知）或任务行缺失（已删除/未同步）不参与判定。
    """
    def _do(cur):
        cur.execute(
            "SELECT e.evaluation_id, es.task_id, "
            "       es.baseline_vuln_total, es.baseline_confirmed_vulnerable, "
            "       es.baseline_confirmed_fp, "
            "       es.baseline_confirmed_not_vulnerable "
            "FROM evaluation e "
            "JOIN evaluation_summary es "
            "  ON es.evaluation_id = e.evaluation_id "
            "WHERE e.evaluation_status IN "
            "      ('COMPLETED','COMPLETED_WITH_WARNINGS') "
            "  AND es.task_id <> '' "
            "  AND es.baseline_vuln_total IS NOT NULL "
            "  AND es.baseline_confirmed_vulnerable IS NOT NULL "
            "  AND es.baseline_confirmed_fp IS NOT NULL "
            "  AND es.baseline_confirmed_not_vulnerable IS NOT NULL")
        rows = cur.fetchall()
        if not rows:
            return []
        task_ids = sorted({r[1] for r in rows if r[1]})
        placeholders = ",".join(["%s"] * len(task_ids))
        cur.execute(
            "SELECT task_id, vuln_total, confirmed_vulnerable, "
            "       confirmed_fp, confirmed_not_vulnerable "
            f"FROM project_task_summary WHERE task_id IN ({placeholders})",
            tuple(task_ids))
        current = {r[0]: (int(r[1] or 0), int(r[2] or 0),
                          int(r[3] or 0), int(r[4] or 0))
                   for r in cur.fetchall()}
        # 只返回 baseline 与当前计数不一致的评测（真变化）。
        # 此前这里漏了比较——所有有基线的评测都被当作"已变化"触发重跑，
        # 无谓重跑占满每轮上限，真正变化的评测反而触发不到。
        out = []
        for r in rows:
            baseline = (int(r[2]), int(r[3]), int(r[4]), int(r[5]))
            cur_counts = current.get(r[1])
            if cur_counts is not None and cur_counts != baseline:
                out.append({"evaluation_id": r[0], "task_id": r[1],
                            "baseline": baseline, "current": cur_counts})
        return out

    return _db_query(_do) or []


def _task_running(task_id: str, exclude_eid: str) -> bool:
    """同一任务是否已有运行中的评测（避免并发重跑写冲突）。"""
    terminal = ",".join(["%s"] * len(_TERMINAL))

    def _do(cur):
        cur.execute(
            "SELECT COUNT(*) FROM evaluation e "
            "JOIN evaluation_snapshot s "
            "  ON s.evaluation_id = e.evaluation_id "
            "WHERE e.evaluation_id <> %s "
            "  AND e.evaluation_status NOT IN (" + terminal + ") "
            "  AND JSON_UNQUOTE(JSON_EXTRACT(s.config_json, "
            "      '$.manifest.kg_task_id')) = %s",
            (exclude_eid, *_TERMINAL, task_id))
        return int(cur.fetchone()[0] or 0) > 0

    try:
        return _db_query(_do)
    except Exception as e:
        log("RETRIGGER", f"任务运行态检查失败 task={task_id}: {e}")
        return True  # 查不清就不触发，保守处理


def _trigger_retry(evaluation_id: str) -> bool:
    """触发该评测的增量重跑（复用 retry 路由：全部门禁 + 报告归档 +
    重跑提交；RCA per-case 缓存保证分析增量）。"""
    try:
        from ...api.routes.evaluations import retry_evaluation
        retry_evaluation(evaluation_id, force=True)
        return True
    except Exception as e:
        log("RETRIGGER", f"{evaluation_id} 触发增量重跑失败: {e}")
        return False


def run_after_sync() -> dict:
    """采集线程每轮采集完成后调用：标注变化的已完成评测主动增量重跑。

    开关与自动创建共用 auto_eval_enabled；按标注签名去重（同一变化
    只触发一次）；单轮最多触发 _MAX_PER_ROUND 个。
    """
    from .auto_eval import is_enabled
    if not is_enabled():
        return {"skipped": "disabled"}
    changed = _changed_evaluations()
    state = _load_state()
    if not changed:
        # 无变化也剪枝：重跑完成/标注回退的评测要从 state 清除——
        # 否则陈旧签名残留，"计数回退到旧状态"时会误判为已触发而漏跑
        if state:
            try:
                _save_state({})
            except Exception as e:
                log("RETRIGGER", f"状态固化失败（不阻断）: {e}")
        return {"changed": 0, "triggered": 0}

    triggered = 0
    considered = 0
    for item in changed:
        eid = item["evaluation_id"]
        # 差异签名 = 当前计数（baseline 固定，差异是当前计数的函数）：
        # 同一当前标注状态只触发一次；重跑完成 FINALIZE 写回新 baseline
        # 后 baseline == 当前计数 → 不再进 changed 列表；当前计数再变
        # → 新签名 → 再次触发。（此前误用 baseline 做签名——baseline
        # 固定不变，去重会把真实的新变化永久挡掉。）
        sig = ",".join(str(x) for x in (
            item.get("current") or item["baseline"]))
        if state.get(eid) == sig:
            continue
        if considered >= _MAX_PER_ROUND:
            log("RETRIGGER", f"单轮触发上限 {_MAX_PER_ROUND}，剩余顺延")
            break
        considered += 1
        if _task_running(item["task_id"], eid):
            log("RETRIGGER", f"{eid}: 同任务已有运行中评测，本轮跳过")
            continue
        if _trigger_retry(eid):
            state[eid] = sig
            triggered += 1
            log("RETRIGGER",
                f"{eid}: 标注已变化（当前计数 {sig}），已触发增量测评")
        else:
            state[eid] = sig  # 触发失败也记签名，避免每轮反复重试
    # 清理已不再变化的评测记录（重跑完成或标注回退）
    changed_ids = {i["evaluation_id"] for i in changed}
    state = {k: v for k, v in state.items() if k in changed_ids}
    try:
        _save_state(state)
    except Exception as e:
        log("RETRIGGER", f"状态固化失败（不阻断）: {e}")
    log("RETRIGGER",
        f"运行完成: 变化 {len(changed)} 个, 触发 {triggered} 个")
    return {"changed": len(changed), "triggered": triggered}
