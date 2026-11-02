"""状态管理与取消信号 — 从 orchestrator 提取的辅助函数。

包含：
- TaskCancelledError 异常
- 取消信号检查（_is_cancelled / _check_cancel / _make_cancel_cb）
- 状态更新（_set_status / _set_failed / _set_status_safe / _fix_check_constraint）
"""
from __future__ import annotations

import os

from ..infra.database import connect
from ..infra.db_utils import db_query as _db_query
from ..infra.log_util import log


# ── 取消异常 ──────────────────────────────────────────


class TaskCancelledError(Exception):
    """评测任务被取消（cancel_requested flag 被 set）。"""
    pass


# ── 取消信号 ──────────────────────────────────────────


def _is_cancelled(evaluation_id: str) -> bool:
    """检查 DB 中的 cancel_requested flag。"""
    conn = None
    try:
        conn = connect(autocommit=True)
        cur = conn.cursor()
        cur.execute(
            "SELECT cancel_requested FROM evaluation WHERE evaluation_id=%s",
            (evaluation_id,),
        )
        row = cur.fetchone()
        return row is not None and row[0] == 1
    except Exception as e:
        log("CANCEL", f"检查取消信号失败（保守取消）: {e}")
        return True
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _check_cancel(evaluation_id: str, phase: str = ""):
    """在阶段边界检查取消信号。"""
    if _is_cancelled(evaluation_id):
        raise TaskCancelledError(
            f"{evaluation_id} 在 {phase} 阶段被取消"
        )


def _make_cancel_cb(evaluation_id: str, phase: str = ""):
    """创建 cancel_cb 闭包，穿透到 LLM 密集内循环。"""
    def _cb():
        _check_cancel(evaluation_id, phase)
    return _cb


# ── 状态更新 ──────────────────────────────────────────


def _set_status(evaluation_id: str, status: str):
    """短连接更新 evaluation 状态。"""

    def _do(cur):
        if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "CANCELLED"):
            cur.execute(
                "UPDATE evaluation SET evaluation_status=%s, "
                "error_message=NULL, finished_at=NOW(3) "
                "WHERE evaluation_id=%s",
                (status, evaluation_id),
            )
        elif status == "FAILED":
            cur.execute(
                "UPDATE evaluation SET evaluation_status=%s, "
                "finished_at=NOW(3) WHERE evaluation_id=%s",
                (status, evaluation_id),
            )
        else:
            cur.execute(
                "UPDATE evaluation SET evaluation_status=%s, "
                "error_message=NULL WHERE evaluation_id=%s",
                (status, evaluation_id),
            )

    try:
        _db_query(_do)
    except Exception as e:
        log("STATUS", f"设状态 {status} 失败: {e}")
        raise


def _set_failed(evaluation_id: str, error_msg: str):
    """标记评测失败，写入 error_message。"""

    def _do(cur):
        cur.execute(
            "UPDATE evaluation SET evaluation_status='FAILED', "
            "error_message=%s, finished_at=NOW(3) WHERE evaluation_id=%s",
            (error_msg[:2000], evaluation_id),
        )

    try:
        _db_query(_do)
    except Exception as e:
        log("STATUS", f"设 FAILED 状态失败: {e}")


def _set_status_safe(evaluation_id: str, status: str):
    """安全设状态（CHECK 约束自动修复）。"""
    try:
        _set_status(evaluation_id, status)
    except Exception as e:
        # CHECK 约束可能不含新状态 → 自动修复约束后重试
        if "Check constraint" in str(e) or "3819" in str(e):
            log("DB", f"CHECK 约束阻止设状态 {status}，自动修复...")
            _fix_check_constraint(evaluation_id, status)
        else:
            raise


def _fix_check_constraint(evaluation_id: str, status: str):
    """修复 evaluation 表的 CHECK 约束以包含 v2 新状态。"""
    def _fix_and_set(cur):
        for stmt in (
            "ALTER TABLE evaluation DROP CHECK evaluation_chk_1",
            "ALTER TABLE evaluation DROP CONSTRAINT evaluation_chk_1",
            "ALTER TABLE evaluation DROP CHECK evaluation_status_chk",
            "ALTER TABLE evaluation DROP CONSTRAINT evaluation_status_chk",
        ):
            try:
                cur.execute(stmt)
            except Exception:
                pass
        try:
            cur.execute(
                "ALTER TABLE evaluation ADD CONSTRAINT evaluation_status_chk "
                "CHECK (evaluation_status IN "
                "('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING',"
                "'PARSING','CASE_MATCHING','ROOT_CAUSE_ANALYSIS',"
                "'RESOLVING',"
                "'REPORTING','FINALIZING',"
                "'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED',"
                "'CANCEL_REQUESTED','CANCELLING','CANCELLED'))"
            )
        except Exception:
            pass
        cur.execute(
            "UPDATE evaluation SET evaluation_status=%s "
            "WHERE evaluation_id=%s",
            (status, evaluation_id),
        )

    try:
        _db_query(_fix_and_set)
        log("DB", f"CHECK 约束已修复，重试设状态 {status} 成功")
    except Exception as e2:
        log("DB", f"CHECK 约束修复后仍失败: {e2}")
        raise
