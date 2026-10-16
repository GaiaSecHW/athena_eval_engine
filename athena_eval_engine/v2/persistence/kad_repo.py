"""knowledge_access_detail 表持久化。

写入约束（参考 docs/knowledge-effect-eval-requirements.md §3.1 / docs/ddl-final.md §1.6）：
- 幂等写入：INSERT ... ON DUPLICATE KEY UPDATE，冲突键 UNIQUE(task_run_id, event_idx)
- 大字段文件存储：query_content/returned_content/reasoning_ref/evidence_json 超过 64KB
  时写入 {reports_dir}/{eid}_lifecycle_data/{access_id}_{field}.json 文件，DB 列存路径到 evidence_file
- NaN/Inf 清洗：evidence_json 中 LLM 返回的 confidence 等浮点字段可能含 NaN/Inf，写入前清洗
- 批量写入：一个 task_run 的全部记录批量 INSERT，不逐条写入
"""
from __future__ import annotations

import json
import math
import os
import time

import pymysql

from ..infra.database import connect
from ...infrastructure.log_util import log, log_to_file


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

_LARGE_FIELD_THRESHOLD = 64 * 1024  # 64KB

_LARGE_TEXT_FIELDS = ("query_content", "returned_content", "reasoning_ref")

_INSERT_SQL = """\
INSERT INTO knowledge_access_detail (
    access_id, evaluation_id, task_run_id, task_id, event_idx,
    source_system, l0_origin, business_phase,
    l1_need_knowledge, l2_initiated, l3_query_accurate, l4_knowledge_exists,
    l5_retrieved, l6_used, l7_influenced, l7_method,
    effect_label, cause_code,
    query_content, returned_content, reasoning_ref, judgment_conclusion,
    evidence_json, evidence_file
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON DUPLICATE KEY UPDATE
    source_system=VALUES(source_system), l0_origin=VALUES(l0_origin),
    business_phase=VALUES(business_phase),
    l1_need_knowledge=VALUES(l1_need_knowledge),
    l2_initiated=VALUES(l2_initiated), l3_query_accurate=VALUES(l3_query_accurate),
    l4_knowledge_exists=VALUES(l4_knowledge_exists), l5_retrieved=VALUES(l5_retrieved),
    l6_used=VALUES(l6_used), l7_influenced=VALUES(l7_influenced), l7_method=VALUES(l7_method),
    effect_label=VALUES(effect_label), cause_code=VALUES(cause_code),
    query_content=VALUES(query_content), returned_content=VALUES(returned_content),
    reasoning_ref=VALUES(reasoning_ref), judgment_conclusion=VALUES(judgment_conclusion),
    evidence_json=VALUES(evidence_json), evidence_file=VALUES(evidence_file)
"""

# 24 个占位符对应 VALUES 中的 24 个 %s
_FIELD_ORDER = (
    "access_id", "evaluation_id", "task_run_id", "task_id", "event_idx",
    "source_system", "l0_origin", "business_phase",
    "l1_need_knowledge", "l2_initiated", "l3_query_accurate", "l4_knowledge_exists",
    "l5_retrieved", "l6_used", "l7_influenced", "l7_method",
    "effect_label", "cause_code",
    "query_content", "returned_content", "reasoning_ref", "judgment_conclusion",
    "evidence_json", "evidence_file",
)


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _clean_nan_inf(obj):
    """递归清洗 dict/list 中的 NaN/Inf 值（转为 None）。

    MySQL 不接受 NaN/Inf，JSON 序列化也不支持标准 NaN。
    遍历 dict 的 value 和 list 的元素，将 float 类的 NaN/Inf 替换为 None。
    """
    if isinstance(obj, dict):
        return {k: _clean_nan_inf(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean_nan_inf(x) for x in obj]
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        return None
    return obj


def _should_store_as_file(value: str, threshold: int = _LARGE_FIELD_THRESHOLD) -> bool:
    """判断字段是否需要存文件。

    超过 threshold 字节的字符串值应写入文件，DB 列存路径。
    """
    if value is None:
        return False
    return len(value.encode("utf-8")) > threshold


def _write_large_field(reports_dir: str, evaluation_id: str, access_id: str,
                       field_name: str, content: str) -> str:
    """写入大字段到文件，返回文件路径。

    文件路径格式：{reports_dir}/{eid}_lifecycle_data/{access_id}_{field_name}.json
    """
    field_dir = os.path.join(reports_dir, f"{evaluation_id}_lifecycle_data")
    os.makedirs(field_dir, exist_ok=True)
    file_path = os.path.join(field_dir, f"{access_id}_{field_name}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    return file_path


def _prepare_record(record: dict, evaluation_id: str, reports_dir: str) -> dict:
    """准备单条记录：大字段处理 + NaN 清洗。

    流程：
    1. 清洗 evidence_json 中的 NaN/Inf
    2. 对 query_content/returned_content/reasoning_ref/evidence_json 做大字段判断
    3. 超过 64KB 的字段写入文件，DB 列存路径（收集到 evidence_file）
    4. 返回处理后的 dict，key 与 _FIELD_ORDER 对齐
    """
    rec = dict(record)
    rec["evaluation_id"] = evaluation_id

    # 1. NaN/Inf 清洗 evidence_json
    evidence_json = rec.get("evidence_json")
    if isinstance(evidence_json, (dict, list)):
        evidence_json = _clean_nan_inf(evidence_json)

    # 序列化 evidence_json 为字符串
    if isinstance(evidence_json, (dict, list)):
        evidence_json_str = json.dumps(evidence_json, ensure_ascii=False, default=str)
    elif isinstance(evidence_json, str):
        # 已经是字符串，仍需清洗可能内嵌的 NaN/Inf
        try:
            parsed = json.loads(evidence_json)
            cleaned = _clean_nan_inf(parsed)
            evidence_json_str = json.dumps(cleaned, ensure_ascii=False, default=str)
        except (json.JSONDecodeError, TypeError):
            evidence_json_str = evidence_json
    else:
        evidence_json_str = None

    # 2. 收集大字段文件路径
    file_paths: list[str] = []

    # 3. 处理文本大字段
    for field_name in _LARGE_TEXT_FIELDS:
        value = rec.get(field_name)
        if _should_store_as_file(value):
            path = _write_large_field(reports_dir, evaluation_id,
                                      rec["access_id"], field_name, value)
            file_paths.append(path)
            rec[field_name] = path

    # 4. 处理 evidence_json 大字段
    if _should_store_as_file(evidence_json_str):
        path = _write_large_field(reports_dir, evaluation_id,
                                  rec["access_id"], "evidence_json", evidence_json_str)
        file_paths.append(path)
        rec["evidence_json"] = None
    else:
        rec["evidence_json"] = evidence_json_str

    # evidence_file 列存所有大字段文件路径（JSON 数组）
    rec["evidence_file"] = json.dumps(file_paths, ensure_ascii=False) if file_paths else None

    # 确保所有字段存在，缺失的填 None
    return {k: rec.get(k) for k in _FIELD_ORDER}


# ---------------------------------------------------------------------------
# DB 连接重试
# ---------------------------------------------------------------------------

def _db_query(fn, _retries: int = 8):
    """短连接 + 重试包装器。

    2006/2013（连接丢失）时指数退避重试，其他错误直接抛出。
    与 evaluation_service._db_query 同模式。
    """
    last_err = None
    for attempt in range(_retries):
        conn = None
        try:
            conn = connect(autocommit=True)
            return fn(conn.cursor())
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
            last_err = e
            # 强制关闭底层连接，防止池复用坏连接
            if conn:
                try:
                    inner = getattr(conn, "_con", None)
                    if inner is not None and not getattr(inner, "_closed", True):
                        inner.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            if e.args and e.args[0] in (2013, 2006) and attempt < _retries - 1:
                _wait = min(2 * (attempt + 1), 30)
                log("KAD_REPO", f"DB retry {attempt+1}/{_retries}: {e.args[0]}, retry in {_wait}s...")
                log_to_file("KAD_REPO", f"DB retry {attempt+1}/{_retries}: {e.args[0]} {e}, retry in {_wait}s...")
                time.sleep(_wait)
                continue
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------

def upsert_knowledge_access_details(records: list[dict], evaluation_id: str,
                                    reports_dir: str) -> int:
    """批量写入 knowledge_access_detail 记录。

    参数:
        records: knowledge_access_detail 记录列表（dict），每条含 access_id、task_run_id、
                 event_idx、source_system 等。
        evaluation_id: 评测 ID。
        reports_dir: 报告目录，大字段文件存储根目录。

    返回:
        写入的记录条数。

    约束:
        - 幂等写入：INSERT ... ON DUPLICATE KEY UPDATE，冲突键 UNIQUE(task_run_id, event_idx)
        - 大字段文件存储：超过 64KB 的字段写入文件，DB 列存路径
        - NaN/Inf 清洗：evidence_json 中的 NaN/Inf 转为 None
        - 批量写入：全部记录一次性 executemany
    """
    if not records:
        return 0

    # 准备所有记录
    prepared = [_prepare_record(r, evaluation_id, reports_dir) for r in records]

    # 批量写入
    def _do_insert(cur):
        args = [tuple(prepared[i][k] for k in _FIELD_ORDER) for i in range(len(prepared))]
        cur.executemany(_INSERT_SQL, args)
        return len(prepared)

    count = _db_query(_do_insert)
    log("KAD_REPO", f"upsert_knowledge_access_details: wrote {count} records for eval={evaluation_id}")
    return count
