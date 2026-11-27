"""平台部门树查询（org_department 表）。

数据由 system 页「拉取部门」手动同步（见 v2/sync/org_sync.py）。
path 为根→叶名称用 " / " 连接——子部门判定用 path 前缀匹配。
"""
from __future__ import annotations

from ..infra.db_utils import db_query as _db_query


def list_departments() -> list[dict]:
    """部门扁平列表（按层级路径排序，供筛选下拉树形展示）。"""
    def _do(cur):
        cur.execute(
            "SELECT id, parent_id, name, path, depth "
            "FROM org_department ORDER BY path")
        return [{"id": int(r[0]), "parent_id": r[1], "name": r[2],
                 "path": r[3], "depth": int(r[4] or 0)}
                for r in cur.fetchall()]

    try:
        return _db_query(_do) or []
    except Exception:
        # 表未建（迁移未执行）时降级为空列表，不影响列表页
        return []


def subtree_ids(department_id: int) -> list[int]:
    """部门自身 + 全部子部门 id（path 前缀匹配）。

    找不到该部门时返回 [department_id]（按原值过滤，结果为空更诚实）。
    """
    def _do(cur):
        cur.execute(
            "SELECT path FROM org_department WHERE id = %s",
            (department_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            return [department_id]
        cur.execute(
            "SELECT id FROM org_department "
            "WHERE id = %s OR path LIKE CONCAT(%s, ' / %%')",
            (department_id, row[0]))
        return [int(r[0]) for r in cur.fetchall()]

    try:
        return _db_query(_do) or [department_id]
    except Exception:
        return [department_id]
