"""有效 case 筛选模块（§4.4）。

有效 case = trace 里的挖掘结论与基线匹配上的 case。
一个 case 有效需要：
1. 该 task_run 有 outcome_fact（有挖掘结论）
2. 该 task_run 的 finding 与 benchmark_item 匹配成功
   （sink-point 匹配或 finding_benchmark_match 表有 MATCHED 记录）
3. 该 task_run 有 knowledge_interaction_fact（有知识访问记录）

降级策略：finding_benchmark_match 表不存在或无记录时，
降级为从 extracted_finding 表查询是否有 finding（运行态标准）。
"""
from __future__ import annotations

from ..core.data_pack import DataPack
from ..infra.database import connect
from ...infrastructure.log_util import log


class CaseFilter:
    """有效 case 筛选器。

    筛选有效 case，只对有效 case 内的知识访问做统计。
    """

    def filter_valid_cases(self, evaluation_id: str, data_packs: list) -> list:
        """从 data_packs 中筛选有效 case。

        返回有效的 DataPack 列表，每个 DataPack 满足：
        - outcome_fact 不为 None
        - knowledge_fact 不为 None 且有知识访问记录
        - benchmark_item 不为 None
        - finding 与 benchmark 匹配成功
        """
        valid_packs: list[DataPack] = []

        for dp in data_packs:
            # 条件 1: outcome_fact 不为 None
            if dp.outcome_fact is None:
                log("CASE_FILTER", f"skip {dp.task_run_id}: no outcome_fact",
                    eval_id=evaluation_id)
                continue

            # 条件 2: knowledge_fact 不为 None 且有知识访问记录
            if dp.knowledge_fact is None:
                log("CASE_FILTER", f"skip {dp.task_run_id}: no knowledge_fact",
                    eval_id=evaluation_id)
                continue

            kf = dp.knowledge_fact
            has_knowledge_access = (
                getattr(kf, "access", False)
                or getattr(kf, "memory_access", False)
            )
            if not has_knowledge_access:
                log("CASE_FILTER",
                    f"skip {dp.task_run_id}: no knowledge access record",
                    eval_id=evaluation_id)
                continue

            # 条件 3: benchmark_item 不为 None
            if dp.benchmark_item is None:
                log("CASE_FILTER", f"skip {dp.task_run_id}: no benchmark_item",
                    eval_id=evaluation_id)
                continue

            # 条件 4: finding 与 benchmark 匹配成功
            if not self._has_matched_findings(dp.task_run_id, evaluation_id):
                log("CASE_FILTER",
                    f"skip {dp.task_run_id}: finding not matched to benchmark",
                    eval_id=evaluation_id)
                continue

            valid_packs.append(dp)

        log("CASE_FILTER",
            f"filtered {len(valid_packs)}/{len(data_packs)} valid cases",
            eval_id=evaluation_id)
        return valid_packs

    def _has_matched_findings(self, task_run_id: str, evaluation_id: str) -> bool:
        """检查该 task_run 的 finding 是否与 benchmark 匹配成功。

        查询 finding_benchmark_match 表是否有该 task_run 的 MATCHED 记录。
        如果该表不存在或无记录，降级为从 extracted_finding 表查询是否有 finding。
        """
        conn = None
        try:
            conn = connect(autocommit=True)
            cur = conn.cursor()

            # 主路径: 查 finding_benchmark_match 表
            # status='MATCHED' 表示匹配成功（AMBIGUOUS/UNMATCHED 不算）
            try:
                cur.execute(
                    "SELECT 1 FROM finding_benchmark_match "
                    "WHERE evaluation_id = %s AND task_run_id = %s "
                    "AND status = 'MATCHED' "
                    "LIMIT 1",
                    (evaluation_id, task_run_id),
                )
                if cur.fetchone() is not None:
                    return True
            except Exception as e:
                # 表不存在等异常，降级到 extracted_finding
                log("CASE_FILTER",
                    f"finding_benchmark_match query failed, "
                    f"falling back to extracted_finding: {str(e)[:120]}",
                    eval_id=evaluation_id)

            # 降级路径: 查 extracted_finding 表是否有 finding
            try:
                cur.execute(
                    "SELECT 1 FROM extracted_finding "
                    "WHERE evaluation_id = %s AND task_run_id = %s "
                    "LIMIT 1",
                    (evaluation_id, task_run_id),
                )
                if cur.fetchone() is not None:
                    return True
            except Exception as e:
                log("CASE_FILTER",
                    f"extracted_finding query failed: {str(e)[:120]}",
                    eval_id=evaluation_id)

            return False
        finally:
            if conn is not None:
                conn.close()
