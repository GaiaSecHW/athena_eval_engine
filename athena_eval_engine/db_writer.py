"""子进程 DB 写入器：从 pickle 文件读取 facts 并写入 MySQL。
被 evaluation_service.py 通过 subprocess 调用，绕过主进程的 MySQL 连接问题。"""
import sys, os, pickle, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from athena_eval_engine.infrastructure.database import connect
from athena_eval_engine.persistence.repositories import fact_repo

def main(pickle_path):
    with open(pickle_path, 'rb') as f:
        data = pickle.load(f)

    evaluation_id = data['evaluation_id']
    task_runs = data['task_runs']
    facts = data['facts']
    source_uri = data.get('source_uri', '')

    conn = connect(autocommit=True)
    cur = conn.cursor()
    cur.execute("SET FOREIGN_KEY_CHECKS=0")
    cur.execute("UPDATE evaluation SET evaluation_status=%s WHERE evaluation_id=%s", ("RESOLVING", evaluation_id))

    for tr in task_runs:
        f = facts[tr.task_run_id]
        # 保存实际值到文件用于调试
        import json as _j
        oc = f["outcome"]
        _dump = {
            'outcome_fact_id': oc.outcome_fact_id,
            'task_run_id': tr.task_run_id,
            'evaluation_id': evaluation_id,
            'condition': oc.condition.value,
            'condition_source': oc.condition_source.value,
            'condition_conflict': oc.condition_conflict,
            'benchmark_item_id': oc.benchmark_item_id,
            'gt_label': oc.gt_label.value if oc.gt_label else None,
            'prediction': oc.prediction.value if oc.prediction else None,
            'outcome': oc.outcome.value,
            'confusion_label': oc.confusion_label.value if oc.confusion_label else None,
            'target_finding_id': oc.target_finding_id,
            'validation_result': repr(oc.validation_result),  # repr 看类型
            'resolver_status': oc.resolver_status,
            'resolver_version': oc.resolver_version,
            'evidence_json': _j.dumps({'evidence': [], 'case_results': getattr(oc, 'case_results', []) or []}, ensure_ascii=False),
        }
        with open(os.path.join(tempfile.gettempdir(), 'outcome_dump.json'), 'w') as _df:
            _j.dump(_dump, _df, ensure_ascii=False, indent=2)
        try:
            fact_repo.insert_trace_source(cur, tr.trace_id, evaluation_id, source_uri)
            fact_repo.insert_task_run(cur, tr)
            fact_repo.insert_outcome_fact(cur, f["outcome"])
            fact_repo.insert_knowledge_fact(cur, f["knowledge"])
            fact_repo.insert_tool_action_fact(cur, f["tool"])
            fact_repo.insert_resource_fact(cur, f["resource"])
        except Exception as e:
            if "1062" in str(e) or "Duplicate" in str(e):
                pass  # 幂等，跳过
            else:
                print(f"[DB WRITER ERR] code={e.args[0] if e.args else '?'} tr={tr.task_run_id[:40]}: {repr(e)[:200]}", file=sys.stderr)
                raise

    cur.execute("SET FOREIGN_KEY_CHECKS=1")
    conn.close()
    print("[DB WRITER] All facts inserted successfully", file=sys.stderr)

if __name__ == '__main__':
    main(sys.argv[1])
