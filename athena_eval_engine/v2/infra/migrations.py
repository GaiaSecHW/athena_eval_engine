"""Schema 迁移机制。

启动时自动检查并应用未执行的迁移。每条迁移用唯一 ID 跟踪，
已应用的跳过。每条迁移在事务中执行，全部 SQL 成功（或幂等跳过）才提交并标记已应用。
真实错误回滚事务、不标记已应用，下次启动重试。
"""
from __future__ import annotations
from ...infrastructure.database import connect
from ...infrastructure.log_util import log

# 迁移列表：按顺序执行，每条用唯一 ID 跟踪
MIGRATIONS = [
    {
        "id": "001_evaluation_status_ai_matching",
        "desc": "evaluation_status CHECK 增加 AI_MATCHING",
        "sql": [
            "ALTER TABLE evaluation DROP CHECK evaluation_chk_1",
            "ALTER TABLE evaluation ADD CONSTRAINT evaluation_status_chk CHECK (evaluation_status IN "
            "('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING','PARSING','AI_MATCHING','RESOLVING','PAIRING',"
            "'CALCULATING','STATISTICAL_ANALYSIS','DIAGNOSING','REPORTING','FINALIZING',"
            "'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED',"
            "'CANCEL_REQUESTED','CANCELLING','CANCELLED'))",
        ],
    },
    {
        "id": "002_metric_result_m11_m12",
        "desc": "metric_result CHECK 增加 M11/M12",
        "sql": [
            "ALTER TABLE metric_result DROP CHECK metric_result_chk_1",
            "ALTER TABLE metric_result ADD CONSTRAINT metric_result_metric_id_chk CHECK (metric_id IN "
            "('M1','M2','M3','M4','M5','M6','M7','M8','M9','M10','M11','M12'))",
        ],
    },
    {
        "id": "003_outcome_sink_status",
        "desc": "outcome_fact resolver_status CHECK 增加 SINK_*",
        "sql": [
            "ALTER TABLE outcome_fact DROP CHECK outcome_fact_chk_8",
            "ALTER TABLE outcome_fact ADD CONSTRAINT outcome_fact_resolver_status_chk CHECK (resolver_status IN "
            "('RESOLVED','NO_FINDING','NO_UPDATE','NO_GT','BENCHMARK_UNMATCHED','PARSE_ERROR',"
            "'AI_MATCHED','AI_MATCH_ERROR','AI_AMBIGUOUS','AI_PARTIAL_MATCH','AI_UNMATCHED','NO_VALIDATION',"
            "'SINK_MATCHED','SINK_PARTIAL_MATCH','SINK_UNMATCHED'))",
        ],
    },
    {
        "id": "004_system_config_table",
        "desc": "创建 system_config 表（运行时参数持久化）",
        "sql": [
            "CREATE TABLE IF NOT EXISTS system_config ("
            "  config_key VARCHAR(64) PRIMARY KEY,"
            "  config_value VARCHAR(512) NOT NULL,"
            "  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        ],
    },
    {
        "id": "005_evaluation_cancel_requested",
        "desc": "evaluation 表增加 cancel_requested 列（跨 worker 取消信号）",
        "sql": [
            "ALTER TABLE evaluation ADD COLUMN cancel_requested TINYINT(1) NOT NULL DEFAULT 0",
        ],
    },
    {
        "id": "006_extracted_finding_session_id_widen",
        "desc": "extracted_finding.session_id/verify_session_id 扩容到 VARCHAR(512)",
        "sql": [
            "ALTER TABLE extracted_finding MODIFY COLUMN session_id VARCHAR(512)",
            "ALTER TABLE extracted_finding MODIFY COLUMN verify_session_id VARCHAR(512)",
        ],
    },
    {
        "id": "007_knowledge_access_detail",
        "desc": "新增知识访问明细表",
        "sql": [
            # 1. 创建 knowledge_access_detail 表
            "CREATE TABLE IF NOT EXISTS knowledge_access_detail ("
            "  access_id VARCHAR(128) PRIMARY KEY,"
            "  evaluation_id VARCHAR(64) NOT NULL,"
            "  task_run_id VARCHAR(64) NOT NULL,"
            "  task_id VARCHAR(128) NOT NULL,"
            "  event_idx INT NOT NULL,"
            "  source_system VARCHAR(32) NOT NULL"
            "    CHECK (source_system IN ('KNOWLEDGE_BASE','MEMORY_ENGINE')),"
            "  l0_origin VARCHAR(64),"
            "  l1_need_knowledge BOOLEAN,"
            "  l2_initiated BOOLEAN,"
            "  l3_query_accurate BOOLEAN,"
            "  l4_knowledge_exists BOOLEAN,"
            "  l5_retrieved BOOLEAN,"
            "  l6_used BOOLEAN,"
            "  l7_influenced BOOLEAN,"
            "  l7_method VARCHAR(32),"
            "  effect_label VARCHAR(16)"
            "    CHECK (effect_label IS NULL OR effect_label IN ('POSITIVE','NEGATIVE','NEUTRAL')),"
            "  cause_code VARCHAR(8)"
            "    CHECK (cause_code IS NULL OR cause_code IN ('A','B','C','D','E','F','G')),"
            "  query_content TEXT,"
            "  returned_content TEXT,"
            "  reasoning_ref TEXT,"
            "  judgment_conclusion TEXT,"
            "  evidence_json JSON,"
            "  evidence_file TEXT,"
            "  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),"
            "  UNIQUE (task_run_id, event_idx),"
            "  INDEX idx_kad_eval (evaluation_id),"
            "  INDEX idx_kad_effect (evaluation_id, effect_label),"
            "  INDEX idx_kad_cause (evaluation_id, cause_code),"
            "  CONSTRAINT fk_kad_trun FOREIGN KEY (evaluation_id, task_run_id)"
            "    REFERENCES task_run(evaluation_id, task_run_id)"
            ") ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        ],
    },
    {
        "id": "008_agent_datasource_config",
        "desc": "新增 Agent 数据源配置表 + 初始数据（6 条）",
        "sql": [
            # 1. 创建 agent_datasource_config 表
            "CREATE TABLE IF NOT EXISTS agent_datasource_config ("
            "  id INT AUTO_INCREMENT PRIMARY KEY,"
            "  agent_type VARCHAR(32) NOT NULL UNIQUE"
            "    CHECK (agent_type IN ('turing','argo','secmate','cvuln_verify','webvuln_verify','dataflow')),"
            "  display_name VARCHAR(64) NOT NULL,"
            "  db_type VARCHAR(16) NOT NULL"
            "    CHECK (db_type IN ('mysql','postgresql','none')),"
            "  host VARCHAR(256),"
            "  port INT,"
            "  username VARCHAR(64),"
            "  password VARCHAR(256),"
            "  database_name VARCHAR(128),"
            "  relation_tables JSON,"
            "  phase_identifier JSON,"
            "  enabled BOOLEAN NOT NULL DEFAULT TRUE,"
            "  last_connected_at DATETIME(3),"
            "  last_error TEXT,"
            "  _version INT NOT NULL DEFAULT 1,"
            "  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),"
            "  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),"
            "  INDEX idx_adc_type (agent_type)"
            ") ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            # 2. 初始数据 INSERT IGNORE（6 条）
            "INSERT IGNORE INTO agent_datasource_config"
            "  (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled) VALUES"
            "  ('turing', 'Turing MySQL', 'mysql',"
            "   'turing-app-security-mysql.secflow-ns.svc.cluster.local', 3306,"
            "   'root', 'turing_app_security_pass', 'turing_app_security',"
            "   JSON_OBJECT('task_table','turing_task','parent_field','parent_task_id','session_field','agent_session_id',"
            "               'task_type_field','task_type','agent_name_field','agent_name',"
            "               'trace_table','turing_task_trace',"
            "               'investigation_table','turing_investigation','investigation_parent_field','parent_investigation_id',"
            "               'investigation_origin_field','origin_detection_id','investigation_target_field','target_task_id',"
            "               'investigation_depth_field','depth'),"
            "   JSON_OBJECT('table','turing_task','id_field','agent_session_id','label_fields',JSON_ARRAY('agent_name','task_type')),"
            "   1)",
            "INSERT IGNORE INTO agent_datasource_config"
            "  (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled) VALUES"
            "  ('argo', 'Argo MySQL', 'mysql',"
            "   'chirmera-platform-nazhua-mysql.secflow-ns.svc.cluster.local', 3306,"
            "   'root', 'Icsl_argo', 'argo_c',"
            "   JSON_OBJECT('table','intents','session_field','session_id','fact_field','to_fact_id',"
            "               'suggestion_field','suggestion_refs','task_type_field','task_type'),"
            "   JSON_OBJECT('table','intents','id_field','session_id','label_field','task_type'),"
            "   1)",
            "INSERT IGNORE INTO agent_datasource_config"
            "  (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled) VALUES"
            "  ('secmate', 'SecMate MySQL', 'mysql',"
            "   'secmate-mysql.secflow-ns.svc.cluster.local', 3306,"
            "   'root', 'Huawei12#$', 'secmate',"
            "   JSON_OBJECT('finding_table','finding','finding_id_field','id','source_field','source_finding_id',"
            "               'vuln_type_field','vuln_type','level_field','level',"
            "               'file_path_field','file_path','fingerprint_field','fingerprint',"
            "               'task_table','task','task_tool_task_id_field','tool_task_id',"
            "               'task_external_task_id_field','external_task_id','task_file_path_field','file_path'),"
            "   JSON_OBJECT('source','trace','note','persona and finding level extracted from JSONL trace; DB has no persona field'),"
            "   1)",
            "INSERT IGNORE INTO agent_datasource_config"
            "  (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled) VALUES"
            "  ('dataflow', 'DataflowVulnScan MySQL', 'mysql',"
            "   'secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local', 3306,"
            "   'root', 'Huawei12#$', 'dvs_{project_id}',"
            "   JSON_OBJECT('sessions_table','dvs_task_graph_sessions','session_relpath_field','session_relpath',"
            "               'session_task_id_field','task_id','session_node_id_field','node_id',"
            "               'session_edge_id_field','edge_id','session_role_field','session_role','session_kind_field','session_kind',"
            "               'nodes_table','dvs_task_graph_nodes','node_id_field','node_id','node_task_id_field','task_id',"
            "               'node_depth_field','depth','node_primary_session_field','primary_session_relpath',"
            "               'edges_table','dvs_task_graph_edges','edge_id_field','edge_id','edge_task_id_field','task_id',"
            "               'edge_source_node_field','source_node_id','edge_target_node_field','target_node_id',"
            "               'edge_source_func_field','source_func_id','edge_target_func_field','target_func_id',"
            "               'fallback_table','orchestration','fallback_edge_id_field','edge_id','fallback_path_id_field','path_id',"
            "               'fallback_source_func_field','source_func_id','fallback_target_func_field','target_func_id',"
            "               'fallback_task_id_field','task_id'),"
            "   JSON_OBJECT('source','filename','field','analysisType',"
            "               'note','analysisType extracted from JSONL filename; DB has no direct phase identifier column'),"
            "   1)",
            "INSERT IGNORE INTO agent_datasource_config"
            "  (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled) VALUES"
            "  ('cvuln_verify', 'CVulnVerify PostgreSQL', 'postgresql',"
            "   'secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local', 5432,"
            "   'postgres', 'secflow123', 'secflow_vuln_verify_v2',"
            "   JSON_OBJECT('attempt_table','vuln_verify_attempt','attempt_id_field','id','attempt_task_id_field','task_id',"
            "               'worker_type_field','worker_type','predecessor_field','predecessor_attempt_id',"
            "               'successor_reason_field','successor_reason','status_field','status',"
            "               'task_table','vuln_verify_task','task_id_field','id','task_project_id_field','project_id',"
            "               'task_case_id_field','case_id','task_vuln_id_field','vuln_id',"
            "               'task_file_field','file','task_function_field','function',"
            "               'task_business_task_id_field','business_task_id'),"
            "   JSON_OBJECT('table','vuln_verify_attempt','id_field','id','label_field','worker_type'),"
            "   1)",
            "INSERT IGNORE INTO agent_datasource_config"
            "  (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled) VALUES"
            "  ('webvuln_verify', 'WebVulnVerify (无独立DB)', 'none',"
            "   NULL, NULL, NULL, NULL, NULL,"
            "   JSON_OBJECT('source','trace','parent_field','session.parent_id','vuln_id_field','metadata.vulnerability_id'),"
            "   JSON_OBJECT('source','trace','tool_field','tool_call.name'),"
            "   1)",
        ],
    },
    {
        "id": "009_fix_argo_hostname",
        "desc": "修正 Argo MySQL 主机名拼写：chirmra → chirmera",
        "sql": [
            "UPDATE agent_datasource_config SET host='chirmera-platform-nazhua-mysql.secflow-ns.svc.cluster.local' "
            "WHERE agent_type='argo' AND host='chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local'",
        ],
    },
    {
        "id": "010_dts_issue",
        "desc": "新增问题单表",
        "sql": [
            "CREATE TABLE IF NOT EXISTS dts_issue ("
            "  dts_id VARCHAR(64) PRIMARY KEY,"
            "  evaluation_id VARCHAR(64) NOT NULL,"
            "  task_run_id VARCHAR(64) NOT NULL,"
            "  task_id VARCHAR(128) NOT NULL,"
            "  agent_type VARCHAR(32) NOT NULL,"
            "  case_type VARCHAR(8) NOT NULL"
            "    CHECK (case_type IN ('FP','FN')),"
            "  fp_type VARCHAR(64),"
            "  cause_code VARCHAR(8) NOT NULL"
            "    CHECK (cause_code IN ('A','B','C','D','E','F','G')),"
            "  breakpoint_level VARCHAR(8) NOT NULL,"
            "  access_id VARCHAR(128),"
            "  breakpoint_desc TEXT,"
            "  evidence_uri VARCHAR(512),"
            "  root_cause TEXT,"
            "  solution TEXT,"
            "  replay_eval_id VARCHAR(64),"
            "  replay_result VARCHAR(16),"
            "  status VARCHAR(32) NOT NULL DEFAULT 'unlocated'"
            "    CHECK (status IN ('unlocated','improving','confirmed','closing','passed','failed','not_issue')),"
            "  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),"
            "  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),"
            "  closed_at DATETIME(3),"
            "  INDEX idx_dts_eval (evaluation_id),"
            "  INDEX idx_dts_agent (agent_type),"
            "  INDEX idx_dts_status (status),"
            "  INDEX idx_dts_task (task_id),"
            "  CONSTRAINT fk_dts_trun FOREIGN KEY (evaluation_id, task_run_id)"
            "    REFERENCES task_run(evaluation_id, task_run_id)"
            ") ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        ],
    },
    {
        "id": "011_evaluation_status_v2_merge",
        "desc": "evaluation_status CHECK 移除 LIFECYCLE_ANALYSIS/CAUSAL_CHAIN，对齐 v2 合并后阶段",
        "sql": [
            "ALTER TABLE evaluation DROP CHECK evaluation_status_chk",
            "ALTER TABLE evaluation ADD CONSTRAINT evaluation_status_chk CHECK (evaluation_status IN "
            "('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING','PARSING',"
            "'CASE_MATCHING','ROOT_CAUSE_ANALYSIS','RESOLVING',"
            "'REPORTING','FINALIZING',"
            "'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED',"
            "'CANCEL_REQUESTED','CANCELLING','CANCELLED'))",
        ],
    },
    {
        "id": "012_dts_issue_schema_v2",
        "desc": "dts_issue 表适配根因分析结果：case_id 替代 task_run_id/task_id，新增 responsibility，删除 access_id/fp_type/FK",
        "sql": [
            "ALTER TABLE dts_issue DROP FOREIGN KEY fk_dts_trun",
            "ALTER TABLE dts_issue DROP INDEX idx_dts_task",
            "ALTER TABLE dts_issue DROP COLUMN task_run_id",
            "ALTER TABLE dts_issue DROP COLUMN access_id",
            "ALTER TABLE dts_issue DROP COLUMN fp_type",
            "ALTER TABLE dts_issue ADD COLUMN case_id VARCHAR(64) NOT NULL DEFAULT '' AFTER evaluation_id",
            "ALTER TABLE dts_issue ADD COLUMN responsibility VARCHAR(16) AFTER status",
            "ALTER TABLE dts_issue ADD INDEX idx_dts_case (case_id)",
        ],
    },
    {
        "id": "013_dts_issue_add_task_id",
        "desc": "dts_issue 表新增 task_id 字段（原始数据任务 ID，用于按任务查询问题单）",
        "sql": [
            "ALTER TABLE dts_issue ADD COLUMN task_id VARCHAR(128) NOT NULL DEFAULT '' AFTER evaluation_id",
            "ALTER TABLE dts_issue ADD INDEX idx_dts_task_id (task_id)",
        ],
    },
    {
        "id": "014_dts_issue_add_vuln_type",
        "desc": "dts_issue 表新增 vuln_title 字段（漏洞标题，列表展示用）",
        "sql": [
            "ALTER TABLE dts_issue ADD COLUMN vuln_title VARCHAR(512) NOT NULL DEFAULT '' AFTER case_id",
        ],
    },
    {
        "id": "015_dts_issue_rename_vuln_type_to_vuln_title",
        "desc": "将 dts_issue.vuln_type 列改名为 vuln_title（修正 migration 014 旧版加的列名）",
        "sql": [
            "ALTER TABLE dts_issue CHANGE COLUMN vuln_type vuln_title VARCHAR(512) NOT NULL DEFAULT ''",
        ],
    },
    {
        "id": "016_dts_issue_backfill_vuln_title",
        "desc": "从 breakpoint_desc 中回填已有问题单的 vuln_title（提取'漏洞标题: XXX'或'漏洞类型: XXX'文本）",
        "sql": [
            "UPDATE dts_issue SET vuln_title = TRIM(SUBSTRING_INDEX("
            "  SUBSTRING_INDEX(breakpoint_desc, '漏洞标题:', -1), ' |', 1"
            ")) WHERE vuln_title = '' AND breakpoint_desc LIKE '%漏洞标题:%'",
            "UPDATE dts_issue SET vuln_title = TRIM(SUBSTRING_INDEX("
            "  SUBSTRING_INDEX(breakpoint_desc, '漏洞类型:', -1), ' |', 1"
            ")) WHERE vuln_title = '' AND breakpoint_desc LIKE '%漏洞类型:%'",
        ],
    },
]

# 幂等错误关键词：这些错误表示 SQL 已应用过，可安全跳过
_IDEMPOTENT_KEYWORDS = (
    "duplicate", "already exists", "can't drop",
    "unknown constraint", "check that does not exist",
    "duplicate key name", "is not found",
    "unknown column",
)


def run_migrations():
    """启动时执行未应用的 schema 迁移。"""
    try:
        conn = connect(autocommit=False)
        try:
            cur = conn.cursor()
            # 创建迁移跟踪表
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "  migration_id VARCHAR(128) PRIMARY KEY,"
                "  description VARCHAR(256) NOT NULL,"
                "  applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
            conn.commit()
            # 查已应用的迁移
            cur.execute("SELECT migration_id FROM schema_migrations")
            applied = {row[0] for row in cur.fetchall()}
            pending = [m for m in MIGRATIONS if m["id"] not in applied]
            if not pending:
                log("MIGRATE", f"无待执行迁移（已应用 {len(applied)} 条）")
                return
            log("MIGRATE", f"待执行 {len(pending)} 条迁移")
            for m in pending:
                _run_one(cur, conn, m)
        finally:
            conn.close()
    except Exception as e:
        log("MIGRATE", f"迁移机制异常（DB 可能未就绪）: {e}")


def _run_one(cur, conn, migration: dict):
    """执行单条迁移。在事务中执行，全部 SQL 成功或幂等跳过才提交并标记已应用。

    真实错误回滚事务、不标记已应用，下次启动重试。
    """
    mid = migration["id"]
    desc = migration["desc"]
    real_errors = []
    try:
        for sql in migration["sql"]:
            try:
                cur.execute(sql)
            except Exception as e:
                err = str(e)[:200]
                if any(kw in err.lower() for kw in _IDEMPOTENT_KEYWORDS):
                    pass  # 幂等：已应用过，跳过
                else:
                    real_errors.append(err)
                    log("MIGRATE", f"[{mid}] SQL 错误: {err}")
        if real_errors:
            conn.rollback()
            log("MIGRATE", f"[{mid}] {desc} — 失败（回滚，{len(real_errors)} 条真实错误，下次重试）")
            return
        # 全部成功或幂等跳过 → 提交 + 标记已应用
        cur.execute(
            "INSERT INTO schema_migrations (migration_id, description) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE migration_id=migration_id",
            (mid, desc))
        conn.commit()
        log("MIGRATE", f"[{mid}] {desc} — 完成")
    except Exception as e:
        conn.rollback()
        log("MIGRATE", f"[{mid}] {desc} — 异常回滚: {e}")
