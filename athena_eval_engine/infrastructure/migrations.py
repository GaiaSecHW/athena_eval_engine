"""Schema 迁移机制。

启动时自动检查并应用未执行的迁移。每条迁移用唯一 ID 跟踪，
已应用的跳过，失败的记录错误但不阻断启动。

迁移 SQL 必须幂等（可重复执行不报错）或用 try/except 包裹。
"""
from __future__ import annotations
from .database import connect
from .log_util import log

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
]


def run_migrations():
    """启动时执行未应用的 schema 迁移。"""
    try:
        conn = connect(autocommit=True)
        try:
            cur = conn.cursor()
            # 创建迁移跟踪表
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "  migration_id VARCHAR(128) PRIMARY KEY,"
                "  description VARCHAR(256) NOT NULL,"
                "  applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
            # 查已应用的迁移
            cur.execute("SELECT migration_id FROM schema_migrations")
            applied = {row[0] for row in cur.fetchall()}
            pending = [m for m in MIGRATIONS if m["id"] not in applied]
            if not pending:
                log("MIGRATE", f"无待执行迁移（已应用 {len(applied)} 条）")
                return
            log("MIGRATE", f"待执行 {len(pending)} 条迁移")
            for m in pending:
                _run_one(cur, m)
        finally:
            conn.close()
    except Exception as e:
        log("MIGRATE", f"迁移机制异常（DB 可能未就绪）: {e}")


def _run_one(cur, migration: dict):
    """执行单条迁移。SQL 失败时记录错误但标记为已应用（避免反复重试）。"""
    mid = migration["id"]
    desc = migration["desc"]
    errors = []
    for sql in migration["sql"]:
        try:
            cur.execute(sql)
        except Exception as e:
            err = str(e)[:200]
            # 常见可忽略错误：约束已存在、表已存在、列已存在
            if any(kw in err.lower() for kw in (
                "duplicate", "already exists", "can't drop",
                "unknown constraint", "check that does not exist",
            )):
                pass  # 幂等：已应用过
            else:
                errors.append(err)
                log("MIGRATE", f"[{mid}] SQL 错误: {err}")
    # 标记为已应用（无论有无错误，避免反复重试同一条）
    cur.execute(
        "INSERT INTO schema_migrations (migration_id, description) VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE migration_id=migration_id",
        (mid, desc))
    if errors:
        log("MIGRATE", f"[{mid}] {desc} — 完成（{len(errors)} 条 SQL 跳过）")
    else:
        log("MIGRATE", f"[{mid}] {desc} — 完成")
