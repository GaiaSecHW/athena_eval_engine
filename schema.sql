-- Athena 知识图谱2.0 评测引擎 Schema (MySQL 8.0+)
-- 生成自 athena-知识图谱2.0评测-开发需求.md §7 + §12 + §7.27
-- 建表顺序见 §7.20；无 inline REFERENCES，FK 全部显式（§7.27）

CREATE DATABASE IF NOT EXISTS athena_eval
  CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
USE athena_eval;

SET FOREIGN_KEY_CHECKS=0;
DROP TABLE IF EXISTS outbox_event;
DROP TABLE IF EXISTS evaluation_state_transition;
DROP TABLE IF EXISTS job_lease;
DROP TABLE IF EXISTS evaluation_job;
DROP TABLE IF EXISTS evaluation_stage_run;
DROP TABLE IF EXISTS evaluation_coverage;
DROP TABLE IF EXISTS exclusion_record;
DROP TABLE IF EXISTS evaluation_report;
DROP TABLE IF EXISTS statistical_result;
DROP TABLE IF EXISTS metric_result;
DROP TABLE IF EXISTS evaluation_population_snapshot;
DROP TABLE IF EXISTS evaluation_calculation_run;
DROP TABLE IF EXISTS pair_derived_fact;
DROP TABLE IF EXISTS finding_benchmark_match;
DROP TABLE IF EXISTS resource_fact;
DROP TABLE IF EXISTS tool_action_fact;
DROP TABLE IF EXISTS knowledge_interaction_fact;
DROP TABLE IF EXISTS outcome_fact;
DROP TABLE IF EXISTS task_pair;
DROP TABLE IF EXISTS task_run;
DROP TABLE IF EXISTS trace_artifact;
DROP TABLE IF EXISTS trace_source;
DROP TABLE IF EXISTS evaluation_snapshot;
DROP TABLE IF EXISTS evaluation;
DROP TABLE IF EXISTS benchmark_item;
DROP TABLE IF EXISTS benchmark_set;
DROP TABLE IF EXISTS schema_version;
SET FOREIGN_KEY_CHECKS=1;

-- ===== L0/L1 Source & Control =====

CREATE TABLE schema_version (
    schema_version_id     VARCHAR(64) PRIMARY KEY,
    component_type        VARCHAR(64) NOT NULL,
    component_name        VARCHAR(128) NOT NULL,
    version               VARCHAR(64) NOT NULL,
    definition_json       JSON NOT NULL,
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (component_type, component_name, version)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE benchmark_set (
    benchmark_set_id   VARCHAR(128) PRIMARY KEY,
    name               VARCHAR(256) NOT NULL,
    version            VARCHAR(64) NOT NULL,
    manifest_hash      VARCHAR(128) NOT NULL,
    status             VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
                       CHECK (status IN ('ACTIVE','DEPRECATED','FROZEN')),
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (name, version)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE benchmark_item (
    benchmark_item_id     VARCHAR(128) PRIMARY KEY,
    benchmark_set_id      VARCHAR(64) NOT NULL,
    task_id               VARCHAR(128) NOT NULL,
    expected_label        VARCHAR(32) NOT NULL CHECK (expected_label IN ('VULNERABLE','NON_VULNERABLE')),
    target_finding_id     VARCHAR(256),
    metadata_json         JSON,
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (benchmark_set_id, benchmark_item_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE evaluation (
    evaluation_id          VARCHAR(64) PRIMARY KEY,
    evaluation_name        VARCHAR(256) NOT NULL,
    benchmark_set_id       VARCHAR(128) NOT NULL,
    agent_name             VARCHAR(128) NOT NULL,
    agent_version          VARCHAR(128),
    model_name             VARCHAR(256),
    model_version          VARCHAR(128),
    prompt_version         VARCHAR(128),
    environment_version    VARCHAR(128),
    evaluation_status      VARCHAR(32) NOT NULL DEFAULT 'CREATED'
                            CHECK (evaluation_status IN
                            ('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING','PARSING','AI_MATCHING','RESOLVING','PAIRING',
                             'CALCULATING','STATISTICAL_ANALYSIS','DIAGNOSING','REPORTING','FINALIZING',
                             'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED',
                             'CANCEL_REQUESTED','CANCELLING','CANCELLED')),
    evaluator_version      VARCHAR(64) NOT NULL DEFAULT '1.0',
    parser_version         VARCHAR(64) NOT NULL DEFAULT '1.0',
    resolver_version       VARCHAR(64) NOT NULL DEFAULT '1.0',
    metric_version         VARCHAR(64) NOT NULL DEFAULT '1.0',
    statistics_version     VARCHAR(64) NOT NULL DEFAULT '1.0',
    action_schema_version  VARCHAR(64) NOT NULL DEFAULT '1.0',
    error_message          TEXT,
    version                BIGINT NOT NULL DEFAULT 0,
    created_at             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    started_at             DATETIME(3),
    finished_at            DATETIME(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE evaluation_snapshot (
    snapshot_id              VARCHAR(64) PRIMARY KEY,
    evaluation_id           VARCHAR(64) NOT NULL,
    parser_version           VARCHAR(64) NOT NULL,
    resolver_version         VARCHAR(64) NOT NULL,
    metric_profile_version  VARCHAR(64) NOT NULL,
    statistical_profile     VARCHAR(64) NOT NULL,
    canonical_action_schema VARCHAR(64) NOT NULL,
    knowledge_rule_version  VARCHAR(64) NOT NULL,
    token_schema_version    VARCHAR(64) NOT NULL,
    bootstrap_b             INTEGER NOT NULL DEFAULT 2000,
    confidence_level        DECIMAL(5,4) NOT NULL DEFAULT 0.95,
    bootstrap_seed          BIGINT,
    experiment_fingerprint_json JSON NOT NULL,
    code_hashes_json        JSON NOT NULL,
    config_json             JSON NOT NULL,
    created_at               DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT uk_evaluation_snapshot UNIQUE (evaluation_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE trace_source (
    trace_id               VARCHAR(64) PRIMARY KEY,
    evaluation_id          VARCHAR(64) NOT NULL,
    source_type            VARCHAR(32) NOT NULL,
    source_uri             TEXT NOT NULL,
    content_hash           VARCHAR(128) NOT NULL,
    sidecar_uri            TEXT,
    sidecar_hash           VARCHAR(128),
    condition_evidence_hash VARCHAR(128),
    condition_hint         VARCHAR(16) CHECK (condition_hint IN ('KG','NOGK','UNKNOWN')),
    schema_version         VARCHAR(64),
    trace_status           VARCHAR(32),
    created_at             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE trace_artifact (
    artifact_id     VARCHAR(128) PRIMARY KEY,
    trace_id        VARCHAR(64) NOT NULL,
    uri             TEXT NOT NULL,
    sha256          VARCHAR(64) NOT NULL,
    size_bytes      BIGINT NOT NULL,
    trace_schema    VARCHAR(64),
    created_at      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== L2 Fact =====

CREATE TABLE task_run (
    task_run_id           VARCHAR(64) PRIMARY KEY,
    evaluation_id         VARCHAR(64) NOT NULL,
    task_id               VARCHAR(128) NOT NULL,
    benchmark_item_id     VARCHAR(128),
    trace_id              VARCHAR(64) NOT NULL,
    turing_session_id     VARCHAR(128),
    `condition`             VARCHAR(16) NOT NULL CHECK (`condition` IN ('KG','NOGK','UNKNOWN')),
    condition_source      VARCHAR(32) NOT NULL CHECK (condition_source IN
                          ('MANIFEST','TRACE_METADATA','ENV_METADATA','FILENAME','UNKNOWN')),
    condition_conflict    BOOLEAN NOT NULL DEFAULT FALSE,
    agent_name            VARCHAR(128),
    model_name            VARCHAR(256),
    experiment_fingerprint_hash VARCHAR(128),
    trace_valid           BOOLEAN NOT NULL DEFAULT false,
    runtime_valid         BOOLEAN NOT NULL DEFAULT false,
    runtime_invalid_reason VARCHAR(64),
    runtime_evidence_json JSON,
    kg_runtime_state      VARCHAR(32) CHECK (kg_runtime_state IN
                    ('KG_READY','KG_MOUNT_FAILED','KG_UNAVAILABLE','KG_UNKNOWN','NOT_APPLICABLE')),
    started_at            BIGINT,
    finished_at           BIGINT,
    parser_status         VARCHAR(32),
    parser_error          TEXT,
    parser_version        VARCHAR(64) NOT NULL DEFAULT '1.0',
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (evaluation_id, task_id, `condition`),
    UNIQUE (evaluation_id, task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_task_run_eval ON task_run(evaluation_id);
CREATE INDEX idx_task_run_task ON task_run(evaluation_id, task_id);

CREATE TABLE finding_benchmark_match (
    match_id            VARCHAR(64) PRIMARY KEY,
    evaluation_id        VARCHAR(64) NOT NULL,
    task_run_id         VARCHAR(64) NOT NULL,
    finding_id          VARCHAR(256) NOT NULL,
    benchmark_item_id   VARCHAR(128),
    match_method         VARCHAR(32) NOT NULL
                         CHECK (match_method IN ('EXACT_ID','RULE','AI')),
    confidence           DECIMAL(5,4),
    model_name           VARCHAR(256),
    model_version        VARCHAR(64),
    prompt_hash          VARCHAR(128),
    config_json          JSON,
    code_hash            VARCHAR(128),
    response_hash        VARCHAR(128),
    status               VARCHAR(32) NOT NULL
                         CHECK (status IN ('MATCHED','AMBIGUOUS','UNMATCHED')),
    evidence_json        JSON,
    created_at           DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id, finding_id),
    CHECK (match_method <> 'AI' OR (prompt_hash IS NOT NULL AND model_name IS NOT NULL AND confidence IS NOT NULL))
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE task_pair (
    task_pair_id          VARCHAR(64) PRIMARY KEY,
    evaluation_id         VARCHAR(64) NOT NULL,
    task_id               VARCHAR(128) NOT NULL,
    benchmark_item_id     VARCHAR(128),
    nogk_task_run_id      VARCHAR(64),
    kg_task_run_id        VARCHAR(64),
    pair_experiment_valid BOOLEAN NOT NULL DEFAULT false,
    pair_fingerprint_status VARCHAR(32) CHECK (pair_fingerprint_status IN
                          ('SAME','MISMATCH','UNKNOWN')),
    pair_match_status     VARCHAR(32) NOT NULL CHECK (pair_match_status IN
                          ('VALID_PAIR','INCOMPLETE','UNMATCHED')),
    outcome_valid         BOOLEAN NOT NULL DEFAULT false,
    pair_transition       VARCHAR(64) CHECK (pair_transition IN
                          ('PRESERVED','REGRESSED','RECOVERED','PERSISTED_FAILURE','NA')),
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (evaluation_id, task_id),
    UNIQUE (evaluation_id, task_pair_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_task_pair_outcome ON task_pair(evaluation_id, outcome_valid);
CREATE INDEX idx_task_pair_trans   ON task_pair(evaluation_id, pair_transition);

CREATE TABLE pair_derived_fact (
    derived_fact_id       VARCHAR(64) PRIMARY KEY,
    evaluation_id         VARCHAR(64) NOT NULL,
    task_pair_id          VARCHAR(64) NOT NULL,
    derived_fact_type     VARCHAR(32) NOT NULL
                          CHECK (derived_fact_type IN
                          ('PAIR_TRANSITION','JSD','DELTA_TOKEN','DELTA_STEPS','DELTA_TIME')),
    value_numeric         DECIMAL(20,6),
    value_string          VARCHAR(64),
    status                VARCHAR(32) NOT NULL DEFAULT 'CALCULATED'
                          CHECK (status IN ('CALCULATED','NA','BLOCKED')),
    reason_code           VARCHAR(64)
                          CHECK (reason_code IS NULL OR reason_code IN
                          ('PAIR_OUTCOME_UNDETERMINED','MISSING_KG_FACT','MISSING_NOGK_FACT',
                           'TOOL_EVENT_MISSING','TOKEN_INVALID','STEP_INVALID','TIME_INVALID',
                           'NO_VALID_DENOMINATOR',
                           'PAIR_INCOMPLETE','PAIR_UNMATCHED','FINGERPRINT_MISMATCH','CONDITION_CONFLICT',
                           'BENCHMARK_ITEM_MISMATCH','BENCHMARK_SET_MISMATCH','CONDITION_UNKNOWN','PAIR_NOT_EXPERIMENT_VALID')),
    resolver_version      VARCHAR(64) NOT NULL DEFAULT '1.0',
    evidence_json         JSON,
    source_fact_refs_json JSON,
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_pair_id, derived_fact_type)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE outcome_fact (
    outcome_fact_id       VARCHAR(64) PRIMARY KEY,
    task_run_id           VARCHAR(64) NOT NULL,
    evaluation_id         VARCHAR(64) NOT NULL,
    `condition`             VARCHAR(16) NOT NULL CHECK (`condition` IN ('KG','NOGK','UNKNOWN')),
    condition_source      VARCHAR(32) NOT NULL CHECK (condition_source IN
                          ('MANIFEST','TRACE_METADATA','ENV_METADATA','FILENAME','UNKNOWN')),
    condition_conflict    BOOLEAN NOT NULL DEFAULT FALSE,
    benchmark_item_id     VARCHAR(128),
    gt_label              VARCHAR(32) CHECK (gt_label IN ('VULNERABLE','NON_VULNERABLE','NA')),
    prediction            VARCHAR(32) CHECK (prediction IN ('POSITIVE','NEGATIVE','UNDETERMINED')),
    outcome               VARCHAR(32) NOT NULL CHECK (outcome IN ('SUCCESS','FAIL','UNDETERMINED')),
    confusion_label       VARCHAR(8) CHECK (confusion_label IN ('TP','FP','FN','TN','NA')),
    target_finding_id     VARCHAR(256),
    validation_result     VARCHAR(64) CHECK (validation_result IN ('CONFIRMED','FALSE_POSITIVE','NA')),
    resolver_status       VARCHAR(32) NOT NULL CHECK (resolver_status IN
                          ('RESOLVED','NO_FINDING','NO_UPDATE','NO_GT','BENCHMARK_UNMATCHED','PARSE_ERROR',
                           'AI_MATCHED','AI_MATCH_ERROR','AI_AMBIGUOUS','AI_PARTIAL_MATCH','AI_UNMATCHED','NO_VALIDATION')),
    resolver_version      VARCHAR(64) NOT NULL DEFAULT '1.0',
    evidence_json         JSON,
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_outcome_eval ON outcome_fact(evaluation_id);

CREATE TABLE knowledge_interaction_fact (
    knowledge_fact_id      VARCHAR(64) PRIMARY KEY,
    task_run_id            VARCHAR(64) NOT NULL,
    evaluation_id          VARCHAR(64) NOT NULL,
    access                 BOOLEAN NOT NULL DEFAULT false,
    delivery               BOOLEAN NOT NULL DEFAULT false,
    mount_status           VARCHAR(32) CHECK (mount_status IN ('SUCCESS','FAILED','UNKNOWN')),
    access_event_count     INTEGER NOT NULL DEFAULT 0,
    read_event_count       INTEGER NOT NULL DEFAULT 0,
    successful_read_count  INTEGER NOT NULL DEFAULT 0,
    evidence_json          JSON,
    resolver_version       VARCHAR(64) NOT NULL DEFAULT '1.0',
    created_at             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_kif_access ON knowledge_interaction_fact(evaluation_id, access);

CREATE TABLE tool_action_fact (
    tool_action_fact_id    VARCHAR(64) PRIMARY KEY,
    task_run_id            VARCHAR(64) NOT NULL,
    evaluation_id          VARCHAR(64) NOT NULL,
    action_schema_version  VARCHAR(64) NOT NULL DEFAULT '1.0',
    kg_count               INTEGER NOT NULL DEFAULT 0,
    finding_count          INTEGER NOT NULL DEFAULT 0,
    code_count             INTEGER NOT NULL DEFAULT 0,
    shell_count            INTEGER NOT NULL DEFAULT 0,
    other_count            INTEGER NOT NULL DEFAULT 0,
    total_tool_calls       INTEGER NOT NULL DEFAULT 0,
    action_distribution    JSON NOT NULL,
    evidence_json          JSON,
    created_at             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE resource_fact (
    resource_fact_id       VARCHAR(64) PRIMARY KEY,
    task_run_id            VARCHAR(64) NOT NULL,
    evaluation_id          VARCHAR(64) NOT NULL,
    input_tokens           BIGINT,
    output_tokens          BIGINT,
    reasoning_tokens       BIGINT,
    cache_read_tokens      BIGINT,
    effective_tokens       BIGINT,
    token_schema_valid     BOOLEAN NOT NULL DEFAULT false,
    token_schema_version   VARCHAR(64),
    steps                  INTEGER,
    step_source            VARCHAR(32) CHECK (step_source IN ('step-start','step-finish','NA')),
    step_integrity_warning BOOLEAN NOT NULL DEFAULT false,
    duration_ms            BIGINT,
    time_valid             BOOLEAN NOT NULL DEFAULT false,
    validity_status        VARCHAR(32),
    evidence_json          JSON,
    created_at             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== L3 Calculation / Result =====

CREATE TABLE evaluation_calculation_run (
    calculation_run_id     VARCHAR(64) PRIMARY KEY,
    evaluation_id          VARCHAR(64) NOT NULL,
    run_type               VARCHAR(32) NOT NULL,
    metric_profile_version VARCHAR(64),
    statistical_profile    VARCHAR(64),
    bootstrap_config       JSON,
    seed                   BIGINT,
    config_snapshot_id     VARCHAR(64) NOT NULL,
    created_by             VARCHAR(128),
    created_at             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE evaluation_population_snapshot (
    population_snapshot_id VARCHAR(64) PRIMARY KEY,
    calculation_run_id VARCHAR(64) NOT NULL,
    population_type    VARCHAR(64) NOT NULL,
    population_entity_type VARCHAR(16) NOT NULL CHECK (population_entity_type IN ('TASK_PAIR','TASK_RUN')),
    task_count         INTEGER NOT NULL,
    fact_version       VARCHAR(64),
    estimator_version VARCHAR(64) NOT NULL,
    population_ids_uri  TEXT NOT NULL,
    population_ids_hash VARCHAR(128) NOT NULL,
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE metric_result (
    metric_result_id      VARCHAR(64) PRIMARY KEY,
    evaluation_id         VARCHAR(64) NOT NULL,
    calculation_run_id    VARCHAR(64) NOT NULL,
    population_snapshot_id VARCHAR(64) NOT NULL,
    metric_id             VARCHAR(32) NOT NULL CHECK (metric_id IN
                          ('M1','M2','M3','M4','M5','M6','M7','M8','M9','M10','M11','M12')),
    metric_name           VARCHAR(128) NOT NULL,
    metric_version        VARCHAR(64) NOT NULL DEFAULT '1.0',
    estimate              DECIMAL(20,6),
    unit                  VARCHAR(32),
    n                     INTEGER NOT NULL,
    n_population          VARCHAR(64),
    median                DECIMAL(20,6),
    q1                    DECIMAL(20,6),
    q3                    DECIMAL(20,6),
    iqr                   DECIMAL(20,6),
    reason_code           VARCHAR(64),
    calculation_status    VARCHAR(32) NOT NULL DEFAULT 'CALCULATED'
                          CHECK (calculation_status IN ('CALCULATED','NA','BLOCKED','ERROR')),
    calculation_method    VARCHAR(128),
    details_json          JSON,
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (calculation_run_id, metric_id, metric_version)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_metric_eval ON metric_result(evaluation_id, metric_id);

CREATE TABLE statistical_result (
    statistical_result_id  VARCHAR(64) PRIMARY KEY,
    evaluation_id          VARCHAR(64) NOT NULL,
    calculation_run_id     VARCHAR(64) NOT NULL,
    population_snapshot_id VARCHAR(64) NOT NULL,
    metric_id              VARCHAR(32),
    metric_version         VARCHAR(64) NOT NULL DEFAULT '1.0',
    test_name              VARCHAR(128) NOT NULL,
    statistic              DECIMAL(20,6),
    p_value                DECIMAL(20,6),
    alternative            VARCHAR(64),
    effect_size            DECIMAL(20,6),
    effect_type            VARCHAR(64),
    ci_lower               DECIMAL(20,6),
    ci_upper               DECIMAL(20,6),
    testing_tier           VARCHAR(32) NOT NULL CHECK (testing_tier IN ('PRIMARY','SECONDARY')),
    scope_type             VARCHAR(16) NOT NULL DEFAULT 'METRIC' CHECK (scope_type IN ('METRIC','JOINT')),
    joint_analysis_id      VARCHAR(64),
    related_metric_ids     JSON,
    joint_result_id        VARCHAR(64),
    correction_method      VARCHAR(64),
    method_version         VARCHAR(64) NOT NULL DEFAULT '1.0',
    status                 VARCHAR(32) NOT NULL DEFAULT 'CALCULATED'
                          CHECK (status IN ('CALCULATED','NA','BLOCKED','ERROR')),
    reason_code            VARCHAR(64),
    details_json           JSON,
    created_at             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    identity_key VARCHAR(64) GENERATED ALWAYS AS (COALESCE(metric_id, joint_analysis_id)) STORED,
    UNIQUE (calculation_run_id, identity_key, test_name)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE evaluation_report (
    report_id           VARCHAR(64) PRIMARY KEY,
    evaluation_id       VARCHAR(64) NOT NULL,
    calculation_run_id  VARCHAR(64) NOT NULL,
    snapshot_id         VARCHAR(64) NOT NULL,
    report_version      VARCHAR(64) NOT NULL DEFAULT '1.0',
    json_uri            TEXT,
    html_uri            TEXT,
    content_hash        VARCHAR(128),
    report_model_name    VARCHAR(256),
    report_model_version VARCHAR(64),
    report_prompt_hash   VARCHAR(128),
    report_code_hash     VARCHAR(128),
    report_config_hash   VARCHAR(128),
    report_config_json   JSON,
    status              VARCHAR(32) NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING','READY','DEGRADED','FAILED')),
    updated_at          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_at          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (calculation_run_id, report_version)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== L4 QA =====

CREATE TABLE exclusion_record (
    exclusion_id          VARCHAR(64) PRIMARY KEY,
    evaluation_id         VARCHAR(64) NOT NULL,
    task_id               VARCHAR(128) NOT NULL,
    `condition`             VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN'
                          CHECK (`condition` IN ('KG','NOGK','UNKNOWN')),
    exclusion_stage       VARCHAR(64) NOT NULL,
    exclusion_reason      VARCHAR(64) NOT NULL,
    detail                TEXT,
    created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (evaluation_id, task_id, `condition`, exclusion_stage, exclusion_reason)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_excl_reason ON exclusion_record(evaluation_id, exclusion_reason);

CREATE TABLE evaluation_coverage (
    coverage_id               VARCHAR(64) PRIMARY KEY,
    evaluation_id             VARCHAR(64) NOT NULL UNIQUE,
    total_benchmark_tasks     INTEGER NOT NULL DEFAULT 0,
    valid_paired_tasks        INTEGER NOT NULL DEFAULT 0,
    outcome_valid_tasks       INTEGER NOT NULL DEFAULT 0,
    jsd_valid_tasks           INTEGER NOT NULL DEFAULT 0,
    token_valid_tasks         INTEGER NOT NULL DEFAULT 0,
    steps_valid_tasks         INTEGER NOT NULL DEFAULT 0,
    time_valid_tasks          INTEGER NOT NULL DEFAULT 0,
    pairing_coverage          DECIMAL(10,6),
    outcome_coverage          DECIMAL(10,6),
    access_valid_tasks        INTEGER NOT NULL DEFAULT 0,
    delivery_valid_tasks      INTEGER NOT NULL DEFAULT 0,
    kg_ready_count            INTEGER NOT NULL DEFAULT 0,
    kg_mount_failed_count     INTEGER NOT NULL DEFAULT 0,
    kg_unavailable_count      INTEGER NOT NULL DEFAULT 0,
    kg_unknown_count          INTEGER NOT NULL DEFAULT 0,
    kg_not_applicable_count   INTEGER NOT NULL DEFAULT 0,
    unpaired_count            INTEGER NOT NULL DEFAULT 0,
    outcome_undetermined_count INTEGER NOT NULL DEFAULT 0,
    benchmark_unmatched_count INTEGER NOT NULL DEFAULT 0,
    trace_invalid_count       INTEGER NOT NULL DEFAULT 0,
    token_invalid_count       INTEGER NOT NULL DEFAULT 0,
    step_invalid_count        INTEGER NOT NULL DEFAULT 0,
    time_invalid_count        INTEGER NOT NULL DEFAULT 0,
    jsd_invalid_count         INTEGER NOT NULL DEFAULT 0,
    details_json              JSON,
    created_at                DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== Control Plane =====

CREATE TABLE evaluation_stage_run (
    stage_run_id      VARCHAR(64) PRIMARY KEY,
    evaluation_id     VARCHAR(64) NOT NULL,
    stage             VARCHAR(64) NOT NULL
                      CHECK (stage IN ('VALIDATE','INGEST','PARSE','RESOLVE','PAIR','METRIC','STATISTICS','DIAGNOSIS','REPORT','FINALIZE')),
    status            VARCHAR(32) NOT NULL
                      CHECK (status IN ('PENDING','RUNNING','COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCELLED')),
    started_at        DATETIME(3),
    completed_at      DATETIME(3),
    total_jobs        BIGINT DEFAULT 0,
    success_jobs      BIGINT DEFAULT 0,
    failed_jobs       BIGINT DEFAULT 0,
    version           BIGINT NOT NULL DEFAULT 0,
    UNIQUE (evaluation_id, stage)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE evaluation_job (
    job_id             VARCHAR(64) PRIMARY KEY,
    evaluation_id      VARCHAR(64) NOT NULL,
    stage_run_id       VARCHAR(64) NOT NULL,
    job_type           VARCHAR(64) NOT NULL,
    task_id            VARCHAR(128),
    metric_id          VARCHAR(32),
    status             VARCHAR(32) NOT NULL
                       CHECK (status IN ('PENDING','READY','RUNNING','SUCCESS','FAILED','RETRY_WAIT','FAILED_PERMANENT')),
    attempt            INTEGER NOT NULL DEFAULT 0,
    max_attempts       INTEGER NOT NULL DEFAULT 3,
    available_at       DATETIME(3) NOT NULL,
    started_at         DATETIME(3),
    completed_at       DATETIME(3),
    worker_id          VARCHAR(128),
    idempotency_key    VARCHAR(512) NOT NULL,
    error_code         VARCHAR(128),
    error_message      TEXT,
    version            BIGINT NOT NULL DEFAULT 0,
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE(idempotency_key)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_job_ready ON evaluation_job(status, available_at);

CREATE TABLE job_lease (
    job_id          VARCHAR(64) PRIMARY KEY,
    worker_id       VARCHAR(128) NOT NULL,
    lease_token     VARCHAR(128) NOT NULL,
    acquired_at     DATETIME(3) NOT NULL,
    heartbeat_at    DATETIME(3) NOT NULL,
    expire_at       DATETIME(3) NOT NULL,
    version         BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE evaluation_state_transition (
    transition_id   BIGINT AUTO_INCREMENT PRIMARY KEY,
    evaluation_id   VARCHAR(64) NOT NULL,
    from_status     VARCHAR(32),
    to_status       VARCHAR(32) NOT NULL,
    reason          VARCHAR(512),
    actor_type      VARCHAR(32),
    actor_id        VARCHAR(128),
    created_at      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE outbox_event (
    event_id        VARCHAR(64) PRIMARY KEY,
    aggregate_type  VARCHAR(64) NOT NULL,
    aggregate_id    VARCHAR(64) NOT NULL,
    event_type      VARCHAR(64) NOT NULL,
    payload         JSON NOT NULL,
    published       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    published_at    DATETIME(3)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== §7.27 显式 FOREIGN KEY =====

ALTER TABLE evaluation_snapshot
    ADD CONSTRAINT fk_snapshot_evaluation
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE trace_source
    ADD CONSTRAINT fk_trace_evaluation
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE benchmark_item
    ADD CONSTRAINT fk_bitem_bset
    FOREIGN KEY (benchmark_set_id) REFERENCES benchmark_set(benchmark_set_id);

ALTER TABLE task_run
    ADD CONSTRAINT fk_trun_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE task_run
    ADD CONSTRAINT fk_trun_trace
    FOREIGN KEY (trace_id) REFERENCES trace_source(trace_id);

ALTER TABLE task_run
    ADD CONSTRAINT fk_trun_bitem
    FOREIGN KEY (benchmark_item_id) REFERENCES benchmark_item(benchmark_item_id);

ALTER TABLE task_pair
    ADD CONSTRAINT fk_tpair_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE task_pair
    ADD CONSTRAINT fk_tpair_nogk
    FOREIGN KEY (evaluation_id, nogk_task_run_id) REFERENCES task_run(evaluation_id, task_run_id);

ALTER TABLE task_pair
    ADD CONSTRAINT fk_tpair_kg
    FOREIGN KEY (evaluation_id, kg_task_run_id) REFERENCES task_run(evaluation_id, task_run_id);

ALTER TABLE task_pair
    ADD CONSTRAINT fk_tpair_bitem
    FOREIGN KEY (benchmark_item_id) REFERENCES benchmark_item(benchmark_item_id);

ALTER TABLE outcome_fact
    ADD CONSTRAINT fk_ofact_trun
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id);

ALTER TABLE knowledge_interaction_fact
    ADD CONSTRAINT fk_kif_trun
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id);

ALTER TABLE tool_action_fact
    ADD CONSTRAINT fk_taf_trun
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id);

ALTER TABLE resource_fact
    ADD CONSTRAINT fk_rf_trun
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id);

ALTER TABLE finding_benchmark_match
    ADD CONSTRAINT fk_fbm_trun
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id);

ALTER TABLE finding_benchmark_match
    ADD CONSTRAINT fk_fbm_bitem
    FOREIGN KEY (benchmark_item_id) REFERENCES benchmark_item(benchmark_item_id);

ALTER TABLE pair_derived_fact
    ADD CONSTRAINT fk_pdf_pair
    FOREIGN KEY (evaluation_id, task_pair_id) REFERENCES task_pair(evaluation_id, task_pair_id);

ALTER TABLE evaluation_calculation_run
    ADD CONSTRAINT fk_crun_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE evaluation_calculation_run
    ADD CONSTRAINT fk_crun_snapshot
    FOREIGN KEY (config_snapshot_id) REFERENCES evaluation_snapshot(snapshot_id);

ALTER TABLE evaluation_population_snapshot
    ADD CONSTRAINT fk_popsnap_crun
    FOREIGN KEY (calculation_run_id) REFERENCES evaluation_calculation_run(calculation_run_id);

ALTER TABLE metric_result
    ADD CONSTRAINT fk_mr_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE metric_result
    ADD CONSTRAINT fk_mr_popsnap
    FOREIGN KEY (population_snapshot_id) REFERENCES evaluation_population_snapshot(population_snapshot_id);

ALTER TABLE metric_result
    ADD CONSTRAINT fk_mr_crun
    FOREIGN KEY (calculation_run_id) REFERENCES evaluation_calculation_run(calculation_run_id);

ALTER TABLE statistical_result
    ADD CONSTRAINT fk_sr_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE statistical_result
    ADD CONSTRAINT fk_sr_popsnap
    FOREIGN KEY (population_snapshot_id) REFERENCES evaluation_population_snapshot(population_snapshot_id);

ALTER TABLE statistical_result
    ADD CONSTRAINT fk_sr_crun
    FOREIGN KEY (calculation_run_id) REFERENCES evaluation_calculation_run(calculation_run_id);

ALTER TABLE evaluation_report
    ADD CONSTRAINT fk_report_crun
    FOREIGN KEY (calculation_run_id) REFERENCES evaluation_calculation_run(calculation_run_id);

ALTER TABLE evaluation_report
    ADD CONSTRAINT fk_report_snap
    FOREIGN KEY (snapshot_id) REFERENCES evaluation_snapshot(snapshot_id);

ALTER TABLE evaluation_report
    ADD CONSTRAINT fk_report_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE exclusion_record
    ADD CONSTRAINT fk_excl_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE evaluation_coverage
    ADD CONSTRAINT fk_cov_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE evaluation_stage_run
    ADD CONSTRAINT fk_stage_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE evaluation_job
    ADD CONSTRAINT fk_job_stage
    FOREIGN KEY (stage_run_id) REFERENCES evaluation_stage_run(stage_run_id);

ALTER TABLE evaluation_job
    ADD CONSTRAINT fk_job_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE job_lease
    ADD CONSTRAINT fk_lease_job
    FOREIGN KEY (job_id) REFERENCES evaluation_job(job_id);

ALTER TABLE evaluation_state_transition
    ADD CONSTRAINT fk_trans_eval
    FOREIGN KEY (evaluation_id) REFERENCES evaluation(evaluation_id);

ALTER TABLE trace_artifact
    ADD CONSTRAINT fk_artifact_trace
    FOREIGN KEY (trace_id) REFERENCES trace_source(trace_id);

ALTER TABLE evaluation
    ADD CONSTRAINT fk_eval_bset
    FOREIGN KEY (benchmark_set_id) REFERENCES benchmark_set(benchmark_set_id);

-- Migration: add AI_MATCHING to evaluation_status CHECK (for existing deployments)
ALTER TABLE evaluation DROP CHECK evaluation_chk_1;
ALTER TABLE evaluation ADD CONSTRAINT evaluation_status_chk CHECK (evaluation_status IN
    ('CREATED','QUEUED','RUNNING','VALIDATING','INGESTING','PARSING','AI_MATCHING','RESOLVING','PAIRING',
     'CALCULATING','STATISTICAL_ANALYSIS','DIAGNOSING','REPORTING','FINALIZING',
     'COMPLETED','COMPLETED_WITH_WARNINGS','FAILED',
     'CANCEL_REQUESTED','CANCELLING','CANCELLED'));

-- Migration: add M11/M12 to metric_result CHECK (for existing deployments)
ALTER TABLE metric_result DROP CHECK metric_result_chk_1;
ALTER TABLE metric_result ADD CONSTRAINT metric_result_metric_id_chk CHECK (metric_id IN
    ('M1','M2','M3','M4','M5','M6','M7','M8','M9','M10','M11','M12'));
