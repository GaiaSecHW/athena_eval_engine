# DDL 定稿——知识效果评测引擎

> 本文为两张新增表的完整 DDL 定稿，基于 `docs/knowledge-effect-eval-requirements.md` §3.1/§3.4 草案，经设计问题解决后定稿。
> 所有 DDL 遵循现有 `schema.sql` 约定：`ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`，显式 FK 约束。

---

## 1. knowledge_access_detail（知识访问明细表）

### 1.1 设计决策

| 问题 | 决策 | 理由 |
|------|------|------|
| business_phase 单值 | 每次知识访问一条记录，business_phase 存单一值 | 一个 session 可能跨多个阶段，但第三层 LLM 细分后每次知识访问被归到单一阶段 |
| cause_code 单值 | 每条记录对应一次知识访问的一个阶段，cause_code 为单一值 | 一个 case 可能在多个阶段有断点，但每条记录只对应一个阶段的一个断点 |
| 大字段存储 | 新增 `evidence_file` 列存大文件路径 | query_content / returned_content / reasoning_ref / evidence_json 可能是大文本，超过 64KB 写入 `{reports_dir}/{eid}_lifecycle_data/` 目录，DB 列存文件路径 |
| source_system 值 | `KNOWLEDGE_BASE` / `MEMORY_ENGINE` | 与现有 `is_kg_interaction` / `is_memory_interaction` 二分法对齐 |
| effect_label 值 | `POSITIVE` / `NEGATIVE` / `NEUTRAL` | — |
| cause_code 值 | `A` / `B` / `C` / `D` / `E` / `F` / `G` / `H` / `NULL` | L1=False 时不产生断链，cause_code 为 NULL |

### 1.2 完整 DDL

```sql
CREATE TABLE IF NOT EXISTS knowledge_access_detail (
    access_id            VARCHAR(128) PRIMARY KEY,
    evaluation_id        VARCHAR(64) NOT NULL,
    task_run_id          VARCHAR(64) NOT NULL,
    task_id              VARCHAR(128) NOT NULL,
    event_idx            INT NOT NULL,
    source_system        VARCHAR(32) NOT NULL
                         CHECK (source_system IN ('KNOWLEDGE_BASE','MEMORY_ENGINE')),
    l0_origin            VARCHAR(64),
    business_phase       VARCHAR(32) NOT NULL
                         CHECK (business_phase IN
                         ('ENTRY_IDENTIFICATION','DATA_FLOW_TRACKING','VULN_PATTERN_RECOGNITION',
                          'SINK_POINT_LOCALIZATION','VULN_VERDICT_REPORTING',
                          'VULN_UNDERSTANDING','CODE_LOCALIZATION','VERIFICATION_EXECUTION','VERDICT_REPORTING')),
    l1_need_knowledge    BOOLEAN,
    l2_initiated         BOOLEAN,
    l3_query_accurate    BOOLEAN,
    l4_knowledge_exists  BOOLEAN,
    l5_retrieved         BOOLEAN,
    l6_used              BOOLEAN,
    l7_influenced        BOOLEAN,
    l7_method            VARCHAR(32),
    effect_label         VARCHAR(16)
                         CHECK (effect_label IS NULL OR effect_label IN ('POSITIVE','NEGATIVE','NEUTRAL')),
    cause_code           VARCHAR(8)
                         CHECK (cause_code IS NULL OR cause_code IN ('A','B','C','D','E','F','G','H')),
    query_content        TEXT,
    returned_content     TEXT,
    reasoning_ref        TEXT,
    judgment_conclusion  TEXT,
    evidence_json        JSON,
    evidence_file        TEXT,
    created_at           DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id, event_idx),
    INDEX idx_kad_eval (evaluation_id),
    INDEX idx_kad_phase (evaluation_id, business_phase),
    INDEX idx_kad_effect (evaluation_id, effect_label),
    INDEX idx_kad_cause (evaluation_id, cause_code),
    CONSTRAINT fk_kad_trun FOREIGN KEY (evaluation_id, task_run_id)
        REFERENCES task_run(evaluation_id, task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 1.3 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `access_id` | VARCHAR(128) PK | 格式 `{evaluation_id}_{task_run_id}_{event_idx}` |
| `evaluation_id` | VARCHAR(64) NOT NULL | 关联 evaluation 表 |
| `task_run_id` | VARCHAR(64) NOT NULL | 关联 task_run 表 |
| `task_id` | VARCHAR(128) NOT NULL | 任务 ID |
| `event_idx` | INT NOT NULL | 对应 RawEvent 在 events 列表中的序号 |
| `source_system` | VARCHAR(32) NOT NULL | `KNOWLEDGE_BASE`=知识库 / `MEMORY_ENGINE`=记忆进化 |
| `l0_origin` | VARCHAR(64) | L0 知识原始来源（用户上传/历史漏洞经验/已有知识升华等，仅标记 provenance，不参与断链判定） |
| `business_phase` | VARCHAR(32) NOT NULL | 业务流程阶段（见下方枚举映射） |
| `l1_need_knowledge` | BOOLEAN | 该阶段是否需要知识（LLM 判定） |
| `l2_initiated` | BOOLEAN | 该阶段是否发起访问（程序判定） |
| `l3_query_accurate` | BOOLEAN | 查询是否聚焦于该阶段（LLM 判定） |
| `l4_knowledge_exists` | BOOLEAN | 返回内容是否非空（程序判定） |
| `l5_retrieved` | BOOLEAN | 工具是否成功取回（程序判定） |
| `l6_used` | BOOLEAN | 该阶段推理是否引用（LLM 判定） |
| `l7_influenced` | BOOLEAN NULL | 是否影响该阶段结论（LLM 判定，NULL=无法确认） |
| `l7_method` | VARCHAR(32) | L7 判定方法（`EVIDENCE_CHAIN`） |
| `effect_label` | VARCHAR(16) | `POSITIVE` / `NEGATIVE` / `NEUTRAL` / `NULL`（L1=False 时为 NULL） |
| `cause_code` | VARCHAR(8) | `A`–`H` / `NULL`（L1=False 时不产生断链） |
| `query_content` | TEXT | 查询内容（超过 64KB 存文件，此列存路径） |
| `returned_content` | TEXT | 返回内容摘要（超过 64KB 存文件，此列存路径） |
| `reasoning_ref` | TEXT | 推理引用片段（超过 64KB 存文件，此列存路径） |
| `judgment_conclusion` | TEXT | 判定结论 |
| `evidence_json` | JSON | 完整证据（LLM 分析结果等，超过 64KB 存文件） |
| `evidence_file` | TEXT | 大文件路径（`{reports_dir}/{eid}_lifecycle_data/{access_id}_{field}.json`） |
| `created_at` | DATETIME(3) | 记录创建时间 |

### 1.4 business_phase 枚举映射

| 枚举值 | 中文 | 适用 Agent |
|--------|------|-----------|
| `ENTRY_IDENTIFICATION` | 入口识别 | 挖掘 Agent |
| `DATA_FLOW_TRACKING` | 数据流追踪 | 挖掘 Agent |
| `VULN_PATTERN_RECOGNITION` | 漏洞模式识别 | 挖掘 Agent |
| `SINK_POINT_LOCALIZATION` | Sink 点定位 | 挖掘 Agent |
| `VULN_VERDICT_REPORTING` | 漏洞判定与上报 | 挖掘 Agent |
| `VULN_UNDERSTANDING` | 漏洞理解 | 验证 Agent |
| `CODE_LOCALIZATION` | 代码定位 | 验证 Agent |
| `VERIFICATION_EXECUTION` | 验证执行 | 验证 Agent |
| `VERDICT_REPORTING` | 判定上报 | 验证 Agent |

### 1.5 cause_code 断点映射

| cause_code | 断点位置 | 含义 | 责任方 |
|------------|---------|------|--------|
| `A` | L2 断 | 该查没查 | Agent |
| `B` | L3 断 | 查询太泛 | Agent |
| `C` | L4 断 | 查了没得 | 知识方 |
| `D` | L5 断 | 链路问题 | Agent + 知识方 |
| `E` | L6 断 | 查到没用 | Agent |
| `F` | L7 断 | 用了没推动 | Agent / 知识方 |
| `G` | L7 负向 | 导致误判 | 知识方 |
| `H` | G 的根因 | 内容有误 | 知识方 |
| `NULL` | — | L1=False 不产生断链 | — |

### 1.6 DB 写入约束

| 约束 | 说明 |
|------|------|
| 大字段文件存储 | `query_content` / `returned_content` / `reasoning_ref` / `evidence_json` 超过 64KB 时写入 `{reports_dir}/{eid}_lifecycle_data/` 目录，DB 列存文件路径到 `evidence_file` |
| 幂等写入 | `INSERT ... ON DUPLICATE KEY UPDATE`，以 `UNIQUE(task_run_id, event_idx)` 为冲突键 |
| NaN/Inf 清洗 | `evidence_json` 中 LLM 返回的 `confidence` 等浮点字段可能含 NaN/Inf，写入前用 `_clean_nan_inf()` 清洗 |
| 批量写入 | 一个 task_run 的全部 knowledge_access_detail 记录批量 INSERT，不逐条写入 |

---

## 2. agent_datasource_config（Agent 数据源配置表）

### 2.1 设计决策

| 问题 | 决策 | 理由 |
|------|------|------|
| relation_tables JSON 结构 | 按 Agent 类型定制，字段名对照实际 Agent DB schema | 各 Agent DB schema 差异大，统一结构反而冗余 |
| phase_identifier JSON 结构 | 按 Agent 类型定制 | 各 Agent 阶段标识符来源不同 |
| DataflowVulnScan database_name | 模板 `dvs_{project_id}` | 每个 project 一个库，运行时替换 `{project_id}` 占位符 |
| WebVulnVerify db_type | `none` | 无独立 DB，session 信息在 JSONL trace 中 |
| 版本控制 | 复用 `system_config` 的 `_version` 机制 | 修改后递增 `_version`，watcher 轮询触发重载 |

### 2.2 完整 DDL

```sql
CREATE TABLE IF NOT EXISTS agent_datasource_config (
    id                 INT AUTO_INCREMENT PRIMARY KEY,
    agent_type         VARCHAR(32) NOT NULL UNIQUE
                       CHECK (agent_type IN ('turing','argo','secmate','cvuln_verify','webvuln_verify','dataflow')),
    display_name       VARCHAR(64) NOT NULL,
    db_type            VARCHAR(16) NOT NULL
                       CHECK (db_type IN ('mysql','postgresql','none')),
    host               VARCHAR(256),
    port               INT,
    username           VARCHAR(64),
    password           VARCHAR(256),
    database_name      VARCHAR(128),
    relation_tables    JSON,
    phase_identifier   JSON,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    last_connected_at  DATETIME(3),
    last_error         TEXT,
    _version           INT NOT NULL DEFAULT 1,
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    INDEX idx_adc_type (agent_type)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 2.3 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INT AUTO_INCREMENT PK | 自增主键 |
| `agent_type` | VARCHAR(32) UNIQUE | Agent 类型枚举：`turing`/`argo`/`secmate`/`cvuln_verify`/`webvuln_verify`/`dataflow` |
| `display_name` | VARCHAR(64) | 显示名称（如 "Turing MySQL"） |
| `db_type` | VARCHAR(16) | `mysql` / `postgresql` / `none` |
| `host` | VARCHAR(256) | k8s 内 svc 地址 |
| `port` | INT | 端口 |
| `username` | VARCHAR(64) | 用户名 |
| `password` | VARCHAR(256) | 明文存储（k8s 内网，与现有各 Agent DB 一致） |
| `database_name` | VARCHAR(128) | 库名（DataflowVulnScan 为模板 `dvs_{project_id}`，运行时替换） |
| `relation_tables` | JSON | 关系表配置（表名、关系字段），供 parser `build_session_graph()` 查询 |
| `phase_identifier` | JSON | 阶段标识符配置（表名、字段名、映射逻辑），供 parser `label_session_phases()` 查询 |
| `enabled` | BOOLEAN | 是否启用此数据源 |
| `last_connected_at` | DATETIME(3) | 最近成功连接时间 |
| `last_error` | TEXT | 最近连接错误信息 |
| `_version` | INT | 修改后递增，watcher 轮询触发重载（复用 `system_config` 机制） |
| `created_at` | DATETIME(3) | 创建时间 |
| `updated_at` | DATETIME(3) | 更新时间 |

### 2.4 初始数据（INSERT IGNORE）

```sql
INSERT IGNORE INTO agent_datasource_config
    (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled)
VALUES
(
    'turing', 'Turing MySQL', 'mysql',
    'turing-app-security-mysql.secflow-ns.svc.cluster.local', 3306,
    'root', 'turing_app_security_pass', 'turing_app_security',
    JSON_OBJECT(
        'task_table', 'turing_task',
        'parent_field', 'parent_task_id',
        'session_field', 'agent_session_id',
        'task_type_field', 'task_type',
        'agent_name_field', 'agent_name',
        'trace_table', 'turing_task_trace',
        'investigation_table', 'turing_investigation',
        'investigation_parent_field', 'parent_investigation_id',
        'investigation_origin_field', 'origin_detection_id',
        'investigation_target_field', 'target_task_id',
        'investigation_depth_field', 'depth'
    ),
    JSON_OBJECT(
        'table', 'turing_task',
        'id_field', 'agent_session_id',
        'label_fields', JSON_ARRAY('agent_name', 'task_type')
    ),
    1
),
(
    'argo', 'Argo MySQL', 'mysql',
    'chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local', 3306,
    'root', 'Icsl_argo', 'argo_c',
    JSON_OBJECT(
        'table', 'intents',
        'session_field', 'session_id',
        'fact_field', 'to_fact_id',
        'suggestion_field', 'suggestion_refs',
        'task_type_field', 'task_type'
    ),
    JSON_OBJECT(
        'table', 'intents',
        'id_field', 'session_id',
        'label_field', 'task_type'
    ),
    1
),
(
    'secmate', 'SecMate MySQL', 'mysql',
    'secmate-mysql.secflow-ns.svc.cluster.local', 3306,
    'root', 'Huawei12#$', 'secmate',
    JSON_OBJECT(
        'finding_table', 'finding',
        'finding_id_field', 'id',
        'source_field', 'source_finding_id',
        'vuln_type_field', 'vuln_type',
        'level_field', 'level',
        'file_path_field', 'file_path',
        'fingerprint_field', 'fingerprint',
        'task_table', 'task',
        'task_tool_task_id_field', 'tool_task_id',
        'task_external_task_id_field', 'external_task_id',
        'task_file_path_field', 'file_path'
    ),
    JSON_OBJECT(
        'source', 'trace',
        'note', 'persona and finding level extracted from JSONL trace; DB has no persona field'
    ),
    1
),
(
    'dataflow', 'DataflowVulnScan MySQL', 'mysql',
    'secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local', 3306,
    'root', 'Huawei12#$', 'dvs_{project_id}',
    JSON_OBJECT(
        'sessions_table', 'dvs_task_graph_sessions',
        'session_relpath_field', 'session_relpath',
        'session_task_id_field', 'task_id',
        'session_node_id_field', 'node_id',
        'session_edge_id_field', 'edge_id',
        'session_role_field', 'session_role',
        'session_kind_field', 'session_kind',
        'nodes_table', 'dvs_task_graph_nodes',
        'node_id_field', 'node_id',
        'node_task_id_field', 'task_id',
        'node_depth_field', 'depth',
        'node_primary_session_field', 'primary_session_relpath',
        'edges_table', 'dvs_task_graph_edges',
        'edge_id_field', 'edge_id',
        'edge_task_id_field', 'task_id',
        'edge_source_node_field', 'source_node_id',
        'edge_target_node_field', 'target_node_id',
        'edge_source_func_field', 'source_func_id',
        'edge_target_func_field', 'target_func_id',
        'fallback_table', 'orchestration',
        'fallback_edge_id_field', 'edge_id',
        'fallback_path_id_field', 'path_id',
        'fallback_source_func_field', 'source_func_id',
        'fallback_target_func_field', 'target_func_id',
        'fallback_task_id_field', 'task_id'
    ),
    JSON_OBJECT(
        'source', 'filename',
        'field', 'analysisType',
        'note', 'analysisType extracted from JSONL filename; DB has no direct phase identifier column'
    ),
    1
),
(
    'cvuln_verify', 'CVulnVerify PostgreSQL', 'postgresql',
    'secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local', 5432,
    'postgres', 'secflow123', 'secflow_vuln_verify_v2',
    JSON_OBJECT(
        'attempt_table', 'vuln_verify_attempt',
        'attempt_id_field', 'id',
        'attempt_task_id_field', 'task_id',
        'worker_type_field', 'worker_type',
        'predecessor_field', 'predecessor_attempt_id',
        'successor_reason_field', 'successor_reason',
        'status_field', 'status',
        'task_table', 'vuln_verify_task',
        'task_id_field', 'id',
        'task_project_id_field', 'project_id',
        'task_case_id_field', 'case_id',
        'task_vuln_id_field', 'vuln_id',
        'task_file_field', 'file',
        'task_function_field', 'function',
        'task_business_task_id_field', 'business_task_id'
    ),
    JSON_OBJECT(
        'table', 'vuln_verify_attempt',
        'id_field', 'id',
        'label_field', 'worker_type'
    ),
    1
),
(
    'webvuln_verify', 'WebVulnVerify (无独立DB)', 'none',
    NULL, NULL, NULL, NULL, NULL,
    JSON_OBJECT(
        'source', 'trace',
        'parent_field', 'session.parent_id',
        'vuln_id_field', 'metadata.vulnerability_id'
    ),
    JSON_OBJECT(
        'source', 'trace',
        'tool_field', 'tool_call.name'
    ),
    1
);
```

### 2.5 relation_tables JSON 结构说明

#### Turing (`turing`)

| JSON key | 对应 DB 字段 | 说明 |
|----------|-------------|------|
| `task_table` | `turing_task` | 任务表 |
| `parent_field` | `parent_task_id` | 父任务 ID 字段 |
| `session_field` | `agent_session_id` | session 标识符字段 |
| `task_type_field` | `task_type` | 任务类型字段 |
| `agent_name_field` | `agent_name` | Agent 名称字段 |
| `trace_table` | `turing_task_trace` | trace 关系表 |
| `investigation_table` | `turing_investigation` | 调查关系表 |
| `investigation_parent_field` | `parent_investigation_id` | 父调查 ID |
| `investigation_origin_field` | `origin_detection_id` | 原始检测 ID |
| `investigation_target_field` | `target_task_id` | 目标任务 ID |
| `investigation_depth_field` | `depth` | 深度字段 |

#### Argo (`argo`)

| JSON key | 对应 DB 字段 | 说明 |
|----------|-------------|------|
| `table` | `intents` | 意图表 |
| `session_field` | `session_id` | session 标识符 |
| `fact_field` | `to_fact_id` | 目标 fact ID |
| `suggestion_field` | `suggestion_refs` | 建议引用 |
| `task_type_field` | `task_type` | 任务类型（bootstrap/investigate/verify/reason） |

#### SecMate (`secmate`)

| JSON key | 对应 DB 字段 | 说明 |
|----------|-------------|------|
| `finding_table` | `finding` | finding 表 |
| `finding_id_field` | `id` | finding ID |
| `source_field` | `source_finding_id` | 源 finding ID（关系字段） |
| `vuln_type_field` | `vuln_type` | 漏洞类型 |
| `level_field` | `level` | finding 级别 |
| `file_path_field` | `file_path` | 文件路径 |
| `fingerprint_field` | `fingerprint` | 指纹 |
| `task_table` | `task` | 任务表 |
| `task_tool_task_id_field` | `tool_task_id` | 工具任务 ID |
| `task_external_task_id_field` | `external_task_id` | 外部任务 ID |
| `task_file_path_field` | `file_path` | 文件路径 |

#### DataflowVulnScan (`dataflow`)

| JSON key | 对应 DB 字段 | 说明 |
|----------|-------------|------|
| `sessions_table` | `dvs_task_graph_sessions` | session 关系表 |
| `session_relpath_field` | `session_relpath` | session 相对路径 |
| `session_task_id_field` | `task_id` | 任务 ID |
| `session_node_id_field` | `node_id` | 节点 ID |
| `session_edge_id_field` | `edge_id` | 边 ID |
| `session_role_field` | `session_role` | session 角色 |
| `session_kind_field` | `session_kind` | session 类型 |
| `nodes_table` | `dvs_task_graph_nodes` | 节点表 |
| `node_id_field` | `node_id` | 节点 ID |
| `node_task_id_field` | `task_id` | 任务 ID |
| `node_depth_field` | `depth` | 深度 |
| `node_primary_session_field` | `primary_session_relpath` | 主 session 路径 |
| `edges_table` | `dvs_task_graph_edges` | 边表 |
| `edge_id_field` | `edge_id` | 边 ID |
| `edge_task_id_field` | `task_id` | 任务 ID |
| `edge_source_node_field` | `source_node_id` | 源节点 |
| `edge_target_node_field` | `target_node_id` | 目标节点 |
| `edge_source_func_field` | `source_func_id` | 源函数 ID |
| `edge_target_func_field` | `target_func_id` | 目标函数 ID |
| `fallback_table` | `orchestration` | 老版本兼容表 |
| `fallback_edge_id_field` | `edge_id` | 边 ID |
| `fallback_path_id_field` | `path_id` | 路径 ID |
| `fallback_source_func_field` | `source_func_id` | 源函数 ID |
| `fallback_target_func_field` | `target_func_id` | 目标函数 ID |
| `fallback_task_id_field` | `task_id` | 任务 ID |

> `database_name` = `dvs_{project_id}`：运行时将 `{project_id}` 替换为实际项目 ID，每个 project 一个独立库。

#### CVulnVerify (`cvuln_verify`)

| JSON key | 对应 DB 字段 | 说明 |
|----------|-------------|------|
| `attempt_table` | `vuln_verify_attempt` | 验证尝试表 |
| `attempt_id_field` | `id` | 尝试 ID |
| `attempt_task_id_field` | `task_id` | 任务 ID |
| `worker_type_field` | `worker_type` | worker 类型（source-verifier/c-formal-verifier/binary-instrumentation-poc） |
| `predecessor_field` | `predecessor_attempt_id` | 前驱尝试 ID（关系字段） |
| `successor_reason_field` | `successor_reason` | 后继原因 |
| `status_field` | `status` | 状态 |
| `task_table` | `vuln_verify_task` | 验证任务表 |
| `task_id_field` | `id` | 任务 ID |
| `task_project_id_field` | `project_id` | 项目 ID |
| `task_case_id_field` | `case_id` | case ID |
| `task_vuln_id_field` | `vuln_id` | 漏洞 ID |
| `task_file_field` | `file` | 文件 |
| `task_function_field` | `function` | 函数 |
| `task_business_task_id_field` | `business_task_id` | 业务任务 ID |

#### WebVulnVerify (`webvuln_verify`)

无独立 DB，`relation_tables` 和 `phase_identifier` 的 `source` 均为 `trace`，字段路径指向 JSONL trace 中的路径。

### 2.6 phase_identifier JSON 结构说明

| Agent | source | 标识符 | 获取方式 |
|-------|--------|--------|---------|
| Turing | DB | `agent_name` + `task_type` | DB 查询 `agent_session_id -> agent_name, task_type` |
| Argo | DB | `task_type` | DB 查询 `session_id -> task_type` |
| SecMate | trace | persona 名 + finding level | parser 从 trace 提取（DB 无 persona 字段） |
| DataflowVulnScan | filename | `analysisType` | parser 从 JSONL 文件名提取 |
| CVulnVerify | DB | `worker_type` | DB 查询 `attempt_id -> worker_type` |
| WebVulnVerify | trace | 工具名序列 | parser 从 trace `tool_call.name` 提取 |

### 2.7 环境变量覆盖

每个 Agent 数据源支持环境变量覆盖（优先级高于 DB 配置），命名规则 `EVAL_{AGENT}_DB_{KEY}`：

| 环境变量 | 说明 |
|---------|------|
| `EVAL_TURING_DB_HOST` | Turing MySQL host 覆盖 |
| `EVAL_TURING_DB_PORT` | Turing MySQL port 覆盖 |
| `EVAL_TURING_DB_USER` | Turing MySQL user 覆盖 |
| `EVAL_TURING_DB_PASSWORD` | Turing MySQL password 覆盖 |
| `EVAL_TURING_DB_NAME` | Turing MySQL database 覆盖 |
| `EVAL_ARGO_DB_HOST` | Argo MySQL host 覆盖 |
| `EVAL_ARGO_DB_PORT` | Argo MySQL port 覆盖 |
| `EVAL_ARGO_DB_USER` | Argo MySQL user 覆盖 |
| `EVAL_ARGO_DB_PASSWORD` | Argo MySQL password 覆盖 |
| `EVAL_ARGO_DB_NAME` | Argo MySQL database 覆盖 |
| `EVAL_SECMATE_DB_HOST` | SecMate MySQL host 覆盖 |
| `EVAL_SECMATE_DB_PORT` | SecMate MySQL port 覆盖 |
| `EVAL_SECMATE_DB_USER` | SecMate MySQL user 覆盖 |
| `EVAL_SECMATE_DB_PASSWORD` | SecMate MySQL password 覆盖 |
| `EVAL_SECMATE_DB_NAME` | SecMate MySQL database 覆盖 |
| `EVAL_DATAFLOW_DB_HOST` | DataflowVulnScan MySQL host 覆盖 |
| `EVAL_DATAFLOW_DB_PORT` | DataflowVulnScan MySQL port 覆盖 |
| `EVAL_DATAFLOW_DB_USER` | DataflowVulnScan MySQL user 覆盖 |
| `EVAL_DATAFLOW_DB_PASSWORD` | DataflowVulnScan MySQL password 覆盖 |
| `EVAL_DATAFLOW_DB_NAME` | DataflowVulnScan MySQL database 覆盖（覆盖模板 `dvs_{project_id}`） |
| `EVAL_CVULN_DB_HOST` | CVulnVerify PostgreSQL host 覆盖 |
| `EVAL_CVULN_DB_PORT` | CVulnVerify PostgreSQL port 覆盖 |
| `EVAL_CVULN_DB_USER` | CVulnVerify PostgreSQL user 覆盖 |
| `EVAL_CVULN_DB_PASSWORD` | CVulnVerify PostgreSQL password 覆盖 |
| `EVAL_CVULN_DB_NAME` | CVulnVerify PostgreSQL database 覆盖 |

> 环境变量优先级高于 DB 配置。`config_loader.py` 在读取 `agent_datasource_config` 表后，检查对应环境变量，有则覆盖。

### 2.8 配置界面 API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/v2/datasources` | GET | 列出全部 Agent 数据源配置（password 脱敏为 `***`） |
| `/api/v2/datasources/{agent_type}` | GET | 获取单个 Agent 数据源配置（password 脱敏为 `***`） |
| `/api/v2/datasources/{agent_type}` | PUT | 修改数据源配置（host/port/username/password/database_name/enabled），修改后递增 `_version` |
| `/api/v2/datasources/{agent_type}/test` | POST | 测试连接，返回连接结果（成功/失败+错误信息），更新 `last_connected_at` / `last_error` |

**密码脱敏规则**：GET 返回时 `password` 字段返回 `***`，不返回明文。PUT 时如果 `password` 字段为 `***` 或空则不更新密码。

**`_version` 递增规则**：PUT 成功后 `_version = _version + 1`，watcher 轮询检测到版本变化后重载内存配置。多 worker 部署时直接改 DB 必须递增 `_version`，否则 watcher 不重载。

---

## 3. 迁移脚本

### 3.1 迁移 007：knowledge_access_detail + metric_result CHECK 扩展

```python
{
    "id": "007_knowledge_access_detail",
    "desc": "新增知识访问明细表 + metric_result CHECK 扩展 M15-M21/M26",
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
        "  business_phase VARCHAR(32) NOT NULL"
        "    CHECK (business_phase IN"
        "    ('ENTRY_IDENTIFICATION','DATA_FLOW_TRACKING','VULN_PATTERN_RECOGNITION',"
        "     'SINK_POINT_LOCALIZATION','VULN_VERDICT_REPORTING',"
        "     'VULN_UNDERSTANDING','CODE_LOCALIZATION','VERIFICATION_EXECUTION','VERDICT_REPORTING')),"
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
        "    CHECK (cause_code IS NULL OR cause_code IN ('A','B','C','D','E','F','G','H')),"
        "  query_content TEXT,"
        "  returned_content TEXT,"
        "  reasoning_ref TEXT,"
        "  judgment_conclusion TEXT,"
        "  evidence_json JSON,"
        "  evidence_file TEXT,"
        "  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),"
        "  UNIQUE (task_run_id, event_idx),"
        "  INDEX idx_kad_eval (evaluation_id),"
        "  INDEX idx_kad_phase (evaluation_id, business_phase),"
        "  INDEX idx_kad_effect (evaluation_id, effect_label),"
        "  INDEX idx_kad_cause (evaluation_id, cause_code),"
        "  CONSTRAINT fk_kad_trun FOREIGN KEY (evaluation_id, task_run_id)"
        "    REFERENCES task_run(evaluation_id, task_run_id)"
        ") ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        # 2. metric_result CHECK 扩展（幂等：DROP IF EXISTS + ADD）
        "ALTER TABLE metric_result DROP CHECK IF EXISTS metric_result_metric_id_chk",
        "ALTER TABLE metric_result ADD CONSTRAINT metric_result_metric_id_chk"
        "  CHECK (metric_id IN"
        "  ('M1','M2','M3','M4','M5','M6','M7','M8','M9','M10','M11','M12','M13',"
        "   'M15','M16','M17','M18','M19','M20','M21','M26'))",
    ],
}
```

### 3.2 迁移 008：agent_datasource_config + 初始数据

```python
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
        "   'chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local', 3306,"
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
}
```

### 3.3 迁移注册位置

在 `infrastructure/migrations.py` 的 `MIGRATIONS` 列表末尾追加迁移 007 和 008：

```python
# existing migrations 001-006 ...

    {
        "id": "007_knowledge_access_detail",
        "desc": "新增知识访问明细表 + metric_result CHECK 扩展 M15-M21/M26",
        "sql": [
            # ... 见 §3.1
        ],
    },
    {
        "id": "008_agent_datasource_config",
        "desc": "新增 Agent 数据源配置表 + 初始数据（6 条）",
        "sql": [
            # ... 见 §3.2
        ],
    },
]
```

### 3.4 schema.sql 同步

在 `schema.sql` 中同步新增两张表的 DDL（放在 `session_graph` 表之后、显式 FK 约束段之前）：

```sql
-- ===== Knowledge Access Detail (知识访问明细) =====

CREATE TABLE IF NOT EXISTS knowledge_access_detail (
    -- ... 见 §1.2
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== Agent Datasource Config (Agent 数据源配置) =====

CREATE TABLE IF NOT EXISTS agent_datasource_config (
    -- ... 见 §2.2
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

在 `schema.sql` 末尾的显式 FK 约束段追加：

```sql
ALTER TABLE knowledge_access_detail
    ADD CONSTRAINT fk_kad_trun
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id);
```

> `agent_datasource_config` 无 FK 约束（独立配置表，不关联 evaluation/task_run）。

---

## 4. 涉及文件清单

| 文件 | 改什么 |
|------|--------|
| `schema.sql` | 新增 `knowledge_access_detail` 表 DDL + `agent_datasource_config` 表 DDL + 初始数据 + FK 约束 |
| `infrastructure/migrations.py` | 新增迁移 007 (`knowledge_access_detail` + `metric_result` CHECK 扩展) + 迁移 008 (`agent_datasource_config` + 初始数据) |
