# 奇美拉误报归因与改进测评——需求设计说明书

> 本文档基于 `docs/knowledge-effect-eval-overview.md` 方案，对照现有代码结构，逐条说明每个改造项的现状、改什么、怎么改。

---

## 1 背景与目标

> 系统架构、现状误报表、测评范围推导详见 `docs/knowledge-effect-eval-overview.md` §0。

### 1.1 现状问题

6 个 Agent（4 挖掘 + 2 验证）在漏洞挖掘与验证流程中会访问知识库和记忆进化模块。当前评测引擎（M5–M13）只能回答"知识有没有被访问"，无法回答"误报根因在哪"、"知识有没有用"、"为什么没用"、"谁的责任"。

### 1.2 目标

在现有评测引擎上增量改造，新增：
- 知识盘点（覆盖度/质量）
- L0–L7 误报根因全链路分析（L0 标记知识原始来源，L1–L7 逐级定位误报根因在哪断了）
- 效果判定（正向/负向/中性，每次知识访问独立判定）
- 因果链分析（按业务流程阶段拆解误报）
- 新增指标 M15–M21/M26（生命周期过程指标 + 因果链指标）
- 报告扩展（lifecycle / causal_chain / inventory 段）
- 产出闭环（改进建议 + 回归验证（case 重放判断误报是否消除）+ 基线集回流）

### 1.3 约束

- 不新建项目，基于现有 `athena_eval_engine` 代码增量改造
- 所有改造一次性开发，不分期
- 统计单元 = 每次知识访问，只对有效 case 内的知识访问做统计
- 禁止截断、禁止降级跳过（遵循 AGENTS.md）

---

## 2 现有代码结构摘要

### 2.1 目录结构

> 完整目录结构见 `AGENTS.md`。本次改造涉及的文件见 §9。

### 2.2 现有指标（M5–M13）

| 指标 | 名称 | 计算函数 | 统计方法 |
|------|------|---------|---------|
| M5 | KAR 知识访问率 | `calc_m5()` | Wilson CI |
| M6 | KDR 知识交付率 | `calc_m6()` | Wilson CI |
| M7 | JSD 行为偏移 | `calc_m7()` | median+IQR + paired bootstrap |
| M8 | ΔToken | `calc_m8()` | median+IQR + paired bootstrap + Wilcoxon |
| M9 | ΔSteps | `calc_m9()` | median+IQR + paired bootstrap + Wilcoxon |
| M10 | ΔTime | `calc_m10()` | median+IQR + paired bootstrap + Wilcoxon |
| M11 | MAR 记忆访问率 | `calc_m11()` | Wilson CI |
| M12 | MDR 记忆交付率 | `calc_m12()` | Wilson CI |
| M13 | FPR 误报率 | `calc_m13()` | 占位 NA，REPORTING 阶段填充 |

注意：M1–M4 在 docstring 中提及但未实现，DB CHECK 只允许 M5–M13。新增 M15–M21/M26 编号连续。

### 2.3 现有知识访问标记

RawEvent 已有两个 flag：

| flag | 设置者 | 检测条件 |
|------|--------|---------|
| `is_kg_interaction` | 各 parser 的 `_is_kg_call()` / `_detect_kg_interaction()` | `athena_ask` MCP 工具，或 bash 含 `scripts/athena`（调 ask） |
| `is_memory_interaction` | 各 parser 调用 `detect_memory_flags()` | bash 含 `mem recall/get/search`，或 read/grep 读 `memengine` 目录或 `/app/memory/` 目录（读目录） |

KnowledgeInteractionFact 已有 memory 字段（存在 `evidence_json.memory` 子对象中，非独立 DB 列）。

**结论：RawEvent 和 KnowledgeInteractionFact 不需要新增字段。** 当前二分法已与方案的"知识库/记忆进化"二分法对齐。记忆与进化是一个整体，都走 memengine，parser 已能通过 `is_memory_interaction` 识别。

---

## 3 数据模型变更

### 3.1 新增表：knowledge_access_detail（知识访问明细）

存储每次知识访问的 L0–L7 生命周期判定结果和效果标签。**每个业务阶段独立做 L0–L7 判定**——一个 case 跨多个业务阶段，每个阶段的知识访问各自走一遍 L0–L7。L0 标记知识的原始来源（用户上传/历史漏洞经验/已有知识升华等），不参与断链判定和后续逻辑。

```sql
CREATE TABLE knowledge_access_detail (
    access_id          VARCHAR(128) PRIMARY KEY,  -- {evaluation_id}_{task_run_id}_{event_idx}
    evaluation_id      VARCHAR(64) NOT NULL,
    task_run_id        VARCHAR(64) NOT NULL,
    task_id            VARCHAR(128) NOT NULL,
    event_idx          INT NOT NULL,              -- 对应 RawEvent 在 events 列表中的序号
    source_system      VARCHAR(32) NOT NULL,      -- 知识库 / 记忆进化（区分访问的是哪个后端系统）
    l0_origin          VARCHAR(64),               -- L0 知识原始来源（用户上传/历史漏洞经验/已有知识升华等，仅标记 provenance，不参与断链判定）
    business_phase     VARCHAR(32) NOT NULL,      -- 业务流程阶段（入口识别/数据流追踪/漏洞模式识别/Sink点定位/漏洞判定与上报/漏洞理解/代码定位/验证执行/判定上报）
    -- L1–L6 判定
    l1_need_knowledge  BOOLEAN,                   -- 该阶段是否需要知识
    l2_initiated       BOOLEAN,                   -- 该阶段是否发起访问
    l3_query_accurate  BOOLEAN,                   -- 查询是否聚焦于该阶段
    l4_knowledge_exists BOOLEAN,                  -- 返回内容是否非空
    l5_retrieved       BOOLEAN,                   -- 工具是否成功取回
    l6_used            BOOLEAN,                   -- 该阶段推理是否引用
    -- L7 判定（LLM 方向一致性 + 知识正确性）
    l7_influenced      BOOLEAN,                   -- 是否影响该阶段结论
    l7_method          VARCHAR(32),               -- EVIDENCE_CHAIN
    -- 效果标签
    effect_label       VARCHAR(16),               -- POSITIVE / NEGATIVE / NEUTRAL
    -- 成因标签
    cause_code         VARCHAR(8),                -- A–H
    -- 证据
    query_content      TEXT,                      -- 查询内容
    returned_content   TEXT,                      -- 返回内容摘要
    reasoning_ref      TEXT,                      -- 推理引用片段
    judgment_conclusion TEXT,                     -- 判定结论
    evidence_json      JSON,                      -- 完整证据（LLM 分析结果等）
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id, event_idx),
    INDEX idx_kad_eval (evaluation_id),
    INDEX idx_kad_phase (evaluation_id, business_phase),
    INDEX idx_kad_effect (evaluation_id, effect_label),
    INDEX idx_kad_cause (evaluation_id, cause_code),
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

**DB 写入约束**：

| 约束 | 说明 |
|------|------|
| 大字段文件存储 | `query_content` / `returned_content` / `reasoning_ref` / `evidence_json` 可能是大文本，遵循现有"大 payload 存文件 DB 存路径"模式：超过 64KB 的字段写入 `{reports_dir}/{eid}_lifecycle_data/` 目录，DB 列存文件路径 |
| 幂等写入 | 复用 `_upsert` 模式（`INSERT ... ON DUPLICATE KEY UPDATE`），以 `UNIQUE(task_run_id, event_idx)` 为冲突键 |
| NaN/Inf 清洗 | `evidence_json` 中 LLM 返回的 `confidence` 等浮点字段可能含 NaN/Inf，写入前用 `_clean_nan_inf()` 清洗 |
| 批量写入 | 一个 task_run 的全部 knowledge_access_detail 记录批量 INSERT，不逐条写入 |

### 3.2 metric_result 表 CHECK 约束扩展

```sql
-- 迁移：metric_result 的 metric_id CHECK 增加 M15–M21/M26
ALTER TABLE metric_result DROP CONSTRAINT IF EXISTS metric_id_check;
ALTER TABLE metric_result ADD CONSTRAINT metric_id_check
    CHECK (metric_id IN ('M5','M6','M7','M8','M9','M10','M11','M12','M13',
                         'M15','M16','M17','M18','M19','M20','M21',
                         'M26'));
```

### 3.3 迁移脚本

在 `infrastructure/migrations.py` 的 `MIGRATIONS` 列表新增：

```python
{
    "id": "007_knowledge_access_detail",
    "desc": "新增知识访问明细表 + metric_result CHECK 扩展",
    "sql": [
        "CREATE TABLE IF NOT EXISTS knowledge_access_detail (...)",  # 上文 DDL
        # metric_result CHECK 扩展（幂等处理）
    ],
}
```

**涉及文件**：
- `schema.sql` — 新增 knowledge_access_detail 表 DDL
- `infrastructure/migrations.py` — 新增迁移条目

### 3.4 新增表：agent_datasource_config（Agent 数据源配置）

存储各 Agent 的数据库连接信息，供 v2 parser 直连 Agent 数据库查询 session 级标识符和 session 关系图。**支持通过配置界面修改**，修改后立即生效（复用 `system_config` 的 `_version` 机制）。

```sql
CREATE TABLE agent_datasource_config (
    id                 INT AUTO_INCREMENT PRIMARY KEY,
    agent_type         VARCHAR(32) NOT NULL UNIQUE,  -- turing/argo/secmate/cvuln_verify/webvuln_verify/dataflow
    display_name       VARCHAR(64) NOT NULL,          -- 显示名称（如"Turing MySQL"）
    db_type            VARCHAR(16) NOT NULL,          -- mysql / postgresql / none
    host               VARCHAR(256),                  -- k8s 内 svc 地址
    port               INT,                           -- 端口
    username           VARCHAR(64),
    password           VARCHAR(256),                  -- 明文存储（k8s 内网，与现有各 Agent DB 一致）
    database_name      VARCHAR(128),                  -- 库名（DataflowVulnScan 为模板，含 {project_id} 占位符）
    -- session 关系数据来源
    relation_tables    JSON,                          -- 关系表配置（表名、关系字段），供 parser build_session_graph() 查询
    -- session 标识符来源
    phase_identifier   JSON,                          -- 阶段标识符配置（表名、字段名、映射逻辑），供 parser label_session_phases() 查询
    -- 连接状态
    enabled            BOOLEAN NOT NULL DEFAULT TRUE, -- 是否启用此数据源
    last_connected_at  DATETIME(3),                   -- 最近成功连接时间
    last_error         TEXT,                          -- 最近连接错误信息
    -- 版本控制（复用 system_config 机制）
    _version           INT NOT NULL DEFAULT 1,        -- 修改后递增，watcher 轮询触发重载
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    INDEX idx_adc_type (agent_type)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

**初始数据**（迁移时 INSERT IGNORE）：

```sql
INSERT IGNORE INTO agent_datasource_config (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, phase_identifier, enabled) VALUES
('turing', 'Turing MySQL', 'mysql',
 'turing-app-security-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'turing_app_security_pass', 'turing_app_security',
 JSON_OBJECT('task', 'turing_task', 'parent_field', 'parent_task_id', 'session_field', 'agent_session_id',
             'trace_table', 'turing_task_trace', 'investigation_table', 'turing_investigation'),
 JSON_OBJECT('table', 'turing_task', 'id_field', 'agent_session_id', 'label_fields', JSON_ARRAY('agent_name', 'task_type')),
 1),
('argo', 'Argo MySQL', 'mysql',
 'chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'Icsl_argo', 'argo_c',
 JSON_OBJECT('table', 'intents', 'session_field', 'session_id', 'fact_field', 'to_fact_id', 'suggestion_field', 'suggestion_refs'),
 JSON_OBJECT('table', 'intents', 'id_field', 'session_id', 'label_field', 'task_type'),
 1),
('secmate', 'SecMate MySQL', 'mysql',
 'secmate-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'Huawei12#$', 'secmate',
 JSON_OBJECT('finding_table', 'finding', 'source_field', 'source_finding_id', 'task_table', 'task'),
 JSON_OBJECT('table', 'task', 'id_field', 'tool_task_id'),  -- persona 从 trace 提取，DB 无 persona 字段
 1),
('dataflow', 'DataflowVulnScan MySQL', 'mysql',
 'secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'Huawei12#$', 'dvs_{project_id}',
 JSON_OBJECT('sessions_table', 'dvs_task_graph_sessions', 'nodes_table', 'dvs_task_graph_nodes', 'edges_table', 'dvs_task_graph_edges',
             'fallback_table', 'orchestration'),
 JSON_OBJECT('source', 'filename', 'field', 'analysisType'),  -- 从文件名提取，DB 无直接标识符
 1),
('cvuln_verify', 'CVulnVerify PostgreSQL', 'postgresql',
 'secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local', 5432, 'postgres', 'secflow123', 'secflow_vuln_verify_v2',
 JSON_OBJECT('table', 'vuln_verify_attempt', 'predecessor_field', 'predecessor_attempt_id', 'reason_field', 'successor_reason'),
 JSON_OBJECT('table', 'vuln_verify_attempt', 'id_field', 'id', 'label_field', 'worker_type'),
 1),
('webvuln_verify', 'WebVulnVerify (无独立DB)', 'none',
 NULL, NULL, NULL, NULL, NULL,
 JSON_OBJECT('source', 'trace', 'parent_field', 'session.parent_id', 'vuln_id_field', 'metadata.vulnerability_id'),
 JSON_OBJECT('source', 'trace', 'tool_field', 'tool_call.name'),
 1);
```

**环境变量覆盖**：

每个 Agent 数据源支持环境变量覆盖（优先级高于 DB 配置），命名规则 `EVAL_{AGENT}_DB_{KEY}`：

| 环境变量 | 说明 |
|---------|------|
| `EVAL_TURING_DB_HOST` / `EVAL_TURING_DB_PORT` / `EVAL_TURING_DB_USER` / `EVAL_TURING_DB_PASSWORD` / `EVAL_TURING_DB_NAME` | Turing MySQL 覆盖 |
| `EVAL_ARGO_DB_HOST` / `EVAL_ARGO_DB_PORT` / `EVAL_ARGO_DB_USER` / `EVAL_ARGO_DB_PASSWORD` / `EVAL_ARGO_DB_NAME` | Argo MySQL 覆盖 |
| `EVAL_SECMATE_DB_HOST` / `EVAL_SECMATE_DB_PORT` / `EVAL_SECMATE_DB_USER` / `EVAL_SECMATE_DB_PASSWORD` / `EVAL_SECMATE_DB_NAME` | SecMate MySQL 覆盖 |
| `EVAL_DATAFLOW_DB_HOST` / `EVAL_DATAFLOW_DB_PORT` / `EVAL_DATAFLOW_DB_USER` / `EVAL_DATAFLOW_DB_PASSWORD` / `EVAL_DATAFLOW_DB_NAME` | DataflowVulnScan MySQL 覆盖 |
| `EVAL_CVULN_DB_HOST` / `EVAL_CVULN_DB_PORT` / `EVAL_CVULN_DB_USER` / `EVAL_CVULN_DB_PASSWORD` / `EVAL_CVULN_DB_NAME` | CVulnVerify PostgreSQL 覆盖（已有） |

**配置界面 API**：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/v2/datasources` | GET | 列出全部 Agent 数据源配置（password 脱敏） |
| `/api/v2/datasources/{agent_type}` | GET | 获取单个 Agent 数据源配置（password 脱敏） |
| `/api/v2/datasources/{agent_type}` | PUT | 修改数据源配置（host/port/username/password/database_name/enabled），修改后递增 `_version` |
| `/api/v2/datasources/{agent_type}/test` | POST | 测试连接，返回连接结果（成功/失败+错误信息），更新 `last_connected_at` / `last_error` |

**密码脱敏规则**：GET 返回时 `password` 字段返回 `***`，不返回明文。PUT 时如果 `password` 字段为 `***` 或空则不更新密码。

**涉及文件**：
- `schema.sql` — 新增 agent_datasource_config 表 DDL + 初始数据
- `infrastructure/migrations.py` — 新增迁移条目 `008_agent_datasource_config`
- `infrastructure/agent_db.py` — **新建**，Agent 数据库连接管理（读取配置、建立连接池、短连接+重试）
- `api/routes/datasources.py` — **新建**，配置界面 CRUD + 测试连接 API

**迁移脚本新增**：

```python
{
    "id": "008_agent_datasource_config",
    "desc": "新增 Agent 数据源配置表 + 初始数据",
    "sql": [
        "CREATE TABLE IF NOT EXISTS agent_datasource_config (...)",  # 上文 DDL
        # INSERT IGNORE 初始数据（上文 6 条）
    ],
}
```

---

## 4 模块设计

### 4.1 L0–L7 误报根因全链路分析模块

**新建文件**：`domain/lifecycle/analyzer.py`

**职责**：对每次知识访问，先标注其所属业务阶段，再在该阶段内逐级判定 L0–L7。L0 标记知识的原始来源（用户上传/历史漏洞经验/已有知识升华等），不参与断链判定；L1–L7 逐级判定断点，输出 cause_code（A–H）。

**核心设计**：每个业务阶段都有独立的 L0–L7 链条。一个 case 跨多个业务阶段，每个阶段的知识访问各自走一遍 L0–L7。L0 仅标记原始来源 provenance，不产生断链；L1–L7 逐级判定断点。一个误报可能在多个阶段都有断点，每个断点独立标注成因——一个 case 可能对应多条改进建议。

**输入**：
- `events: list[RawEvent]` — 一个 task_run 的全部事件
- `interactions: list[dict]` — KnowledgeInteractionFact 的 interactions 列表
- `memory_interactions: list[dict]` — 记忆交互列表
- `findings: list[dict]` — 提取的 finding
- `outcome: OutcomeFact` — 最终判定结果

**输出**：`list[KnowledgeAccessDetail]` — 每次知识访问一条，含 `business_phase` 字段

**业务阶段标注**（先于 L0–L7 判定）：

采用三层标注架构，逐层缩小粒度。第一层和第二层为程序确定性判定，第三层才调 LLM：

| 层级 | 方法 | 确定性 | 说明 |
|------|------|--------|------|
| 第一层：程序确定性标注 | parser 从 trace 或 Agent DB 提取 session 级标识符 | 100% 确定 | 每个 Agent 有不同的标识符来源（见下表） |
| 第二层：程序规则映射 | 标识符 → 业务阶段映射表 | 确定但粒度粗 | 部分标识符跨多个阶段 |
| 第三层：LLM 细分 | 对跨阶段的 session，从 REASONING 事件用 LLM 细分 | LLM 判定 | 仅对第二层无法单一归类的 session 调用 |

**各 Agent 第一层标识符来源**（调研结论详见 `docs/agent-session-phase-classification.md`）：

| Agent | 标识符 | 数据来源 | 获取方式 |
|-------|--------|---------|---------|
| Argo | `task_type`（bootstrap/investigate/verify/reason） | JSONL prompt 标题 或 MySQL `argo_c.intents` 表 | parser 从 trace 提取或 DB 查询 |
| Turing | `agent_name` + `task_type` | MySQL `turing_app_security.turing_task` 表 | DB 查询 `agent_session_id → agent_name` |
| SecMate | persona 名 + finding level | JSONL trace agent prompt 标题 + `store_finding` 工具参数 | parser 从 trace 提取 |
| DataflowVulnScan | `analysisType`（taint/track/fptrack/vuln-judge 等） | JSONL 文件名编码 | parser 从文件名提取 |
| CVulnVerify | `worker_type`（source-verifier/c-formal-verifier/binary-instrumentation-poc） | PostgreSQL `secflow_vuln_verify_v2.vuln_verify_attempt` 表 | DB 查询 `attempt_id → worker_type` |
| WebVulnVerify | 工具名序列（vulnerability_analyze/verify/cvss） | JSONL trace `tool_call.name` | parser 从 trace 提取 |

**第二层标识符 → 业务阶段映射**：

挖掘 Agent 5 阶段（不固定顺序）：入口识别 / 数据流追踪 / 漏洞模式识别 / Sink 点定位 / 漏洞判定与上报

验证 Agent 4 阶段：漏洞理解 / 代码定位 / 验证执行 / 判定上报

| Agent | 标识符 | 映射的业务阶段 | 需 LLM 细分？ |
|-------|--------|--------------|-------------|
| Argo | bootstrap | 入口识别 + 数据流追踪 | 是 |
| Argo | investigate | 漏洞模式识别 / Sink 点定位 / 漏洞判定与上报 | 是 |
| Argo | verify | 漏洞判定与上报 | 否 |
| Argo | reason | 不属于 5 阶段（调度） | 否（跳过 L0–L7） |
| Turing | strategy | 入口识别 | 否 |
| Turing | detection | 入口识别 + 数据流追踪 | 是 |
| Turing | mining / deep_mining | 漏洞模式识别 + Sink 点定位 + 漏洞判定与上报 | 是 |
| Turing | semantic_analysis | 漏洞模式识别 | 否 |
| Turing | validation | 漏洞判定与上报 | 否 |
| Turing | preprocess | 不属于 5 阶段（预处理） | 否（跳过 L0–L7） |
| SecMate | architect | 入口识别 + 数据流追踪 | 是 |
| SecMate | flow-tracer | 数据流追踪 + Sink 点定位 | 是 |
| SecMate | specialist / variant-hunter | 漏洞模式识别 | 否 |
| SecMate | mdf-composer | 数据流追踪 | 否 |
| SecMate | vuln-analyst / reviewer / fp-analyzer | 漏洞判定与上报 | 否 |
| SecMate | logic-architect | 入口识别 | 否 |
| SecMate | logic-tracer | 数据流追踪 | 否 |
| SecMate | logic-oracle-analyzer | 漏洞模式识别 | 否 |
| SecMate | explorer / distiller / noise-distiller / report | 不属于 5 阶段 | 否（跳过 L0–L7） |
| DataflowVulnScan | taint / track / fptrack | 数据流追踪 | 否 |
| DataflowVulnScan | vuln-judge / vuln-false-positive-judge / vuln-report | 漏洞判定与上报 | 否 |
| DataflowVulnScan | vuln-pattern-enhancement | 漏洞模式识别 | 否 |
| CVulnVerify | source-verifier | 漏洞理解 + 代码定位 + 验证执行 | 是 |
| CVulnVerify | c-formal-verifier / binary-instrumentation-poc | 验证执行 | 否 |
| WebVulnVerify | vulnerability_analyze | 漏洞理解 + 代码定位 | 是 |
| WebVulnVerify | vulnerability_verify / vulnerability_cvss | 判定上报 | 否 |
| WebVulnVerify | read / bash / grep | 验证执行 | 否 |

**不产生知识访问的阶段**（L0–L7 分析跳过）：

| Agent | 不产生知识访问的阶段/标识符 |
|-------|--------------------------|
| Argo | reason（调度阶段） |
| Turing | preprocess（预处理阶段） |
| SecMate | explorer / distiller / noise-distiller / report |
| DataflowVulnScan | 无（所有 analysisType 都可能产生知识访问） |
| CVulnVerify | 无（所有 worker_type 都可能产生知识访问） |
| WebVulnVerify | 无（所有 session 都可能产生知识访问） |

**L0 来源标记**：从知识条目的 frontmatter `来源` 字段读取（如"工具"/"人工"/"蒸馏"等），或从记忆目录的 `init.json` 的 `dirs[].source` 字段读取（如"vuln-center"/"knowledge-shelf"等），写入 `l0_origin` 字段。不产生断链，不参与后续逻辑。

**L1–L6 判定逻辑**（在标注的业务阶段内判定）：

| 级别 | 判定方法 | 数据来源 |
|------|---------|---------|
| L1 需要知识？ | **LLM 判定** 该业务阶段是否需要知识支撑 | 该阶段的推理上下文 + benchmark_item 漏洞类型 |
| L2 发起访问？ | 程序判定：该阶段是否存在 `is_kg_interaction` 或 `is_memory_interaction` 为 True 的事件 | RawEvent flag + 阶段标注 |
| L3 查询准确？ | **LLM 判定** 查询内容是否聚焦于该阶段的任务 | interaction.command + 该阶段的推理上下文 |
| L4 知识存在？ | 程序判定：工具返回内容是否非空 | interaction.output_preview |
| L5 成功取回？ | 程序判定：工具是否报错/超时 | interaction 中是否有 error/timeout 标记 |
| L6 被使用？ | **LLM 判定** 该阶段的推理文本是否引用了知识返回内容 | 该阶段的 REASONING/MESSAGE 文本 vs interaction.output_preview |

**L7 判定逻辑**（对 L6 已通过的访问，用 LLM 判定）：

输入：知识返回内容 + 推理引用片段 + 判定结论 + 基线漏洞信息

输出：JSON `{knowledge_correct: bool, direction_consistent: bool, confidence: float, reason: str}`

| 知识正确性 | 方向一致性 | 效果标签 | 成因 |
|-----------|-----------|---------|------|
| 正确 | 一致 | 正向 | — |
| 错误 | 一致 | 负向 | G/H |
| — | 不一致 | 中性 | F |

- 知识正确性：对比知识内容与基线漏洞信息，判断知识是否正确/过时/不适用
- 方向一致性：知识方向（指向漏洞/非漏洞）与判定结论方向是否一致
- LLM 无法确认（confidence < 阈值）→ 标记为 `l7_influenced=NULL, l7_method=EVIDENCE_CHAIN`

**断点→成因映射**：

```
L2 断 → A（该查没查）
L3 断 → B（查询太泛）
L4 断 → C（查了没得）
L5 断 → D（链路问题）
L6 断 → E（查到没用）
L7 断（未影响结论）→ F（用了没推动）
L7 推动但方向错 → G（导致误判）
G 的根因 → H（内容有误）
```

**漏斗过滤策略**（控制 LLM 调用成本）：

L1–L7 不是逐级都调 LLM。程序判定级别（L2/L4/L5）可短路后续 LLM 调用：

```
L1（LLM）→ L1=False: 该阶段不需要知识，不产生断链，跳过 L2–L7
         → L1=True:  继续 L2
L2（程序）→ L2=False: 断点 A，跳过 L3–L7（无需查询/存在/使用/影响判定）
         → L2=True:  继续 L3
L3（LLM）→ L3=False: 断点 B，跳过 L4–L7
         → L3=True:  继续 L4
L4（程序）→ L4=False: 断点 C，跳过 L5–L7
         → L4=True:  继续 L5
L5（程序）→ L5=False: 断点 D，跳过 L6–L7
         → L5=True:  继续 L6
L6（LLM）→ L6=False: 断点 E，跳过 L7
         → L6=True:  继续 L7
L7（LLM）→ 正向 / 负向(G/H) / 中性(F) / NULL(无法确认)
```

**LLM 调用工程约束**：

| 约束 | 说明 |
|------|------|
| 批处理模式 | 一个 case 的全部知识访问的 L1/L3/L6/L7 判定通过 `submit_llm_batch` 批量提交，不逐条调用 |
| 并发控制 | 复用 `infrastructure/concurrency.py` 的 `llm_max_concurrency` 全局门控，不新建并发参数 |
| 取消信号 | `cancel_cb` 通过 `iter_completed` 穿透到 LLM 内循环，在每批提交前检查 `_check_cancel()` |
| 失败处理 | 复用 `chat_json()` 的 20 次重试 + JSON 自修复 + context-length 检测，不另建重试逻辑 |
| reasoning_effort | L7 判定需要深度推理，设置 `reasoning_effort=high`；L1/L3/L6 判定用默认值 |

**业务阶段标注策略**：

| 约束 | 说明 |
|------|------|
| 程序优先 | 第一层标识符提取 + 第二层规则映射在 parser 阶段完成（`parse()` / `build_session_graph()`），不调 LLM。仅对映射表中标注"需 LLM 细分"的 session 调第三层 LLM |
| LLM 细分范围 | 仅对跨阶段的 session（如 Argo investigate、Turing mining/deep_mining、SecMate architect/flow-tracer、CVulnVerify source-verifier、WebVulnVerify vulnerability_analyze）调 LLM 细分到单一阶段 |
| 批量标注 | 一个 case 的全部需 LLM 细分的知识访问一次性提交标注（非逐条），输入为该 case 的 REASONING/MESSAGE 事件序列 + 每次知识访问的 event_idx + 第二层粗标注结果 |
| 输入大小控制 | 单次标注输入超过 LLM context 上限时，按事件时间序采样，保留知识访问前后各 N 条 REASONING 事件 |
| NULL 处理 | LLM 无法确定阶段时，`business_phase=NULL`，该访问不参与因果链统计，但仍计入知识访问总数 |
| Agent 类型区分 | 挖掘 Agent 5 阶段 vs 验证 Agent 4 阶段，通过 `task_run.agent_type` 判断，prompt 中只给对应 Agent 的阶段列表 |
| 跳过策略 | 不产生知识访问的阶段（Argo reason / Turing preprocess / SecMate explorer 等）直接跳过 L0–L7，不产生 `knowledge_access_detail` 记录 |
| Agent DB 连接 | Argo/Turing/SecMate/DataflowVulnScan/CVulnVerify 有独立数据库，parser 可通过 k8s 内网直连获取 session 级标识符（连接信息见 `docs/agent-session-phase-classification.md` §4.2）。WebVulnVerify 无独立 DB，标识符从 trace 提取 |

**L1/L3/L6 LLM 输出格式**：

| 级别 | 输出 JSON |
|------|----------|
| L1 | `{need_knowledge: bool, reason: str}` |
| L3 | `{query_accurate: bool, reason: str}` |
| L6 | `{used: bool, reason: str}` |

**L7 confidence 阈值**：`confidence < 0.6` 时标记 `l7_influenced=NULL`。阈值通过 `system_config` 表的 `l7_confidence_threshold` 配置项控制，运行时可调。

**涉及文件**：
- 新建 `domain/lifecycle/__init__.py`
- 新建 `domain/lifecycle/analyzer.py`
- 新建 `domain/lifecycle/evidence_chain.py` — L7 判定（LLM 方向一致性 + 知识正确性）
- 复用 `infrastructure/llm.py` 的 `chat_json()` + `submit_llm_batch` + `iter_completed(cancel_cb)`
- 复用 `infrastructure/concurrency.py` 的 `llm_max_concurrency` 全局门控

### 4.2 因果链分析模块

**新建文件**：`domain/causal_chain/analyzer.py`

**职责**：基于 `knowledge_access_detail` 的 `business_phase` + L1–L7 判定结果，按业务阶段聚合误报归因。L0 不参与此模块逻辑。

**输入**：`knowledge_access_detail` 表中该 evaluation 的全部记录（已含 business_phase + L1–L7 判定，L0 l0_origin 仅用于 provenance 标记）

**输出**：
- 交叉归因矩阵：业务阶段（行）× L2–L7 级别（列），每格统计该阶段该级别断链的 case 数和成因分布
- 每个误报 case 的断点清单（一个 case 可能有多个断点，分布在矩阵的不同格子中；L0 不产生断链）
- M26 阶段误报承担率 = 该阶段有断点的 case 数 / 总误报 case 数

**涉及文件**：
- 新建 `domain/causal_chain/__init__.py`
- 新建 `domain/causal_chain/analyzer.py`

### 4.3 知识盘点模块

**新建文件**：`domain/knowledge_inventory/inventory.py`

**职责**：盘点知识库和记忆进化系统中的内容，从两个维度评估。数据来源（API 端点、记忆目录结构、frontmatter 字段）详见 §7。

| 维度 | 内容 | 数据来源 | 落地方式 |
|------|------|---------|---------|
| 覆盖度 | 有哪些漏洞类型的知识、缺哪些 | 知识库 API + 记忆目录 | 调用知识库 API 拉全量清单，读记忆 NFS 目录，按漏洞类型匹配 |
| 内容质量 | 内容是否正确、是否有过时或误导性内容、语言/框架是否匹配 | 知识库 API + Trace 中实际访问的知识内容 | frontmatter `验证状态`/`topic`/`层级` 字段判定；Trace 中访问过的知识用 LLM 对比基线漏洞信息判定正确性 |

**覆盖度判定逻辑**：
1. 调知识库 API（§7.1）拉全量文件清单 + 结构化目录（含 topic 标签）
2. 读记忆 NFS 目录（§7.2），按 type/level 分类统计
3. 从基线集（benchmark_item）获取被测漏洞类型列表
4. 用知识文档的 `topic` 字段和文件名关键词匹配漏洞类型
5. 对比：基线有的漏洞类型在知识库/记忆中有没有对应知识 → 覆盖/缺失
6. 输出覆盖度清单：`{漏洞类型, has_knowledge, knowledge_count, quality_label}`

**质量判定逻辑**：
1. 从知识文档 frontmatter 读取 `验证状态` 字段（已验证/未验证）
2. 对 Trace 中实际访问过的知识，用 LLM 对比基线漏洞信息判定正确性（复用 §4.1 的 L7 判定逻辑）
3. 从知识文档 frontmatter 读取 `topic`/`层级` 字段，与被测项目配置比对判定语言/框架匹配性
4. 质量标签：正确 / 过时 / 不适用 / 误导性

**输出**：写入报告的 inventory 段，包含覆盖度清单 + 质量标注。

**涉及文件**：
- 新建 `domain/knowledge_inventory/__init__.py`
- 新建 `domain/knowledge_inventory/inventory.py` — 调知识库 API + 读记忆目录
- 复用 `application/platform_service.py` 获取项目信息 + 直接读 NFS 挂载的记忆目录
- 复用 `domain/lifecycle/evidence_chain.py` 的 LLM 质量判定

### 4.4 有效 case 筛选模块

**新建文件**：`v2/lifecycle/case_filter.py`

**职责**：从漏洞中心人工确认数据出发，筛选 FP/FN case 对应的 DataPack，只对有效 case 内的知识访问做统计。

**FP（误报）筛选流程**：
1. 基线标注 `expected_label=NON_VULNERABLE` 的 case
2. 在 trace findings 中找对应 finding
3. 找到且 `validation_result=CONFIRMED` → agent 误报了漏洞

**FN（漏报）筛选流程**（仅开发态）：
1. 基线标注 `expected_label=VULNERABLE` 的 case
2. 将基线漏洞与**告警中心**数据对比
3. 告警中心有匹配 → agent 上报了该漏洞，不是漏报，跳过
4. 告警中心无匹配 → agent 漏报了该漏洞
5. 对漏报的 case，提取 sink 点（`source_file` / `source_function`），用 LLM 匹配在 trace 中找对应 session

**FP 的匹配方式**取决于基线来源（`benchmark_source`）：

| 基线来源 | 匹配方式 | 说明 |
|----------|---------|------|
| 漏洞中心（`vuln_center`） | 纯代码匹配 | finding_id 直接匹配 → 标题（vulnerability_type）匹配 → 内容（description）文本匹配 |
| V-Bench 测评集（`vbench_zip`） | LLM 匹配 | 两阶段：Phase 1 标题预筛（每基线 1 次 LLM）→ Phase 2 1vs1 详细对比（三维度 + 程序校验 sink 路径），复用 v1 `fpr_analysis.py` / `ai_matcher.py` 的方法 |

**FN 的匹配方式**：
- 基线漏洞 vs 告警中心：与 FP 相同的匹配方式（vuln_center 纯代码，vbench_zip LLM）
- 漏报 case vs trace：始终用 LLM 匹配（因为漏报意味着 trace 里没有 finding，只能用 sink 点信息定位 session）

**按 eval_mode 筛选**：

| 触发时机 | 分析 case 类型 |
|----------|--------------|
| 开发态（`dev`） | FP + FN |
| 运行态（`runtime`） | 只 FP |

**跨 session case 处理**：一个 case 对应一个 task，但一个 task 可能有多个 agent（挖掘 agent + 验证 agent），各自一条 trace、一个 DataPack。按 `task_id` 分组，组级别聚合判定 FP/FN，组内保留有知识访问记录的 DataPack。

**找不到对应 trace 的 case**：记录到 `unmatched_cases`，在报告中告警，不参与分析。

**涉及文件**：
- 新建 `v2/lifecycle/case_filter.py`
- 复用 v1 `application/fpr_analysis.py` 的 LLM 匹配方法（`_llm_match_batch` / `_run_matching`）
- 复用 v1 `workers/ai_matcher.py` 的 `_verify_sink` / `_norm_path` / `_parse_bool`
- 依赖 `alert_center_data`（从 INGESTING 阶段获取，用于 FN 判定）

### 4.5 指标计算扩展

**修改文件**：`domain/metrics/__init__.py`

新增函数：

| 指标 | 函数签名 | 计算方法 |
|------|---------|---------|
| M15 知识访问发起率 | `calc_m15(initiated_count, need_count) -> MetricResult` | 比例 + Wilson CI |
| M16 召回意识缺失率 | `calc_m16(not_initiated_count, need_count) -> MetricResult` | 比例 + Wilson CI |
| M17 查询准确率 | `calc_m17(accurate_count, total_query_count) -> MetricResult` | 比例 + Wilson CI |
| M18 知识存在率 | `calc_m18(exists_count, total_query_count) -> MetricResult` | 比例 + Wilson CI |
| M19 知识召回成功率 | `calc_m19(retrieved_count, initiated_count) -> MetricResult` | 比例 + Wilson CI |
| M20 知识使用率 | `calc_m20(used_count, retrieved_count) -> MetricResult` | 比例 + Wilson CI |
| M21 死知识率 | `calc_m21(unused_count, retrieved_count) -> MetricResult` | 比例 + Wilson CI |
| M26 阶段误报承担率 | `calc_m26(stage_break_count, total_fp_count) -> MetricResult` | 比例 + Wilson CI |

修改 `run_all_metrics()`：新增参数 `knowledge_access_details: list[KnowledgeAccessDetail]`，在现有 M5–M13 计算后追加 M15–M21/M26。

**涉及文件**：
- 修改 `domain/metrics/__init__.py` — 新增 calc_m15 ~ calc_m21, calc_m26 函数 + 扩展 run_all_metrics()

### 4.6 报告段扩展

**修改文件**：`application/report_assembler.py` + `application/evaluation_service.py`

现有三段：`{eid}.json`（base）+ `{eid}_fpr.json`（FPR）+ `{eid}_kg.json`（KG）

新增两段：
- `{eid}_lifecycle.json` — 生命周期分析段（L0 原始来源分布 + L1–L7 断点分布 + 成因汇总 + 效果标签分布）
- `{eid}_inventory.json` — 知识盘点段（覆盖度清单 + 质量标注）

**ReportModel 扩展**：
```python
@dataclass
class ReportModel:
    # ... 现有字段 ...
    lifecycle_uri: str = ""    # 生命周期段文件路径
    inventory_uri: str = ""    # 知识盘点段文件路径
```

**报告段 JSON 结构**：

`{eid}_lifecycle.json`：
```json
{
  "evaluation_id": "...",
  "l0_origin_distribution": { "工具": 10, "人工": 5, "蒸馏": 3 },
  "breakpoint_distribution": {
    "入口识别": { "L2": 3, "L3": 1, "L4": 2, "L5": 0, "L6": 1, "L7": 0 },
    "漏洞判定与上报": { "L2": 5, "L3": 2, "L4": 0, "L5": 1, "L6": 3, "L7": 1 }
  },
  "cause_summary": { "A": 8, "B": 3, "C": 2, "D": 1, "E": 4, "F": 1, "G": 1, "H": 1 },
  "effect_label_distribution": { "POSITIVE": 15, "NEGATIVE": 3, "NEUTRAL": 5 },
  "per_case_details": [
    { "task_run_id": "...", "business_phase": "...", "breakpoints": [...], "cause_codes": [...] }
  ]
}
```

`{eid}_inventory.json`：
```json
{
  "evaluation_id": "...",
  "coverage_list": [
    { "vuln_type": "SQL注入", "has_knowledge": true, "knowledge_count": 5, "quality_label": "正确" },
    { "vuln_type": "XSS", "has_knowledge": false, "knowledge_count": 0, "quality_label": null }
  ],
  "quality_labels": [
    { "knowledge_name": "...", "quality_label": "过时", "reason": "框架版本已升级" }
  ]
}
```

**API 端点新增**：
- `GET /api/v1/evaluations/{eid}/report/lifecycle` — 获取生命周期段
- `GET /api/v1/evaluations/{eid}/report/inventory` — 获取知识盘点段

**涉及文件**：
- 修改 `application/report_assembler.py` — ReportModel 新增字段 + lifecycle/inventory 段组装
- 修改 `application/evaluation_service.py` — 新增段写入逻辑 + pipeline 阶段扩展
- 修改 `api/routes/evaluations.py` — 新增 2 个端点

---

## 5 Pipeline 阶段扩展

### 5.1 现有阶段

```
INGESTING → PARSING → AI_MATCHING → RESOLVING → PAIRING → CALCULATING → REPORTING → FINALIZE
```

### 5.2 新增阶段

在 CALCULATING 和 REPORTING 之间插入三个新阶段：

```
CALCULATING → INVENTORY → LIFECYCLE_ANALYSIS → CAUSAL_CHAIN → REPORTING → FINALIZE
```

| 新阶段 | 状态 | 操作 |
|--------|------|------|
| INVENTORY | `INVENTORY` | 1. 调知识库 API 拉全量清单 + 读记忆目录（NFS） 2. 覆盖度判定（基线漏洞类型 vs 知识库/记忆） 3. 质量标注（含语言/框架匹配性） 4. 写入 inventory 段 |
| LIFECYCLE_ANALYSIS | `LIFECYCLE_ANALYSIS` | 1. 有效 case 筛选 2. 业务阶段标注（LLM，先于 L0–L7 判定） 3. L0 来源标记（程序判定，从 frontmatter `来源` 或 init.json `source` 读取） 4. L1–L6 判定（L1/L3/L6 用 LLM，L2/L4/L5 程序判定） 5. L7 判定（LLM，只读 Trace） 6. 效果标签 + 成因标签写入 knowledge_access_detail |
| CAUSAL_CHAIN | `CAUSAL_CHAIN` | 1. 因果链断点分析（基于 knowledge_access_detail 已有的 business_phase + L1–L7 判定结果聚合，L0 不参与） 2. M26 计算 |

### 5.3 状态机扩展

**修改文件**：`orchestration/state_machine.py`

白名单新增正向跳转：
```
CALCULATING → INVENTORY
INVENTORY → LIFECYCLE_ANALYSIS
LIFECYCLE_ANALYSIS → CAUSAL_CHAIN
CAUSAL_CHAIN → REPORTING
```

恢复路径（与现有 FAILED/CANCEL_REQUESTED 一致）：
```
INVENTORY → FAILED → resume → INVENTORY
LIFECYCLE_ANALYSIS → FAILED → resume → LIFECYCLE_ANALYSIS
CAUSAL_CHAIN → FAILED → resume → CAUSAL_CHAIN
RUNNING → CANCEL_REQUESTED → CANCELLING → CANCELLED（任意阶段可取消）
```

取消检查点：`_check_cancel()` 在每个新阶段入口和 LLM 批次提交前检查。

**修改文件**：`schema.sql` + `infrastructure/migrations.py`

evaluation 表 status CHECK 新增 `INVENTORY`、`LIFECYCLE_ANALYSIS` 和 `CAUSAL_CHAIN`。

### 5.4 重试路径

**修改文件**：`application/evaluation_service.py`

现有重试路径：facts 已在 DB → 跳过解析 → 直接 CALCULATING。

新增重试路径：
- `knowledge_access_detail` 按 `access_id` 幂等检查：该 task_run 的记录已存在 → 跳过 LIFECYCLE_ANALYSIS → 直接 CAUSAL_CHAIN
- inventory 段文件已存在 → 跳过 INVENTORY → 直接 LIFECYCLE_ANALYSIS
- 重跑时不清空 `knowledge_access_detail` 表，通过 `INSERT ... ON DUPLICATE KEY UPDATE` 幂等覆盖

**注意**：现有代码的 `facts_already_exist` 检查在重跑时始终为 False（每次清数据）。新模块不沿用此模式，改为按 `access_id` 幂等检查，避免重跑时丢失已完成的分析结果。

### 5.5 产出闭环

**职责**：从分析结果到改进动作到回归验证的完整闭环。回归验证 = 通过 case 重放判断该误报是否消除。

**核心原则**：一个 FP case 跨多个业务阶段，每个阶段各自有独立的 L0–L7 链条，可能存在**多个断点**。L0 标记知识原始来源（provenance）不产生断链；L1–L7 的断点独立输出成因和改进建议，一个 case 可能对应多条改进动作。

| 环节 | 内容 | 实现方式 |
|------|------|---------|
| 指标看板 | 2 个核心指标（E2E FPR / 负向知识率） | 报告 base 段已有，dashboard 展示 |
| 归因报告 | 交叉归因矩阵（效果 × 生命周期 × 业务流程 × 知识来源），每个断点一条记录 | lifecycle 段 + causal_chain 段 |
| 改进建议 | **按断点逐条输出**：每个断点的阶段 × 级别 × 成因 → 责任方 + 改进动作 + 预期收益 | LLM 基于归因结果生成，写入报告 |
| 回归验证 | 通过 case 重放判断该误报是否消除 | 详见 §6.1 Case 重放协议 |

**改进建议生成逻辑**（每个断点独立生成一条建议，一个 case 可能有多条）：

| 成因 | 断点位置 | 责任方 | 改进动作 | 预期收益 |
|------|---------|--------|---------|---------|
| A 该查没查 | 某阶段 L2 断 | Agent | 在该阶段增加知识触发点 | 提高该阶段知识访问率 |
| B 查询太泛 | 某阶段 L3 断 | Agent | 改进该阶段查询模板 | 提高该阶段查询准确率 |
| C 查了没得 | 某阶段 L4 断 | 知识方 | 补充该阶段所需知识 | 提高该阶段知识存在率 |
| D 链路问题 | 某阶段 L5 断 | Agent + 知识方 | 修复工具/超时 | 提高该阶段召回成功率 |
| E 查到没用 | 某阶段 L6 断 | Agent | 改进该阶段推理引用 | 提高该阶段使用率 |
| F 用了没推动 | 某阶段 L7 断 | Agent / 知识方 | 优化该阶段知识内容 | 提高该阶段行为影响率 |
| G 导致误判 | 某阶段 L7 负向 | 知识方 | 修正该阶段引用的知识 | 降低负向知识率 |
| H 内容有误 | 某阶段 G 的根因 | 知识方 | 更新该阶段知识内容 | 消除该阶段的知识误导 |

**涉及文件**：
- 修改 `application/report_assembler.py` — 改进建议生成
- 新建 `application/replay_verifier.py` — 从漏洞中心/Trace 读取重放结果 + FP 消除判定
- 复用 `infrastructure/vuln_center_client.py` — 按 case_id 查询重放后的判定结论

---

## 6 Agent 改造接口

### 6.1 Case 重放协议（回归验证）

**职责**：各 Agent 自行实现 Case 重放——人工在 Agent 管理界面操作，对原误报 case 在知识改进后重跑。评测引擎不参与重放执行，只从漏洞中心或 Trace 读取重放结果，判定该误报是否消除。

**核心流程**：

```
人工操作者              Agent                      评测引擎
   │                       │                           │
   │── 1. 在 Agent 管理界面 │                           │
   │   发起重放             │                           │
   │   (选择原误报 case +   │                           │
   │    确认知识已改进)     │                           │
   │                       │                           │
   │                       │── 2. 重放执行（Agent 自行实现）│
   │                       │   可从头重放整个 case      │
   │                       │   也可从中间步骤开始重放     │
   │                       │   全程记录 Trace           │
   │                       │                           │
   │                       │                           │── 3. 读取重放结果
   │                       │                           │   从漏洞中心读 Agent 判定结论
   │                       │                           │   或从 Trace 读取重放过程
   │                       │                           │
   │                       │                           │── 4. 判定 FP 是否消除
   │                       │                           │   对比原始判定 vs 重放判定
   │                       │                           │
```

**1. 人工发起重放（在各 Agent 管理界面操作）**

人工在各 Agent 的管理界面选择原误报 case 发起重放，需确认：

| 确认项 | 说明 |
|--------|------|
| `case_id` | 原误报 case 标识（从测评报告的改进建议清单中获取） |
| 知识已改进 | 对应的成因所指向的知识条目已完成更新/新增/删除 |
| 期望结果 | TN（该 case 应变为非漏洞判定） |

**2. Agent 重放执行（各 Agent 自行实现）**

Agent 自行实现重放逻辑，评测引擎不规定重放的具体执行方式。Agent 可自行决定：

| 重放方式 | 说明 |
|---------|------|
| 单个 case 重头重放 | 从头重放该 case，用改进后的知识重新执行完整流程 |
| 中间步骤重放 | 从误报产生的业务阶段开始重放，前置阶段沿用原始结果 |

Agent 需保证：

| 保证项 | 说明 |
|--------|------|
| 知识已更新 | Agent 使用的知识库/记忆进化内容已包含本轮改进的知识变更 |
| 全程 Trace | 重放过程完整记录 Trace，格式与正常执行一致（含 REASONING / TOOL / KG / MEMORY 事件） |
| 重放标记 | Trace 中标记 `replay=true`，并携带 `original_case_id`，供评测引擎区分重放 Trace 与正常 Trace |
| 不改逻辑 | Agent 的推理逻辑、工具调用方式不变——只变知识内容，验证知识改进的效果 |

**3. 读取重放结果（评测引擎）**

评测引擎不接收 Agent 提交，而是主动从以下来源读取重放结果：

| 数据来源 | 读取内容 | 方式 |
|---------|---------|------|
| 漏洞中心 | Agent 重放后的判定结论（verdict） | 复用 `vuln_center_client.py` 按 case_id 查询 |
| Trace | 重放过程完整 Trace | 复用现有 parser 解析，按 `replay=true` 标记区分重放 Trace |

**4. FP 消除判定（评测引擎）**

评测引擎对比原始判定与重放判定，判定该误报是否消除：

| 原始判定 | 重放判定 | 判定结果 |
|---------|---------|---------|
| FP（误报） | TN（正确排除） | **FP 已消除** — 知识改进有效 |
| FP（误报） | FP（仍误报） | **FP 未消除** — 知识改进无效或不足 |
| FP（误报） | TP（正确报告） | **异常** — 知识改进引入了新问题（误报变漏报），需人工介入 |

**涉及文件**：
- 新建 `application/replay_verifier.py` — 从漏洞中心/Trace 读取重放结果 + FP 消除判定
- 复用 `infrastructure/vuln_center_client.py` — 按 case_id 查询重放后的判定结论
- 复用现有 parser — 解析重放 Trace（按 `replay=true` 标记区分）
- 各 Agent 自行实现重放执行逻辑（人工在 Agent 管理界面操作，重放方式由 Agent 自行决定）

---

## 7 知识系统改造接口

**结论：知识库和记忆进化模块均无需改造。** 知识库已有完整 API，记忆进化数据在共享 NFS 卷上可直接读取，Trace 中已可通过 `is_kg_interaction` / `is_memory_interaction` 区分访问来源。

### 7.1 知识库（已确认 API 可用，无需额外开发）

知识库（athena）已提供完整 API，评测引擎直接调用即可：

| API 端点 | 用途 | 盘点维度 |
|---------|------|---------|
| `GET /api/athena/projects/{pid}/knowledge/tree` | 全量文件清单（path + size + modified_at） | 覆盖度 |
| `GET /api/athena/projects/{pid}/knowledge/index?dir={dir}` | 结构化目录树（directories + documents，含 name/description/topic） | 覆盖度 |
| `GET /api/athena/projects/{pid}/knowledge/file?path={path}` | 单条文档全文（含 frontmatter 元数据） | 质量 |
| `GET /api/athena/projects/{pid}` | 项目信息（counts: A/B/C/raw，knowledge_enabled） | 覆盖度 |
| `GET /api/athena/management/analytics/projects/{pid}` | 知识使用效果统计（success_rate/nohit_rate/recall_hits） | 质量 |

**知识条目 frontmatter 已有元数据**（无需知识库额外开发）：

| frontmatter 字段 | 用途 | 盘点维度 |
|-----------------|------|---------|
| `name` | 知识条目名称 | 标识 |
| `description` | 一句话描述 | 覆盖度 |
| `type` | 知识类型（判例模式/负结论/安全假设等） | 覆盖度 |
| `层级` | L1/L2/L3 层级标识 | 覆盖度 |
| `topic` | 漏洞类型标签列表 | 覆盖度（按漏洞类型匹配） |
| `锚点` | 含 `代码版本:x.x.x` | 质量 |
| `来源` | 知识来源（工具/人工） | 质量 |
| `验证状态` | 已验证/未验证 | 质量 |

→ **结论：知识库不需要额外开发 API。** 现有 API + frontmatter 元数据已覆盖两个维度的盘点需求。

### 7.2 记忆进化模块（直接读文件系统，无需 API）

记忆进化系统的数据存储在共享 NFS 卷上，评测引擎可直接读取。记忆数据按 task 粒度存储，每个 task 的 `init.json` 定义目录 schema、知识蒸馏链和 keeper 角色。

| 数据来源 | 路径 | type | level | 说明 |
|---------|------|------|-------|------|
| 目录 schema | `seeddir/init.json` | — | — | 定义所有桶的 name/type/level/source/distill/keeper/annotation + 蒸馏链 |
| 历史漏洞 | `seeddir/historical-vulns/*.md` | long-term | L1 | 从漏洞中心拉取的已确认漏洞，蒸馏→vuln-patterns/hunting-ideas |
| 历史误报 | `seeddir/historical-fps/*.md` | long-term | L1 | 从漏洞中心拉取的已确认误报，蒸馏→fp-patterns |
| 漏洞模式 | `seeddir/vuln-patterns/*.md` | long-term | L2 | 可复用漏洞模式（source/sink/sanitize），蒸馏→hunting-ideas/target-profile |
| 误报模式 | `seeddir/fp-patterns/*.md` | long-term | L2 | 可复用误报判别信号与查证规则 |
| 产品文档 | `seeddir/product-docs/*.md` | long-term | L1 | 被测项目产品/架构文档 |
| 信任边界 | `seeddir/business-assumptions/*.md` | long-term | L2 | 信任边界与安全假设 |
| 狩猎思路 | `seeddir/hunting-ideas/*.md` | long-term | L3 | 可执行的漏洞挖掘检查点 |
| 目标画像 | `seeddir/target-profile/*.md` | long-term | L4 | 模块清单/入口/攻击面 |
| 敏感入口 | `seeddir/entry-assessment/entry-assessment.json` | short-term | L1 | 外部可控入口函数清单（JSON 格式，keeper=mem-entry） |
| 内部入口 | `seeddir/entry-internal/entry-internal.json` | short-term | L1 | 内部危险函数/sink 清单（JSON 格式，keeper=mem-entry） |
| 运行轨迹 | `seeddir/trace/` | trace | — | agent 运行 trace（外部写入） |
| 提问画像 | `seeddir/request-profile/` | archive | L1 | 知识货架提问记录与分类统计（只读消费） |
| Agent 记忆 | `seeddir/memory/` | memory | L1 | 含 MEMORY.md 索引 + raw/{agent}/ + details/{agent}/，由 agent 写入 |

→ **结论：记忆进化不需要额外开发 API。** 评测引擎在 INVENTORY 阶段遍历 `/data/files/{pid}/tasks/*/tools/memengine-*/seeddir/` 目录，读 `init.json` 获取目录 schema，按 type（long-term/short-term/trace/archive/memory）和 level（L1–L4）分类盘点。

**实现方式**：评测引擎 Pod 挂载了与 Agent Pod 相同的 NFS 卷（`/data`），可直接读取记忆目录，无需 kubectl exec。

### 7.3 返回内容标记来源

| 改造项 | 说明 | 优先级 |
|--------|------|--------|
| Trace 中标记知识访问目标系统 | 现有 `is_kg_interaction`（知识库）/ `is_memory_interaction`（记忆进化）已区分，无需改 | 已完成 |

---

## 8 指标计算详细设计

### 8.1 端到端指标

| 指标 | 定义 | 数据来源 |
|------|------|---------|
| E2E FPR | 误判非漏洞数 / (Agent命中基线漏洞数 + Agent命中基线Sink未上报数) | 现有 FPR 分析 |
| 负向知识率 | 负向效果知识访问数 / 总知识访问数 | knowledge_access_detail |

### 8.2 生命周期过程指标（M15–M21）

| 指标 | 定义 | 分子来源 | 分母来源 |
|------|------|---------|---------|
| M15 知识访问发起率 | 发起访问的 case 数 / 需要知识的 case 数 | l2_initiated=True 的去重 case 数 | l1_need_knowledge=True 的去重 case 数 |
| M16 召回意识缺失率 | 未发起访问 / 需要知识的 case 数 | l2_initiated=False 的去重 case 数 | l1_need_knowledge=True 的去重 case 数 |
| M17 查询准确率 | 准确查询数 / 总查询数 | l3_query_accurate=True 的访问数 | l2_initiated=True 的访问数 |
| M18 知识存在率 | 返回内容的查询数 / 总查询数 | l4_knowledge_exists=True 的访问数 | l2_initiated=True 的访问数 |
| M19 知识召回成功率 | 成功取回的访问数 / 发起访问数 | l5_retrieved=True 的访问数 | l2_initiated=True 的访问数 |
| M20 知识使用率 | 推理引用了知识的召回数 / 成功召回数 | l6_used=True 的访问数 | l5_retrieved=True 的访问数 |
| M21 死知识率 | 召回但未使用的数 / 成功召回数 | l6_used=False 的访问数 | l5_retrieved=True 的访问数 |

### 8.3 因果链指标（M26）

| 指标 | 定义 | 分子来源 | 分母来源 |
|------|------|---------|---------|
| M26 阶段误报承担率 | 该阶段断点 case 数 / 总误报 case 数 | causal_chain 标注的断点阶段 | 总 FP case 数 |

### 8.4 NA 契约

遵循现有 NA 契约：零分母返回 `calculation_status=NA` + `reason_code`。NA 行不携带估计值。

各新指标的具体 reason_code：

| 指标 | reason_code | 触发条件 |
|------|------------|---------|
| M15/M16 | `NO_NEED_KNOWLEDGE_CASE` | 无 `l1_need_knowledge=True` 的 case（分母=0） |
| M17/M18 | `NO_INITIATED_ACCESS` | 无 `l2_initiated=True` 的访问（分母=0） |
| M19 | `NO_INITIATED_ACCESS` | 无 `l2_initiated=True` 的访问（分母=0） |
| M20/M21 | `NO_RETRIEVED_ACCESS` | 无 `l5_retrieved=True` 的访问（分母=0） |
| M26 | `NO_FP_CASE` | 总 FP case 数=0（分母=0） |

---

## 9 涉及文件清单

### 9.1 新建文件

| 文件 | 说明 |
|------|------|
| `domain/lifecycle/__init__.py` | 模块入口 |
| `domain/lifecycle/analyzer.py` | L0–L7 误报根因全链路分析 |
| `domain/lifecycle/evidence_chain.py` | L7 判定（LLM 方向一致性 + 知识正确性） |
| `domain/lifecycle/case_filter.py` | 有效 case 筛选 |
| `domain/knowledge_inventory/__init__.py` | 模块入口 |
| `domain/knowledge_inventory/inventory.py` | 知识盘点（覆盖度/质量） |
| `domain/causal_chain/__init__.py` | 模块入口 |
| `domain/causal_chain/analyzer.py` | 因果链断点分析 |
| `application/replay_verifier.py` | 从漏洞中心/Trace 读取重放结果 + FP 消除判定 |

### 9.2 修改文件

| 文件 | 改什么 |
|------|--------|
| `domain/metrics/__init__.py` | 新增 calc_m15~calc_m21, calc_m26 + 扩展 run_all_metrics() |
| `application/report_assembler.py` | ReportModel 新增 lifecycle_uri/inventory_uri + 段组装 + 改进建议生成 |
| `application/evaluation_service.py` | pipeline 新增 INVENTORY / LIFECYCLE_ANALYSIS / CAUSAL_CHAIN 阶段 + 段写入 + 重试路径 |
| `orchestration/state_machine.py` | 白名单新增跳转 |
| `persistence/repositories/fact_repo.py` | 新增 knowledge_access_detail 的 INSERT 函数 |
| `infrastructure/migrations.py` | 新增迁移条目 |
| `api/routes/evaluations.py` | 新增 2 个端点（lifecycle/inventory 报告） |
| `schema.sql` | 新增 knowledge_access_detail 表 DDL + CHECK 约束扩展 |

### 9.3 不改文件

| 文件 | 为什么不改 |
|------|-----------|
| `domain/raw_event.py` | `is_kg_interaction` + `is_memory_interaction` 二分法已与方案对齐 |
| `domain/facts/__init__.py` | KnowledgeInteractionFact 已有 memory 字段 |
| `workers/resolvers.py` | KnowledgeResolverImpl 已支持 memory 标记 |
| `workers/sink_matcher.py` | 匹配逻辑不变 |
| `workers/ai_matcher.py` | 匹配逻辑不变 |

---

## 10 改造排期

> 详见 `docs/knowledge-effect-eval-overview.md` §9。

---

## 11 待确认项

| # | 问题 | 影响 | 状态 |
|---|------|------|------|
| 1 | ~~L3 查询准确率的判定标准——关键词匹配还是 LLM 判定？~~ | ~~影响计算成本和准确性~~ | **已确认：用 LLM 判定**（与 L7 判定一致） |
| 2 | ~~L1 需要知识的判定标准——哪些漏洞类型算"需要知识"？~~ | ~~需要漏洞类型规则表~~ | **已确认：用 LLM 判定**（与 L3/L7 一致） |
| 3 | ~~消融对照方案~~ | ~~多知识访问粒度 + 跨 session 衔接复杂度~~ | **已取消**（复杂度过高，L7 改为方向一致性判定） |
| 4 | ~~知识库覆盖度 API 是否可用？~~ | ~~知识盘点依赖此 API~~ | **已确认可用**（§7.1） |
| 5 | ~~记忆进化盘点 API 是否需要开发？~~ | ~~记忆盘点数据来源~~ | **已确认不需要**（§7.2，直接读文件系统） |
| 6 | ~~知识条目是否有质量元数据？~~ | ~~质量判定~~ | **已确认有**（frontmatter 含 `锚点`/`验证状态`/`topic`） |
