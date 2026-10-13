# 奇美拉误报归因与改进测评——需求设计说明书

> 本文档基于 `docs/knowledge-effect-eval-overview.md` 方案，对照现有代码结构，逐条说明每个改造项的现状、改什么、怎么改。

---

## 1 背景与目标

> 系统架构、现状误报表、测评范围推导详见 `docs/knowledge-effect-eval-overview.md` 第 0 节。

### 1.1 现状

V2 评测引擎已实现 L0–L7 误报根因全链路分析（`lifecycle/analyzer.py`）、因果链断点分析（`causal_chain/analyzer.py`）、有效 case 筛选（`lifecycle/case_filter.py`）、knowledge_access_detail 持久化、agent_datasource_config 数据源配置、lifecycle 报告段组装。已能回答"误报根因在哪"、"知识有没有用"、"谁的责任"。

**尚缺**：
- 召回率 + 准确率指标（从漏洞中心终审数据计算，驱动平台能力持续迭代）
- DTS 问题单系统（case 级根因定位：哪个 case 误报/漏报、跨了哪些 session、根因发生在哪个 session）
- 回归验证（case 重放判断误报/漏报是否消除）
- 看板界面（平台级误报归因与改进看板）

**需清理的废弃代码**：
- `knowledge_inventory/` 整个目录（知识盘点已从方案中删除）
- `metrics/m15_m26.py`（M15–M26 过程指标已从方案中删除，只保留召回率+准确率）
- INVENTORY pipeline 阶段（知识盘点阶段已删除）
- business_phase 相关逻辑（方案明确"不深入业务阶段"，Agent 级别判定即可）
- cause_code H（方案只有 A–G 七种成因，无 H）

### 1.2 目标

在 V2 评测引擎基础上增量改造，新增：
- 召回率 + 准确率指标（从漏洞中心终审数据计算，驱动平台能力持续迭代）
- DTS 问题单系统（case 级根因定位：哪个 case 误报/漏报、跨了哪些 session、根因发生在哪个 session）
- 回归验证（case 重放判断误报/漏报是否消除）
- 看板界面（平台级误报归因与改进看板）
- 产出闭环（DTS 问题单 + 回归验证 + 基线集回流）

同时清理废弃代码：删除 knowledge_inventory 模块、M15–M26 过程指标、INVENTORY 阶段、business_phase 逻辑。

### 1.3 约束

- 不新建项目，基于现有 `athena_eval_engine` 代码增量改造
- 所有改造一次性开发，不分期
- 统计单元 = 每次知识访问，只对有效 case 内的知识访问做统计
- 禁止截断、禁止降级跳过（遵循 AGENTS.md）

---

## 2 现有代码结构摘要

### 2.1 目录结构

> 完整目录结构见 `AGENTS.md`。本次改造涉及的文件见第 10 节。

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

注意：M1–M4 在 docstring 中提及但未实现，DB CHECK 只允许 M5–M13。本次改造不新增 metric_result 指标，召回率/准确率从漏洞中心终审数据直接计算，写入 lifecycle 报告段。

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

存储每次知识访问的 L0–L7 生命周期判定结果和效果标签。**在 Agent 级别做 L0–L7 判定**——不深入业务阶段，具体根因由 DTS 单驱动 Agent 自行排查。L0 标记知识的原始来源（用户上传/历史漏洞经验/已有知识升华等），不参与断链判定和后续逻辑。

```sql
CREATE TABLE knowledge_access_detail (
    access_id          VARCHAR(128) PRIMARY KEY,  -- {evaluation_id}_{task_run_id}_{event_idx}
    evaluation_id      VARCHAR(64) NOT NULL,
    task_run_id        VARCHAR(64) NOT NULL,
    task_id            VARCHAR(128) NOT NULL,
    agent_type         VARCHAR(32) NOT NULL,       -- turing/argo/secmate/dataflow/cvuln_verify/webvuln_verify
    event_idx          INT NOT NULL,              -- 对应 RawEvent 在 events 列表中的序号
    source_system      VARCHAR(32) NOT NULL,      -- 知识库 / 记忆进化（区分访问的是哪个后端系统）
    l0_origin          VARCHAR(64),               -- L0 知识原始来源（用户上传/历史漏洞经验/已有知识升华等，仅标记 provenance，不参与断链判定）
    -- L1–L6 判定
    l1_need_knowledge  BOOLEAN,                   -- 是否需要知识
    l2_initiated       BOOLEAN,                   -- 是否发起访问
    l3_query_accurate  BOOLEAN,                   -- 查询是否聚焦
    l4_knowledge_exists BOOLEAN,                  -- 返回内容是否非空
    l5_retrieved       BOOLEAN,                   -- 工具是否成功取回
    l6_used            BOOLEAN,                   -- 推理是否引用
    -- L7 判定（LLM 方向一致性 + 知识正确性）
    l7_influenced      BOOLEAN,                   -- 是否影响结论
    l7_method          VARCHAR(32),               -- EVIDENCE_CHAIN
    -- 效果标签
    effect_label       VARCHAR(16),               -- POSITIVE / NEGATIVE / NEUTRAL
    -- 成因标签
    cause_code         VARCHAR(8),                -- A–G
    -- 证据
    query_content      TEXT,                      -- 查询内容
    returned_content   TEXT,                      -- 返回内容摘要
    reasoning_ref      TEXT,                      -- 推理引用片段
    judgment_conclusion TEXT,                     -- 判定结论
    evidence_json      JSON,                      -- 完整证据（LLM 分析结果等）
    created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE (task_run_id, event_idx),
    INDEX idx_kad_eval (evaluation_id),
    INDEX idx_kad_agent (evaluation_id, agent_type),
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

### 3.2 迁移脚本

在 `infrastructure/migrations.py` 的 `MIGRATIONS` 列表新增：

```python
{
    "id": "007_knowledge_access_detail",
    "desc": "新增知识访问明细表",
    "sql": [
        "CREATE TABLE IF NOT EXISTS knowledge_access_detail (...)",  # 上文 DDL
    ],
}
```

**涉及文件**：
- `schema.sql` — 新增 knowledge_access_detail 表 DDL
- `infrastructure/migrations.py` — 新增迁移条目

### 3.3 新增表：agent_datasource_config（Agent 数据源配置）

存储各 Agent 的数据库连接信息，供 parser 直连 Agent 数据库查询 session 关系图。方案不深入业务阶段，因此**不需要阶段标识符配置**——只需要 session 之间的 parent-child 调用关系，用于跨 session case 链分析。**支持通过配置界面修改**，修改后立即生效（复用 `system_config` 的 `_version` 机制）。

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
INSERT IGNORE INTO agent_datasource_config (agent_type, display_name, db_type, host, port, username, password, database_name, relation_tables, enabled) VALUES
('turing', 'Turing MySQL', 'mysql',
 'turing-app-security-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'turing_app_security_pass', 'turing_app_security',
 JSON_OBJECT('task', 'turing_task', 'parent_field', 'parent_task_id', 'session_field', 'agent_session_id',
             'trace_table', 'turing_task_trace', 'investigation_table', 'turing_investigation'),
 1),
('argo', 'Argo MySQL', 'mysql',
 'chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'Icsl_argo', 'argo_c',
 JSON_OBJECT('table', 'intents', 'session_field', 'session_id', 'fact_field', 'to_fact_id', 'suggestion_field', 'suggestion_refs'),
 1),
('secmate', 'SecMate MySQL', 'mysql',
 'secmate-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'Huawei12#$', 'secmate',
 JSON_OBJECT('finding_table', 'finding', 'source_field', 'source_finding_id', 'task_table', 'task'),
 1),
('dataflow', 'DataflowVulnScan MySQL', 'mysql',
 'secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local', 3306, 'root', 'Huawei12#$', 'dvs_{project_id}',
 JSON_OBJECT('sessions_table', 'dvs_task_graph_sessions', 'nodes_table', 'dvs_task_graph_nodes', 'edges_table', 'dvs_task_graph_edges',
             'fallback_table', 'orchestration'),
 1),
('cvuln_verify', 'CVulnVerify PostgreSQL', 'postgresql',
 'secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local', 5432, 'postgres', 'secflow123', 'secflow_vuln_verify_v2',
 JSON_OBJECT('table', 'vuln_verify_attempt', 'predecessor_field', 'predecessor_attempt_id', 'reason_field', 'successor_reason'),
 1),
('webvuln_verify', 'WebVulnVerify (无独立DB)', 'none',
 NULL, NULL, NULL, NULL, NULL,
 JSON_OBJECT('source', 'trace', 'parent_field', 'session.parent_id', 'vuln_id_field', 'metadata.vulnerability_id'),
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

**职责**：对每次知识访问，在 Agent 级别逐级判定 L0–L7。L0 标记知识的原始来源（用户上传/历史漏洞经验/已有知识升华等），不参与断链判定；L1 为前置判定，不产生断链；L2–L7 逐级判定断点，输出 cause_code（A–G）。**不深入业务阶段**——具体根因定位由 DTS 单驱动 Agent 自行排查。

**核心设计**：在 Agent 级别做 L0–L7 判定。L0 仅标记原始来源 provenance，不产生断链；L1 为前置判定，不产生断链；L2–L7 逐级判定断点。一个误报可能有多个断点，每个断点独立标注成因——一个 case 可能对应多条 DTS 单。

**输入**：
- `events: list[RawEvent]` — 一个 task_run 的全部事件
- `interactions: list[dict]` — KnowledgeInteractionFact 的 interactions 列表
- `memory_interactions: list[dict]` — 记忆交互列表
- `findings: list[dict]` — 提取的 finding
- `outcome: OutcomeFact` — 最终判定结果
- `benchmark_item: BenchmarkItem` — 基线 case 信息（漏洞类型 vulnerability_type、漏洞描述 description、sink 点 source_file/source_function），供 L7 判定知识正确性时对比

**输出**：`list[KnowledgeAccessDetail]` — 每次知识访问一条，含 `agent_type` 字段

**L0 来源标记**：从知识条目的 frontmatter `来源` 字段读取（如"工具"/"人工"/"蒸馏"等），或从记忆目录的 `init.json` 的 `dirs[].source` 字段读取（如"vuln-center"/"knowledge-shelf"等），写入 `l0_origin` 字段。不产生断链，不参与后续逻辑。

**L1–L6 判定逻辑**：

| 级别 | 判定方法 | 数据来源 |
|------|---------|---------|
| L1 需要知识？ | **LLM 判定** 是否需要知识支撑 | 推理上下文 + benchmark_item 漏洞类型 |
| L2 发起访问？ | 程序判定：是否存在 `is_kg_interaction` 或 `is_memory_interaction` 为 True 的事件 | RawEvent flag |
| L3 查询准确？ | **LLM 判定** 查询内容是否聚焦 | interaction.command + 推理上下文 |
| L4 知识存在？ | 程序判定：工具返回内容是否非空 | interaction.output_preview |
| L5 成功取回？ | 程序判定：工具是否报错/超时 | interaction 中是否有 error/timeout 标记 |
| L6 被使用？ | **LLM 判定** 推理文本是否引用了知识返回内容 | REASONING/MESSAGE 文本 vs interaction.output_preview |

**L7 判定逻辑**（对 L6 已通过的访问，用 LLM 判定）：

输入：知识返回内容 + 推理引用片段 + 判定结论 + 基线漏洞信息（benchmark_item 的 vulnerability_type / description / source_file / source_function）

输出：JSON `{knowledge_correct: bool, direction_consistent: bool, confidence: float, reason: str}`

| 知识正确性 | 方向一致性 | 效果标签 | 成因 |
|-----------|-----------|---------|------|
| 正确 | 一致 | 正向 | — |
| 错误 | 一致 | 负向 | G |
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
L7 推动但方向错 → G（导致误判，知识内容有误/过时/不适用）
```

**漏斗过滤策略**（控制 LLM 调用成本）：

L1–L7 不是逐级都调 LLM。程序判定级别（L2/L4/L5）可短路后续 LLM 调用：

```
L1（LLM）→ L1=False: 不需要知识，不产生断链，跳过 L2–L7
         → L1=True:  继续 L2
L2（程序）→ L2=False: 断点 A，跳过 L3–L7
         → L2=True:  继续 L3
L3（LLM）→ L3=False: 断点 B，跳过 L4–L7
         → L3=True:  继续 L4
L4（程序）→ L4=False: 断点 C，跳过 L5–L7
         → L4=True:  继续 L5
L5（程序）→ L5=False: 断点 D，跳过 L6–L7
         → L5=True:  继续 L6
L6（LLM）→ L6=False: 断点 E，跳过 L7
         → L6=True:  继续 L7
L7（LLM）→ 正向 / 负向(G) / 中性(F) / NULL(无法确认)
```

**LLM 调用工程约束**：

| 约束 | 说明 |
|------|------|
| 批处理模式 | 一个 case 的全部知识访问的 L1/L3/L6/L7 判定通过 `submit_llm_batch` 批量提交，不逐条调用 |
| 并发控制 | 复用 `infrastructure/concurrency.py` 的 `llm_max_concurrency` 全局门控，不新建并发参数 |
| 取消信号 | `cancel_cb` 通过 `iter_completed` 穿透到 LLM 内循环，在每批提交前检查 `_check_cancel()` |
| 失败处理 | 复用 `chat_json()` 的 20 次重试 + JSON 自修复 + context-length 检测，不另建重试逻辑 |
| reasoning_effort | L7 判定需要深度推理，设置 `reasoning_effort=high`；L1/L3/L6 判定用默认值 |

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

**职责**：基于 `knowledge_access_detail` 的 `agent_type` + L1–L7 判定结果，按 Agent 维度聚合误报归因。L0 不参与此模块逻辑。**不深入业务阶段**——具体根因由 DTS 单驱动 Agent 自行排查。

**输入**：`knowledge_access_detail` 表中该 evaluation 的全部记录（已含 agent_type + L1–L7 判定，L0 l0_origin 仅用于 provenance 标记）

**输出**：
- 交叉归因矩阵：Agent（行）× L2–L7 级别（列），每格统计该 Agent 该级别断链的 case 数和成因分布
- 每个误报 case 的断点清单（一个 case 可能有多个断点，分布在矩阵的不同格子中；L0 不产生断链）

**涉及文件**：
- 新建 `domain/causal_chain/__init__.py`
- 新建 `domain/causal_chain/analyzer.py`

### 4.3 有效 case 筛选模块

**新建文件**：`domain/lifecycle/case_filter.py`

**职责**：从漏洞中心人工确认数据出发，筛选 FP/FN case 对应的 task_run，只对有效 case 内的知识访问做统计。

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

**跨 session case 处理**：一个 case 在 Agent 内部可能跨多个 session（入口识别→数据流追踪→漏洞模式识别→Sink 定位→判定上报，每步可能独立 session）。session 间的 parent-child 调用关系存储在各 Agent 自己的数据库中，评测引擎通过 `agent_datasource_config` 配置的 `relation_tables` 直连 Agent DB 查询，构建 session 调用链。按 `task_id` 分组，组级别聚合判定 FP/FN，组内保留有知识访问记录的 task_run。

**找不到对应 trace 的 case**：记录到 `unmatched_cases`，在报告中告警，不参与分析。

#### 4.3.1 误报类型提取（漏洞中心终审理由）

漏洞中心的人工确认数据中包含结构化误报分类字段，直接提供 C1-C10 的映射来源，无需 L0-L7 推断。

**数据来源**：`human_confirmation` 对象（case 详情 API 返回）

| 字段 | 类型 | 说明 |
|------|------|------|
| `false_positive_reason` | string | 误报原因关键词（结构化枚举，非自由文本） |
| `false_positive_group` | string | 误报分组：`confirmed_fp`（确认为误报）/ `non_fp`（非误报） |
| `summary` | string | 终审理由全文（格式为"误报：{关键词}：{详细说明}"） |
| `operator` | string | 终审者工号 |
| `confirmed_at` | datetime | 终审时间 |

**`false_positive_reason` → C1-C10 映射表**：

| 漏洞中心 `false_positive_reason` | 方案编号 | 方案名称 |
|---|---|---|
| 重复上报 | C1 | 重复上报 |
| 入口不可达 | C2 | 入口不可达 |
| 输入实际可控或已过滤校验 | C3 | 已有校验或过滤 |
| 输入实际不可控或已过滤校验 | C4 | 参数实际不可控 |
| 上下文不足导致 | C5 | 上下文不足 |
| 调用链不存在 | C6 | 调用链不存在（幻觉） |
| 有框架防御但未提供 | C7 | 框架/组件自带防御 |
| 配置或部署导致 | C8 | 配置或部署导致 |
| 业务场景需要 | C9 | 业务设计如此 |
| 测试/示例代码 | C10 | 测试/示例代码 |
| 其他误报原因 | — | 未覆盖，DTS 单 fp_type 记录原始值 |

**`false_positive_group` 过滤规则**：
- `confirmed_fp` → 确认为误报，参与分析
- `non_fp` → 非误报（终审认为不是漏洞但理由不属于误报分类），不生成 DTS 单

**API 改造**：`vuln_center_client.py` 的 `list_vuln_cases()` 需开启 `include_decision_reason=true`，`_case_to_benchmark()` 需提取 `false_positive_reason` 和 `false_positive_group`。

**涉及文件**：
- 新建 `domain/lifecycle/case_filter.py`
- `infrastructure/vuln_center_client.py` — `list_vuln_cases()` 参数改为 `include_decision_reason=true`；`_case_to_benchmark()` 新增 `fp_reason` / `fp_group` 字段提取
- 复用 v1 `application/fpr_analysis.py` 的 LLM 匹配方法（`_llm_match_batch` / `_run_matching`）
- 复用 v1 `workers/ai_matcher.py` 的 `_verify_sink` / `_norm_path` / `_parse_bool`
- 依赖 `alert_center_data`（从 INGESTING 阶段获取，用于 FN 判定）

### 4.4 召回率/准确率计算

**修改文件**：`application/evaluation_service.py` + `infrastructure/vuln_center_client.py`

从漏洞中心终审数据直接计算，不经过 metric_result 表，不新增 metric 函数：

| 指标 | 定义 | 计算方式 |
|------|------|---------|
| 召回率 | TP / (TP + FN) | TP = 基线 VULNERABLE 且 Agent 上报的 case 数；FN = 基线 VULNERABLE 且 Agent 未上报的 case 数。数据来自 benchmark_item + 有效 case 筛选结果 |
| 准确率 | TP / (TP + FP) | TP 同上；FP = 基线 NON_VULNERABLE 且 Agent 上报 finding 且 CONFIRMED 的 case 数。数据来自 benchmark_item + 有效 case 筛选结果 |

在 REPORTING 阶段计算，写入 lifecycle 报告段。现有 M5–M13 不受影响。

**涉及文件**：
- 修改 `application/evaluation_service.py` — REPORTING 阶段新增召回率/准确率计算
- 修改 `application/report_assembler.py` — ReportModel 新增 recall_rate / precision_rate 字段

### 4.5 报告段扩展

**修改文件**：`application/report_assembler.py` + `application/evaluation_service.py`

现有三段：`{eid}.json`（base）+ `{eid}_fpr.json`（FPR）+ `{eid}_kg.json`（KG）

新增一段：
- `{eid}_lifecycle.json` — 生命周期分析段（召回率 + 准确率 + L0 原始来源分布 + L1–L7 断点分布 + 逐 case 详情）

**ReportModel 扩展**：
```python
@dataclass
class ReportModel:
    # ... 现有字段 ...
    lifecycle_uri: str = ""    # 生命周期段文件路径
```

**报告段 JSON 结构**：

`{eid}_lifecycle.json`：
```json
{
  "evaluation_id": "...",
  "l0_origin_distribution": { "工具": 10, "人工": 5, "蒸馏": 3 },
  "breakpoint_distribution": {
    "Turing": { "L2": 3, "L3": 1, "L4": 2, "L5": 0, "L6": 1, "L7": 0 },
    "CVulnVerify": { "L2": 5, "L3": 2, "L4": 0, "L5": 1, "L6": 3, "L7": 1 }
  },
  "recall_rate": 0.85,
  "precision_rate": 0.72,
  "per_case_details": [
    { "task_run_id": "...", "agent_type": "...", "breakpoints": [...], "cause_codes": [...] }
  ]
}
```

**API 端点新增**：
- `GET /api/v1/evaluations/{eid}/report/lifecycle` — 获取生命周期段

**涉及文件**：
- 修改 `application/report_assembler.py` — ReportModel 新增字段 + lifecycle 段组装
- 修改 `application/evaluation_service.py` — 新增段写入逻辑 + pipeline 阶段扩展
- 修改 `api/routes/evaluations.py` — 新增 1 个端点（lifecycle 报告）

---

## 5 Pipeline 阶段扩展

### 5.1 现有阶段

```
INGESTING → PARSING → AI_MATCHING → RESOLVING → PAIRING → CALCULATING → REPORTING → FINALIZE
```

### 5.2 新增阶段

在 CALCULATING 和 REPORTING 之间插入两个新阶段：

```
CALCULATING → LIFECYCLE_ANALYSIS → CAUSAL_CHAIN → REPORTING → FINALIZE
```

| 新阶段 | 状态 | 操作 |
|--------|------|------|
| LIFECYCLE_ANALYSIS | `LIFECYCLE_ANALYSIS` | 1. 有效 case 筛选 2. L0 来源标记（程序判定，从 frontmatter `来源` 或 init.json `source` 读取） 3. L1–L6 判定（L1/L3/L6 用 LLM，L2/L4/L5 程序判定） 4. L7 判定（LLM，只读 Trace） 5. 效果标签 + 成因标签写入 knowledge_access_detail |
| CAUSAL_CHAIN | `CAUSAL_CHAIN` | 1. Agent 级别断点分析（基于 knowledge_access_detail 已有的 agent_type + L1–L7 判定结果聚合，L0 不参与） 2. 自动生成 DTS 问题单 |

### 5.3 状态机扩展

**修改文件**：`orchestration/state_machine.py`

白名单新增正向跳转：
```
CALCULATING → LIFECYCLE_ANALYSIS
LIFECYCLE_ANALYSIS → CAUSAL_CHAIN
CAUSAL_CHAIN → REPORTING
```

恢复路径（与现有 FAILED/CANCEL_REQUESTED 一致）：
```
LIFECYCLE_ANALYSIS → FAILED → resume → LIFECYCLE_ANALYSIS
CAUSAL_CHAIN → FAILED → resume → CAUSAL_CHAIN
RUNNING → CANCEL_REQUESTED → CANCELLING → CANCELLED（任意阶段可取消）
```

取消检查点：`_check_cancel()` 在每个新阶段入口和 LLM 批次提交前检查。

**修改文件**：`schema.sql` + `infrastructure/migrations.py`

evaluation 表 status CHECK 新增 `LIFECYCLE_ANALYSIS` 和 `CAUSAL_CHAIN`。

### 5.4 重试路径

**修改文件**：`application/evaluation_service.py`

现有重试路径：facts 已在 DB → 跳过解析 → 直接 CALCULATING。

新增重试路径：
- `knowledge_access_detail` 按 `access_id` 幂等检查：该 task_run 的记录已存在 → 跳过 LIFECYCLE_ANALYSIS → 直接 CAUSAL_CHAIN
- 重跑时不清空 `knowledge_access_detail` 表，通过 `INSERT ... ON DUPLICATE KEY UPDATE` 幂等覆盖

**注意**：现有代码的 `facts_already_exist` 检查在重跑时始终为 False（每次清数据）。新模块不沿用此模式，改为按 `access_id` 幂等检查，避免重跑时丢失已完成的分析结果。

### 5.5 产出闭环

**职责**：从分析结果到改进动作到回归验证的完整闭环。回归验证 = 通过 case 重放判断该误报/漏报是否消除。

**核心原则**：一个 case 在 Agent 级别做 L0–L7 判定，可能存在**多个断点**。L0 标记知识原始来源（provenance）不产生断链；L1–L7 的断点独立输出成因，由本系统提 DTS 单给对应责任方（Agent 或知识方），责任方自行定位具体根因与解决方案。**一个 case 的全部 DTS 单关闭后统一触发一次回归测试**，回归重放由产生误报/漏报的 Agent 执行（知识方不参与重放，只负责更新知识内容）。开发态 FP 和 FN 都有回归判定（FP→TN=消除，FN→TP=消除），运行态只判定 FP。

| 环节 | 内容 | 实现方式 |
|------|------|---------|
| 看板界面 | 召回率 + 准确率 + 误报类型分布 + 根因断点分布 + DTS 问题单状态 | 看板页面展示 |
| 归因报告 | 交叉归因矩阵（效果 × 生命周期 × Agent × 知识来源），每个断点一条记录 | lifecycle 段（含因果链分析） |
| DTS 问题单 | **按断点逐条生成**：每个断点的 Agent × 级别 × 成因 → 责任方（Agent 或知识方）+ 误报类型（从漏洞中心终审理由 `false_positive_reason` 映射 C1-C10，详见 4.3.1 节） | CAUSAL_CHAIN 阶段自动生成 |
| 回归验证 | 全部 DTS 单关闭后统一触发一次回归测试，产生误报/漏报的 Agent 重放 case，判定该误报/漏报是否消除 | 详见 6.1 节 DTS 问题单管理 + 7.1 节 Case 重放协议 |

**DTS 问题单生成逻辑**（每个断点独立生成一条 DTS 单，一个 case 可能有多条）：

| 成因 | 断点位置 | 责任方 | DTS 内容 |
|------|---------|--------|---------|
| A 该查没查 | L2 断 | Agent | 该 Agent 未发起知识访问，需自行排查原因并增加知识触发点 |
| B 查询太泛 | L3 断 | Agent | 该 Agent 查询不聚焦，需自行排查查询模板并改进 |
| C 查了没得 | L4 断 | 知识方 | 知识不存在，需补充对应知识 |
| D 链路问题 | L5 断 | Agent + 知识方 | 工具失败/超时，需排查链路 |
| E 查到没用 | L6 断 | Agent | 该 Agent 召回知识但未引用，需自行排查推理引用逻辑 |
| F 用了没推动 | L7 断 | Agent / 知识方 | 知识未影响结论，需自行排查原因 |
| G 导致误判 | L7 负向 | 知识方 | 知识内容有误/过时/不适用，推动了错误判定，需修正知识内容 |

**涉及文件**：
- 修改 `application/report_assembler.py` — DTS 问题单生成
- 新建 `application/replay_verifier.py` — 从漏洞中心/Trace 读取重放结果 + FP/FN 消除判定
- 复用 `infrastructure/vuln_center_client.py` — 按 case_id 查询重放后的判定结论

---

## 6 DTS 问题单系统

### 6.1 DTS 问题单管理

**新建文件**：`domain/dts/issue.py` + `persistence/dts_repo.py` + `api/routes/dts.py`

**职责**：CAUSAL_CHAIN 阶段自动生成 DTS 问题单，责任方（Agent 或知识方）在系统中查看、定位、解决。本系统只负责提单和跟踪状态，不负责定位具体根因——具体根因由对应责任方自行排查。**一个 case 的全部 DTS 单关闭后统一触发一次回归测试**，产生误报/漏报的 Agent 重放该 case（知识方不参与重放，只负责更新知识内容），评测引擎给出"回归通过"或"回归不通过"结论。开发态 FP 和 FN 都有回归判定（FP→TN=消除，FN→TP=消除），运行态只判定 FP。

**DTS 状态流转**：

```
unlocated → improving → confirmed → [责任方 close] → closing → 自动触发回归测试
                                                                      ↓
                                                          passed / failed（退回 improving）
                                              ↓
                                          not_issue（责任方确认非其责任）
```

| status 值 | 含义 | 操作方 | 触发条件 |
|-----------|------|--------|---------|
| `unlocated` | DTS 单刚创建，责任方尚未查看 | 系统（自动创建） | CAUSAL_CHAIN 阶段生成 |
| `improving` | 责任方已确认问题，正在改进 | 责任方（Agent / 知识方） | 责任方查看后更新状态 |
| `confirmed` | 责任方已定位根因，填写了 root_cause + solution，准备关闭 | 责任方 | root_cause 和 solution 非空时可更新 |
| `closing` | 责任方已关闭 DTS 单，等待回归测试 | 系统（自动） | 责任方调用 POST /close |
| `passed` | 回归测试完成，FP/FN 已消除 | 评测引擎（自动判定） | 回归重放后判定 FP→TN 或 FN→TP |
| `failed` | 回归测试完成，FP/FN 未消除，DTS 单退回 improving | 评测引擎（自动判定） | 回归重放后判定 FP→FP 或 FN→FN |
| `not_issue` | 责任方确认非其责任或误报类型不成立 | 责任方 | 责任方调用 POST /reject + 填写 reason |

**多 DTS 单回归规则**：一个 case 可能有多条 DTS 单（多断点）。**全部 DTS 单关闭后统一触发一次回归测试**，不逐条触发。回归通过→全部 DTS 单关闭；回归不通过→全部 DTS 单退回改进确认，各责任方重新改进。

**知识方 DTS 单回归**：知识方（C/D/G 成因）的 DTS 单，回归重放由产生误报/漏报的 Agent 执行——知识方不参与重放，只负责更新知识内容。

**DTS 问题单数据模型**：

```sql
CREATE TABLE dts_issue (
    dts_id              VARCHAR(64) PRIMARY KEY,
    evaluation_id       VARCHAR(64) NOT NULL,
    task_run_id         VARCHAR(64) NOT NULL,
    task_id             VARCHAR(128) NOT NULL,        -- 关联 task（一个 case = 一个 task）
    agent_type          VARCHAR(32) NOT NULL,          -- 责任方（turing/argo/secmate/dataflow/cvuln_verify/webvuln_verify/knowledge_base）
    case_type           VARCHAR(8) NOT NULL,           -- FP / FN（误报 / 漏报）
    fp_type             VARCHAR(64),                   -- 误报类型（C1-C10），case 级属性，从漏洞中心终审理由映射，同一 case 的所有 DTS 单共用
    cause_code          VARCHAR(8) NOT NULL,           -- 成因（A-G）
    breakpoint_level    VARCHAR(8) NOT NULL,           -- 断点级别（L2-L7）
    -- 系统自动填充（生成时写入）
    access_id           VARCHAR(128),                  -- 关联的知识访问明细 ID（knowledge_access_detail.access_id）
    breakpoint_desc     TEXT,                          -- 断点描述（系统自动生成的摘要，如"Turing 在 L2 未发起知识访问"）
    evidence_uri        VARCHAR(512),                  -- 证据文件路径（推理引用片段、知识返回内容等，存文件 DB 存路径）
    -- Agent / 知识方填写
    root_cause          TEXT,                          -- 责任方定位的具体根因
    solution            TEXT,                          -- 责任方提出的解决方案
    -- 回归验证
    replay_eval_id      VARCHAR(64),                   -- 回归重放的评测 ID
    replay_result       VARCHAR(16),                   -- passed / failed
    -- 状态
    status              VARCHAR(32) NOT NULL DEFAULT 'unlocated',  -- unlocated/improving/confirmed/closing/passed/failed/not_issue
    -- 时间
    created_at          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    closed_at           DATETIME(3),                   -- Agent 关闭 DTS 单的时间
    INDEX idx_dts_eval (evaluation_id),
    INDEX idx_dts_agent (agent_type),
    INDEX idx_dts_status (status),
    INDEX idx_dts_task (task_id),
    FOREIGN KEY (evaluation_id, task_run_id) REFERENCES task_run(evaluation_id, task_run_id)
) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

**字段说明**：

| 字段 | 来源 | 说明 |
|------|------|------|
| `dts_id` | 系统生成 | `{evaluation_id}_{task_run_id}_{access_id}_{breakpoint_idx}` |
| `task_id` | task_run 关联 | 一个 case = 一个 task，用于多 DTS 单回归时按 task 分组 |
| `agent_type` | CAUSAL_CHAIN 阶段判定 | 责任方 Agent 名称；知识方 DTS 单为 `knowledge_base` |
| `case_type` | 有效 case 筛选结果 | FP 或 FN，决定回归判定逻辑（FP→TN=消除，FN→TP=消除） |
| `fp_type` | 漏洞中心终审理由映射 | C1-C10 误报类型，case 级属性，从 `human_confirmation.false_positive_reason` 映射（详见 4.3.1 节），同一 case 的所有 DTS 单共用 |
| `cause_code` | L0–L7 判定结果 | A-G，对应断点级别 |
| `breakpoint_level` | L0–L7 判定结果 | L2-L7，断点所在级别 |
| `access_id` | knowledge_access_detail | 关联的知识访问明细，用于追溯具体哪次知识访问出了问题 |
| `breakpoint_desc` | 系统自动生成 | 摘要描述，如"Turing 在 L2 未发起知识访问，场景需要参数可控性知识但未查询" |
| `evidence_uri` | 系统自动填充 | 证据文件路径（推理引用片段、知识返回内容、查询内容等），遵循大 payload 存文件模式 |
| `root_cause` | 责任方填写 | Agent / 知识方自行排查后填写的具体根因 |
| `solution` | 责任方填写 | Agent / 知识方提出的解决方案 |
| `replay_eval_id` | 回归测试触发后写入 | 回归重放对应的评测 ID，用于追溯重放过程 |
| `replay_result` | 评测引擎判定后写入 | passed（FP/FN 消除）/ failed（未消除） |
| `status` | 状态流转 | unlocated → improving → confirmed → closing → passed/failed/not_issue |
| `closed_at` | Agent 调用 /close 时写入 | Agent 关闭 DTS 单的时间戳 |

**迁移脚本新增**：

```python
{
    "id": "009_dts_issue",
    "desc": "新增 DTS 问题单表",
    "sql": [
        "CREATE TABLE IF NOT EXISTS dts_issue (...)",  # 上文 DDL
    ],
}
```

**涉及文件**：
- `schema.sql` — 新增 dts_issue 表 DDL
- `infrastructure/migrations.py` — 新增迁移条目 `009_dts_issue`

**API 端点**：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/v2/dts` | GET | 列出 DTS 问题单（支持按 evaluation_id / agent_type / status / cause_code / case_type 筛选 + 分页） |
| `/api/v2/dts/{dts_id}` | GET | 获取单个 DTS 问题单详情（含 breakpoint_desc + evidence_uri 证据内容 + 关联的 knowledge_access_detail） |
| `/api/v2/dts/{dts_id}` | PUT | 更新 DTS 单（责任方填写 root_cause / solution，更新 status） |
| `/api/v2/dts/{dts_id}/close` | POST | 责任方关闭 DTS 单（status → closing），触发回归检查 |
| `/api/v2/dts/{dts_id}/reject` | POST | 责任方标记为"非问题"（status → not_issue），需填写 reason |
| `/api/v2/dts/stats` | GET | DTS 统计（按 status / agent_type 聚合，供看板状态流水线使用） |
| `/api/v2/dts/by-task/{task_id}` | GET | 按 task 列出该 case 的全部 DTS 单（用于多 DTS 单回归时查看同 case 的全部单状态） |

**回归测试自动触发流程**：

```
Agent 调用 POST /api/v2/dts/{dts_id}/close
    ↓
评测引擎将 DTS 状态设为 closing
    ↓
检查该 case 是否还有未关闭的 DTS 单
    ├─ 有 → 等待其他 DTS 单关闭
    └─ 无 → 全部进入 closing，统一触发一次回归测试
    ↓
自动创建回归评测任务（重放该 case）
    ↓
产生误报/漏报的 Agent 按 7.1 节协议重放 case
（知识方不参与重放，只负责更新知识内容）
    ↓
评测引擎读取重放结果，判定 FP/FN 是否消除
    ↓
FP/FN 消除 → 全部 DTS 单状态设为 passed
FP/FN 未消除 → 全部 DTS 单状态设为 failed（退回 improving）
    ↓
结论写入全部 DTS 单（replay_result + replay_eval_id）
```

### 6.2 看板界面

**新建文件**：`static/dashboard.html`（看板总览页）+ `static/dts-detail.html`（DTS 单详情页）

**看板总览页**（`dashboard.html`）展示：

| 区块 | 内容 |
|------|------|
| 召回率 + 准确率 | 整体召回率（TP/(TP+FN)）+ 准确率（TP/(TP+FP)），从漏洞中心终审数据计算 |
| 误报类型分布 | C1-C10 误报类型 × 条数 × 占比 |
| 根因断点分布 | 按 Agent × L2-L7 断点矩阵 |
| DTS 问题单状态流水线 | 总数 → unlocated → improving → confirmed → closing → passed/failed → not_issue |
| DTS 问题单列表 | 表格：DTS ID / 责任方 / 成因 / 误报类型 / case 类型 / 状态 / 创建时间，点击行跳转详情页 |

**DTS 单详情页**（`dts-detail.html`）展示：

| 区块 | 内容 | 数据来源 |
|------|------|---------|
| DTS 单头 | dts_id / 状态徽章 / 责任方 / case 类型（FP/FN）/ 误报类型 / 成因 / 断点级别 | `GET /api/v2/dts/{dts_id}` |
| 断点描述 | 系统自动生成的 breakpoint_desc（如"Turing 在 L2 未发起知识访问，场景需要参数可控性知识但未查询"） | 同上 |
| 证据区 | 推理引用片段、知识返回内容、查询内容等（从 evidence_uri 读取文件内容展示） | evidence_uri 文件 |
| 关联知识访问 | access_id 对应的 knowledge_access_detail 记录摘要（L0-L7 判定结果 + effect_label） | 关联查询 |
| 同 case 其他 DTS 单 | 同 task_id 下的其他 DTS 单列表（DTS ID / 责任方 / 成因 / 状态），用于查看回归是否被其他单阻塞 | `GET /api/v2/dts/by-task/{task_id}` |
| 根因填写 | root_cause 文本框（责任方填写） | PUT /api/v2/dts/{dts_id} |
| 解决方案填写 | solution 文本框（责任方填写） | 同上 |
| 操作按钮 | "确认改进"（unlocated→improving）/ "提交根因"（improving→confirmed，需 root_cause+solution 非空）/ "关闭 DTS 单"（confirmed→closing）/ "标记非问题"（→not_issue，需 reason） | POST /close 或 /reject |
| 回归结果 | replay_eval_id / replay_result / 回归判定详情（原始判定 vs 重放判定） | 回归完成后自动填充 |

**数据来源**：调用 `/api/v2/dts` + `/api/v2/dts/{dts_id}` + `/api/v2/dts/stats` + 报告段 API 获取数据。

---

## 7 Agent 改造接口

### 7.1 Case 重放协议（回归验证）

**职责**：产生误报/漏报的 Agent 自行实现 Case 重放——人工在 Agent 管理界面操作，对原误报/漏报 case 在知识改进后重跑。评测引擎不参与重放执行，只从漏洞中心或 Trace 读取重放结果，判定该误报/漏报是否消除。知识方（C/D/G 成因）不参与重放，只负责更新知识内容——重放时 Agent 使用的知识库/记忆进化内容已包含知识方的改进。开发态 FP 和 FN 都有回归判定（FP→TN=消除，FN→TP=消除），运行态只判定 FP。

**核心流程**：

```
人工操作者              Agent                      评测引擎
   │                       │                           │
   │── 1. 在 Agent 管理界面 │                           │
   │   发起重放             │                           │
   │   (选择原误报/漏报     │                           │
   │    case + 确认知识     │                           │
   │    已改进)             │                           │
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
   │                       │                           │── 4. 判定 FP/FN 是否消除
   │                       │                           │   对比原始判定 vs 重放判定
   │                       │                           │
```

**1. 人工发起重放（在各 Agent 管理界面操作）**

人工在各 Agent 的管理界面选择原误报/漏报 case 发起重放，需确认：

| 确认项 | 说明 |
|--------|------|
| `case_id` | 原误报/漏报 case 标识（从测评报告的改进建议清单中获取） |
| 知识已改进 | 对应的成因所指向的知识条目已完成更新/新增/删除 |
| 期望结果 | FP case 期望 TN（变为非漏洞判定）；FN case 期望 TP（变为正确报告漏洞） |

**2. Agent 重放执行（各 Agent 自行实现）**

Agent 自行实现重放逻辑，评测引擎不规定重放的具体执行方式。Agent 可自行决定：

| 重放方式 | 说明 |
|---------|------|
| 单个 case 重头重放 | 从头重放该 case，用改进后的知识重新执行完整流程 |
| 中间步骤重放 | 从误报产生前序步骤开始重放，前置步骤沿用原始结果 |

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

**4. FP/FN 消除判定（评测引擎）**

评测引擎对比原始判定与重放判定，判定该误报/漏报是否消除：

| 原始判定 | 重放判定 | 判定结果 |
|---------|---------|---------|
| FP（误报） | TN（正确排除） | **FP 已消除** — 知识改进有效 |
| FP（误报） | FP（仍误报） | **FP 未消除** — 知识改进无效或不足 |
| FP（误报） | TP（正确报告） | **异常** — 知识改进引入了新问题（误报变漏报），需人工介入 |
| FN（漏报） | TP（正确报告） | **FN 已消除** — 知识改进有效 |
| FN（漏报） | FN（仍漏报） | **FN 未消除** — 知识改进无效或不足 |
| FN（漏报） | FP（误报） | **异常** — 知识改进引入了新问题（漏报变误报），需人工介入 |

> FP 判定适用于开发态和运行态，FN 判定仅适用于开发态（运行态只分析 FP）。

**涉及文件**：
- 新建 `application/replay_verifier.py` — 从漏洞中心/Trace 读取重放结果 + FP/FN 消除判定
- 复用 `infrastructure/vuln_center_client.py` — 按 case_id 查询重放后的判定结论

### 7.2 DTS 单处理

**职责**：Agent 接收 DTS 问题单后，自行定位具体根因与解决方案。**全部 DTS 单关闭后统一触发一次回归测试**，评测引擎重放该 case 并给出"回归通过"或"回归不通过"结论。开发态 FP 和 FN 都有回归判定（FP→TN=消除，FN→TP=消除），运行态只判定 FP。

**流程**：

```
评测引擎                    Agent / 知识方
   │                         │
   │── 1. 自动生成 DTS 单     │
   │   (CAUSAL_CHAIN 阶段)   │
   │   含：Agent × 成因 ×    │
   │   误报类型 × 断点级别    │
   │   知识方 DTS 单含成因    │
   │   C/D/G                │
   │                         │
   │── 2. DTS 单推送          │
   │   Agent/知识方在看板/   │
   │   系统中查看到 DTS 单   │
   │                         │
   │                         │── 3. 定位根因
   │                         │   自行排查具体原因
   │                         │   填写 root_cause
   │                         │   状态：未定位→改进确认
   │                         │
   │                         │── 4. 提出解决方案
   │                         │   填写 solution
   │                         │   状态：改进确认→根因确认
   │                         │
   │                         │── 5. 关闭 DTS 单
   │                         │   调用 POST /close
   │                         │   确认改进已完成
   │                         │
   │── 6. 检查全部 DTS 单     │
   │   是否已关闭             │
   │   ├─ 否 → 等待          │
   │   └─ 是 → 触发回归      │
   │   DTS 状态→关闭中        │
   │   自动创建回归评测任务   │
   │   产生误报/漏报的Agent  │
   │   重放（知识方不参与）  │
   │   评测引擎读取重放结果   │
   │   判定 FP/FN 是否消除   │
   │                         │
   │── 7. 给出回归结论        │
   │   FP/FN 消除→回归通过  │
   │   全部 DTS 单关闭        │
   │   FP/FN 未消除→回归不通过│
   │   全部 DTS 单退回改进确认│
   │   结论写入全部 DTS 单    │
```

**Agent / 知识方职责**：

| 职责 | 说明 |
|------|------|
| 查看 DTS 单 | Agent / 知识方在看板或 API 中查看分配给自己的 DTS 单 |
| 定位根因 | Agent / 知识方自行排查 DTS 单中描述的问题（成因 + 误报类型），定位具体根因 |
| 提出解决方案 | Agent / 知识方根据根因提出解决方案并实施 |
| 更新状态 | Agent / 知识方在 DTS 系统中更新状态（未定位→改进确认→根因确认） |
| 关闭 DTS 单 | Agent / 知识方确认改进已完成，调用 `/close` 关闭 DTS 单 |
| 回归结论 | 评测引擎自动判定，给出"回归通过"或"回归不通过"结论 |
- 复用现有 parser — 解析重放 Trace（按 `replay=true` 标记区分）
- 各 Agent 自行实现重放执行逻辑（人工在 Agent 管理界面操作，重放方式由 Agent 自行决定）

---

## 8 知识系统改造接口

**结论：知识库和记忆进化模块均无需改造。** Trace 中已可通过 `is_kg_interaction` / `is_memory_interaction` 区分访问来源，L0–L7 全链路分析基于 Trace 中的实际知识访问记录判定，不需要知识库/记忆进化系统提供额外接口。

| 改造项 | 说明 | 优先级 |
|--------|------|--------|
| Trace 中标记知识访问目标系统 | 现有 `is_kg_interaction`（知识库）/ `is_memory_interaction`（记忆进化）已区分，无需改 | 已完成 |

---

## 9 指标计算详细设计

指标分两层：**最终结果指标**面向领导，从漏洞中心终审数据计算召回率和准确率；**case 级根因定位**面向工程团队，通过 DTS 问题单逐 case 定位根因，不做指标聚合。

### 9.1 最终结果指标（面向领导）

从漏洞中心终审数据直接计算，不经过 metric_result 表：

| 指标 | 定义 | 分子 | 分母 | 数据来源 |
|------|------|------|------|---------|
| 召回率 | TP / (TP + FN) | 基线 VULNERABLE 且 Agent 上报的 case 数 | 基线 VULNERABLE 的 case 总数 | benchmark_item + 有效 case 筛选结果 |
| 准确率 | TP / (TP + FP) | 基线 VULNERABLE 且 Agent 上报的 case 数 | Agent 上报 finding 且漏洞中心确认的 case 总数 | benchmark_item + 有效 case 筛选结果 |

在 REPORTING 阶段计算，写入 lifecycle 报告段。遵循现有 NA 契约：零分母返回 `calculation_status=NA`。

### 9.2 case 级根因定位（面向工程团队）

不做指标聚合，通过 DTS 问题单逐 case 定位根因。knowledge_access_detail 表存储 L0–L7 判定结果，是 DTS 单的数据来源，但不用于指标计算。

---

## 10 涉及文件清单

### 10.1 新建文件

| 文件 | 说明 |
|------|------|
| `domain/lifecycle/__init__.py` | 模块入口 |
| `domain/lifecycle/analyzer.py` | L0–L7 误报根因全链路分析 |
| `domain/lifecycle/evidence_chain.py` | L7 判定（LLM 方向一致性 + 知识正确性） |
| `domain/lifecycle/case_filter.py` | 有效 case 筛选 |
| `domain/causal_chain/__init__.py` | 模块入口 |
| `domain/causal_chain/analyzer.py` | 因果链断点分析 |
| `domain/dts/issue.py` | DTS 问题单数据模型 + 生成逻辑 |
| `application/replay_verifier.py` | 从漏洞中心/Trace 读取重放结果 + FP/FN 消除判定 |
| `persistence/dts_repo.py` | DTS 问题单 DB 读写 |
| `api/routes/dts.py` | DTS 问题单 API（CRUD + close + stats） |
| `api/routes/datasources.py` | Agent 数据源配置 API（CRUD + 测试连接） |
| `infrastructure/agent_db.py` | Agent 数据库连接管理 |
| `static/dashboard.html` | 看板总览页 |
| `static/dts-detail.html` | DTS 单详情页（查看证据 + 填写根因/解决方案 + 操作状态） |

### 10.2 修改文件

| 文件 | 改什么 |
|------|--------|
| `application/report_assembler.py` | ReportModel 新增 lifecycle_uri + recall_rate + precision_rate + 段组装 + DTS 问题单生成 |
| `application/evaluation_service.py` | pipeline 新增 LIFECYCLE_ANALYSIS / CAUSAL_CHAIN 阶段 + 段写入 + 重试路径 + DTS 回归触发 + REPORTING 阶段计算召回率/准确率 |
| `orchestration/state_machine.py` | 白名单新增跳转 |
| `persistence/repositories/fact_repo.py` | 新增 knowledge_access_detail 的 INSERT 函数 |
| `infrastructure/migrations.py` | 新增迁移条目（007 + 008 + 009） |
| `infrastructure/vuln_center_client.py` | `list_vuln_cases()` 开启 `include_decision_reason=true`；`_case_to_benchmark()` 提取 `false_positive_reason` / `false_positive_group` 字段 |
| `api/routes/evaluations.py` | 新增 1 个端点（lifecycle 报告） |
| `schema.sql` | 新增 knowledge_access_detail + dts_issue + agent_datasource_config 表 DDL |

### 10.3 不改文件

| 文件 | 为什么不改 |
|------|-----------|
| `domain/raw_event.py` | `is_kg_interaction` + `is_memory_interaction` 二分法已与方案对齐 |
| `domain/facts/__init__.py` | KnowledgeInteractionFact 已有 memory 字段 |
| `workers/resolvers.py` | KnowledgeResolverImpl 已支持 memory 标记 |
| `workers/sink_matcher.py` | 匹配逻辑不变 |
| `workers/ai_matcher.py` | 匹配逻辑不变 |

---

## 11 改造排期

> 详见 `docs/knowledge-effect-eval-overview.md` 第 9 节。

---

## 12 待确认项

| # | 问题 | 影响 | 状态 |
|---|------|------|------|
| 1 | ~~L3 查询准确率的判定标准——关键词匹配还是 LLM 判定？~~ | ~~影响计算成本和准确性~~ | **已确认：用 LLM 判定**（与 L7 判定一致） |
| 2 | ~~L1 需要知识的判定标准——哪些漏洞类型算"需要知识"？~~ | ~~需要漏洞类型规则表~~ | **已确认：用 LLM 判定**（与 L3/L7 一致） |
| 3 | ~~消融对照方案~~ | ~~多知识访问粒度 + 跨 session 衔接复杂度~~ | **已取消**（复杂度过高，L7 改为方向一致性判定） |
