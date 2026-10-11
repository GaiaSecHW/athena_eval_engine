# Agent 数据库查询 SQL 手册

> 本文档为评测引擎 v2 的 6 个 Agent parser 提供直连 Agent 数据库的 SQL 语句，覆盖两类查询：
> 1. **session 关系图**（`build_session_graph`）：查询 session 之间的 parent-child 关系
> 2. **session 阶段标识符**（`label_session_phases`）：查询每个 session 的阶段标识符（如 task_type、agent_name、worker_type 等）
>
> 所有 SQL 使用真实表名和字段名，来源：`docs/agent-session-phase-classification.md`、`docs/ddl-final.md`、`docs/v2-architecture-design.md` §4.3。

---

## 1. Turing

### 数据库连接

| 参数 | 值 |
|------|------|
| db_type | `mysql` |
| host | `turing-app-security-mysql.secflow-ns.svc.cluster.local` |
| port | `3306` |
| database_name | `turing_app_security` |
| username | `root` |
| password | `turing_app_security_pass` |
| 环境变量覆盖 | `EVAL_TURING_DB_HOST` / `EVAL_TURING_DB_PORT` / `EVAL_TURING_DB_USER` / `EVAL_TURING_DB_PASSWORD` / `EVAL_TURING_DB_NAME` |

### Session 关系图查询 (build_session_graph)

Turing 的 session 关系图有两个来源：`turing_task` 表的 `parent_task_id` 构建 parent-child task 链（主要），以及 `turing_investigation` 表构建跨模块深度追踪的 investigation 树（补充）。

#### 方式一：turing_task 表 parent_task_id 链

```sql
-- 查询同一 job 下所有 task 的 parent-child 关系
-- 输入：job_id（或 agent_session_id 用于单 session 查询）
-- 输出：agent_session_id, parent_task_id, agent_name, task_type
SELECT
    agent_session_id,
    parent_task_id,
    agent_name,
    task_type
FROM turing_task
WHERE job_id = :job_id
  AND parent_task_id IS NOT NULL;
```

单 session 查询（向上追溯 parent 链）：

```sql
-- 输入：agent_session_id
-- 输出：该 session 的 parent_task_id 及其 agent_name/task_type
SELECT
    t1.agent_session_id,
    t1.parent_task_id,
    t1.agent_name,
    t1.task_type,
    t2.agent_name AS parent_agent_name,
    t2.task_type  AS parent_task_type
FROM turing_task t1
LEFT JOIN turing_task t2 ON t1.parent_task_id = t2.id
WHERE t1.agent_session_id = :agent_session_id;
```

递归查询完整 parent 链（MySQL 8.0+ CTE）：

```sql
-- 输入：agent_session_id
-- 输出：从当前 session 到根 session 的完整 parent 链
WITH RECURSIVE task_chain AS (
    SELECT
        id,
        agent_session_id,
        parent_task_id,
        agent_name,
        task_type,
        0 AS depth_level
    FROM turing_task
    WHERE agent_session_id = :agent_session_id
    UNION ALL
    SELECT
        t.id,
        t.agent_session_id,
        t.parent_task_id,
        t.agent_name,
        t.task_type,
        tc.depth_level + 1
    FROM turing_task t
    INNER JOIN task_chain tc ON t.id = tc.parent_task_id
)
SELECT * FROM task_chain;
```

#### 方式二：turing_task_trace 表 phase 链

```sql
-- 查询 trace 级别的 parent-child 关系
-- turing_task_trace.phase = agent_name，parent_task_id 链接上下游 task
-- 输入：task_id（turing_task.id）
-- 输出：task_id, phase, parent_task_id, finding_id
SELECT
    task_id,
    phase,
    parent_task_id,
    finding_id
FROM turing_task_trace
WHERE parent_task_id IS NOT NULL
  AND task_id IN (
      SELECT id FROM turing_task WHERE job_id = :job_id
  );
```

#### 方式三：turing_investigation 表深度追踪树

```sql
-- 查询跨模块/跨服务深度追踪的 investigation 父子链
-- 输入：origin_detection_id 或 parent_investigation_id
-- 输出：investigation 链，含 depth 标记追踪深度
SELECT
    id,
    parent_investigation_id,
    origin_detection_id,
    target_task_id,
    depth
FROM turing_investigation
WHERE origin_detection_id = :detection_id
   OR parent_investigation_id IS NOT NULL;
```

### 阶段标识符查询 (label_session_phases)

```sql
-- 查询 session 的阶段标识符：agent_name + task_type
-- 输入：agent_session_id（可批量 IN 查询）
-- 输出：agent_session_id, agent_name, task_type
SELECT
    agent_session_id,
    agent_name,
    task_type
FROM turing_task
WHERE agent_session_id IN (:session_ids);
```

单 session 查询：

```sql
-- 输入：agent_session_id
-- 输出：agent_name, task_type
SELECT
    agent_name,
    task_type
FROM turing_task
WHERE agent_session_id = :agent_session_id;
```

### 注意事项

- **agent_name 是主要阶段标识符**：22 种 agent_name 覆盖 preprocess / strategy / detection / mining / deep_mining / semantic_analysis / validation 等 task_type，程序规则映射到业务阶段。
- **parent_task_id 构建 task 链**：detection → mining → validation → deep_mining 的 session 链通过 `turing_task.parent_task_id` 直接链接，是构建 session 关系图的主要来源。
- **turing_task_trace.phase = agent_name**：trace 表的 `phase` 列值等于 task 表的 `agent_name`，可用于交叉验证。
- **turing_investigation 表为补充**：跨模块/跨服务的深度追踪通过 investigation 树构建，`depth` 字段标记追踪深度。
- **mining/deep_mining 跨 3 个阶段**：agent_name 为 mining/deep_mining 的 session 涵盖"漏洞模式识别 + Sink 点定位 + 漏洞判定与上报"，需第三层 LLM 细分。
- **preprocess 不产生知识访问**：agent_name 为 preprocess/auto-preprocess/app-preprocess/tpc-preprocess 的 session 属于预处理阶段，L0-L7 分析可跳过。

---

## 2. Argo

### 数据库连接

| 参数 | 值 |
|------|------|
| db_type | `mysql` |
| host | `chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local` |
| port | `3306` |
| database_name | `argo_c` |
| username | `root` |
| password | `Icsl_argo` |
| 环境变量覆盖 | `EVAL_ARGO_DB_HOST` / `EVAL_ARGO_DB_PORT` / `EVAL_ARGO_DB_USER` / `EVAL_ARGO_DB_PASSWORD` / `EVAL_ARGO_DB_NAME` |

### Session 关系图查询 (build_session_graph)

Argo 的 session 关系通过 `intents` 表的 `to_fact_id` 和 `suggestion_refs` 关联，形成 bootstrap → investigate → verify 的 session 链。

#### 方式一：intents 表 fact/suggestion 链

```sql
-- 查询同一 project 下所有 intent 的 session、fact、suggestion 关联
-- 输入：project_id
-- 输出：session_id, to_fact_id, suggestion_refs, task_type, retry_count
SELECT
    session_id,
    to_fact_id,
    suggestion_refs,
    task_type,
    retry_count
FROM intents
WHERE project_id = :project_id
ORDER BY session_id;
```

#### 方式二：通过 fact/suggestion 表构建 session 链

```sql
-- 联合 facts 和 suggestions 表，构建 bootstrap→investigate→verify 的 session 链
-- facts.type = 'fact'/'finding'，metadata 含 source/sink/propagation
-- suggestions.fact_id 关联到 facts，status 标记建议状态
-- 输入：project_id（通过 intents 表限定）
-- 输出：fact_id, fact_type, suggestion_id, suggestion_status, session_id
SELECT
    i.session_id,
    i.task_type,
    i.to_fact_id,
    f.type AS fact_type,
    f.metadata AS fact_metadata,
    s.id AS suggestion_id,
    s.status AS suggestion_status
FROM intents i
LEFT JOIN facts f ON i.to_fact_id = f.id
LEFT JOIN suggestions s ON s.fact_id = f.id
WHERE i.project_id = :project_id
ORDER BY i.session_id;
```

#### 方式三：retry 关系

```sql
-- 查询重试 session：retry_count > 0 的 session 是前一个同类型 session 的重试
-- 输入：project_id
-- 输出：session_id, task_type, retry_count
SELECT
    session_id,
    task_type,
    retry_count
FROM intents
WHERE project_id = :project_id
  AND retry_count > 0;
```

### 阶段标识符查询 (label_session_phases)

```sql
-- 查询 session 的阶段标识符：task_type
-- 输入：session_id（可批量 IN 查询）
-- 输出：session_id, task_type
SELECT
    session_id,
    task_type
FROM intents
WHERE session_id IN (:session_ids);
```

单 session 查询：

```sql
-- 输入：session_id
-- 输出：task_type
SELECT
    task_type
FROM intents
WHERE session_id = :session_id;
```

### 注意事项

- **task_type 有 4 种值**：`bootstrap`（入口识别+数据流追踪）、`investigate`（跨 3 阶段，需 LLM 细分）、`verify`（漏洞判定与上报）、`reason`（调度阶段，不属于 5 阶段）。
- **session 链通过 fact/suggestion 关联**：bootstrap session 产生 fact，fact 驱动 investigate session，investigate 产生 suggestion，suggestion 驱动 verify session。不是简单的 parent_id 链。
- **task_type 也可从 JSONL 提取**：JSONL 第一行 `queue-operation.content` 的 prompt 标题可直接提取 task_type，DB 查询为交叉验证或补充。
- **reason 阶段不产生知识访问**：task_type=reason 的 session 是调度阶段（blackboard review + dispatch），L0-L7 分析可跳过。
- **retry_count 标记重试**：retry_count > 0 的 session 是同类型前序 session 的重试，可在 session 关系图中标注为 retry 边。

---

## 3. SecMate

### 数据库连接

| 参数 | 值 |
|------|------|
| db_type | `mysql` |
| host | `secmate-mysql.secflow-ns.svc.cluster.local` |
| port | `3306` |
| database_name | `secmate` |
| username | `root` |
| password | `Huawei12#$` |
| 环境变量覆盖 | `EVAL_SECMATE_DB_HOST` / `EVAL_SECMATE_DB_PORT` / `EVAL_SECMATE_DB_USER` / `EVAL_SECMATE_DB_PASSWORD` / `EVAL_SECMATE_DB_NAME` |

### Session 关系图查询 (build_session_graph)

SecMate 的 session 关系图通过 `finding` 表的 `source_finding_id` 构建 finding 父子链（source → sink → dataflow → review_claim 等），以及 `task` 表的 `tool_task_id` ↔ `external_task_id` 映射。

#### 方式一：finding 表 source_finding_id 父子链

```sql
-- 查询 finding 的父子关系（source_finding_id 链）
-- 不同 level 的 finding（source/sink/dataflow/review_claim 等）通过 source_finding_id 链接
-- 输入：tool_task_id（对应一个 SecMate session/workflow 运行）
-- 输出：finding id, source_finding_id, level, vuln_type, file_path, fingerprint
SELECT
    id,
    source_finding_id,
    level,
    vuln_type,
    file_path,
    fingerprint
FROM finding
WHERE tool_task_id = :tool_task_id
ORDER BY level, id;
```

递归查询完整 finding 父子链（MySQL 8.0+ CTE）：

```sql
-- 输入：tool_task_id
-- 输出：从根 finding 到所有子 finding 的完整链
WITH RECURSIVE finding_chain AS (
    SELECT
        id,
        source_finding_id,
        level,
        vuln_type,
        file_path,
        0 AS depth_level
    FROM finding
    WHERE tool_task_id = :tool_task_id
      AND source_finding_id IS NULL
    UNION ALL
    SELECT
        f.id,
        f.source_finding_id,
        f.level,
        f.vuln_type,
        f.file_path,
        fc.depth_level + 1
    FROM finding f
    INNER JOIN finding_chain fc ON f.source_finding_id = fc.id
    WHERE f.tool_task_id = :tool_task_id
)
SELECT * FROM finding_chain;
```

#### 方式二：task 表 tool_task_id ↔ external_task_id 映射

```sql
-- 查询 task 映射：一个 tool_task_id 对应一个 SecMate session（workflow 运行）
-- 输入：external_task_id（或 tool_task_id）
-- 输出：tool_task_id, external_task_id, file_path
SELECT
    tool_task_id,
    external_task_id,
    file_path
FROM task
WHERE external_task_id = :external_task_id;
```

#### 方式三：task_event 表 session 生命周期

```sql
-- 查询 session（task）的事件流，用于辅助判断 session 阶段边界
-- 输入：tool_task_id
-- 输出：event_type, from_status, to_status, created_at
SELECT
    event_type,
    from_status,
    to_status,
    created_at
FROM task_event
WHERE tool_task_id = :tool_task_id
ORDER BY created_at;
```

### 阶段标识符查询 (label_session_phases)

SecMate 的阶段标识符（persona 名）**不在数据库中**，需从 JSONL trace 提取。DB 查询可获取 workflow 名作为辅助。

```sql
-- 查询 task 的 workflow 名（从 params JSON 字段提取）
-- 输入：tool_task_id
-- 输出：workflow 名（如 secmate-logic-lite / secmate-all-lite / secmate-flash）
-- 注意：persona 名不在 DB 中，需从 JSONL trace 的 agent prompt 标题提取
SELECT
    tool_task_id,
    JSON_UNQUOTE(JSON_EXTRACT(params, '$.agentfl.workflow')) AS workflow_name
FROM task
WHERE tool_task_id = :tool_task_id;
```

从 trace JSONL 提取 persona 名（非 SQL，parser 实现）：

```text
提取方式：扫描 JSONL trace 中 agent 的 prompt 标题行，识别 persona 名。
支持 persona 列表（secmate-logic-lite workflow）：
  explorer, architect, flow-tracer, specialist, mdf-composer,
  vuln-analyst, reviewer, variant-hunter, distiller, fp-analyzer,
  deep-researcher, noise-distiller, logic-architect, logic-tracer,
  logic-oracle-analyzer, report
```

### 注意事项

- **persona 名不在 DB 中**：SecMate 的 `task` 表无 agent_name/persona 字段，persona 信息仅在 JSONL trace 中，parser 必须从 trace 提取。DB 查询仅用于获取 finding 父子链和 workflow 名。
- **finding level 是辅助阶段标识符**：从 JSONL trace 中 `store_finding` 工具调用的 `level` 参数提取，16 种 level（module → final_verdict）各自映射到业务阶段。
- **finding 父子链是 session 关系图的主要来源**：`source_finding_id` 链接 source → sink → dataflow → review_claim 等不同 level 的 finding，构建 session 内的 finding 关系图。
- **SEED_ID 共享**：JSONL trace 中 planner prompt 的 `SEED_ID=xxx` 标记同一 workflow 运行的所有 session，是 session 关系图的补充来源。
- **explorer/distiller/noise-distiller/report 不产生知识访问**：这些 persona 的 session 属于预处理或报告阶段，L0-L7 分析可跳过。
- **workflow 变体**：不同 workflow（secmate-logic-lite / secmate-all-lite / secmate-flash 等）的 persona 集合不同，阶段映射需按 workflow 区分。

---

## 4. DataflowVulnScan

### 数据库连接

| 参数 | 值 |
|------|------|
| db_type | `mysql` |
| host | `secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local` |
| port | `3306` |
| database_name | `dvs_{project_id}`（模板，运行时将 `{project_id}` 替换为实际项目 ID） |
| username | `root` |
| password | `Huawei12#$` |
| 环境变量覆盖 | `EVAL_DATAFLOW_DB_HOST` / `EVAL_DATAFLOW_DB_PORT` / `EVAL_DATAFLOW_DB_USER` / `EVAL_DATAFLOW_DB_PASSWORD` / `EVAL_DATAFLOW_DB_NAME` |

> **database_name 模板替换**：配置表中 `database_name` 存储为 `dvs_{project_id}`，parser 在连接前需将 `{project_id}` 替换为当前任务的项目 ID。环境变量 `EVAL_DATAFLOW_DB_NAME` 可覆盖整个模板。

### Session 关系图查询 (build_session_graph)

DataflowVulnScan 的 session 关系图通过 `dvs_task_graph_sessions`、`dvs_task_graph_nodes`、`dvs_task_graph_edges` 三张表构建，session 通过 node_id/edge_id 关联到函数调用图。

#### 方式一：dvs_task_graph_sessions 表 session → node/edge 映射

```sql
-- 查询 session 与 task graph node/edge 的映射关系
-- session_kind = analysisType（taint/track/fptrack/vuln-judge 等）
-- 输入：task_id
-- 输出：session_relpath, node_id, edge_id, session_role, session_kind
SELECT
    session_relpath,
    node_id,
    edge_id,
    session_role,
    session_kind
FROM dvs_task_graph_sessions
WHERE task_id = :task_id
ORDER BY session_kind, session_relpath;
```

#### 方式二：dvs_task_graph_nodes 表 node → session 深度关系

```sql
-- 查询 node 的深度和主 session 路径
-- depth 标记函数调用深度（d00 → d01 → d02）
-- 输入：task_id
-- 输出：node_id, task_id, depth, primary_session_relpath
SELECT
    node_id,
    task_id,
    depth,
    primary_session_relpath
FROM dvs_task_graph_nodes
WHERE task_id = :task_id
ORDER BY depth, node_id;
```

#### 方式三：dvs_task_graph_edges 表函数调用关系

```sql
-- 查询函数调用图的边关系
-- edge 连接 source_node → target_node，每个 edge 关联 source_func_id 和 target_func_id
-- 输入：task_id
-- 输出：edge_id, source_node_id, target_node_id, source_func_id, target_func_id
SELECT
    edge_id,
    source_node_id,
    target_node_id,
    source_func_id,
    target_func_id
FROM dvs_task_graph_edges
WHERE task_id = :task_id
ORDER BY edge_id;
```

#### 方式四：三表联合查询完整 session 关系图

```sql
-- 联合 sessions + nodes + edges 三表，构建完整的 session → node → edge 关系图
-- 输入：task_id
-- 输出：session_relpath, session_kind, node_id, depth, edge_id, source_node_id, target_node_id
SELECT
    s.session_relpath,
    s.session_kind,
    s.session_role,
    s.node_id,
    n.depth,
    s.edge_id,
    e.source_node_id,
    e.target_node_id
FROM dvs_task_graph_sessions s
LEFT JOIN dvs_task_graph_nodes n ON s.node_id = n.node_id AND n.task_id = s.task_id
LEFT JOIN dvs_task_graph_edges e ON s.edge_id = e.edge_id AND e.task_id = s.task_id
WHERE s.task_id = :task_id
ORDER BY n.depth, s.session_kind, s.session_relpath;
```

#### 方式五（兼容）：orchestration 老版本表

```sql
-- 部分旧项目无 dvs_task_graph_* 表，使用 orchestration 表查询调用路径
-- 输入：task_id
-- 输出：edge_id, path_id, source_func_id, target_func_id
SELECT
    edge_id,
    path_id,
    source_func_id,
    target_func_id
FROM orchestration
WHERE task_id = :task_id
ORDER BY path_id, edge_id;
```

> parser 在查询前应先检测 `dvs_task_graph_sessions` 表是否存在，不存在则降级到 `orchestration` 表。

### 阶段标识符查询 (label_session_phases)

DataflowVulnScan 的阶段标识符（analysisType）**不在 DB 的直接字段中**，从 JSONL 文件名提取。但 DB 的 `dvs_task_graph_sessions.session_kind` 字段存储了 analysisType，可用于交叉验证。

```sql
-- 查询 session 的 analysisType（session_kind 字段）
-- 输入：task_id
-- 输出：session_relpath, session_kind（即 analysisType）
SELECT
    session_relpath,
    session_kind
FROM dvs_task_graph_sessions
WHERE task_id = :task_id
  AND session_kind IS NOT NULL;
```

单 session 查询：

```sql
-- 输入：session_relpath
-- 输出：session_kind（analysisType）
SELECT
    session_kind,
    session_role
FROM dvs_task_graph_sessions
WHERE session_relpath = :session_relpath;
```

从 JSONL 文件名提取 analysisType（非 SQL，parser 实现）：

```text
文件名格式：d{depth:02d}-{func}-{kind}-{taint}-{NN}.jsonl
示例：d00-main_handler-taint-taint_param-01.jsonl
解析规则：
  - d{depth} → depth = 00（调用深度）
  - {func} → func_name = main_handler（函数名）
  - {kind} → analysisType = taint（分析类型）
  - {taint} → taint 参数
  - {NN} → 序号

analysisType 枚举：
  taint, track, fptrack, vuln-judge, vuln-pattern-enhancement,
  vuln-false-positive-judge, vuln-report
```

### 注意事项

- **database_name 是模板**：配置为 `dvs_{project_id}`，parser 连接前必须替换 `{project_id}` 为实际项目 ID。全局库 `dvs_init` 存储项目元数据，每个 project 有独立的 `dvs_{project_id}` 库。
- **session_kind = analysisType**：`dvs_task_graph_sessions.session_kind` 字段值与 JSONL 文件名中的 analysisType 一致，可用于交叉验证。
- **dvs_task_graph_* 表可能不存在**：部分旧项目只有 `orchestration` 表，parser 需先检测表是否存在再选择查询路径。
- **session 关系通过 node/edge 间接关联**：session 不直接有 parent_id，而是通过 `node_id`（调用深度）和 `edge_id`（函数调用关系）间接关联。跨深度关系通过 node 的 depth（d00→d01→d02）构建。
- **analysisType 已足够细粒度**：7 种 analysisType 各自确定性映射到业务阶段，无需 LLM 细分。
- **所有 analysisType 都可能产生知识访问**：无跳过阶段。

---

## 5. CVulnVerify

### 数据库连接

| 参数 | 值 |
|------|------|
| db_type | `postgresql` |
| host | `secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local` |
| port | `5432` |
| database_name | `secflow_vuln_verify_v2` |
| username | `postgres` |
| password | `secflow123` |
| 环境变量覆盖 | `EVAL_CVULN_DB_HOST` / `EVAL_CVULN_DB_PORT` / `EVAL_CVULN_DB_USER` / `EVAL_CVULN_DB_PASSWORD` / `EVAL_CVULN_DB_NAME` |

> **PostgreSQL 语法**：使用 `$1`、`$2` 等占位符（或 `:param` 命名占位符，取决于驱动），与 MySQL 的 `:param` 不同。下方 SQL 使用 `$1` 风格。

### Session 关系图查询 (build_session_graph)

CVulnVerify 的 session 关系图通过 `vuln_verify_attempt` 表的 `predecessor_attempt_id` 构建验证链，`successor_reason` 区分 manager_dispatch（跨阶段分发）和 failure_retry（同类型重试）。

#### 方式一：查询所有 predecessor 关系（批量）

```sql
-- 查询所有有前驱的 attempt，构建验证链
-- 无输入参数，全量查询（用于批量构建 session 关系图）
-- 输出：attempt_id, predecessor_attempt_id
SELECT
    id,
    predecessor_attempt_id
FROM vuln_verify_attempt
WHERE predecessor_attempt_id IS NOT NULL;
```

#### 方式二：查询单个 attempt 的验证链

```sql
-- 查询指定 attempt 的 predecessor 和 successor_reason
-- 输入：attempt_id（$1，对应 JSONL 文件名）
-- 输出：id, task_id, worker_type, predecessor_attempt_id, successor_reason, status
SELECT
    id,
    task_id,
    worker_type,
    predecessor_attempt_id,
    successor_reason,
    status
FROM vuln_verify_attempt
WHERE id = $1;
```

#### 方式三：递归查询完整验证链（PostgreSQL CTE）

```sql
-- 递归查询从当前 attempt 到链头的完整 predecessor 链
-- 输入：attempt_id（$1）
-- 输出：完整验证链（从当前到根）
WITH RECURSIVE attempt_chain AS (
    SELECT
        id,
        task_id,
        worker_type,
        predecessor_attempt_id,
        successor_reason,
        status,
        0 AS depth_level
    FROM vuln_verify_attempt
    WHERE id = $1
    UNION ALL
    SELECT
        v.id,
        v.task_id,
        v.worker_type,
        v.predecessor_attempt_id,
        v.successor_reason,
        v.status,
        ac.depth_level + 1
    FROM vuln_verify_attempt v
    INNER JOIN attempt_chain ac ON v.id = ac.predecessor_attempt_id
)
SELECT * FROM attempt_chain;
```

#### 方式四：查询同一 task 下所有 attempt（构建同 task 验证链）

```sql
-- 查询同一 task 下所有 attempt 的验证链关系
-- 输入：task_id（$1）
-- 输出：id, worker_type, predecessor_attempt_id, successor_reason, status
SELECT
    id,
    worker_type,
    predecessor_attempt_id,
    successor_reason,
    status
FROM vuln_verify_attempt
WHERE task_id = $1
ORDER BY id;
```

#### 方式五：查询 successor（向下追溯）

```sql
-- 查询指定 attempt 的所有 successor（向下追溯验证链）
-- 输入：attempt_id（$1）
-- 输出：successor attempt 的 id, worker_type, successor_reason
SELECT
    id,
    worker_type,
    successor_reason,
    status
FROM vuln_verify_attempt
WHERE predecessor_attempt_id = $1
ORDER BY id;
```

### 阶段标识符查询 (label_session_phases)

```sql
-- 查询 attempt 的阶段标识符：worker_type + successor_reason
-- 输入：attempt_id（$1，对应 JSONL 文件名 UUID）
-- 输出：worker_type, successor_reason
SELECT
    worker_type,
    successor_reason
FROM vuln_verify_attempt
WHERE id = $1;
```

批量查询：

```sql
-- 输入：attempt_id 列表（$1 为数组）
-- 输出：id, worker_type, successor_reason
SELECT
    id,
    worker_type,
    successor_reason
FROM vuln_verify_attempt
WHERE id = ANY($1::uuid[]);
```

关联 task 表查询完整信息：

```sql
-- 联合 vuln_verify_task 表查询完整验证信息
-- 输入：attempt_id（$1）
-- 输出：attempt 的 worker_type + task 的 project/case/vuln 信息
SELECT
    a.id AS attempt_id,
    a.worker_type,
    a.successor_reason,
    a.status,
    t.id AS task_id,
    t.project_id,
    t.case_id,
    t.vuln_id,
    t.file,
    t.function,
    t.business_task_id
FROM vuln_verify_attempt a
LEFT JOIN vuln_verify_task t ON a.task_id = t.id
WHERE a.id = $1;
```

### 注意事项

- **PostgreSQL 语法**：使用 `$1`、`$2` 占位符，不支持 MySQL 的 `:param` 命名占位符（除非使用 psycopg2 的命名参数）。批量 IN 查询用 `= ANY($1::uuid[])` 而非 `IN (...)`。
- **JSONL 文件名 = attempt_id（UUID）**：parser 从文件名提取 attempt_id，与 DB `vuln_verify_attempt.id` 直接对应，无需额外映射。
- **predecessor_attempt_id 是主要关系字段**：构建验证链的核心字段，`successor_reason` 区分链类型（manager_dispatch = 跨阶段分发，failure_retry = 同类型重试）。
- **worker_type 有 3 种值**：`source-verifier`（跨 3 阶段，需 LLM 细分）、`c-formal-verifier`（验证执行）、`binary-instrumentation-poc`（验证执行）。早期任务可能 worker_type 为空。
- **eval-engine 已有集成**：`cvuln_verify_trace_parser.py` 的 `_fetch_predecessor_map()` 已实现 PostgreSQL 查询 predecessor_attempt_id 映射，v2 parser 可参考其连接逻辑（环境变量、psycopg2 驱动、connect_timeout=5）。
- **连接失败时 graceful degradation**：现有实现中 DB 连接失败返回空 dict，v2 可参考但应遵循"禁止降级跳过"原则——连接失败时应记录错误并重试，重试耗尽后向上抛异常。
- **验证链结构**：
  ```
  source-verifier（首次，successor_reason 为空）
      ├── manager_dispatch → c-formal-verifier
      ├── manager_dispatch → binary-instrumentation-poc
      └── failure_retry → source-verifier（重试）
  ```

---

## 6. WebVulnVerify

### 数据库连接

WebVulnVerify **无独立数据库**，使用 Athena 框架，session 关系和阶段标识符全部从 JSONL trace 提取。

| 参数 | 值 |
|------|------|
| db_type | `none` |
| host | 无 |
| port | 无 |
| database_name | 无 |

### Session 关系图查询 (build_session_graph)

无 SQL 查询，从 JSONL trace 提取。

#### 从 trace JSONL 提取 session 关系

```text
数据来源：JSONL trace 文件中的 session_meta 行

关系边类型：
1. parent_id 父子边
   字段路径：session_meta.session.parent_id
   说明：37/82 session 有 parent_id，构建 parent-child 边

2. vulnerability_id 共享边
   字段路径：session_meta.metadata.vulnerability_id
   说明：100% session 有 vulnerability_id，同一 vulnerability 的 session 关联

提取方式（parser 实现）：
  - 读取 JSONL 文件第一行（session_meta 类型行）
  - 解析 JSON，提取 session.id、session.parent_id、metadata.vulnerability_id
  - 以 session.id 为节点，parent_id 为 parent-child 边
  - 以 vulnerability_id 为分组键，同 vulnerability_id 的 session 互相关联
```

### 阶段标识符查询 (label_session_phases)

无 SQL 查询，从 JSONL trace 提取工具名序列。

#### 从 trace JSONL 提取阶段标识符

```text
数据来源：JSONL trace 文件中的 message_completed 行

标识符：工具名序列（tool_call.name）

字段路径：message_completed 行中 tool_call.name

提取方式（parser 实现）：
  - 遍历 JSONL 所有 message_completed 类型行
  - 提取每个 tool_call 的 name 字段
  - 汇总为 session 的工具名集合（session_tool_set）

工具名 → 业务阶段映射：
  vulnerability_analyze → 漏洞理解 + 代码定位（需 LLM 细分）
  vulnerability_verify  → 判定上报
  vulnerability_cvss    → 判定上报
  read / bash / grep    → 验证执行

验证结论提取：
  从 vulnerability_verify 工具调用的 status 参数提取 validation_result：
    EXTERNAL_REQUEST_EXPLOITABLE  → confirmed
    INTERNAL_REQUEST_EXPLOITABLE  → confirmed
    UNIT_TEST_EXPLOITABLE         → confirmed
    NOT_EXPLOITABLE               → ruled_out
```

### 注意事项

- **无 DB 查询**：WebVulnVerify 使用 Athena 框架，无独立 MySQL/PostgreSQL，所有 session 信息在 JSONL trace 中。
- **trace 格式**：自定义 JSONL，行类型 `session_meta` / `tool_schema` / `message_completed`。
- **session_meta 是入口行**：JSONL 第一行为 `session_meta` 类型，含 `session.id`、`session.parent_id`、`metadata.vulnerability_id`。
- **finding 入口**：`vulnerability_verify` 是唯一验证结论写入工具，parser 从此工具调用提取 verdict。
- **analyze 和 verify 在不同 session**：vulnerability_analyze 和 vulnerability_verify 100% 出现在不同 session 中，通过 vulnerability_id 或 parent_id 关联。
- **parent_id 非全覆盖**：82 个 session 中仅 37 个有 parent_id，需结合 vulnerability_id 共享边补全关系图。
- **vulnerability_analyze 跨 2 阶段**：涵盖"漏洞理解 + 代码定位"，需第三层 LLM 从 REASONING 事件细分。
- **所有 session 都可能产生知识访问**：无跳过阶段。

---

## 附：数据库连接汇总

| Agent | db_type | host | port | database | 驱动 |
|-------|---------|------|------|----------|------|
| Turing | MySQL | `turing-app-security-mysql.secflow-ns.svc.cluster.local` | 3306 | `turing_app_security` | pymysql |
| Argo | MySQL | `chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local` | 3306 | `argo_c` | pymysql |
| SecMate | MySQL | `secmate-mysql.secflow-ns.svc.cluster.local` | 3306 | `secmate` | pymysql |
| DataflowVulnScan | MySQL | `secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local` | 3306 | `dvs_{project_id}` | pymysql |
| CVulnVerify | PostgreSQL | `secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local` | 5432 | `secflow_vuln_verify_v2` | psycopg2 |
| WebVulnVerify | none | — | — | — | 无 DB |

## 附：阶段标识符来源汇总

| Agent | 标识符 | 来源 | DB 查询 | Trace 提取 |
|-------|--------|------|---------|-----------|
| Turing | `agent_name` + `task_type` | DB | `turing_task` 表 | 否 |
| Argo | `task_type` | DB + Trace | `intents` 表 | JSONL prompt 标题 |
| SecMate | persona 名 + finding level | Trace | 无（仅辅助 workflow 名） | JSONL trace |
| DataflowVulnScan | `analysisType` | DB + Filename | `dvs_task_graph_sessions.session_kind` | JSONL 文件名 |
| CVulnVerify | `worker_type` + `successor_reason` | DB | `vuln_verify_attempt` 表 | 否 |
| WebVulnVerify | 工具名序列 | Trace | 无 DB | JSONL trace `tool_call.name` |
