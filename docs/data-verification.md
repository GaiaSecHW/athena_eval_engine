# 数据验证报告

> 验证日期：2026-10-11
> 验证目的：为知识效果测评方案设计提供真实数据支撑

---

## 验证 1: 知识库 API 端点可用性

### 验证方法

- 找到 athena-api pod：`kubectl get pods -n secflow-ns | grep athena-api` -> `athena-api-59df656dcd-2nfj9`
- 找到 athena-api service：`athena-api` ClusterIP `10.108.227.89`，端口 8000
- 使用 `kubectl port-forward -n secflow-ns svc/athena-api 28090:8000` 端口转发
- 使用项目 ID `00cd313bb85b7aed`（"供应/计划/供应计划/加工计划/加工计划/com.huawei.iscp.mfp"）测试各端点

### 端点验证结果

| # | API 端点 | HTTP 状态 | 返回格式 | 与文档一致性 | 备注 |
|---|---------|----------|---------|-------------|------|
| 1 | `GET /api/athena/projects/{pid}/knowledge/tree` | 200 | `{project_id, items: [{path, size, modified_at}, ...]}` | 一致 | 返回全量文件清单，含 path + size + modified_at（Unix 时间戳），文档描述"全量文件清单（path + size + modified_at）"完全匹配 |
| 2 | `GET /api/athena/projects/{pid}/knowledge/index?dir={dir}` | 200 (dir=空) / 404 (dir=不存在) | `{project_id, dir, index_path, directories: [{name, path, index_path, document_count}], documents: []}` | 一致 | 空 dir 参数返回根目录结构（directories + documents）。文档描述"结构化目录树（directories + documents，含 name/description/topic）"。实际返回有 name 但无 description/topic 字段，topic 字段在单条文档的 frontmatter 中而非目录索引。目录不存在时返回 404 + `{"detail":"directory not found"}` |
| 3 | `GET /api/athena/projects/{pid}/knowledge/file?path={path}` | 200 | `{project_id, path, content, size}` | 一致 | 返回文档全文（含 frontmatter 元数据）。文档描述"单条文档全文（含 frontmatter 元数据）"完全匹配。content 字段为 Markdown 原文 |
| 4 | `GET /api/athena/projects/{pid}` | 200 | `{project_id, name, shelf_path, shelf_missing, initialization_status, knowledge_enabled, retrieval_cache_enabled, layer, counts: {A, B, C, raw}}` | 一致 | 文档描述"项目信息（counts: A/B/C/raw，knowledge_enabled）"。实际返回含 counts 对象（A=3/B=1/C=2/raw=7）和 knowledge_enabled=true，完全匹配 |
| 5 | `GET /api/athena/management/analytics/projects/{pid}` | 200 | `{effectiveness: {success_rate: {value, num, denom, sample, is_lower_bound}, nohit_rate: {value, num, denom, ...}, recall_hits: {value, num, denom, ...}}, nohit_recent: [{created_at, caller, project_id, question}, ...]}` | 一致 | 文档描述"知识使用效果统计（success_rate/nohit_rate/recall_hits）"。实际返回含这三个字段 + nohit_recent 最近未命中查询列表。success_rate=0.349（29/83），nohit_rate=0.651（54/83） |

### 验证结论

**5 个端点全部可用**，返回格式与需求文档 §7.1 描述一致。

补充发现：
- endpoint 2 的 `index` 返回的 directories 数组含 `name`/`path`/`index_path`/`document_count`，但不含 `description`/`topic` 字段——这些字段在单条文档的 frontmatter 中（需调 endpoint 3 获取）
- endpoint 5 的 `effectiveness` 字段含 `is_lower_bound` 布尔标记和 `sample` 字段（值为 "succeeded"），表明统计口径基于成功调用样本
- endpoint 5 的 `nohit_recent` 数组提供最近未命中查询的内容（含 caller、question、时间戳），可用于知识覆盖度分析

---

## 验证 2: DataflowVulnScan dvs_task_graph_* 表兼容性

### 验证方法

- 连接信息：`kubectl exec -n secflow-ns secflow-app-dataflow-vuln-scan-mysql-0 -- mysql -uroot -p'Huawei12#$'`
- 列出所有 `dvs_*` 数据库，逐个检查表结构

### dvs_* 数据库总览（14 个）

| # | 数据库 | 有 dvs_task_graph_* 表 | 有 orchestration 表 | orchestration 行数 | dvs_task_graph_sessions 行数 |
|---|--------|----------------------|---------------------|---------------------|------------------------------|
| 1 | dvs_17f1f181c2e1badb | 否 | 是 | 0 | N/A |
| 2 | dvs_2532c8fb2d720b86 | 否 | 是 | 0 | N/A |
| 3 | dvs_759a462a6697221c | **是** | 是 | 310 | 1,500 |
| 4 | dvs_823efc5ad22b3a50 | **是** | 是 | 2,719 | 5,881 |
| 5 | dvs_839263a1e8824df1 | **是** | 是 | 49 | 151 |
| 6 | dvs_af1d8f52c61ebe7c | **是** | 是 | 1,886 | 5,280 |
| 7 | dvs_ba5b39004ffdccb3 | 否 | 是 | 0 | N/A |
| 8 | dvs_bbeaeaa4dc080621 | **是** | 是 | 263 | 568 |
| 9 | dvs_cd1463fb2f1f12d7 | 否 | 是 | 0 | N/A |
| 10 | dvs_d137fa2168427813 | 否 | 是 | 0 | N/A |
| 11 | dvs_e38d0ddc9f6e0d97 | 否 | 是 | 0 | N/A |
| 12 | dvs_e4303da70917d00f | **是** | 是 | 17 | 72 |
| 13 | dvs_fee61a5d4b16a888 | 否 | 是 | 0 | N/A |
| 14 | dvs_init | 否（空库） | 否（空库） | N/A | N/A |

### 统计汇总

| 分类 | 数量 | 说明 |
|------|------|------|
| 有 dvs_task_graph_* 表（含数据） | 6 个 | dvs_759a.../dvs_823e.../dvs_8392.../dvs_af1d.../dvs_bbea.../dvs_e430... |
| 只有 orchestration 表（全部 0 行） | 7 个 | 已初始化但从未运行过扫描的空库 |
| 空模板库 | 1 个 | dvs_init，无任何表 |

### dvs_task_graph_sessions 表结构（14 列）

| 字段 | 类型 | 可空 | 键 | 默认值 |
|------|------|------|-----|---------|
| session_relpath | varchar(512) | NO | PRI | |
| task_id | varchar(64) | NO | MUL | |
| epoch | varchar(8) | NO | | |
| node_id | varchar(256) | NO | | |
| edge_id | varchar(256) | NO | | |
| session_role | varchar(64) | NO | | |
| **session_kind** | **varchar(64)** | **NO** | | |
| display_name | varchar(256) | NO | | |
| status | varchar(32) | NO | | unknown |
| started_at | varchar(40) | YES | | NULL |
| ended_at | varchar(40) | YES | | NULL |
| mtime | double | YES | | NULL |
| event_count | int | NO | | 0 |
| extra_json | text | YES | | NULL |

### session_kind 值分布（6 个新表库合计）

| session_kind 值 | 含义 | 需求文档 §4.1 映射的业务阶段 |
|-----------------|------|---------------------------|
| taint | 污点分析 | 数据流追踪 |
| vuln-judge | 漏洞判定 | 漏洞判定与上报 |
| vuln-pattern-enhancement | 漏洞模式增强 | 漏洞模式识别 |
| vuln-false-positive-judge | 误报判定 | 漏洞判定与上报 |
| vuln-report | 漏洞报告 | 漏洞判定与上报 |

各库 session_kind 分布：

| 数据库 | taint | vuln-judge | vuln-pattern-enhancement | vuln-false-positive-judge | vuln-report | 总计 |
|--------|-------|------------|--------------------------|---------------------------|-------------|------|
| dvs_759a462a6697221c | 736 | 426 | 167 | 103 | 68 | 1,500 |
| dvs_823efc5ad22b3a50 | 1,853 | 1,834 | 1,409 | 437 | 348 | 5,881 |
| dvs_839263a1e8824df1 | 67 | 67 | — | 10 | 7 | 151 |
| dvs_af1d8f52c61ebe7c | 2,281 | 1,958 | 857 | 97 | 87 | 5,280 |
| dvs_bbeaeaa4dc080621 | 335 | 228 | — | — | 5 | 568 |
| dvs_e4303da70917d00f | 38 | 34 | — | — | — | 72 |

补充：所有库的 session_role 均为 `"worker"`。

### orchestration 表结构（12 列，所有库结构一致）

| 字段 | 类型 | 可空 | 键 | 默认值 |
|------|------|------|-----|---------|
| edge_id | varchar(128) | NO | PRI | |
| path_id | varchar(128) | NO | | |
| source_func_id | varchar(128) | NO | | |
| target_func_id | varchar(128) | NO | | |
| taint_params | text | NO | | |
| depth | int | NO | | |
| edge_order | int | NO | | |
| status | varchar(32) | YES | MUL | pending |
| task_id | varchar(64) | NO | PRI | |
| source_function | varchar(512) | NO | | |
| source_signature | varchar(512) | NO | | |
| target_function | varchar(512) | NO | | |
| target_signature | varchar(512) | NO | | |

### 新表库的 6 张表（旧库无）

新表库额外有 6 张表：`dvs_task_graph_sessions`、`dvs_task_graph_nodes`、`dvs_task_graph_edges`、`dvs_task_graph_runs`、`dvs_analysis_runs`、`dvs_vuln_findings`。

### 兼容性结论

1. **session_kind 就是 analysisType**：`dvs_task_graph_sessions.session_kind` 字段的 5 个值（taint/vuln-judge/vuln-pattern-enhancement/vuln-false-positive-judge/vuln-report）与需求文档 §4.1 中 DataflowVulnScan 的 analysisType 标识符完全一致，确认 session_kind 就是 analysisType
2. **7 个旧库的 orchestration 表全部为 0 行**：这些是初始化但从未运行扫描的空库，parser 查询 `dvs_task_graph_sessions` 会遇到"表不存在"错误
3. **新表与旧表共存**：6 个有新表的库同时保留了 `orchestration` 表（且有数据），两套 schema 并存
4. **parser 需要降级处理**：查询时需先检查 `dvs_task_graph_sessions` 是否存在（`SHOW TABLES LIKE`），不存在则降级查 `orchestration`，但 orchestration 无 session_kind 字段（只有 edge/path 级数据），无法提取 analysisType
5. **dvs_init 是模板库**：新建项目时从此库复制 schema

---

## 验证 3: SecMate persona 提取兼容性

### 验证方法

- 在 SecMate pod (`secmate-58dd65b6fc-4wj54`) 上查看 workflow 定义文件
- 路径：`/opt/agentfl/workflows/`（注意：不是 `/app/workflows/`，pod 中 app 目录不存在）
- 读取各变体的 `routing_sdl.py` 中的 `wf.persona(...)` 定义
- 读取 `routing.lock.json` 中的 persona name 列表（default + legacy 变体）
- 对比 parser（`athena_eval_engine/workers/secmate_trace_parser.py`）的 persona 提取逻辑

### SecMate workflow 变体及 persona 集合

共发现 10 个顶层变体 + 7 个 legacy 子变体 = 17 个 workflow 变体。

#### 当前变体（/opt/agentfl/workflows/）

| 变体 | persona 集合 |
|------|-------------|
| **default** | chain-builder, exploit-builder, explorer, recon, report, reviewer, sink-hunter, source-hunter, verifier, vuln-hunter, final-report |
| **goal-mode** | goal-intake, goal-worker, goal-verifier, final-reporter |
| **secmate-all-lite** | explorer, architect, flow, specialist, mdf, vuln, reviewer, variant-hunter, distiller, fp-analyzer, deep-researcher, noise-distiller, logic-architect, logic-tracer, logic-oracle-analyzer, report, intent-producer |
| **secmate-cybergym** | import-intake, vuln-reproducer, primitive-analyzer, primitive-explorer, primitive-explorer-gate, poc-reporter |
| **secmate-flash** | partition-init, architect, architect-deep, targeted-tracer, deep-tracer, report, intent-producer, attack-surface, pattern-matcher |
| **secmate-for-dyn** | dyn-intake, dyn-campaign-control-init, dyn-seed-producer, build-worker, test-worker, observe-worker, troubleshoot-worker, improve-worker, dyn-final-reporter, queen-agent |
| **secmate-lite** | explorer, architect, flow, specialist, mdf, vuln, reviewer, variant-hunter, distiller, fp-analyzer, deep-researcher, noise-distiller, logic-architect, logic-tracer, logic-oracle-analyzer, report |
| **secmate-logic-lite** | explorer, architect, flow, specialist, mdf, vuln, reviewer, variant-hunter, distiller, fp-analyzer, deep-researcher, noise-distiller, logic-architect, logic-tracer, logic-oracle-analyzer, report |
| **secmate-memengine-eval** | mem-init, case-hunter, pattern-hunter, idea-producer, idea-hunter, reviewer, scout, report |
| **secmate-user-exp** | import-intake, vuln-reproducer, primitive-analyzer, primitive-explorer, primitive-explorer-gate, poc-reporter |

#### Legacy 变体（/opt/agentfl/workflows/legacy/）

| 变体 | persona 集合 |
|------|-------------|
| **secmate-for-agent** | attack-surface-analyst, auto-designer, end-to-end-auditor, explorer, flow-tracer, mdf-composer, module-seed-producer, queen-agent, report, reviewer, vuln-analyst, final-report |
| **secmate-for-oh** | explorer, ipc-exploit-auditor, oob-auditor, poc-builder, report, final-report |
| **secmate-logic** | architect, deep-researcher, distiller, explorer, fast-path-hint-scout, fast-path-logic-scout, fast-path-sink-scout, fast-path-source-scout, flow-tracer, fp-analyzer, logic-architect, logic-oracle-analyzer, logic-tracer, mdf-composer, module-seed-producer, noise-distiller, report, reviewer, specialist, variant-hunter, vuln-analyst, final-report |
| **secmate-logic-tp** | architect, distiller, explorer, flow-tracer, logic-architect, logic-oracle-analyzer, logic-tracer, mdf-composer, replay-barrier, replay-check, replay-intake, report, reviewer, specialist, vuln-analyst, final-report |
| **secmate-ng** | architect, deep-researcher, distiller, explorer, fast-path-hint-scout, fast-path-sink-scout, fast-path-source-scout, flow-tracer, fp-analyzer, mdf-composer, module-seed-producer, noise-distiller, ql-db-builder, ql-dict-flow-tracer, report, reviewer, specialist, variant-hunter, vuln-analyst, final-report |
| **secmate-ng-fp** | architect, deep-researcher, explorer, flow-tracer, fp-analyzer, import-intake, mdf-composer, module-seed-producer, noise-distiller, report, reviewer, specialist, vuln-analyst, final-report |
| **secmate-ng-tp** | architect, distiller, flow-tracer, mdf-composer, ql-db-builder, replay-check, replay-intake, report, reviewer, variant-hunter, vuln-analyst, final-report |

### 需求文档 §4.1 中定义的 SecMate persona → 业务阶段映射

需求文档列出的 SecMate persona 及其映射：

| persona | 映射的业务阶段 | 需 LLM 细分 |
|---------|--------------|-----------|
| architect | 入口识别 + 数据流追踪 | 是 |
| flow-tracer | 数据流追踪 + Sink 点定位 | 是 |
| specialist / variant-hunter | 漏洞模式识别 | 否 |
| mdf-composer | 数据流追踪 | 否 |
| vuln-analyst / reviewer / fp-analyzer | 漏洞判定与上报 | 否 |
| logic-architect | 入口识别 | 否 |
| logic-tracer | 数据流追踪 | 否 |
| logic-oracle-analyzer | 漏洞模式识别 | 否 |
| explorer / distiller / noise-distiller / report | 不属于 5 阶段 | 否（跳过 L0–L7） |

### Parser persona 提取逻辑分析

**当前 parser（`secmate_trace_parser.py`）的 persona 处理现状：**

1. **parser 不从 JSONL trace 提取 persona 名**——parse() 方法遍历 JSONL 行，提取 TOOL_CALL/TEXT/REASONING/TOOL_RESULT 事件，但不读取 persona 标识符
2. **findings.db 的 `source_persona` 字段被查询但未输出**——`extract_findings()` 的 SQL 查询包含 `source_persona` 列（第 707 行），但构建 finding dict 时（第 730-743 行）未将 `source_persona` 放入输出 dict
3. **无 persona 到业务阶段的映射逻辑**——parser 中不存在任何 persona -> business_phase 映射表

### 兼容性差距分析

| 差距 | 影响 | 涉及的变体 |
|------|------|-----------|
| parser 不从 trace 提取 persona 名 | 无法标注 SecMate session 的业务阶段 | 所有变体 |
| findings.db source_persona 字段未输出 | 有数据但丢弃 | 有 findings.db 的变体（secmate-all-lite, secmate-lite, secmate-logic-lite, secmate-flash, secmate-memengine-eval） |
| 需求文档只覆盖 13 个 persona，实际有 60+ 个 | 大量 persona 无业务阶段映射 | goal-mode, secmate-cybergym, secmate-flash, secmate-for-dyn, secmate-memengine-eval, legacy 变体 |

### 需求文档 persona 覆盖率分析

需求文档 §4.1 列出的 13 个 SecMate persona 在各变体中的覆盖情况：

| persona | 需求文档有定义 | 出现在哪些变体 | 缺失的变体 |
|---------|--------------|-------------|-----------|
| architect | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/secmate-logic, legacy/secmate-logic-tp, legacy/secmate-ng, legacy/secmate-ng-fp, legacy/secmate-ng-tp, secmate-flash(作为 architect) | goal-mode, secmate-cybergym, secmate-for-dyn, secmate-memengine-eval, default, legacy/secmate-for-oh |
| flow-tracer | 是 | legacy/secmate-for-agent, legacy/secmate-logic, legacy/secmate-logic-tp, legacy/secmate-ng, legacy/secmate-ng-fp, legacy/secmate-ng-tp | secmate-all-lite(用 flow), secmate-lite(用 flow), secmate-logic-lite(用 flow) |
| specialist | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/* | — |
| variant-hunter | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/* | — |
| mdf-composer | 是 | legacy/* | secmate-all-lite(用 mdf), secmate-lite(用 mdf), secmate-logic-lite(用 mdf) |
| vuln-analyst | 是 | legacy/* | secmate-all-lite(用 vuln), secmate-lite(用 vuln), secmate-logic-lite(用 vuln) |
| reviewer | 是 | 大部分变体 | — |
| fp-analyzer | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/* | — |
| logic-architect | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/* | — |
| logic-tracer | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/* | — |
| logic-oracle-analyzer | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/* | — |
| explorer | 是 | 多数变体 | — |
| distiller | 是 | 多数变体 | — |
| noise-distiller | 是 | secmate-all-lite, secmate-lite, secmate-logic-lite, legacy/* | — |
| report | 是 | 几乎所有变体 | — |

**关键发现：persona 命名存在新旧变体差异**

| 旧变体（legacy）persona 名 | 新变体（lite/all-lite）persona 名 | 差异说明 |
|---------------------------|----------------------------------|---------|
| flow-tracer | flow | 新变体简写为 flow |
| mdf-composer | mdf | 新变体简写为 mdf |
| vuln-analyst | vuln | 新变体简写为 vuln |
| variant-hunter | variant-hunter | 一致 |
| specialist | specialist | 一致 |
| reviewer | reviewer | 一致 |
| fp-analyzer | fp-analyzer | 一致 |
| architect | architect | 一致 |
| logic-architect | logic-architect | 一致 |
| logic-tracer | logic-tracer | 一致 |
| logic-oracle-analyzer | logic-oracle-analyzer | 一致 |
| explorer | explorer | 一致 |
| distiller | distiller | 一致 |
| noise-distiller | noise-distiller | 一致 |
| report | report | 一致 |

### 兼容性结论

1. **parser 当前不提取 persona 名**——SecMateTraceParser 的 parse() 方法不从 JSONL trace 提取 persona 标识符，需求文档 §4.1 表"SecMate | persona 名 + finding level | JSONL trace agent prompt 标题 + store_finding 工具参数 | parser 从 trace 提取"这一设计目标尚未实现
2. **findings.db 已有 source_persona 字段但被丢弃**——`extract_findings()` 的 SQL 查询了 `source_persona`，但构建输出 dict 时未包含此字段。修复方法：在 finding dict 中增加 `"persona": str(row_dict.get("source_persona") or "")` 字段
3. **需求文档的 13 个 persona 映射表不够完整**——实际有 17 个 workflow 变体，60+ 个不同 persona 名。但大部分非常规变体（goal-mode/cybergym/for-dyn/memengine-eval/user-exp）的 persona 不属于漏洞挖掘 5 阶段，可跳过 L0–L7 分析
4. **新旧变体 persona 命名差异需处理**——`flow-tracer` -> `flow`、`mdf-composer` -> `mdf`、`vuln-analyst` -> `vuln`。parser 的 persona -> business_phase 映射表需同时支持新旧命名
5. **source_persona 从 AGENTFL_SESSION_ID 注入**——根据 parser 注释（第 478 行），`source_session_id` 是 agent_spawner 从 `AGENTFL_SESSION_ID` 环境变量注入的。同理 `source_persona` 可能从 `AGENTFL_PERSONA` 等环境变量注入到 findings.db，而非从 store_finding 工具参数中提取
