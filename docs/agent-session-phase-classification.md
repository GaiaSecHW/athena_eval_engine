# 6 Agent Session 业务阶段归类调研报告

> 本文档基于对各 Agent 源码、数据库、trace 数据的实际调研，记录每个 Agent 能否将 session 归类到设计书定义的业务阶段。

## 1 设计书定义的业务阶段

### 1.1 挖掘 Agent 5 阶段（不固定顺序）

| 阶段 | 说明 |
|------|------|
| 入口识别 | 识别用户可控输入源 |
| 数据流追踪 | 追踪 source → sink 传播路径 |
| 漏洞模式识别 | 判断代码模式是否符合漏洞模式 |
| Sink 点定位 | 定位漏洞触发的具体代码位置 |
| 漏洞判定与上报 | 综合判断是否为漏洞并提交 finding |

### 1.2 验证 Agent 4 阶段

| 阶段 | 说明 |
|------|------|
| 漏洞理解 | 读取 finding 描述、理解待验证漏洞 |
| 代码定位 | 定位 finding 涉及的代码位置 |
| 验证执行 | 执行分析、构造 PoC、运行测试 |
| 判定上报 | 写入 verdict（confirmed / ruled_out） |

## 2 总览

| Agent | 类型 | 可归类性 | 数据来源 | 确定性 |
|------|------|---------|---------|--------|
| Argo | 挖掘 | **可归类**（task_type 确定性 + LLM 细分） | JSONL prompt 标题 + MySQL intents 表 | task_type 100% 确定；阶段细分需 LLM |
| Turing | 挖掘 | **可归类**（agent_name 确定性） | MySQL turing_task 表 agent_name + task_type | 100% 确定 |
| SecMate | 挖掘 | **部分可归类**（persona 名 + finding level） | JSONL trace 中的 persona 名 + finding level | persona 确定性；阶段映射需规则 |
| DataflowVulnScan | 挖掘 | **可归类**（session ID 编码 analysisType） | JSONL 文件名 analysisType 字段 | 100% 确定 |
| CVulnVerify | 验证 | **部分可归类**（worker_type + successor_reason） | PostgreSQL vuln_verify_attempt 表 worker_type | worker_type 确定性；阶段映射需规则 |
| WebVulnVerify | 验证 | **部分可归类**（工具名区分） | JSONL trace 工具名（vulnerability_analyze/verify/cvss） | 工具名确定性；阶段映射需规则 |

## 3 逐 Agent 调研结论

### 3.1 Argo（挖掘 Agent）

#### 数据来源

| 数据 | 位置 | 获取方式 |
|------|------|---------|
| task_type | JSONL 第一行 `queue-operation.content` 的 prompt 标题 | parser 从 trace 提取 |
| task_type | MySQL `argo_c.intents` 表 `session_id → task_type` | k8s 内直连 Argo MySQL |
| Task Description | JSONL prompt 中的 `Task Description` 字段 | parser 从 trace 提取 |
| Finding 描述 | JSONL prompt 中的 `Finding to Verify` 字段 | parser 从 trace 提取 |

#### task_type 分布

| task_type | 数量 | prompt 标题 |
|-----------|------|------------|
| bootstrap | 831 | `# Bootstrap: Codebase Reconnaissance` |
| investigate | 66 | `# Investigate: Source Code Review` |
| verify | 75 | `# Verify: Finding Confirmation` |
| reason | 7 | `# Reason: Blackboard Review and Dispatch` |

#### task_type → 业务阶段映射

| task_type | 映射的业务阶段 | 说明 |
|-----------|--------------|------|
| bootstrap | 入口识别 + 数据流追踪 | 代码侦察阶段，识别项目结构、模块入口、数据流路径 |
| investigate | 漏洞模式识别 / Sink 点定位 / 漏洞判定与上报 | prompt 的 Task Description 包含具体分析任务（如 "SQL injection analysis"、"taint analysis"），可指示侧重哪个阶段 |
| verify | 漏洞判定与上报 | Argo 内部 finding 确认，对应挖掘 Agent 的判定上报阶段（非验证 Agent） |
| reason | 不属于 5 阶段 | 调度阶段，blackboard review + dispatch，不产生知识访问 |

#### 归类方案

| 层级 | 方法 | 确定性 |
|------|------|--------|
| 第一层：task_type 确定性标注 | 从 JSONL 第一行 prompt 标题提取，或查 Argo MySQL `intents` 表 | 100% 确定 |
| 第二层：task_type → 业务阶段粗映射 | 程序规则映射 | 确定但粒度粗 |
| 第三层：LLM 细分 | 对 investigate 类 session，从 Task Description + REASONING 事件用 LLM 细分到具体阶段 | LLM 判定 |

#### v2 parser 实现要点

- `parse()` 阶段：读 JSONL 第一行，提取 `queue-operation.content` 第一行 prompt 标题 → 设置 `session_task_type`
- 对 investigate 类，提取 `Task Description` 字段内容 → 传递给 LLM 阶段标注器
- `build_session_graph()`：同一 project 下的 bootstrap → investigate → verify session 通过 `parent_id` 边构成链

#### Argo 源码关键文件

| 文件 | 路径 | 说明 |
|------|------|------|
| models.py | `/app/src/argo/server/models.py` | `TaskType = Literal["bootstrap", "reason", "investigate", "verify", "synthesize", "reopen", "module_expand"]` |
| scheduler/loop.py | `/app/src/argo/dispatcher/scheduler/loop.py` | 调度逻辑，按 task_type 分发到对应 run_*_task 函数 |
| tasks/investigate.py | `/app/src/argo/dispatcher/tasks/investigate.py` | investigate 任务实现 |
| tasks/verify.py | `/app/src/argo/dispatcher/tasks/verify.py` | verify 任务实现 |
| prompts/investigate.md | `/app/src/argo/dispatcher/prompts/investigate.md` | `# Investigate: Source Code Review` |
| prompts/verify.md | `/app/src/argo/dispatcher/prompts/verify.md` | `# Verify: Finding Confirmation` |
| prompts/bootstrap.md | `/app/src/argo/dispatcher/prompts/bootstrap.md` | `# Bootstrap: Codebase Reconnaissance` |

#### Argo MySQL 连接信息

| 参数 | 值 |
|------|------|
| Pod | `chirmera-platform-nazhua-mysql-0` |
| Host | `chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local` |
| User | `root` |
| Password | `Icsl_argo` |
| Database | `argo_c` |
| 关键表 | `intents`（id, project_id, task_type, session_id） |

---

### 3.2 Turing（挖掘 Agent）

#### 数据来源

| 数据 | 位置 | 获取方式 |
|------|------|---------|
| agent_name | MySQL `turing_app_security.turing_task` 表 `agent_name` 列 | k8s 内直连 Turing MySQL |
| task_type | MySQL `turing_app_security.turing_task` 表 `task_type` 列 | 同上 |
| agent_session_id | MySQL `turing_app_security.turing_task` 表 `agent_session_id` 列 | 同上 |
| phase | MySQL `turing_app_security.turing_task_trace` 表 `phase` 列 | 同上（= agent_name） |

#### agent_name + task_type 分布

| task_type | agent_name | 数量 |
|-----------|-----------|------|
| mining | vuln-hunt-mine | 84,677 |
| mining | web-mine | 60,199 |
| validation | web-validate | 28,816 |
| detection | web-detect | 26,768 |
| validation | vuln-hunt-validate | 16,115 |
| deep_mining | web-deep-mine | 15,154 |
| detection | vuln-hunt-detect | 11,573 |
| strategy | web-strategy | 3,785 |
| deep_mining | vuln-hunt-deep-mine | 3,323 |
| mining | app-mine | 1,722 |
| preprocess | preprocess | 1,632 |
| mining | tpc-mine | 1,160 |
| detection | app-detect | 734 |
| validation | tpc-validate | 688 |
| semantic_analysis | semantic-analysis | 479 |
| validation | app-validate | 451 |
| deep_mining | tpc-deep-mine | 205 |
| detection | tpc-detect | 196 |
| preprocess | auto-preprocess | 123 |
| deep_mining | app-deep-mine | 121 |
| strategy | app-strategy | 94 |
| preprocess | app-preprocess | 37 |
| strategy | tpc-strategy | 42 |
| preprocess | tpc-preprocess | 12 |

#### agent_name → 业务阶段映射

| agent_name | task_type | 映射的业务阶段 | 说明 |
|-----------|-----------|--------------|------|
| preprocess / auto-preprocess / app-preprocess / tpc-preprocess | preprocess | 不属于 5 阶段 | 预处理阶段（反编译、目录组织），不产生知识访问 |
| web-strategy / app-strategy / tpc-strategy | strategy | 入口识别 | 全局扫描产出应用级知识（业务定位、框架、入口、防护机制），对应入口识别 |
| web-detect / app-detect / tpc-detect / vuln-hunt-detect | detection | 入口识别 + 数据流追踪 | 攻击面探测，识别入口和污点汇聚点 |
| web-mine / app-mine / tpc-mine / vuln-hunt-mine | mining | 漏洞模式识别 + Sink 点定位 + 漏洞判定与上报 | 从探测记录出发挖掘漏洞，涵盖模式匹配、sink 确认、finding 写入 |
| web-deep-mine / app-deep-mine / tpc-deep-mine / vuln-hunt-deep-mine | deep_mining | 漏洞模式识别 + Sink 点定位 + 漏洞判定与上报 | 深度挖掘，疑点逐一核实 |
| semantic-analysis | semantic_analysis | 漏洞模式识别 | 语义分析，跨 jar 分析 |
| web-validate / app-validate / tpc-validate / vuln-hunt-validate | validation | 漏洞判定与上报 | 独立审计验证，四维度判定真伪（Turing 内部验证，非验证 Agent） |

#### 归类方案

| 层级 | 方法 | 确定性 |
|------|------|--------|
| 第一层：agent_name 确定性标注 | 查 Turing MySQL `turing_task` 表 `agent_session_id → agent_name + task_type` | 100% 确定 |
| 第二层：agent_name → 业务阶段映射 | 程序规则映射（上表） | 确定但 mining/deep_mining 涵盖 3 个阶段 |
| 第三层：LLM 细分 | 对 mining/deep_mining 类 session，从 REASONING 事件用 LLM 细分到具体阶段 | LLM 判定 |

#### Turing 源码关键发现

- **Agent 定义文件**：`/app/agents/*.md`，每个 agent 有 frontmatter 声明 `capabilities.phase`（5/10/20/30）
- **phase 值**：preprocess=5, strategy=5, detect=10, mine=20, validate=30
- **任务分发**：`/app/app/service/scan_runner.py` 按 `agent_name` 路由
- **状态机**：`/app/app/statemachine/task.py` 管理 task 生命周期
- **黑板模式**：agent 运行期 `submit_artifact` 驱动下游（detection → mining → validation → deep_mining）
- **Session 关系**：`turing_task_trace.phase` = `agent_name`，`turing_task.agent_session_id` 是 session ID

#### Turing MySQL 连接信息

| 参数 | 值 |
|------|------|
| Pod | `turing-app-security-mysql-0` |
| Host | `turing-app-security-mysql.secflow-ns.svc.cluster.local` |
| User | `root` |
| Password | `turing_app_security_pass` |
| Database | `turing_app_security` |
| 关键表 | `turing_task`（id, task_type, agent_name, agent_session_id, working_dir） |
| 关键表 | `turing_task_trace`（task_id, phase, parent_task_id） |

---

### 3.3 SecMate（挖掘 Agent）

#### 数据来源

| 数据 | 位置 | 获取方式 |
|------|------|---------|
| persona 名 | JSONL trace 中 agent 的 prompt 标题 | parser 从 trace 提取 |
| finding level | JSONL trace 中 `store_finding` 工具调用的 `level` 参数 | parser 从 trace 提取 |
| workflow 名 | MySQL `secmate.task` 表 `params.agentfl.workflow` 字段 | k8s 内直连 SecMate MySQL |
| SEED_ID | JSONL trace 中 planner prompt 的 `SEED_ID=xxx` | parser 从 trace 提取 |

#### Persona 分布（secmate-logic-lite workflow）

| Persona | 职责 | 对应业务阶段 |
|---------|------|-------------|
| explorer | INIT 阶段模块划分，partition-modules skill | 不属于 5 阶段（预处理） |
| architect | 模块威胁标注，逐函数安全覆盖 | 入口识别 + 数据流追踪 |
| flow-tracer | 漏洞优先深度证据追踪，source→sink | 数据流追踪 + Sink 点定位 |
| specialist | 专项分析（注入/反序列化/路径/会话等） | 漏洞模式识别 |
| mdf-composer | 微数据流拼接 | 数据流追踪 |
| vuln-analyst | 漏洞判断，输出 review_claim | 漏洞判定与上报 |
| reviewer | 严格证据闭环复核，TP/FP 判定 | 漏洞判定与上报 |
| variant-hunter | 变体挖掘 | 漏洞模式识别 |
| distiller | 知识蒸馏 | 不属于 5 阶段 |
| fp-analyzer | 误报分析 | 漏洞判定与上报 |
| deep-researcher | 深度研究 | 漏洞判定与上报 |
| noise-distiller | 噪声蒸馏 | 不属于 5 阶段 |
| logic-architect | 逻辑架构分析 | 入口识别 |
| logic-tracer | 逻辑追踪 | 数据流追踪 |
| logic-oracle-analyzer | 逻辑预言机分析 | 漏洞模式识别 |
| report | 报告生成 | 不属于 5 阶段 |

#### finding level → 业务阶段映射

| finding level | 阶段 | 说明 |
|---------------|------|------|
| module | 预处理 | 模块划分 |
| hint | 入口识别 | 初步线索 |
| source | 入口识别 + 数据流追踪 | 污点源 |
| sink | Sink 点定位 | 污点汇聚点 |
| dataflow | 数据流追踪 | 完整或片段数据流 |
| logic_anchor / logic_trace | 数据流追踪 | 逻辑链 |
| review_claim | 漏洞判定与上报 | 待复核候选 |
| review_verdict / final_verdict | 漏洞判定与上报 | 最终裁决 |

#### 归类方案

| 层级 | 方法 | 确定性 |
|------|------|--------|
| 第一层：persona 确定性标注 | 从 JSONL trace 提取 agent prompt 标题中的 persona 名 | 确定性（需 parser 识别） |
| 第二层：persona → 业务阶段映射 | 程序规则映射（上表） | 确定但部分 persona 跨多阶段 |
| 第三层：finding level 辅助 | 从 `store_finding` 工具调用的 `level` 参数进一步细分 | 确定性 |
| 第四层：LLM 细分 | 对跨阶段的 persona（如 architect），从 REASONING 事件用 LLM 细分 | LLM 判定 |

#### SecMate 源码关键发现

- **Workflow 定义**：`/app/workflows/secmate-logic-lite/routing_sdl.py`，用 Python SDL 声明 persona、seed、route
- **Agent 定义**：`/app/workflows/secmate-logic-lite/agents/*.md`，每个 persona 有 frontmatter（name, description, abstract, tools）
- **Finding 层级**：`SECURITY_FINDING_LEVELS` 字典定义 16 个 level（module → final_verdict）
- **Session 关联**：通过 SEED_ID 共享、finding_id 共享、finding 父子关系（source_session_id）
- **trace 格式**：Claude SDK JSONL 格式，`entrypoint="sdk-cli"`
- **Workflow 变体**：secmate-logic-lite / secmate-all-lite / secmate-flash 等，不同 workflow 的 persona 集合不同

#### SecMate MySQL 连接信息

| 参数 | 值 |
|------|------|
| Pod | `secmate-mysql-0` |
| Host | `secmate-mysql.secflow-ns.svc.cluster.local` |
| User | `root` |
| Password | `Huawei12#$` |
| Database | `secmate` |
| 关键表 | `task`（tool_task_id, external_task_id, file_path, params） |
| 关键表 | `task_event`（tool_task_id, event_type, from_status, to_status） |
| 注意 | task 表无 agent_name / persona 字段，persona 信息仅在 trace JSONL 中 |

---

### 3.4 DataflowVulnScan（挖掘 Agent）

#### 数据来源

| 数据 | 位置 | 获取方式 |
|------|------|---------|
| analysisType | JSONL 文件名编码 `d{depth}-{func}-{analysisType}-{taint}-{NN}` | parser 从文件名提取 |
| depth | 文件名 `d{depth}` 部分 | parser 从文件名提取 |
| func_name | 文件名 `{func}` 部分 | parser 从文件名提取 |

#### analysisType 分布

| analysisType | 说明 | 数量（相对） |
|-------------|------|-------------|
| taint | 单函数污点传播分析 | 最多 |
| track | 逃逸读者查找 | 中等 |
| fptrack | 间接调用解析（函数指针） | 较少 |
| vuln-judge | 漏洞判断（四维度 D1-D4） | 中等 |
| vuln-pattern-enhancement | 漏洞模式增强 | 较少 |
| vuln-false-positive-judge | 误报判断 | 较少 |
| vuln-report | 漏洞报告 | 最少 |

#### analysisType → 业务阶段映射

| analysisType | 映射的业务阶段 | 说明 |
|-------------|--------------|------|
| taint | 数据流追踪 | 单函数内污点传播分析，输出传播列表 |
| track | 数据流追踪 | 逃逸读者查找，追踪跨函数污点 |
| fptrack | 数据流追踪 | 间接调用解析，解析函数指针/回调 |
| vuln-judge | 漏洞判定与上报 | 四维度判定（code_accurate/path_reachable/unmitigated/security_impact） |
| vuln-pattern-enhancement | 漏洞模式识别 | 模式增强 |
| vuln-false-positive-judge | 漏洞判定与上报 | 误报判断 |
| vuln-report | 漏洞判定与上报 | 漏洞报告 |

#### 归类方案

| 层级 | 方法 | 确定性 |
|------|------|--------|
| 第一层：analysisType 确定性标注 | 从 JSONL 文件名提取 `kind` 字段 | 100% 确定 |
| 第二层：analysisType → 业务阶段映射 | 程序规则映射（上表） | 100% 确定 |
| 无需 LLM 细分 | analysisType 已足够细粒度 | — |

#### Session 关系图

DataflowVulnScan 的 session 关系通过文件名命名规则构建（5 维度）：
1. **跨深度**：d00→d01→d02（函数调用链）
2. **同深度分析流**：taint/track/fptrack → vuln-judge → vuln-pattern-enhancement → vuln-false-positive-judge → vuln-report
3. **错误重试**：`-error{N}` 后缀
4. **TaintFunctionGuess**：子分析
5. **初始分叉**：track/fptrack 从 taint 分叉

#### DataflowVulnScan 源码关键发现

- **Session 命名**：`/app/app/dagflow/session_naming.py`，格式 `d{depth:02d}-{func}-{kind}-{taint}-{NN}.jsonl`
- **编排器**：`/app/app/dagflow/orchestrator.py`，队列驱动 BFS 跟踪
- **挖掘 Agent**：`/app/app/dagflow/mining_agent.py`，Phase 1 链重构 + Phase 2 漏洞判断 + Phase 3 报告
- **Prompt 模板**：`/app/prompts/dagflow/`（taint-dag.md, vuln-mining.md, vuln-judge.md, function-resolver.md, reader-finder.md）
- **analysisType 枚举**：`taint, track, fptrack, vuln-judge, vuln-pattern-enhancement, vuln-false-positive-judge, vuln-report`
- **v2 模块**：`/app/app/dataflow_v2/`（autonomous.py, analysis.py 等，新一代自主分析）

#### DataflowVulnScan MySQL 连接信息

| 参数 | 值 |
|------|------|
| Pod | `secflow-app-dataflow-vuln-scan-mysql-0` |
| Host | `secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local` |
| User | `root` |
| Password | `Huawei12#$` |
| Database | `dvs_init`（全局）+ 每个 project 一个 `dvs_{project_id}` |
| 关键表 | `orchestration`（edge_id, path_id, source_func_id, target_func_id, status, task_id） |
| 注意 | MySQL 主要存储函数调用图和污点传播数据，session 级别信息在 JSONL 文件名中 |

---

### 3.5 CVulnVerify（验证 Agent）

#### 数据来源

| 数据 | 位置 | 获取方式 |
|------|------|---------|
| worker_type | PostgreSQL `vuln_verify_attempt` 表 `worker_type` 列 | k8s 内直连 CVulnVerify PostgreSQL |
| successor_reason | PostgreSQL `vuln_verify_attempt` 表 `successor_reason` 列 | 同上 |
| predecessor_attempt_id | PostgreSQL `vuln_verify_attempt` 表 `predecessor_attempt_id` 列 | 同上 |
| session_id | JSONL 文件名 = attempt_id（UUID） | parser 从文件名提取 |

#### worker_type 分布

| worker_type | 数量 | 说明 |
|-------------|------|------|
| source-verifier | 4,491 | 源码级验证 |
| c-formal-verifier | 2,940 | C 形式化验证 |
| binary-instrumentation-poc | 2,903 | 二进制插桩 PoC |
| (空) | 2,387 | 早期任务无 worker_type |

#### worker_type → 业务阶段映射

| worker_type | 映射的业务阶段 | 说明 |
|-------------|--------------|------|
| source-verifier | 漏洞理解 + 代码定位 + 验证执行 | 源码级验证，读取 finding 描述、定位代码、执行分析 |
| c-formal-verifier | 验证执行 | C 形式化验证，执行形式化分析 |
| binary-instrumentation-poc | 验证执行 | 二进制插桩 PoC 构造与运行 |

#### successor_reason → 验证链结构

| successor_reason | 说明 |
|-----------------|------|
| (空) | 首次尝试（验证链起点） |
| manager_dispatch | Manager 跨阶段分发（source-verifier → c-formal-verifier 或 binary-instrumentation-poc） |
| failure_retry | 同类型重试 |

#### 归类方案

| 层级 | 方法 | 确定性 |
|------|------|--------|
| 第一层：worker_type 确定性标注 | 查 CVulnVerify PostgreSQL `vuln_verify_attempt` 表 `attempt_id → worker_type` | 100% 确定 |
| 第二层：worker_type → 业务阶段映射 | 程序规则映射（上表） | 确定但 source-verifier 涵盖 3 个阶段 |
| 第三层：LLM 细分 | 对 source-verifier，从 JSONL trace 的 REASONING 事件用 LLM 细分到具体阶段 | LLM 判定 |

#### 验证链结构

```
source-verifier (首次) 
    ├── manager_dispatch → c-formal-verifier
    ├── manager_dispatch → binary-instrumentation-poc
    └── failure_retry → source-verifier (重试)
```

#### CVulnVerify 源码关键发现

- **验证器 Prompt**：`/app/app/verifier_prompt.md`，四维度验证（code_accurate / path_reachable / unmitigated / security_impact）
- **验证器实现**：`/app/app/verifier.py`，prompt 渲染 + verdict 修复循环
- **Worker 类型**：`/app/app/worker_types.py`，三种 worker（source-verifier / c-formal-verifier / binary-instrumentation-poc）
- **执行计划**：`/app/app/execution_plan.py`，模型选择 + 威胁模型 + 验证策略
- **Session 关系**：`predecessor_attempt_id` 列存储重试链，JSONL 文件名 = attempt_id
- **Verdict 输出**：`vuln_verify_final_verdict.json`，含 verdict（confirmed / ruled_out / unresolved）

#### CVulnVerify PostgreSQL 连接信息

| 参数 | 值 |
|------|------|
| Pod | `secflow-app-vuln-verify-v2-postgres-0` |
| Host | `secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local` |
| User | `postgres` |
| Password | `secflow123` |
| Database | `secflow_vuln_verify_v2` |
| 关键表 | `vuln_verify_attempt`（id, task_id, worker_type, successor_reason, predecessor_attempt_id, status） |
| 关键表 | `vuln_verify_task`（id, ...） |
| 环境变量 | `EVAL_CVULN_DB_HOST` / `EVAL_CVULN_DB_PORT` / `EVAL_CVULN_DB_USER` / `EVAL_CVULN_DB_PASSWORD` / `EVAL_CVULN_DB_NAME` |

#### eval-engine 已有集成

eval-engine 的 `cvuln_verify_trace_parser.py` 已实现 `_fetch_predecessor_map()` 方法，通过 PostgreSQL 查询 `predecessor_attempt_id` 映射，构建 session 重试链。

---

### 3.6 WebVulnVerify（验证 Agent）

#### 数据来源

| 数据 | 位置 | 获取方式 |
|------|------|---------|
| 工具名 | JSONL trace 中 `tool_call.name` | parser 从 trace 提取 |
| vulnerability_id | JSONL trace `session_meta.metadata.vulnerability_id` | parser 从 trace 提取 |
| parent_id | JSONL trace `session_meta.session.parent_id` | parser 从 trace 提取 |
| verify status | JSONL trace `vulnerability_verify` 工具调用的 `status` 参数 | parser 从 trace 提取 |

#### 工具名分布

| 工具名 | 说明 | 对应业务阶段 |
|--------|------|-------------|
| vulnerability_analyze | 漏洞分析（标题/类型） | 漏洞理解 + 代码定位 |
| vulnerability_verify | 验证结论写入 | 判定上报 |
| vulnerability_cvss | CVSS 评分 | 判定上报 |
| read / bash / grep | 代码读取/命令执行/搜索 | 验证执行 |

#### 工具名 → 业务阶段映射

| 工具名 | 映射的业务阶段 | 说明 |
|--------|--------------|------|
| vulnerability_analyze | 漏洞理解 + 代码定位 | 分析漏洞详情，理解 finding 含义 |
| vulnerability_verify | 判定上报 | 写入验证结论（confirmed / ruled_out） |
| vulnerability_cvss | 判定上报 | CVSS 评分 |
| read / bash / grep | 验证执行 | 代码定位 + PoC 构造 |

#### verify status → validation_result 映射

| status | validation_result | 说明 |
|--------|-------------------|------|
| EXTERNAL_REQUEST_EXPLOITABLE | confirmed | 外部请求可利用 |
| INTERNAL_REQUEST_EXPLOITABLE | confirmed | 内部请求可利用 |
| UNIT_TEST_EXPLOITABLE | confirmed | 单元测试可利用 |
| NOT_EXPLOITABLE | ruled_out | 不可利用 |

#### 归类方案

| 层级 | 方法 | 确定性 |
|------|------|--------|
| 第一层：工具名确定性标注 | 从 JSONL trace 提取每个 session 的工具调用序列 | 100% 确定 |
| 第二层：工具名 → 业务阶段映射 | 程序规则映射（上表） | 确定但 vulnerability_analyze 涵盖 2 个阶段 |
| 第三层：LLM 细分 | 对 vulnerability_analyze session，从 REASONING 事件用 LLM 细分（漏洞理解 vs 代码定位） | LLM 判定 |

#### Session 关系

WebVulnVerify session 关联机制（从 trace 数据验证，82 sessions）：
1. **vulnerability_id 共享**：`session_meta.metadata.vulnerability_id`（100% session 有）
2. **parent_id 父子边**：`session_meta.session.parent_id`（37/82 session 有）
3. **analyze ≠ verify session**：vulnerability_analyze 和 vulnerability_verify 100% 在不同 session

#### WebVulnVerify 源码关键发现

- **Agent 架构**：`athena-agent-worker` pod，运行 Athena 框架
- **Gate 模块**：`/app/athena/modules/gate/`，知识货架门禁 Agent
- **Agent Task 类型**：`AgentTaskType` 枚举（GATE / BUSINESS_KNOWLEDGE / VULNERABILITY_KNOWLEDGE / EXPERIENCE_KNOWLEDGE / RETRIEVAL / CONCEPT_EXTRACTION / KNOWLEDGE_CLUSTER）
- **trace 格式**：自定义 JSONL，行类型 `session_meta` / `tool_schema` / `message_completed`
- **finding 入口**：`vulnerability_verify` 是唯一验证结论写入工具
- **Session 元数据**：`session_meta` 行含 `session.id` / `session.parent_id` / `metadata.vulnerability_id`

#### WebVulnVerify 无独立数据库

WebVulnVerify 使用 Athena 框架，无独立 MySQL/PostgreSQL。session 级别信息全部在 JSONL trace 中。

---

## 4 综合归类策略

### 4.0 各 Agent 数据库中的 Session 关系存储

调研确认：5 个 Agent 的数据库中存储了 session 之间的关系，WebVulnVerify 无独立 DB（关系在 trace JSONL 中）。eval-engine 上线后可通过 k8s 内网直连这些数据库获取 session 关系图。

| Agent | 数据库 | 关系存储表 | 关系字段 | 关系类型 | 说明 |
|-------|--------|----------|---------|---------|------|
| Argo | MySQL `argo_c` | `intents` | `session_id`, `to_fact_id`, `suggestion_refs`, `retry_count` | intent→fact→suggestion 链 | bootstrap→investigate→verify 的 session 链通过 fact/suggestion 关联；`retry_count` 标记重试 session |
| Argo | MySQL `argo_c` | `suggestions` | `fact_id`, `status` | fact→suggestion | finding 产生的建议驱动后续 investigate session |
| Argo | MySQL `argo_c` | `facts` | `type`(fact/finding), `metadata` | fact 链 | finding 的 metadata 含 source/sink/propagation，关联到 verify session |
| Turing | MySQL `turing_app_security` | `turing_task` | `parent_task_id`, `agent_session_id`, `job_id` | parent-child task 链 | `parent_task_id` 直接链接上下游 session（detection→mining→validation→deep_mining） |
| Turing | MySQL `turing_app_security` | `turing_task_trace` | `task_id`, `parent_task_id`, `phase`, `finding_id` | phase 链 + finding 驱动 | `phase` = agent_name，`finding_id` 标记 finding 驱动的下游 task |
| Turing | MySQL `turing_app_security` | `turing_investigation` | `parent_investigation_id`, `origin_detection_id`, `target_task_id`, `depth` | investigation 树 | 跨模块/跨服务深度追踪的 investigation 父子链，`depth` 标记追踪深度 |
| SecMate | MySQL `secmate` | `finding` | `source_finding_id`, `tool_task_id` | finding 父子链 | `source_finding_id` 链接 source→sink→dataflow→review_claim 等不同 level 的 finding |
| SecMate | MySQL `secmate` | `task` | `tool_task_id`, `external_task_id` | task 映射 | 一个 `tool_task_id` 对应一个 SecMate session（workflow 运行） |
| DataflowVulnScan | MySQL `dvs_{project_id}` | `dvs_task_graph_edges` | `source_node_id`, `target_node_id`, `source_func_id`, `target_func_id`, `task_id` | 函数调用图 | 函数调用关系图，edge 连接 source→target 函数，每个 edge 关联 task_id |
| DataflowVulnScan | MySQL `dvs_{project_id}` | `dvs_task_graph_nodes` | `node_id`, `task_id`, `depth`, `primary_session_relpath` | 节点→session | 每个 node 关联 primary session 文件路径，`depth` 标记调用深度 |
| DataflowVulnScan | MySQL `dvs_{project_id}` | `dvs_task_graph_sessions` | `session_relpath`, `node_id`, `edge_id`, `session_role`, `session_kind` | session→node/edge | session 与 task graph node/edge 的映射，`session_kind` = analysisType |
| DataflowVulnScan | MySQL `dvs_{project_id}` | `orchestration` | `edge_id`, `path_id`, `source_func_id`, `target_func_id`, `task_id` | 调用路径 | 老版本调用路径表（部分项目无 `dvs_task_graph_*` 表，用此表） |
| CVulnVerify | PostgreSQL `secflow_vuln_verify_v2` | `vuln_verify_attempt` | `predecessor_attempt_id`, `successor_reason`, `task_id` | 验证链 | `predecessor_attempt_id` 链接 source-verifier→c-formal-verifier/binary-instrumentation-poc；`successor_reason` 区分 manager_dispatch vs failure_retry |
| WebVulnVerify | 无独立 DB | JSONL trace | `session.parent_id`, `metadata.vulnerability_id` | session 父子 + vulnerability 共享 | `parent_id` 父子边（37/82 session 有）；`vulnerability_id` 100% 共享 |

**Session 关系图构建方式**：

eval-engine v2 parser 的 `build_session_graph()` 可从两个来源构建 session 关系图：

| 来源 | 方法 | 优势 |
|------|------|------|
| Agent DB（优先） | 直连 Agent 数据库查询关系表 | 100% 准确，含 DB 级约束；可获取 trace 中不可见的关系（如 Turing parent_task_id） |
| Trace JSONL（补充） | parser 从 trace 提取 parent_id / SEED_ID / vulnerability_id | 无需 DB 连接；WebVulnVerify 唯一来源 |

**各 Agent 推荐的 session 关系图构建路径**：

| Agent | 构建路径 | 关系边类型 |
|-------|---------|-----------|
| Argo | DB `intents` 表：同一 project 下 bootstrap→investigate→verify 的 session 链，通过 `to_fact_id` 和 `suggestion_refs` 关联 | parent_id 边（intent 序列） |
| Turing | DB `turing_task` 表：`parent_task_id` 直接构建 parent-child 边；`turing_investigation` 表：`parent_investigation_id` 构建深度追踪树 | parent_id 边（task 链）+ investigation 树 |
| SecMate | DB `finding` 表：`source_finding_id` 构建 finding 父子链；trace 中 SEED_ID 共享 + finding_id 父子 | finding_id 边 + SEED_ID 边 |
| DataflowVulnScan | DB `dvs_task_graph_sessions` 表：`node_id`/`edge_id` 构建 session→node→edge 关系图；`session_kind` 即 analysisType | task_graph 边（node/edge） |
| CVulnVerify | DB `vuln_verify_attempt` 表：`predecessor_attempt_id` 构建 attempt 验证链；`successor_reason` 区分 dispatch vs retry | predecessor 边（验证链） |
| WebVulnVerify | Trace JSONL：`session.parent_id` 父子边 + `metadata.vulnerability_id` 共享边 | parent_id 边 + vulnerability_id 边 |

### 4.1 分层标注架构

```
Session 归类流程
    │
    ├── 第一层：程序确定性标注（100% 确定）
    │   ├── Argo: JSONL prompt 标题 / MySQL intents 表 → task_type
    │   ├── Turing: MySQL turing_task 表 → agent_name + task_type
    │   ├── SecMate: JSONL trace → persona 名 + finding level
    │   ├── DataflowVulnScan: JSONL 文件名 → analysisType
    │   ├── CVulnVerify: PostgreSQL vuln_verify_attempt 表 → worker_type
    │   └── WebVulnVerify: JSONL trace → 工具名序列
    │
    ├── 第二层：程序规则映射（确定性但粒度粗）
    │   └── 各 Agent 的 task_type/agent_name/persona/analysisType/worker_type/工具名 → 业务阶段
    │
    └── 第三层：LLM 细分（对跨阶段 session）
        ├── Argo investigate: Task Description + REASONING → 具体阶段
        ├── Turing mining/deep_mining: REASONING → 具体阶段
        ├── SecMate architect/flow-tracer: REASONING → 具体阶段
        ├── CVulnVerify source-verifier: REASONING → 具体阶段
        └── WebVulnVerify vulnerability_analyze: REASONING → 具体阶段
```

### 4.2 数据库连接汇总

| Agent | 数据库类型 | 连接信息 |
|-------|----------|---------|
| Argo | MySQL | `chirmra-platform-nazhua-mysql.secflow-ns.svc.cluster.local:3306` / root / Icsl_argo / argo_c |
| Turing | MySQL | `turing-app-security-mysql.secflow-ns.svc.cluster.local:3306` / root / turing_app_security_pass / turing_app_security |
| SecMate | MySQL | `secmate-mysql.secflow-ns.svc.cluster.local:3306` / root / Huawei12#$ / secmate |
| DataflowVulnScan | MySQL | `secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306` / root / Huawei12#$ / dvs_init + dvs_{project_id} |
| CVulnVerify | PostgreSQL | `secflow-app-vuln-verify-v2-postgres.secflow-ns.svc.cluster.local:5432` / postgres / secflow123 / secflow_vuln_verify_v2 |
| WebVulnVerify | 无独立 DB | session 信息在 JSONL trace 中 |

### 4.3 v2 Parser 实现要点

每个 v2 parser 在 `parse()` 阶段需额外提取 session 级别的阶段标注信息：

| Parser | 新增提取字段 | 数据来源 |
|--------|------------|---------|
| ArgoParser | `session_task_type` | JSONL 第一行 prompt 标题 |
| TuringParser | `session_agent_name`, `session_task_type` | Turing MySQL `turing_task` 表 |
| SecMateParser | `session_persona`, `finding_levels` | JSONL trace agent prompt + store_finding 参数 |
| DataflowVulnScanParser | `session_analysis_type`, `session_depth` | JSONL 文件名解析 |
| CVulnVerifyParser | `session_worker_type`, `session_successor_reason` | CVulnVerify PostgreSQL `vuln_verify_attempt` 表 |
| WebVulnVerifyParser | `session_tool_set` | JSONL trace 工具调用序列 |

### 4.4 DataPack 扩展

DataPack 需新增字段承载阶段标注信息：

```python
@dataclass
class DataPack:
    # ... 现有字段 ...
    
    # 新增：session 级别阶段标注
    session_phase_labels: dict[str, str]  # session_id → business_phase（程序标注）
    session_phase_source: dict[str, str]  # session_id → 标注来源（task_type/agent_name/persona/analysisType/worker_type/tool_name）
```

### 4.5 各 Agent 不产生知识访问的阶段

以下阶段的 session 不产生知识访问，L0-L7 分析可跳过：

| Agent | 不产生知识访问的阶段 |
|-------|-------------------|
| Argo | reason（调度阶段） |
| Turing | preprocess（预处理阶段） |
| SecMate | explorer（INIT 模块划分）、distiller/noise-distiller（知识蒸馏）、report（报告生成） |
| DataflowVulnScan | 无（所有 analysisType 都可能产生知识访问） |
| CVulnVerify | 无（所有 worker_type 都可能产生知识访问） |
| WebVulnVerify | 无（所有 session 都可能产生知识访问） |
