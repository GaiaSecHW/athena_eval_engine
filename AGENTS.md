# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## 命令

```bash
# 安装开发环境
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

# 启动 API 服务（端口 8090，健康检查 8091）
python -m uvicorn athena_eval_engine.api.routes.evaluations:app --host 0.0.0.0 --port 8090

# 运行测试
pytest                                          # 全部测试
pytest tests/test_metrics.py                    # 单个文件
pytest tests/test_metrics.py::test_known_effect_kg_recovers_half  # 单个用例
pytest tests/test_trace_to_fact.py              # 仅 fixture 测试（无需 MySQL）

# Docker
docker build -t athena-eval-engine .
docker run -p 8090:8090 athena-eval-engine

# 本地开发：port-forward 远端服务（MySQL/Platform/Schedule/V-Bench）
source ./dev.sh        # 加载环境变量
bash port-forward.sh   # 另一终端运行
```

## 环境与配置

- 配置从 `config.yaml` 加载（路径可通过 `EVAL_CONFIG_FILE` 覆盖）；k8s 中由 ConfigMap 挂载。
- 每个配置 key 都有同名环境变量覆盖（`EVAL_MYSQL_HOST`、`EVAL_LLM_BASE_URL`、`EVAL_LLM_MODEL`、`VBENCH_API_URL`、`PROJECT_API`、`SCHEDULE_API`、`DATA_ROOT`、`PLATFORM_TOKEN`、`EVAL_VULN_CENTER_API_URL` 等）——见 `config_loader.py`。
- **运行时并发参数**通过 `system_config` 表持久化，`infrastructure/concurrency.py` 是单一数据源。DB 修改后 config watcher 轮询 `_version` 字段更新内存值。多 worker 部署时直接改 DB 必须递增 `_version`，否则 watcher 不重载。
- **测试需要 live MySQL**（`test_api.py`、`test_persistence.py`、`test_web.py`、`test_real_trace.py`）。`test_trace_to_fact.py` 和 `test_metrics.py` 纯内存运行，无需 DB。

## 架构

### Pipeline（`evaluation_service.py:run()`，9+ 阶段）

编排器在后台线程中同步运行（ThreadPoolExecutor，最多 3 并发）。使用**短连接 MySQL**——慢操作（trace 解析、LLM 调用）不持有 DB 连接，以在远端防火墙重置后存活。`_db_query()` 包装器在连接丢失（2013/2006）时指数退避重试。

0. **INGESTING** — 取基线 case 详情（漏洞中心 Chimera 或 V-Bench zip，二选一）+ 告警中心数据，写 benchmark_items。FPR 分析在此阶段后启动，与 PARSING **并行**运行（FPR 只依赖 case_details + entries，不依赖 trace 解析）。
1. **PARSING** — 并行 trace 解析（ThreadPoolExecutor）。每个 trace：parser → RawEvents，然后 4 个 resolver + sink matcher 并行运行。`retry` 路径：如 facts 已在 DB 中，跳过解析直接加载。
2. **AI_MATCHING** — 独立阶段。sink-point 匹配 + LLM finding→baseline 匹配。FPR 后台完成后覆盖 AC 匹配结果。
3. **RESOLVING** — Facts 批量写入 MySQL（幂等，重复 key 跳过）。
4. **PAIRING + CALCULATING** — `TaskPairMatcherImpl` 按 `(evaluation_id, task_id)` 匹配 KG/No-KG 运行。`PairDerivedFactComputer` 计算 JSD、ΔToken、ΔSteps、ΔTime、PairTransition。`run_all_metrics()` 计算 M1–M13，并行 bootstrap（numpy 释放 GIL）。按 task_id 分组各自独立算指标。
5. **REPORTING** — `assemble()` 构建报告模型；`ai_per_case_kg_analysis()` 调用 LLM 生成逐漏洞 KG 归因分析。LLM 不可用时有规则降级。报告分三段存储：`{eid}.json`（基础）+ `{eid}_fpr.json`（FPR）+ `{eid}_kg.json`（KG）。
6. **FINALIZE** — 写入 `evaluation_report` 表，状态设为 COMPLETED。固化静态 HTML 报告（打开时零计算）。JSON 瘦身（剥离 dashboard 不使用的大字段）。

### 状态机（`orchestration/state_machine.py`）

严格白名单跳转（CREATED → VALIDATING → INGESTING → PARSING → **AI_MATCHING** → RESOLVING → PAIRING → CALCULATING → STATISTICAL_ANALYSIS → DIAGNOSING → REPORTING → FINALIZING → COMPLETED）。非白名单跳转被拒绝。FAILED/CANCELLED 可 resume 回 VALIDATING。RUNNING 状态可跳转 CANCEL_REQUESTED → CANCELLING → CANCELLED。

**协作取消**：`cancel_requested` DB flag 在阶段边界检查（`_check_cancel`）。取消信号通过 `iter_completed` 的 `cancel_cb` 穿透到 LLM 密集内循环。跨 worker 生效（共享 DB）。

### 分层结构

- **`domain/`** — 纯业务逻辑，无 I/O。`enums.py`（镜像 `schema.sql` CHECK 约束）、`raw_event.py`（规范事件）、`task_run.py`（TaskRun/BenchmarkItem）、`facts/`（4 种 fact）、`metrics/`（M1–M13 + `run_all_metrics`）、`statistics/engine.py`（bootstrap/McNemar/Wilson/Wilcoxon）、`diagnostics/`（规则异常检测）、`resolvers/`（TraceParser 抽象）。
- **`workers/`** — Trace 解析器与 resolver。6 个 parser（见下）、`resolvers.py`（4 个 resolver）、`ai_matcher.py`（LLM finding→baseline 匹配）、`sink_matcher.py`（sink-point 匹配 + session 链构建）、`pairing.py`、`parse_utils.py`（JSON 修复、事件索引等共享工具）。
- **`application/`** — 编排。`evaluation_service.py`（主 `create()`/`run()`/`get_status()`/`get_report()`/`rerun_fpr()`/`rerun_kg()`）、`platform_service.py`（项目/任务发现、dev 模式 kubectl exec 读 trace）、`report_assembler.py`（报告模型 + LLM 叙述）、`fpr_analysis.py`（FPR 基线匹配，LLM 批量匹配 + 程序校验 sink 路径）。
- **`infrastructure/`** — 外部集成。`database.py`（pymysql）、`llm.py`（OpenAI 兼容客户端，SSE 流式，`chat()`/`chat_json()`，全局并发门控）、`vbench_client.py`、`vuln_center_client.py`（漏洞中心 Chimera 数据读取）、`concurrency.py`（统一并发配置，运行时可调）、`parallel.py`（`iter_completed` 替代 `as_completed`，支持取消信号）、`health_server.py`（独立健康检查端口 8091，零锁零 I/O）、`migrations.py`（schema 迁移机制，启动时自动应用）、`log_util.py`（带评测 ID 上下文的统一日志）。
- **`persistence/repositories/fact_repo.py`** — 所有 SQL INSERT 函数。
- **`api/routes/`** — FastAPI 端点。`evaluations.py`（主 app）、`web.py`（dashboard）、`platform.py`、`benchmark_system.py`。

### 关键领域概念

- **Condition**: KG（知识图谱启用）vs NOGK（对照组）vs UNKNOWN。
- **RawEvent**: trace 解析产生的规范事件。`is_kg_interaction` flag 由 parser 设置，决定 KG 交互（resolver 不硬编码工具名）。
- **Facts**: 每个 task run 提取 4 种 fact — OutcomeFact（是否找到漏洞）、KnowledgeInteractionFact（是否访问/交付 KG）、ToolActionFact（工具调用分布）、ResourceFact（token/步数/耗时）。
- **PairView**: KG+No-KG pair 及 outcomes + derived deltas，metric 计算的输入。
- **Metrics M1–M13**: ΔBA（准确率）、IR（改善率）、RR（回归率）、ΔFNR、KAR（知识访问率）、KDR（知识交付率）、JSD（行为偏移）、ΔToken、ΔSteps、ΔTime、MAR（记忆访问率）、MDR（记忆交付率）、FPR（误报率）。M13 FPR 由 FPR 分析模块填充，非 `run_all_metrics` 计算。
- **Canonical Actions**: KG > FINDING > CODE > SHELL > OTHER（工具分类优先级）。
- **Sink-Point Matching**: 基线漏洞 sink 点（文件+行号/方法名）定位 session 链。替代 finding→baseline 语义匹配。流程：扫描 trace 文件读取操作 → sink 点匹配 → session graph 分组为链 → 确定性 confusion（finding 匹配 source_file + validation_result + expected_label）。
- **FPR（误报率）**: 基线集 vs 漏洞中心/告警中心数据，批量 LLM 匹配 + 程序校验 sink 路径。在 INGESTING 后启动，与 PARSING 并行。结果写入 `{eid}_fpr.json`，M13 从中取值。
- **Extracted Finding + Session Graph**: `extracted_finding` 表存储 parser 提取的漏洞 finding；`session_graph` 表存储 session 关系图（parent_id 边，非共享文件 basename 边）。

### Trace 格式

六个 parser（选择在 `evaluation_service.py` 的 `_get_parser()` 中完成，按 `trace_kind` 或路径推断）：

- **TuringTraceParser**: 读 SQLite（`opencode.db`），含 `session` + `part` 表。Schema Gate 在缺少必要表时阻断。
- **ArgoTraceParser**: 读 Claude Code JSONL session 文件（`.jsonl` 目录）。`source_uri` 为目录或 `.jsonl` 结尾时选中。需要 LLM 模块注入。
- **SecMateTraceParser**: 读 SecMate JSONL（`tools/secmate-*/run/.worker-config/projects/*/`）。**session 调用链语义**：parent_map/edges 唯一来源是 findings.db 的 finding_edges（finding 派生链经 source_session_id 映射成 session 级关系），语义为"产生相关漏洞发现的 session 之间的关系"，非严格调用关系。SecMate 的 session（agent CLI 进程一次运行）彼此独立运行、无嵌套调用——与 argo/turing 不同。trace 的 parentUuid 指向 agent_spawner CLI 父进程 session（不在本 run 内），不可用于构建 case 内调用链。finding 权威源是 secmate MySQL `finding` 表（title + report_state=reported），经 source_finding_id 桥接 findings.db 的 source_session_id 关联 session。
- **CVulnVerifyTraceParser**: 读 CVulnVerify JSONL（`tasks/c_vuln_verify/*.jsonl` 或 `{task_id}/run/*.jsonl`）。pi-agent 信封格式：type=session/model_change/message，message.role=user/assistant/toolResult。
- **WebVulnVerifyTraceParser**: 读 WebVulnVerify JSONL（`session/WebVerify/*.jsonl`）。自定义 JSONL 格式：session_meta/tool_schema/message_completed。finding 入口为 `vulnerability_verify`。
- **DataflowVulnScanTraceParser**: 读 dataflow_vuln_scan JSONL（`session/dataflow_vuln_scan/<dvs_run_id>/*.jsonl`）。与 CVulnVerify 同信封但 toolResult/usage 键名不同。按 dvs_run_id 子目录递归读取。

### 基线数据源

二选一（在 manifest 的 `benchmark_source` 字段配置）：
- **vbench_zip** — 从 V-Bench benchmark.zip 读（测评集基线）。
- **vuln_center** — 从漏洞中心 Chimera（`secflow-platform-vuln`）直接读人工确认 case，含漏洞（`confirmation_status=vulnerable`）与非漏洞（`confirmation_status=not_vulnerable`）两类。`vuln_center_client.py` 归一成与 V-Bench 同构结构。

### NA 契约

当 metric 无法计算（零分母、无分层、bootstrap 样本不足）时，返回 `calculation_status=NA` + `reason_code`（如 `NO_STRATUM`、`NO_VALID_DENOMINATOR`、`BOOTSTRAP_UNSTABLE`）。NA 行不携带估计值。这是核心不变量——不要对 metric 输出 0 或 None-as-zero。

### 报告分段

报告分三段存储在 `reports/` 目录（`EVAL_REPORTS_DIR` 可覆盖）：
- `{eid}.json` — 基础报告（指标 + case_results）
- `{eid}_fpr.json` — FPR 分析段（match_details + M13）
- `{eid}_kg.json` — KG 分析段（per_case_kg_analysis + 增强 case_results）
- `{eid}.html` — 固化静态 HTML（打开时零计算）

`/report/status` 端点返回各段就绪状态，供前端分段加载。`/report/fpr` 和 `/report/kg` 分别返回对应段。`rerun-fpr` 和 `rerun-kg` 端点支持重跑单段。

### Schema 迁移

`infrastructure/migrations.py` 在启动时自动检查并应用未执行的迁移。每条迁移用唯一 ID 跟踪，已应用的跳过。每条迁移在事务中执行，全部 SQL 成功（或幂等跳过）才提交并标记已应用。真实错误回滚事务、不标记已应用，下次启动重试。

### 测试 Fixture

- `tests/fixtures/01-12_*` — 单 trace fixture（SQLite `trace.db` + `expected.json`）。覆盖 TP/FP/FN/TN、wiki mount、token reasoning、step mismatch、time invalid。
- `tests/fixtures/13-16_*` — Pair fixture（KG `kg.db` + No-KG `nogk.db` + `expected.json`）。覆盖 no-tool-call、fingerprint mismatch、recovered pair。
- `tests/fixtures/fetched/` — 生产真实 trace 数据。`test_real_trace.py` 使用。

## 任务架构

一个任务只有一个漏洞挖掘 agent，但一个任务可能有两个漏洞验证 agent（CVulnVerify + WebVulnVerify）来验证漏洞。漏洞挖掘上报的全部漏洞都要由漏洞验证 agent 验证。

## 禁止截断

不要用截断来解决数据过大的问题。截断后的内容不是完整的句子，发给大模型处理没有意义。

当数据过大时，应采用以下替代方案：
- 压缩（用 LLM 将原始数据压缩成结构化摘要，保留完整语义）
- 聚合（将多条记录合并成统计摘要）
- 采样（选取有代表性的子集，每条保持完整）
- 跳过（数据过大时跳过 LLM 分析，用规则降级）

## 禁止降级跳过

禁止用降级跳过来掩盖问题。当操作失败或超时时，必须找到根因并修复，不允许跳过失败的任务继续执行。

- 失败时要查清根因（网络、配置、数据、代码 bug），修复后重试，而不是跳过
- 超时时要定位卡住的具体原因，解决阻塞点，而不是放弃等待
- 重试机制必须有明确的退避策略和最大重试次数，重试耗尽后向上抛异常，不允许静默吞掉
- 降级（fallback）只能用于"功能可选"场景（如 LLM 叙述分析失败用规则替代），不能用于"核心数据缺失"场景

## 根因分析铁律

所有根因分析必须以真实数据为支撑。没有看到真实数据，不能下结论，也不能靠猜来修改代码。

- 先查实际数据（日志、数据库、原始报文），再下结论
- 阈值、大小限制等参数必须基于实际数据分布，不能凭空设定
- 如果无法获取真实数据，明确说明"无法确认"，不要猜

## 排查优先级

能看代码解决的，绝不连 k8s 分析。只有在环境问题（部署状态、pod 重启、配置同步等）需要看真实运行数据时，才上 k8s 查日志。

## 禁止 k8s 热补丁

禁止在 k8s pod 上直接修改代码（热补丁）来验证或测试。热补丁会导致 pod 上的代码与仓库不一致，引入难以排查的偏差。

- 代码修改在本地仓库完成后，通过正常部署流程上线
- 需要真实数据验证时，将数据拷贝到本地或在本地用 fixture/单元测试验证
- 只读操作（查日志、读数据）不受此限制
