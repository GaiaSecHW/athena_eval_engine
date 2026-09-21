# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## 命令

```bash
# 安装开发环境
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

# 启动 API 服务（端口 8090）
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
- 每个配置 key 都有同名环境变量覆盖（`EVAL_MYSQL_HOST`、`EVAL_LLM_BASE_URL`、`EVAL_LLM_MODEL`、`VBENCH_API_URL`、`PROJECT_API`、`SCHEDULE_API`、`DATA_ROOT`、`PLATFORM_TOKEN` 等）——见 `config_loader.py`。
- **测试需要 live MySQL**（`test_api.py`、`test_persistence.py`、`test_web.py`、`test_real_trace.py`）。`test_trace_to_fact.py` 和 `test_metrics.py` 纯内存运行，无需 DB。

## 架构

### Pipeline（`evaluation_service.py:run()`，7 阶段）

编排器在后台线程中同步运行（ThreadPoolExecutor，最多 3 并发）。使用**短连接 MySQL**——慢操作（trace 解析、LLM 调用）不持有 DB 连接，以在远端防火墙重置后存活。`_db_query()` 包装器在连接丢失（2013/2006）时指数退避重试。

1. **VALIDATE/INGEST**（`create()`）— 冻结快照，插入 benchmark items（含 V-Bench API 的 case 描述），创建 evaluation 行。
2. **PARSING** — 并行 trace 解析（ThreadPoolExecutor，最多 4 worker）。每个 trace：parser → RawEvents，然后 4 个 resolver + AI matcher 并行运行。`retry` 路径：如 facts 已在 DB 中，跳过解析直接加载。
3. **RESOLVING** — Facts 批量写入 MySQL（幂等，重复 key 跳过）。
4. **PAIRING** — `TaskPairMatcherImpl` 按 `(evaluation_id, task_id)` 匹配 KG/No-KG 运行。`PairDerivedFactComputer` 计算 JSD、ΔToken、ΔSteps、ΔTime、PairTransition。
5. **CALCULATING** — `run_all_metrics()` 计算 M1–M13，并行 bootstrap（numpy 释放 GIL）。统计检验：GT 分层 paired bootstrap（M1/M4）、paired bootstrap（M2/M3/M7/M8–M10）、Wilson CI（M5/M6/M11/M12）、McNemar（M2/M3 joint）、Wilcoxon（M8–M10）。M13 误报率为占位，由 REPORTING 阶段 `_update_m13_fpr` 用 LLM 基线匹配结果填充。
6. **REPORTING** — `assemble()` 构建报告模型；`ai_per_case_kg_analysis()` 调用 LLM 生成逐漏洞 KG 归因分析。LLM 不可用时有规则降级。
7. **FINALIZE** — 写入 `evaluation_report` 表，状态设为 COMPLETED。

### 状态机（`orchestration/state_machine.py`）

严格白名单跳转（CREATED → VALIDATING → INGESTING → PARSING → RESOLVING → PAIRING → CALCULATING → STATISTICAL_ANALYSIS → DIAGNOSING → REPORTING → FINALIZING → COMPLETED）。非白名单跳转被拒绝。FAILED/CANCELLED 可 resume 回 VALIDATING。

### 分层结构

- **`domain/`** — 纯业务逻辑，无 I/O。`enums.py`（镜像 `schema.sql` CHECK 约束）、`raw_event.py`（规范事件）、`task_run.py`（TaskRun/BenchmarkItem）、`facts/`（4 种 fact）、`metrics/`（M1–M13 + `run_all_metrics`）、`statistics/engine.py`（bootstrap/McNemar/Wilson/Wilcoxon）、`diagnostics/`（规则异常检测）。
- **`workers/`** — Trace 解析器与 resolver。`turing_trace_parser.py`（SQLite opencode.db）、`argo_trace_parser.py`（Claude Code JSONL）、`secmate_trace_parser.py`（SecMate JSONL）、`resolvers.py`（4 个 resolver）、`ai_matcher.py`（LLM finding→benchmark 匹配）、`pairing.py`。
- **`application/`** — 编排。`evaluation_service.py`（主 `create()`/`run()`/`get_status()`/`get_report()`）、`platform_service.py`（项目/任务发现、dev 模式 kubectl exec 读 trace）、`report_assembler.py`（报告模型 + LLM 叙述）。
- **`infrastructure/`** — 外部集成。`database.py`（pymysql）、`llm.py`（OpenAI 兼容客户端，SSE 流式，`chat()`/`chat_json()`）、`vbench_client.py`。
- **`persistence/repositories/fact_repo.py`** — 所有 SQL INSERT 函数。
- **`api/routes/`** — FastAPI 端点。`evaluations.py`（主 app）、`web.py`（dashboard）、`platform.py`、`benchmark_system.py`。

### 关键领域概念

- **Condition**: KG（知识图谱启用）vs NOGK（对照组）vs UNKNOWN。
- **RawEvent**: trace 解析产生的规范事件。`is_kg_interaction` flag 由 parser 设置，决定 KG 交互（resolver 不硬编码工具名）。
- **Facts**: 每个 task run 提取 4 种 fact — OutcomeFact（是否找到漏洞）、KnowledgeInteractionFact（是否访问/交付 KG）、ToolActionFact（工具调用分布）、ResourceFact（token/步数/耗时）。
- **PairView**: KG+No-KG pair 及 outcomes + derived deltas，metric 计算的输入。
- **Metrics M1–M13**: ΔBA（准确率）、IR（改善率）、RR（回归率）、ΔFNR、KAR（知识访问率）、KDR（知识交付率）、JSD（行为偏移）、ΔToken、ΔSteps、ΔTime、MAR（记忆访问率）、MDR（记忆交付率）、FPR（误报率）。
- **Canonical Actions**: KG > FINDING > CODE > SHELL > OTHER（工具分类优先级）。

### Trace 格式

三个 parser：
- **TuringTraceParser**: 读 SQLite（`opencode.db`），含 `session` + `part` 表。Schema Gate 在缺少必要表时阻断。
- **ArgoTraceParser**: 读 Claude Code JSONL session 文件（`.jsonl` 目录）。`source_uri` 为目录或 `.jsonl` 结尾时选中。
- **SecMateTraceParser**: 读 SecMate JSONL（`tools/secmate-*/run/.worker-config/projects/*/`）。

Parser 选择在 `evaluation_service.py` 的 `_get_parser()` 中完成。

### NA 契约

当 metric 无法计算（零分母、无分层、bootstrap 样本不足）时，返回 `calculation_status=NA` + `reason_code`（如 `NO_STRATUM`、`NO_VALID_DENOMINATOR`、`BOOTSTRAP_UNSTABLE`）。NA 行不携带估计值。这是核心不变量——不要对 metric 输出 0 或 None-as-zero。

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

