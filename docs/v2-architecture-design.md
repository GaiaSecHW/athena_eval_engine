# v2 架构设计方案

## 1 设计目标

| 目标 | 说明 |
|------|------|
| 可扩展 | 新增 Agent parser 不影响现有 parser 和下游模块 |
| 可维护 | 每个 Agent parser 独立目录，自带工具函数，不共享代码 |
| 数据中间层 | parser → DataPack 标准化数据包 → 下游模块只依赖 DataPack |
| 老代码复用 | 有用的逻辑从老代码拷贝过来，不 import 老代码 |

## 2 目录结构

```
athena_eval_engine/v2/
├── __init__.py
├── core/                          # 核心抽象与数据模型
│   ├── __init__.py
│   ├── data_pack.py               # DataPack 标准化数据包（中间层）
│   ├── raw_event.py               # RawEvent 数据类（从老代码拷贝）
│   ├── facts.py                   # Fact 数据类（从老代码拷贝）
│   ├── enums.py                   # 枚举定义（从老代码拷贝）
│   └── interfaces.py              # Parser/Resolver/Metric 接口定义
│
├── parsers/                       # 6 个 Agent parser，各自独立
│   ├── __init__.py                # parser 注册与选择
│   ├── base.py                    # BaseParser 抽象基类
│   ├── turing/                    # TuringTraceParser
│   │   ├── __init__.py
│   │   ├── parser.py              # 主 parser 逻辑
│   │   └── utils.py               # 该 parser 专用工具函数
│   ├── argo/                      # ArgoTraceParser
│   │   ├── __init__.py
│   │   ├── parser.py
│   │   └── utils.py
│   ├── secmate/                   # SecMateTraceParser
│   │   ├── __init__.py
│   │   ├── parser.py
│   │   └── utils.py
│   ├── cvuln_verify/              # CVulnVerifyTraceParser
│   │   ├── __init__.py
│   │   ├── parser.py
│   │   └── utils.py
│   ├── webvuln_verify/            # WebVulnVerifyTraceParser
│   │   ├── __init__.py
│   │   ├── parser.py
│   │   └── utils.py
│   └── dataflow/                  # DataflowVulnScanTraceParser
│       ├── __init__.py
│       ├── parser.py
│       └── utils.py
│
├── resolvers/                     # 事实提取（从 DataPack 提取 Facts）
│   ├── __init__.py
│   ├── outcome.py                 # OutcomeResolver
│   ├── knowledge.py               # KnowledgeResolver
│   ├── tool_action.py             # ToolActionResolver
│   └── resource.py                # ResourceResolver
│
├── metrics/                       # 指标计算（M5–M13 + M15–M21/M26）
│   ├── __init__.py
│   ├── calculator.py              # run_all_metrics 主入口
│   ├── m5_m13.py                  # 现有指标（从老代码拷贝）
│   └── m15_m26.py                 # 新增指标
│
├── lifecycle/                     # L0–L7 误报根因全链路分析
│   ├── __init__.py
│   ├── analyzer.py                # L0–L7 分析主逻辑
│   ├── case_filter.py             # 有效 case 筛选
│   └── evidence_chain.py          # L7 判定（LLM 方向一致性 + 知识正确性）
│
├── causal_chain/                  # 因果链分析
│   ├── __init__.py
│   └── analyzer.py                # 交叉归因矩阵 + M26
│
├── knowledge_inventory/           # 知识盘点
│   ├── __init__.py
│   └── inventory.py               # 覆盖度 + 质量判定
│
├── pipeline/                      # Pipeline 编排
│   ├── __init__.py
│   ├── orchestrator.py            # 主编排逻辑（替代 evaluation_service.py）
│   ├── state_machine.py           # 状态机（从老代码拷贝 + 扩展）
│   └── stages.py                  # 各阶段定义
│
├── report/                        # 报告生成
│   ├── __init__.py
│   └── assembler.py               # 报告组装
│
├── infra/                         # 基础设施（从老代码拷贝）
│   ├── __init__.py
│   ├── database.py                # MySQL 短连接 + 重试
│   ├── llm.py                     # LLM 客户端
│   ├── concurrency.py             # 并发控制
│   ├── parallel.py                # iter_completed + cancel_cb
│   ├── migrations.py              # schema 迁移
│   └── agent_db.py                # Agent 数据库连接管理（读取 agent_datasource_config 表，连接池+短连接重试）
│
└── api/                           # FastAPI 端点
    ├── __init__.py
    ├── routes.py                  # 评测 API + 报告 API
    └── datasources.py             # Agent 数据源配置 CRUD + 测试连接
```

## 3 数据中间层：DataPack

```python
@dataclass
class DataPack:
    """标准化数据包——parser 输出，下游模块的统一输入。

    parser 负责填充全部字段，下游模块只消费 DataPack，不直接调用 parser。
    """
    # 标识
    task_run_id: str
    evaluation_id: str
    task_id: str
    agent_type: str                    # turing/argo/secmate/cvuln_verify/webvuln_verify/dataflow
    condition: str                     # KG / UNKNOWN

    # 原始数据
    events: list[RawEvent]             # 规范事件序列
    findings: list[dict]               # parser 提取的漏洞 finding
    session_graph: dict                # session 关系图（parent_id 边）
    session_meta: dict                 # session 元数据（token/step/time）

    # session 阶段标注（业务阶段归类，详见 docs/agent-session-phase-classification.md）
    session_phase_labels: dict[str, str]   # session_id → 业务阶段（第一层+第二层程序标注）
    session_phase_source: dict[str, str]   # session_id → 标注来源标识符（task_type/agent_name/persona/analysisType/worker_type/tool_name）

    # Facts（resolver 从 events 提取）
    outcome_fact: OutcomeFact | None
    knowledge_fact: KnowledgeInteractionFact | None
    tool_action_fact: ToolActionFact | None
    resource_fact: ResourceFact | None

    # 基线
    benchmark_item: BenchmarkItem | None
```

### 3.1 数据流

```
Trace Source (SQLite/JSONL)
    │
    ▼
Parser.parse() → list[RawEvent]
Parser.extract_findings() → list[dict]
Parser.build_session_graph() → dict
Parser.load_session() → dict
    │
    ▼
Resolver.resolve(events/...) → 4 个 Fact
    │
    ▼
DataPack(events, findings, session_graph, session_meta, 4 facts, benchmark)
    │
    ├──→ metrics/calculator.py      → M5–M13, M15–M21, M26
    ├──→ lifecycle/analyzer.py      → knowledge_access_detail[]
    ├──→ causal_chain/analyzer.py   → 交叉归因矩阵
    ├──→ knowledge_inventory/       → 覆盖度 + 质量清单
    └──→ report/assembler.py        → 报告 JSON + HTML
```

### 3.2 为什么 DataPack 是中间层

| 问题 | 老代码 | v2 |
|------|--------|-----|
| 下游模块直接依赖 parser | `sink_matcher` 调 `parser.build_session_graph()` | 下游只读 `DataPack.session_graph` |
| resolver 内嵌 6 平台逻辑 | `OutcomeResolverImpl._latest_validation()` 检查全部 6 个平台的工具名 | parser 在 `extract_findings()` 中完成平台特定逻辑，resolver 只消费标准化 events + findings |
| parser 变更影响下游 | 改 parser 可能影响 resolver/metrics | parser 只负责填充 DataPack，改 parser 不影响下游 |
| 新增 parser | 需改 `_get_parser()` + resolver 中的平台逻辑 | 在 `parsers/` 下新建目录，注册到 `parsers/__init__.py`，下游不变 |

## 4 Parser 独立设计

### 4.1 BaseParser 接口

```python
class BaseParser(ABC):
    """所有 parser 的抽象基类。"""

    @property
    @abstractmethod
    def agent_type(self) -> str:
        """返回 agent 类型标识。"""

    @abstractmethod
    def parse(self, trace_source: str) -> list[RawEvent]:
        """解析 trace，返回规范事件序列。"""

    @abstractmethod
    def extract_findings(self, events: list[RawEvent]) -> list[dict]:
        """从事件中提取漏洞 finding。"""

    @abstractmethod
    def build_session_graph(self, events: list[RawEvent]) -> dict:
        """构建 session 关系图。"""

    @abstractmethod
    def load_session(self, trace_source: str) -> dict:
        """加载 session 元数据（token/step/time）。"""

    @abstractmethod
    def label_session_phases(self, events: list[RawEvent], session_meta: dict) -> tuple[dict[str, str], dict[str, str]]:
        """标注 session 的业务阶段。

        返回 (session_phase_labels, session_phase_source)。
        - session_phase_labels: session_id → 业务阶段名称（第一层+第二层程序标注）
        - session_phase_source: session_id → 标注来源标识符

        各 parser 实现自己的标识符提取 + 规则映射：
        - ArgoParser: JSONL prompt 标题 → task_type → 业务阶段
        - TuringParser: MySQL turing_task 表 → agent_name → 业务阶段
        - SecMateParser: JSONL trace persona 名 → 业务阶段
        - DataflowVulnScanParser: JSONL 文件名 analysisType → 业务阶段
        - CVulnVerifyParser: PostgreSQL vuln_verify_attempt 表 → worker_type → 业务阶段
        - WebVulnVerifyParser: JSONL trace 工具名序列 → 业务阶段

        详见 docs/agent-session-phase-classification.md。
        """

    def build_data_pack(self, trace_source: str, task_run: TaskRun) -> DataPack:
        """完整解析，返回 DataPack。模板方法——子类不覆盖。"""
        events = self.parse(trace_source)
        findings = self.extract_findings(events)
        session_graph = self.build_session_graph(events)
        session_meta = self.load_session(trace_source)
        phase_labels, phase_source = self.label_session_phases(events, session_meta)

        # resolver 从 events 提取 facts
        outcome = OutcomeResolver().resolve(task_run, events, findings)
        knowledge = KnowledgeResolver().resolve(task_run, events)
        tool_action = ToolActionResolver().resolve(task_run, events)
        resource = ResourceResolver().resolve(task_run, session_meta)

        return DataPack(
            task_run_id=task_run.task_run_id,
            evaluation_id=task_run.evaluation_id,
            task_id=task_run.task_id,
            agent_type=self.agent_type,
            condition=task_run.condition,
            events=events,
            findings=findings,
            session_graph=session_graph,
            session_meta=session_meta,
            session_phase_labels=phase_labels,
            session_phase_source=phase_source,
            outcome_fact=outcome,
            knowledge_fact=knowledge,
            tool_action_fact=tool_action,
            resource_fact=resource,
            benchmark_item=task_run.benchmark_item,
        )
```

### 4.2 每个 parser 独立目录

每个 parser 目录包含：
- `parser.py` — 主逻辑（继承 BaseParser）
- `utils.py` — 该 parser 专用的工具函数（JSON 修复、路径解析、格式检测等）

**不共享 `parse_utils.py`**。每个 parser 自带需要的工具函数。如果多个 parser 需要相同函数（如 `parse_json_lenient`），各自拷贝一份。

### 4.3 Session 阶段标注实现

每个 parser 的 `label_session_phases()` 方法实现三层标注架构的第一层+第二层（程序确定性部分），第三层 LLM 细分由 lifecycle 分析模块在 `build_data_pack()` 之后统一执行。

| Parser | `label_session_phases()` 实现 | 标识符来源 | 规则映射 |
|--------|------------------------------|-----------|---------|
| ArgoParser | 读 JSONL 第一行 prompt 标题提取 `task_type`，或查 MySQL `argo_c.intents` 表 | `task_type`（bootstrap/investigate/verify/reason） | bootstrap→入口识别+数据流追踪；investigate→跨3阶段（需 LLM）；verify→漏洞判定与上报；reason→不属于5阶段 |
| TuringParser | 查 MySQL `turing_app_security.turing_task` 表 `agent_session_id → agent_name + task_type` | `agent_name`（vuln-hunt-mine/web-detect/web-validate 等） | strategy→入口识别；detection→入口识别+数据流追踪；mining/deep_mining→跨3阶段（需 LLM）；validation→漏洞判定与上报；preprocess→不属于5阶段 |
| SecMateParser | 从 JSONL trace 提取 agent prompt 标题中的 persona 名 + `store_finding` 的 level 参数 | persona 名（architect/flow-tracer/specialist 等） | 16 个 persona 各自映射（见调研文档 §3.3）；explorer/distiller/report→不属于5阶段 |
| DataflowVulnScanParser | 从 JSONL 文件名解析 `analysisType` 字段 | `analysisType`（taint/track/fptrack/vuln-judge 等） | taint/track/fptrack→数据流追踪；vuln-judge→漏洞判定与上报；vuln-pattern-enhancement→漏洞模式识别 |
| CVulnVerifyParser | 查 PostgreSQL `secflow_vuln_verify_v2.vuln_verify_attempt` 表 `attempt_id → worker_type` | `worker_type`（source-verifier/c-formal-verifier/binary-instrumentation-poc） | source-verifier→跨3阶段（需 LLM）；c-formal-verifier/binary-instrumentation-poc→验证执行 |
| WebVulnVerifyParser | 从 JSONL trace 提取 `tool_call.name` 序列 | 工具名（vulnerability_analyze/verify/cvss） | vulnerability_analyze→漏洞理解+代码定位（需 LLM）；vulnerability_verify/cvss→判定上报；read/bash/grep→验证执行 |

**第三层 LLM 细分**（在 lifecycle 分析模块中执行）：

对 `session_phase_labels` 中值为多个阶段（含"+"连接）的 session，lifecycle 分析模块从 REASONING 事件提取推理上下文，用 LLM 细分到单一阶段。LLM 细分结果回写 `session_phase_labels`。

### 4.4 Parser 注册与选择

```python
# parsers/__init__.py
from .turing import TuringParser
from .argo import ArgoParser
from .secmate import SecMateParser
from .cvuln_verify import CVulnVerifyParser
from .webvuln_verify import WebVulnVerifyParser
from .dataflow import DataflowVulnScanParser

PARSER_REGISTRY = {
    "turing": TuringParser,
    "argo": ArgoParser,
    "secmate": SecMateParser,
    "cvuln_verify": CVulnVerifyParser,
    "webvuln_verify": WebVulnVerifyParser,
    "dataflow": DataflowVulnScanParser,
}

def get_parser(trace_kind: str | None, source_uri: str) -> BaseParser:
    """根据 trace_kind 或路径推断选择 parser。"""
    ...
```

## 5 Resolver 解耦设计

### 5.1 OutcomeResolver 去平台化

老代码的 `OutcomeResolverImpl._latest_validation()` 把 6 个平台的工具名硬编码在一个方法里。v2 改为：

- parser 在 `extract_findings()` 中完成平台特定的 finding 提取（已有逻辑）
- parser 在 `parse()` 中设置 `is_finding_submission` flag（已有逻辑）
- OutcomeResolver 只消费标准化的 `is_finding_submission` events + findings 列表，不检查平台特定工具名

```python
class OutcomeResolver:
    def resolve(self, task_run: TaskRun, events: list[RawEvent],
                findings: list[dict]) -> OutcomeFact:
        """从 events + findings 提取判定结果。不依赖平台特定工具名。"""
        # 从 is_finding_submission=True 的事件中提取 validation_result
        # 从 findings 列表中读取 verdict/status
        # 不检查 "vuln-hunt_update_finding" / "vulnerability_verify" 等平台工具名
```

### 5.2 KnowledgeResolver / ToolActionResolver / ResourceResolver

这三个 resolver 已经是平台无关的（只依赖 RawEvent 的 flag），直接从老代码拷贝，去掉对 `parse_utils` 的依赖。

## 6 Pipeline 编排

### 6.1 阶段定义

```
INGESTING → PARSING → RESOLVING → PAIRING → CALCULATING
    → INVENTORY → LIFECYCLE_ANALYSIS → CAUSAL_CHAIN → REPORTING → FINALIZE
```

注意：v2 将 AI_MATCHING 合并到 PARSING 阶段（sink-point 匹配在 parser 的 build_data_pack 中完成），FPR 仍在 INGESTING 后并行运行。

### 6.2 Orchestrator

```python
class Orchestrator:
    def run(self, evaluation_id: str):
        # INGESTING
        benchmark_items = self._ingest(evaluation_id)

        # PARSING（并行）
        data_packs = self._parse_traces(evaluation_id, benchmark_items)

        # RESOLVING（已在上一步完成，此处写 DB）
        self._persist_facts(data_packs)

        # PAIRING + CALCULATING
        pairs = self._pair(data_packs)
        metrics = self._calculate_metrics(pairs, data_packs)

        # INVENTORY
        inventory = self._run_inventory(evaluation_id)

        # LIFECYCLE_ANALYSIS
        access_details = self._run_lifecycle(data_packs, benchmark_items)

        # CAUSAL_CHAIN
        causal_matrix = self._run_causal_chain(access_details)

        # REPORTING
        self._assemble_report(evaluation_id, metrics, inventory, access_details, causal_matrix)

        # FINALIZE
        self._finalize(evaluation_id)
```

### 6.3 状态机

从老代码拷贝 `state_machine.py`，新增 3 个状态（INVENTORY / LIFECYCLE_ANALYSIS / CAUSAL_CHAIN），恢复路径与现有模式一致。

## 7 老代码复用清单

| 老代码文件 | v2 位置 | 复用方式 |
|-----------|---------|---------|
| `domain/raw_event.py` | `v2/core/raw_event.py` | 整体拷贝（RawEvent dataclass + detect_memory_flags + usage_numbers） |
| `domain/facts/__init__.py` | `v2/core/facts.py` | 整体拷贝（5 个 Fact 类 + Evidence） |
| `domain/enums.py` | `v2/core/enums.py` | 整体拷贝 |
| `domain/statistics/engine.py` | `v2/metrics/` 或独立模块 | 整体拷贝（bootstrap/Wilson/Wilcoxon） |
| `workers/parse_utils.py` | 各 parser 的 `utils.py` | 按需拷贝：每个 parser 只拷贝自己用到的函数 |
| `workers/resolvers.py` | `v2/resolvers/*.py` | 拆分拷贝 + 去平台化改造 |
| `infrastructure/llm.py` | `v2/infra/llm.py` | 整体拷贝 |
| `infrastructure/database.py` | `v2/infra/database.py` | 整体拷贝 |
| `infrastructure/concurrency.py` | `v2/infra/concurrency.py` | 整体拷贝 |
| `infrastructure/parallel.py` | `v2/infra/parallel.py` | 整体拷贝 |
| `infrastructure/migrations.py` | `v2/infra/migrations.py` | 拷贝 + 新增迁移条目 |
| `orchestration/state_machine.py` | `v2/pipeline/state_machine.py` | 拷贝 + 扩展 3 个新状态 |
| `domain/metrics/__init__.py` | `v2/metrics/m5_m13.py` | 拷贝现有 M5–M13 计算逻辑 |

## 8 新增模块（本次测评）

| 模块 | v2 位置 | 说明 |
|------|---------|------|
| L0–L7 分析 | `v2/lifecycle/analyzer.py` | 漏斗过滤 + LLM 批处理 + L7 判定 |
| 有效 case 筛选 | `v2/lifecycle/case_filter.py` | 从漏洞中心基线出发，FP/FN 判定 + 双匹配路径（纯代码/LLM） |
| L7 判定 | `v2/lifecycle/evidence_chain.py` | LLM 方向一致性 + 知识正确性 |
| 因果链分析 | `v2/causal_chain/analyzer.py` | 交叉归因矩阵 + M26 |
| 知识盘点 | `v2/knowledge_inventory/inventory.py` | 覆盖度 + 质量判定 |
| 新指标 | `v2/metrics/m15_m26.py` | M15–M21, M26 |
| Agent 数据源管理 | `v2/infra/agent_db.py` | 读取 agent_datasource_config 表，连接各 Agent DB（MySQL/PostgreSQL），短连接+重试 |
| 数据源配置 API | `v2/api/datasources.py` | CRUD + 测试连接，密码脱敏，_version 版本控制 |

## 9 与老代码的共存策略

- v2 和老代码共存于同一个仓库，老代码不删除
- v2 有独立的 `__init__.py`，不 import 老代码
- v2 复用同一个 MySQL 数据库（新表 knowledge_access_detail + agent_datasource_config）
- v2 复用同一个 config.yaml / 环境变量
- v2 有独立的 API 端点前缀（`/api/v2/evaluations/` + `/api/v2/datasources/`），老端点保持不变
- 逐步迁移：v2 功能稳定后，老代码的 API 端点可以代理到 v2

## 10 可扩展性保证

| 扩展场景 | 怎么做 | 影响范围 |
|----------|--------|---------|
| 新增 Agent parser | 在 `v2/parsers/` 下新建目录，实现 BaseParser，注册到 `parsers/__init__.py` | 仅新目录 + 注册表 |
| 新增指标 | 在 `v2/metrics/` 下新增函数，注册到 `calculator.py` | 仅 metrics 目录 |
| 新增 pipeline 阶段 | 在 `v2/pipeline/stages.py` 新增阶段，更新 state_machine | 仅 pipeline 目录 |
| 新增报告段 | 在 `v2/report/assembler.py` 新增段组装逻辑 | 仅 report 目录 |
| 新增 LLM 分析模块 | 在 `v2/lifecycle/` 或新目录下新增 | 仅新目录 |
| 修改 Agent 数据源配置 | 通过配置界面 API（`/api/v2/datasources/{agent_type}` PUT）修改，或改环境变量 | 无需改代码，DB 修改后 `_version` 递增自动重载 |
