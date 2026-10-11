# L7 判定基线漏洞信息数据来源分析

> 本文确认 L7 方向一致性 + 知识正确性判定（Prompt 5）所需基线漏洞信息的数据来源，基于代码搜索结果分析。

---

## 1. L7 Prompt 需要的基线字段清单

根据 `docs/llm-prompts.md` Prompt 5 的 User 输入模板，L7 判定需要以下 5 个基线字段：

| 字段 | 模板变量 | 用途 |
|------|----------|------|
| 漏洞类型 | `{baseline_vuln_type}` | 判断知识描述的漏洞模式与基线漏洞类型是否一致 |
| Source | `{baseline_source}` | 判断知识指向的注入入口与基线 source 是否匹配 |
| Sink | `{baseline_sink}` | 判断知识指向的 sink 函数与基线 sink 是否匹配 |
| 文件 | `{baseline_file}` | 判断知识指向的代码位置与基线文件是否匹配 |
| 描述 | `{baseline_description}` | 综合对比知识内容与基线漏洞的完整描述 |

---

## 2. 现有数据源分析

### 2.1 BenchmarkItem 结构

**定义位置**：`athena_eval_engine/domain/task_run.py` 第 8-14 行

```python
class BenchmarkItem:
    benchmark_item_id: str
    benchmark_set_id: str
    task_id: str
    expected_label: ExpectedLabel | None
    target_finding_id: str | None = None
    metadata: dict | None = None  # case 详情
```

**metadata_json** 存储在 `benchmark_item` 表的 `metadata_json` 列（`schema.sql` 第 62-71 行）。写入时传入的是完整的 `case_details` dict（`evaluation_service.py` 第 1172-1175 行调用 `fact_repo.insert_benchmark_item`，`metadata_json=cd`）。

**metadata 实际包含的字段**（`evaluation_service.py` 第 995-1003、1025-1033 行）：

| 字段 | 来源 | 说明 |
|------|------|------|
| `description` | vuln_center: `_normalize_case_description(c)` / vbench: findings 的 `explanation` 拼接 | 漏洞完整描述 |
| `vulnerability_type` | vuln_center: `c.get("title")` 或 `subject.get("type")` / vbench: `c.get("vulnerability_type")` 或 `c.get("category")` | 漏洞类型 |
| `target_finding_id` | `c.get("source_task").get("finding_id")` | 关联的 finding ID |
| `expected_label` | VULNERABLE / NON_VULNERABLE | 基线标签 |
| `source_file` | 见下文分析 | **实质是 sink 点文件路径** |
| `source_function` | 见下文分析 | **实质是 sink 点函数名** |
| `source_line` | 见下文分析 | **实质是 sink 点行号** |
| `locator` | vuln_center: `subject.locator` | 漏洞中心 sink 点位置字符串 |

> **关键发现**：BenchmarkItem 的 metadata **不包含独立的 `source`（注入入口）字段**。`source_file`/`source_function`/`source_line` 三个字段名字含 "source"，但实际存储的是 **sink 点**信息（文件路径、函数名、行号），不是注入入口 source。

### 2.2 vuln_center_client.py 的基线数据获取

**定义位置**：`athena_eval_engine/infrastructure/vuln_center_client.py`

`_case_to_benchmark()` 函数（第 318-333 行）将漏洞中心 case 归一为基线结构：

```python
def _case_to_benchmark(c: dict, expected_label: str) -> dict:
    subject = c.get("subject") or {}
    locator = subject.get("locator") or ""
    source_file, source_function, source_line = _parse_locator(locator)
    return {
        "case_id": c.get("id") or "",
        "vulnerability_type": c.get("title") or subject.get("type") or "",
        "description": _normalize_case_description(c),
        "target_finding_id": (c.get("source_task") or {}).get("finding_id"),
        "expected_label": expected_label,
        "source_file": source_file,
        "source_function": source_function,
        "source_line": source_line,
        "locator": locator,
    }
```

`_parse_locator()` 函数（第 279-315 行）解析 `subject.locator` 字符串：
- 格式 `path/to/file.c:func_name:414` → (file, func, line)
- **locator 代表漏洞所在位置（sink 点），不是注入入口 source**

**漏洞中心 case 提供的字段**：
- `title` — 漏洞标题（→ `vulnerability_type`）
- `summary` / `display_summary` — 漏洞摘要
- `human_confirmation.summary` — 人工确认摘要
- `latest_human_decision.reason` — 人工判定理由
- `raw_report_summary` — 上游报告摘要
- `subject.locator` — **sink 点位置**（→ `source_file`/`source_function`/`source_line`）
- `subject.type` — 漏洞类型（备用）

**漏洞中心 case 不提供的字段**：
- 独立的 `source`（注入入口）— 漏洞中心数据没有结构化的 source 字段
- 独立的 `sink`（sink 函数名）— 只有 `locator`（位置字符串），包含文件路径和函数名

### 2.3 vbench_client.py 的基线数据获取

**定义位置**：`athena_eval_engine/infrastructure/vbench_client.py`

`_extract_source_from_traces()` 函数（第 134-157 行）从 ground_truths findings 的 traces 中提取信息：

```python
def _extract_source_from_traces(cases: list) -> None:
    """从 ground_truths findings 的 traces 中提取 source_file/source_function。
    traces[].steps[] 中 role=SINK 的 step 的 path/symbol 即漏洞所在文件和函数。
    """
    for c in cases:
        for f in (c.get("findings") or []):
            for trace in (f.get("traces") or []):
                for step in (trace.get("steps") or []):
                    if step.get("role") == "SINK":
                        source_file = step.get("path", "")
                        source_function = step.get("symbol", "")
                        source_line = str(step.get("line", "") or ...)
```

**关键事实**：
- V-Bench ground_truths 的 traces 中有 `role=SINK` 的 step，提取其 `path`/`symbol`/`line`
- **没有提取 `role=SOURCE` 的 step** — trace 中可能存在 SOURCE step，但当前代码未提取
- 提取结果存入 `source_file`/`source_function`/`source_line`，但**实质是 sink 点信息**

### 2.4 extracted_finding 表（parser 提取的 finding）

**表结构**：`schema.sql` 第 563-582 行

```sql
CREATE TABLE extracted_finding (
    finding_id          VARCHAR(256) NOT NULL,
    task_run_id         VARCHAR(64) NOT NULL,
    evaluation_id       VARCHAR(64) NOT NULL,
    platform            VARCHAR(32) NOT NULL,
    session_id          VARCHAR(512),
    verify_session_id   VARCHAR(512),
    vuln_type           TEXT,
    file                TEXT,
    severity            VARCHAR(32),
    validation_result   VARCHAR(32),
    title               TEXT,
    description         TEXT,
    source              TEXT,
    sink                TEXT,
    event_idx           INT,
    finding_json        JSON,
    created_at          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (task_run_id, finding_id)
)
```

**extracted_finding 表有独立的 `source` 和 `sink` 字段**，但这些是 Agent 提取的 finding 信息（Agent 认为的 source/sink），不是基线信息。

**各 parser 的 extract_findings() 提取逻辑**：

| Parser | source 字段来源 | sink 字段来源 |
|--------|---------------|---------------|
| ArgoTraceParser | `f.get("source")` → `_extract_file()` | `f.get("sink")` → `_extract_file()` |
| CVulnVerifyTraceParser | `vdata.get("source_file")` 或 evidence[].location | `vdata.get("function_name")` 或 `vdata.get("sink")` |
| 其他 parser | 各自从 trace 提取 | 各自从 trace 提取 |

> **extracted_finding 表存储的是 Agent 上报的 finding**，不是基线漏洞信息。其 `source`/`sink` 字段是 Agent 认为的 source/sink，不能直接用作 L7 基线对照。

### 2.5 FPR 分析中的基线数据使用

`fpr_analysis.py` 第 557-574 行构建 baseline_rows：

```python
for cid, cd in case_details.items():
    _vuln_type = cd.get("vulnerability_type", "")
    _source_file = cd.get("source_file", "") or cd.get("locator", "") or ""
    _description = cd.get("description", "") or ""
    # 基线描述：标题 + 描述 + sink 路径
    _content_parts = [f"标题: {_vuln_type}"]
    if _description:
        _content_parts.append(f"描述: {_description}")
    if _source_file:
        _content_parts.append(f"Sink: {_source_file}")
```

FPR 分析将 `source_file`（实际是 sink 点路径）用作 `baseline_sink`，进行 sink 路径校验（`_verify_sink()`）。与 L7 的用途一致——都是作为 **sink 点**使用。

### 2.6 sink_matcher.py 中的基线数据使用

`sink_matcher.py` 第 527-530 行：

```python
md = b.metadata or {}
source_file = md.get("source_file", "")
source_line = md.get("source_line", "")
source_function = md.get("source_function", "")
```

用于 `find_sink_sessions()` 检查文件读取是否覆盖基线 sink 点。字段名是 `source_file`，但用作 **sink 点文件**进行匹配。

---

## 3. 字段映射方案

### 3.1 L7 基线字段与现有数据的映射

| L7 基线字段 | 数据来源 | 获取路径 | 完整性 |
|-------------|---------|---------|--------|
| `baseline_vuln_type` | BenchmarkItem.metadata["vulnerability_type"] | benchmark_item 表 metadata_json → vulnerability_type | **完整** |
| `baseline_description` | BenchmarkItem.metadata["description"] | benchmark_item 表 metadata_json → description | **完整** |
| `baseline_file` | BenchmarkItem.metadata["source_file"] | benchmark_item 表 metadata_json → source_file | **完整**（实质是 sink 点文件） |
| `baseline_sink` | BenchmarkItem.metadata["source_function"] 或 metadata["locator"] | benchmark_item 表 metadata_json → source_function（sink 点函数名）/ locator（完整 sink 位置） | **部分完整**（函数名可能为空，locator 更完整） |
| `baseline_source` | **现有数据源不包含** | 无直接来源 | **缺失** |

### 3.2 数据获取路径

L7 判定时获取基线数据的路径：

```
benchmark_item 表
  → SELECT metadata_json FROM benchmark_item WHERE benchmark_set_id = ...
  → metadata_json 解析为 dict
  → metadata["vulnerability_type"]  → baseline_vuln_type
  → metadata["description"]         → baseline_description
  → metadata["source_file"]         → baseline_file（sink 点文件）
  → metadata["source_function"]     → baseline_sink（sink 点函数名）
  → metadata["locator"]             → baseline_sink（更完整的 sink 位置，含文件+函数+行号）
  → metadata["source_line"]         → baseline_sink 的补充（行号）
```

现有代码已有从 `benchmark_item` 表加载 metadata 的完整逻辑（`evaluation_service.py` 第 1212-1219 行 `_load_config()`），可直接复用。

---

## 4. 缺口分析和补充方案

### 4.1 缺口：baseline_source（注入入口）

**问题**：L7 Prompt 模板中有 `{baseline_source}` 字段，但现有基线数据源中**没有结构化的 source（注入入口）字段**。

- 漏洞中心 case 的 `subject.locator` 是 sink 点位置，不含注入入口
- V-Bench ground_truths traces 中可能有 `role=SOURCE` 的 step，但 `_extract_source_from_traces()` 只提取 `role=SINK`，未提取 `role=SOURCE`

**影响**：L7 判定时无法对比知识描述的注入入口与基线 source 是否匹配，影响知识正确性判断的维度一（knowledge_correct）。

### 4.2 命名歧义：source_file 实为 sink 文件

**问题**：`source_file`/`source_function`/`source_line` 字段名中的 "source" 容易误解为注入入口 source，但实际存储的是 **sink 点**信息（文件路径、函数名、行号）。

**证据**：
- `vbench_client.py` 第 134-157 行：`_extract_source_from_traces()` 只提取 `role=SINK` 的 step
- `vuln_center_client.py` 第 279-333 行：`_parse_locator()` 解析的是 `subject.locator`（漏洞位置 = sink 点）
- `fpr_analysis.py` 第 559 行：`_source_file` 直接用作 `baseline_sink` 进行 sink 校验
- `sink_matcher.py` 第 528-530 行：`source_file` 用作 sink 点文件进行 session 匹配

### 4.3 补充方案

#### 方案 A：从 V-Bench ground_truths traces 补充提取 SOURCE step（推荐）

修改 `vbench_client.py` 的 `_extract_source_from_traces()`，同时提取 `role=SOURCE` 的 step 信息：

```python
# 现有逻辑只提取 SINK：
if step.get("role") == "SINK":
    source_file = step.get("path", "")
    ...

# 补充提取 SOURCE：
if step.get("role") == "SOURCE":
    source_entry = step.get("path", "") or step.get("symbol", "")
```

写入 case 的 `source` 字段（注入入口），与 `source_file`（sink 文件）区分。

**适用场景**：benchmark_source = vbench_zip 时有效。V-Bench ground_truths 的 traces 中有 step 级 SOURCE/SINK 标注。

**局限**：漏洞中心数据（benchmark_source = vuln_center）无 traces，无法补充。

#### 方案 B：从漏洞中心 description 中用 LLM 提取 source

漏洞中心 case 的 `description`（`_normalize_case_description()` 生成的 6 段描述）中可能包含注入入口描述。在 INGESTING 阶段的 `_fill_missing_source()` 函数（已有 LLM 补提取逻辑）中，同时提取 source 入口：

```python
# 现有 _ai_extract_source_info() 返回 (source_file, source_function, source_line)
# 补充提取 source 入口：
# prompt 中增加 "注入入口（source）：" 字段
```

**适用场景**：所有数据源通用。LLM 从描述文本中提取 source。

**局限**：LLM 提取的 source 可能不准确，依赖描述文本质量。

#### 方案 C：L7 Prompt 中 baseline_source 标注为"不可用"

如果 source 信息无法从现有数据源获取，在 L7 Prompt 模板中标注：

```
Source: {baseline_source or "（基线无结构化 source 信息，请从描述中推断）"}
```

**适用场景**：短期过渡方案，不补充数据源。

**局限**：L7 判定的知识正确性维度无法完整对比注入入口。

### 4.4 命名规范建议

为避免 `source_file` 字段名歧义，建议在 L7 实现中显式重命名映射：

```python
baseline_vuln_type = metadata.get("vulnerability_type", "")
baseline_description = metadata.get("description", "")
baseline_file = metadata.get("source_file", "")  # 实为 sink 点文件
baseline_sink = metadata.get("source_function", "") or metadata.get("locator", "")  # sink 点函数/位置
baseline_source = metadata.get("source_entry", "")  # 待补充
```

---

## 5. 总结

| 维度 | 结论 |
|------|------|
| baseline_vuln_type | **已有**，从 BenchmarkItem.metadata["vulnerability_type"] 获取 |
| baseline_description | **已有**，从 BenchmarkItem.metadata["description"] 获取 |
| baseline_file | **已有**，从 BenchmarkItem.metadata["source_file"] 获取（实为 sink 点文件） |
| baseline_sink | **部分已有**，从 BenchmarkItem.metadata["source_function"] 或 metadata["locator"] 获取（sink 点函数名/位置） |
| baseline_source | **缺失**，现有基线数据源不含结构化注入入口 source 字段 |

**数据获取路径**：全部从 `benchmark_item` 表的 `metadata_json` 列获取，现有 `_load_config()` 已加载此数据，L7 实现可直接复用。

**缺口补充建议**：方案 A（从 V-Bench traces 补充提取 SOURCE step）+ 方案 B（从 description 用 LLM 提取 source）组合使用，覆盖两种数据源。
