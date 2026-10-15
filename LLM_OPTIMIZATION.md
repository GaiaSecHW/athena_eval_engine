# LLM 调用梳理与优化

> 逐个梳理所有活跃的 LLM 调用点，完成一个打一个钩。

## 总览

共 **8 个活跃 LLM 调用点**（已删除 #5/#6，合并到 #7-#11 统一层；已删除 4 个死代码）。**全部优化完成 ✅**

| 编号 | 阶段 | 文件:行号 | 函数 | 用途 | 调用频率 | 类型 | 状态 |
|------|------|-----------|------|------|----------|------|------|
| 1 | INGEST | `evaluation_service.py:266` | `_ai_extract_source_info` | 从漏洞描述提取 source_file/function/line | 每个缺失 source 的 case 1 次 | 直接有效 | ✅ 已优化 |
| 2 | PARSING | `argo_trace_parser.py:706` | `_extract_accepted_payloads` | 正则解析失败后用 LLM 从文本提取 JSON payload | 每个 verify session 最多 1 次（仅前两种策略失败时） | 直接有效 | ✅ 已优化 |
| 3 | PARSING | `ai_matcher.py:128` | `match_alert_center_to_findings` 预筛选 | 告警中心 case vs 全部 finding，返回候选 ID | 每个告警中心 case 1 次 | 直接有效 | ✅ 已优化 |
| 4 | PARSING | `ai_matcher.py:191` | `match_alert_center_to_findings` 1vs1 | 告警中心 case vs 候选 finding 详细对比 | 每对 (case, 候选) 1 次 | 直接有效 | ✅ 已优化 |
| ~~5~~ | ~~PARSING~~ | ~~`sink_matcher.py`~~ | ~~`_compress_session_actions`~~ | ~~压缩 session 工具调用序列~~ | — | — | ❌ 已删除（合并到 #7-#10 统一压缩层） |
| ~~6~~ | ~~PARSING~~ | ~~`sink_matcher.py`~~ | ~~`analyze_chain_llm`~~ | ~~LLM 判断 is_mining + matched_finding_idx~~ | — | — | ❌ 已删除（confusion 改为确定性，分析合并到 #11） |
| 7-10 | REPORTING | `report_assembler.py:920/1033` | `_compress_one` / `_compress_batch` | 统一压缩层：逐 session 压缩 → 分段 → 合并 → 批量再压缩 | 每个 uncached session 1 次（有缓存） | 中间产物→#11 | ✅ 已优化 |
| 11 | REPORTING | `report_assembler.py:1122` | `_run_llm` 主分析 | 统一分析层：挖掘过程总结 + KG 归因分析 | 每个非 fast-path 的 case 1 次 | 直接有效 | ✅ 已优化 |
| 12 | REPORTING | `fpr_analysis.py:112` | `_llm_match_batch` 1vs1 | 基线 vs 单条 finding 判断是否同一漏洞 | 每对 1 次 | 直接有效 | ✅ 已优化 |
| 13 | REPORTING | `fpr_analysis.py:161` | `_llm_match_batch` 批量 | 基线 vs 多条 finding 批量找出匹配 | 每批 1 次（超限时减半到 1vs1） | 直接有效 | ✅ 已优化 |

## 耗时分布

| 场景 | 典型调用次数 | 单次耗时 | 总耗时占比 |
|------|-------------|----------|------------|
| #1 source 提取 | ~数十次 | 短 | 低 |
| #2 Argo JSON 兜底 | 少量 | 中 | 低 |
| #3-#4 AC 匹配 | 数十~上百次 | 中 | 中 |
| #7-#10 统一压缩层 | session 数（有缓存） | 中~长 | 中 |
| #11 KG 主分析 | case 数（并发 kg_analysis_workers） | 很长 | **最高** |
| #12-#13 FPR 匹配 | 数十次 | 中 | 中 |

## 优化记录

### #1 source 提取（INGEST）— ✅ 已完成

**问题**：漏洞中心 API 返回的 `subject.locator` 字段已包含结构化 sink 信息（`path:func:line` 格式），但 `_case_to_benchmark` 未解析，直接把整个 locator 字符串赋给 `source_file`，`source_function` 用错误的 basename+splitext 猜，`source_line` 始终为空。导致所有漏洞中心 case 都触发 `_fill_missing_source` → LLM 调用。

**修复**：`vuln_center_client.py` 新增 `_parse_locator` 函数，用 `rsplit(":", 2)` 从右向左解析 locator，支持以下格式：
- `path/to/file.c` → 仅文件路径
- `path/to/file.c:func_name` → 文件+函数
- `path/to/file.c:func_name:414` → 文件+函数+行号
- `path/to/file.c:func_name:414-420` → 文件+函数+行号区间（取起始行号）
- `path/to/file.c:414` → 文件+行号
- `path/to/file.c:414-420` → 文件+行号区间

**效果**：locator 完整的 case 不再触发 LLM 调用。locator 不完整的 case（如仅文件路径）仍走 LLM fallback，但 LLM prompt 中包含原始 locator 字符串作为 sink 点位置提示，提高提取准确率。

**文件**：`athena_eval_engine/infrastructure/vuln_center_client.py` — 删除 `_extract_function_name`，新增 `_parse_locator`，更新 `_case_to_benchmark`

---

### #3+#4 告警中心匹配（PARSING）— ✅ 已完成

**问题**：
1. **#4 串行瓶颈**：Phase 2 的 1vs1 对比按 AC case 串行处理（一对一约束），每个 case 内候选并行。100 个 case = 100 轮串行，每轮等 LLM 返回才能进下一个 case。
2. **匹配结果误用**：匹配上的 finding 被 AC 的 `validation_result` 覆盖，未匹配的 AC case 作为兜底 finding 加入列表 → 影响 TP/FP/FN/TN 指标计算。但匹配的真正目的只是建立 AC case ↔ finding 的关联，用于报告展示漏洞挖掘发现过程。

**修复**：
1. **#4 全量并行 + 串行冲突解决**：所有 (AC case, 候选 finding) 对一次性并行提交（max_workers=20），LLM 调用结果全部回来后，按 AC case 顺序串行分配（先到先得，一对一约束）。LLM 调用次数不变，每次 prompt 不变（1vs1），准确率不变，但墙钟时间从 M 轮串行降到 1 轮并行。
2. **#3 并发降低**：预筛选 ThreadPoolExecutor 从 max_workers=50 降到 20，与 #4 一致。
3. **匹配结果只建关联**：Step 3 只记 `ac_case_id`，不改 `validation_result`。Step 4（兜底 finding）删除。指标计算只用 agent 自己上报的 finding。

**文件**：
- `athena_eval_engine/workers/ai_matcher.py` — Phase 2 改为全量并行 + 串行冲突解决；#3 和 #4 的 max_workers 从 50 降到 20
- `athena_eval_engine/application/evaluation_service.py` — 删除 Step 3 的 `validation_result` 覆盖和 Step 4 的兜底 finding；`_analyze_count` 改为基于 agent 自己的 finding 数

---
### #2 Argo JSON 兜底（PARSING）— ✅ 已完成

**问题**：`_extract_accepted_payloads` 的策略 1（```json 块）和策略 2（关键词+花括号匹配）解析失败时直接走 LLM 兜底。但这两个策略的 JSON 解析能力不足——`_try_parse_json_lenient`（花括号补全）只被 Argo parser 用了，其他 parser（Turing/SecMate/CVulnVerify/Dataflow）解析失败直接 `pass` 丢数据。

**修复**：在 `parse_utils.py` 新增两个共享函数，推广到所有 JSON 解析点：

1. **`parse_json_lenient(text)`** — 单个 JSON 对象，三层递进：`json.loads` → `raw_decode`（容忍尾部内容）→ 花括号补全（修复截断）
2. **`extract_json_payloads(text, keywords)`** — 从文本提取多个 JSON：```json 块 → 关键词+花括号匹配 → 裸 `raw_decode`

**迁移的文件**（7 个）：
| 文件 | 修改 |
|---|---|
| `argo_trace_parser.py` | 删除 `_try_parse_json_lenient`（40 行），`_extract_accepted_payloads` 策略 2 改用 `extract_json_payloads`（删除 70 行手写花括号匹配） |
| `cvuln_verify_trace_parser.py` | `_parse_verdict_json` 策略 1+2 合并为 `parse_json_lenient`（删除 15 行） |
| `turing_trace_parser.py` | `_part_to_event` 用 `parse_json_lenient` 替代 `json.loads`（增加 `raw_decode`+花括号补全），`_extract_finding_params_from_cmd` 和 `_normalize_submit_artifact` 也迁移 |
| `resolvers.py` | 3 处迁移：DataflowVulnScan TEXT 用 `extract_json_payloads`，Argo TOOL_RESULT 和 CVulnVerify write 用 `parse_json_lenient` |
| `report_assembler.py` | 4 处迁移：3 个 SecMate 块 + CVulnVerify write content + `_parse_kg_command` |
| `secmate_trace_parser.py` | payload 解析用 `parse_json_lenient` |
| `dataflow_trace_parser.py` | 3 处 `_extract_json_objects_from_text` 升级为 `extract_json_payloads`（增加花括号补全 + 关键词匹配） |

**效果**：
- Argo parser 的 LLM 兜底触发频率降低（策略 1+2 的 JSON 解析能力增强，更多 case 在走 LLM 前就能解析成功）
- 其他 parser 之前 `json.loads` 失败直接 `pass` 丢数据，现在有 `raw_decode` + 花括号补全兜底，减少数据丢失

---

### #7-#10 统一压缩层（REPORTING）— ✅ 已完成

**问题**：旧 #5（`sink_matcher._compress_session_actions`）和旧 #6（`sink_matcher.analyze_chain_llm`）各自独立压缩 session、独立调 LLM 判断 is_mining，调用频率高（基线数 × 链数 × 2 条件），且 #6 的 LLM 判定结果已被确定性 confusion 逻辑替代。

**修复**：删除 #5/#6（`sink_matcher.py` 中已无 `_compress_session_actions` / `analyze_chain_llm`），在 `report_assembler.py` 新增统一压缩层：

1. **`_compress_one`（L920）**：逐 session 压缩，统一 system prompt（L903-917），输出 `{"session_id", "mining_summary", "knowledge_queries", "key_actions"}`。
   - 单 session 过大时分段压缩（`_SEGMENT_CHAR_LIMIT=60000`），各段独立调 LLM，再合并（L929-969）。
   - 合并 prompt 也统一输出 `mining_summary`（L958-966）。
   - 结果缓存到 `_session_compress_cache`，跨 case 复用（L971/974/978）。
2. **`_compress_batch`（L1033）**：压缩后仍超限时，分批聚合再压缩，统一 prompt（L1000-1009），输出 `mining_summary`。
   - 多轮循环直到 fit（L1011-1055）。
3. 并行执行：ThreadPoolExecutor，worker 数从 `get_runtime_workers()["kg_analysis"]` 获取（L983-988, L1046-1052）。

**效果**：
- #5/#6 删除 → LLM 调用次数减少（confusion 改为确定性，is_mining 判定不再调 LLM）
- 统一 prompt → 所有压缩输出格式一致，可直接作为 #11 的输入
- 缓存复用 → 同一 session 在多个 case 中只压缩一次

**文件**：`athena_eval_engine/application/report_assembler.py` L900-1055

---

### #11 主分析层（REPORTING）— ✅ 已完成

**问题**：主分析（`_run_llm`）的 prompt 需要接收 #7-#10 压缩层产出的 `mining_summary` 作为输入，用于 KG 归因分析的挖掘过程描述。

**修复**：
1. `data["mining_actions"]` 存储 #7-#10 的压缩结果（L989），每条包含 `mining_summary`、`knowledge_queries`、`key_actions`。
2. 主分析 prompt（L1062-1098）描述 `mining_actions` 字段："完整挖掘过程（sink 匹配链上行为）。数据量大时已按会话压缩，每条包含：挖掘过程摘要、知识/记忆问答记录、关键操作列表"。
3. `_run_llm`（L1122）并行执行主分析，输出 `{"kg_judgment", "query_summary", "knowledge_summary", "impact", "reason"}`，并附加 `interactions`、`sink_analysis`、`knowledge_intervention` 等结构化字段。
4. LLM 不可用时规则降级（L1140-1159）。

**效果**：
- 主分析直接使用压缩层产出的 `mining_summary`，无需重复压缩
- 挖掘过程描述从原始工具调用序列（可能数万行）压缩到 ≤2000 字摘要，fit 进 LLM context

**文件**：`athena_eval_engine/application/report_assembler.py` L1062-1180

---

### 附：fpr_analysis.py 死代码清理

**问题**：`_get_baseline_path()` 和 `load_baseline()` 两个函数从基线 CSV 时代遗留，基线数据已改为从 `case_details`（benchmark_item 表）获取，这两个函数无任何调用方。

**修复**：删除 `_get_baseline_path()`、`load_baseline()`、`import csv`、`import os`，更新模块 docstring 去掉"基线 CSV"引用。

**文件**：`athena_eval_engine/application/fpr_analysis.py`

---

### 附：sink_matcher.py ac_case_id 传播修复

**问题**：`sink_match_baselines` 构建 `case_results` 时没有从 finding 拷贝 `ac_case_id` 字段，导致报告渲染器读 `c.ac_case_id` 一直是空值。这是 #3/#4 匹配结果用途变更后暴露的预先存在 bug — 之前 AC 匹配覆盖 `validation_result` 时不需要传播 `ac_case_id`。

**修复**：在 matched case_result 中添加 `"ac_case_id": f.get("ac_case_id", "")`。

**文件**：`athena_eval_engine/workers/sink_matcher.py`

---

### #12+#13 FPR 匹配（REPORTING）— ✅ 已完成

**核心逻辑**：baseline 漏洞描述 ↔ AC case 漏洞描述的 LLM 匹配是核心，确认是同一个漏洞。传递链 `baseline → (sink_match) → agent_finding → (#3/#4 ac_case_id) → AC case` 是补充，用户自行实现。

**问题**：
1. 漏洞中心 FPR 和告警中心 FPR 分别独立跑 LLM 匹配，但漏洞中心 case ID 是告警中心的真子集（case ID 一致），独立匹配导致结果可能不一致。
2. LLM 匹配结果只存在内存中，后续环节无法复用。

**修复**：
1. **只跑一次告警中心 LLM 匹配**：`run_fpr_analysis(source="alert_center")` 拿到全部告警中心 case 的 LLM 匹配结果。
2. **漏洞中心 FPR 从告警中心结果派生**：`derive_fpr_from_subset(_ac_result, _vc_ids)` 按 case ID 从告警中心结果中筛选子集，保证一致性。无需独立 LLM 匹配。
3. **结果持久化到文件**：FPR 匹配结果（含 match_details + vc_ids）写入 `{evaluation_id}_fpr_match.json`，供后续环节（传递链等）使用。
4. **文件不被报告瘦身删除**：瘦身阶段只删 `_cr.json` 临时文件，`_fpr_match.json` 持久保留。

**文件格式**：
```json
{
  "fpr": 0.12, "matched": 6, "fp": 1, "tp": 5, "total_findings": 50, "total_baseline": 10, "match_details": [...], "vc_ids": ["case-id-1", "case-id-2"]
}
```

**效果**：
- 漏洞中心 LLM 匹配调用次数 → 0（从告警中心结果按 case ID 筛选派生）
- 告警中心 LLM 匹配保持不变（N×ceil(M/5) 批调用）
- 结果一致性保证：漏洞中心是告警中心的子集，case ID 一致
- 后续环节可直接读取 `_fpr_match.json` 获取匹配结果

**文件**：
- `athena_eval_engine/application/evaluation_service.py` — FPR 分析后将 `_ac_fpr_result` + `vc_ids` 写入 `{evaluation_id}_fpr_match.json`

---
