"""误报根因分析器 — 挖掘链 + 验证链各自独立压缩，最后合并输出。

对每个 FP case：
  1. 挖掘 agent session 链 → 每个 session 独立压缩 → 各自摘要 + L0-L7
  2. 验证 agent session 链 → 每个 session 独立压缩 → 各自摘要 + L0-L7
  3. 挖掘链所有 session 摘要合并 → LLM 合并压缩 → 最终根因 + 修复建议
  4. 验证链所有 session 摘要合并 → LLM 合并压缩 → 最终根因 + 修复建议

两步独立，各自有各自的 session 链、压缩过程、根因和修复建议。
session 链直接用 PARSING 阶段建好的 session_graph（parent_map），不重新构建。

独立压缩（不滚动）：
  session1 → LLM 压缩 → 摘要1 + L0-L7
  session2 → LLM 压缩 → 摘要2 + L0-L7
  ...
  sessionN → LLM 压缩 → 摘要N + L0-L7

合并压缩：
  摘要1 + 摘要2 + ... + 摘要N → LLM → 最终根因 + 修复建议 + L0-L7

不截断，不丢信息。压缩去掉冗余，保留逻辑链路。
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..infra import llm as llm_mod
from ..infra.parallel import iter_completed
from ..infra.log_util import log, log_error

# ── 输出截断重试 ──
# finish_reason=length 说明本次路由到的后端输出空间不够。网关按别名随机
# 分发后端（1M 的 DeepSeek-V4 / 204800 的 GLM），重发同一请求可能命中
# 上下文更大的后端。重试上限独立于 chat_json 内部的 JSON 修正重试。
_TRUNCATION_RETRIES = 5
_TRUNCATION_RETRY_DELAY = 3

# ── 证据卡预算（每 case 每条链）──
# 原文太大、分块压缩后证据卡可能无限增长。按 case 设总预算，
# 超出时按 fact_type 优先级保留，并记录截断数量。
_EVIDENCE_CARD_BUDGET = 300
_EVIDENCE_PRIORITY = {
    "deployment_fact": 0,
    "knowledge_access": 1,
    "agent_conclusion": 2,
    "omission": 3,
    "counter_evidence": 4,
    "repo_fact": 5,
}

# ── 系统 prompt（固定）──

_SYSTEM_PROMPT = """你是漏洞根因分析专家。你将收到一条漏洞的某个 session（漏洞挖掘或验证过程中的一个环节），以及人工标注的原因。

该漏洞可能是误报（FP，agent 报了但实际不是漏洞）或漏报（FN，agent 漏报了真实漏洞）。
用户消息中会标明 outcome=FP 或 outcome=FN。
- FP：分析 agent 为什么误报——知识访问问题、推理错误、验证维度遗漏等
- FN：分析 agent 为什么漏报——挖掘链没找到 sink 点、验证链误判为非漏洞、知识缺失导致没查到等

# 任务

## 压缩模式
将收到的 session 内容压缩为结构化摘要，保留以下信息，丢弃冗余文本：
- 推理逻辑：agent 的分析思路、判断依据
- 工具调用：调了什么工具、参数是什么、返回了什么
- 知识访问：查了知识库什么内容、返回了什么、是否被引用
- 判定结论：agent 对漏洞的判定结果

**重点保留**：知识与记忆访问的总结与影响——agent 查了什么知识/记忆、返回了什么内容、这些内容是否影响了 agent 的推理和判定。

同时，对这个 session 里的每次知识访问，执行 L0-L7 逐级判定。
如果 session 中没有知识访问断点，但存在其他导致误报的问题（如推理逻辑错误、验证不充分等），执行 L8 判定；如果"验证维度遗漏"是因为所需事实**根本没访问**，那是 L2/A，不是 L8。

# 事实依据要求

**所有分析必须基于 session 中的实际内容，禁止推测。**
- returned_content 字段：必须直接引用或概括 session 中 `[知识库返回]`/`[记忆返回]` 标记后的实际返回文本，禁止用"可能包含"、"推测"等猜测性语言描述返回内容
- query_content 字段：必须填写 agent 实际执行的查询命令或查询参数，从 `[知识库访问]`/`[记忆访问]` 标记后的文本中提取
- kb_search_query 字段：当 breakpoint=L2 或 L4 时必填，其他断点填空字符串。
  **必须是单一的方法论问题**——只问"如何/怎么验证、判断、识别、评估"某类问题，一句话一个检索意图。
  知识库里存的是方法论与漏洞模式，不是具体客户的部署现状，因此：
  * 禁止问环境事实（某端口是否暴露、某接口是否部署、某网关是否隔离、某输入是否已被上游过滤、某服务是否可达）——这类问题知识库永远答不了
  * 禁止把多个问题用逗号拼成复合查询
  * 禁止堆砌具体资产名（IP、端口、文件名、函数名），只保留问题所需的漏洞类型/场景
  * 正确示例："如何判断路径参数是否已被有效校验"
  * 错误示例："comm_mgr 的 TCP 8888 端口是否对外暴露，file_name 是否已被上游过滤"
- summary 和 key_findings 中的每一句话都必须能在 session 文本中找到对应的事实依据，禁止添加 session 中不存在的信息
- 如果知识返回内容为空或无法判断，直接写"返回内容为空"或"无法从 session 文本中确认"，不要猜测

# 压缩保留清单与证据卡（强制）

压缩不是自由摘要。你必须先在 session 原文中逐项核对下列内容，再把原文证据落成"证据卡"：

- agent 读取/执行过的文件与命令，及其与判定相关的输出
- 配置文件、默认值、部署/暴露面相关原文
- 知识/记忆访问：来源、查询、返回内容、是否被引用
- agent 的判定结论及其依据
- agent 明确跳过的检查、自相矛盾之处
- 与人工标注直接相关的事实
- 与已有结论冲突的反证

每张证据卡必须包含：
- evidence_id：本 session 内唯一（如 E-<session 前 8 位>-<序号>）
- event_idx：原文事件位置（原文每行以 `[En]` 开头，填对应的 n）
- source：文件/命令/工具
- quote：原文逐字摘录（保留完整句子，禁止转述、禁止截断）
- fact_type：repo_fact / deployment_fact / knowledge_access / agent_conclusion / omission / counter_evidence

规则：
- 原文中出现的清单项必须保留；原文没有的写"材料中未出现"，不许补。
- 找不到原文依据的内容，不得写进 summary 或假设。
- summary 只能基于证据卡，不得引入证据卡之外的信息。
- 每个 session 的证据卡数量服从全局预算；超出时优先保留 deployment_fact、knowledge_access、agent_conclusion、omission，其次 counter_evidence、repo_fact，并记录 truncated 数量。

# 知识库与记忆访问的识别

session 文本中，评测引擎已在工具调用和工具返回的文本里标记了知识访问行为：
- `[知识库访问]`：agent 通过 athena_ask MCP 工具、bash athena CLI、或 vuln_hunt_submit_knowledge 访问知识库（Athena）
- `[知识库返回]`：知识库返回的内容
- `[记忆访问]`：agent 通过 mem.sh CLI 或 cat 读 wiki .md 文件访问记忆（Memory/Wiki）
- `[记忆返回]`：记忆返回的内容

这些标记是评测引擎预处理的结果，代表 agent 实际发生了知识/记忆访问行为。
没有标记的工具调用不是知识访问（如代码搜索、文件读写、shell 命令等）。

**知识库**：Athena 知识库，存储以下类型的知识，agent 通过 athena_ask 查询：
- 漏洞挖掘模式知识（如 SQL 注入 sink 点判定）
- 误报判别方法知识（如"如何验证接口可达性"）
- 业务环境知识（如"哪些接口部署在内网、非对外暴露"）
- 部署架构约束知识（如"该系统通过 OLC 网关隔离"）
**记忆**：Wiki/记忆模块，存储以下类型的文档，agent 通过 mem.sh 或 cat 读取：
- 经验总结、最佳实践 .md
- 接口暴露面清单（哪些接口对外暴露、哪些内网隔离）
- 不可调用文档（哪些路由/接口不可从公网触达）
- 部署环境约束文档（网关/防火墙/认证门槛说明）

在 L0-L7 判定中：
- L0 来源：从标记判断是"知识库"还是"记忆"
- L2 发起访问：有 `[知识库访问]` 或 `[记忆访问]` 标记即为 true

# L0-L8 知识访问全链路判定规则

对 session 里的每次知识访问（带 `[知识库访问]`/`[记忆访问]` 标记的工具调用），逐级判定：

| 级别 | 追问 | 判定方法 | 断了是什么成因 | 责任方 |
|------|------|---------|---------------|--------|
| L0 | 知识来源？ | 从知识返回内容的来源标记判断 | —（不产生断链） | — |
| L1 | 事实是否已访问？ | 正确结论所需的事实，agent 在 trace 中是否实际访问过（读过/查过） | 未访问 → A（具体断点记在 L2） | Agent |
| L2 | 发起访问？ | agent 是否实际调用了知识库/记忆工具 | A 该查没查 | Agent |
| L3 | 查询准确？ | 查询内容是否聚焦当前任务（含具体漏洞类型/框架名/函数名等） | B 查询太泛/不聚焦 | Agent |
| L4 | 知识存在？ | 知识库是否有对应知识（返回内容非空且相关） | C 查了没得 | 知识方 |
| L5 | 成功取回？ | 返回内容是否有效（无 error/timeout/exception） | D 链路问题 | Agent + 知识方 |
| L6 | 被使用？ | agent 推理文本是否引用了知识返回内容 | E 查到没用 | Agent |
| L7 | 影响结论？ | 知识是否影响了判定结论（positive/negative/null 三种，映射见下） | F 用了没推动（L7=null 且 L6=true） / G 知识误导（L7=negative） | F: Agent, G: 知识方 |
| L8 | 其他问题？ | 知识链路全程通过（L7=positive）或 L1=false 后，agent 仍误报。分析知识访问之外的问题 | H 流程缺陷 / I 调用链中断 / J 模型幻觉 / K 验证否定真漏洞（**按实际选，不要一律填 H**） | Agent |

## L6 判定关键规则

L6 判定"agent 推理文本是否引用了知识返回内容"，判定方法：
- 在 session 的 `[推理]` 文本中搜索是否出现了知识返回内容的关键信息（如具体技术名词、建议、模式名等）
- 只有推理文本中明确引用了知识返回内容的具体信息时，L6 才为 true
- 如果 agent 只是读取了知识但推理中未提及返回内容的具体信息，L6 为 false
- **L6=false 时，returned_content 必须如实概括 `[记忆返回]`/`[知识库返回]` 后的实际文本内容，不要添加"可能包含"等推测性描述**

## L7 判定与 cause_code 映射（必须逐条填）

L7 有三种结果，各自对应的断点与 cause_code **不同**，不要一律跳到 L8：

| L7 取值 | 含义 | 是否断点 | cause_code |
|---------|------|---------|-----------|
| `positive` | 知识正确且推动了正确结论 | 不是断点 | 无（继续判 L8） |
| `negative` | 知识内容错误/过时，且影响了结论 | 断点 L7 | **G**（知识误导，责任方=知识方） |
| `null` | 知识存在但未影响结论，或结论与知识不一致 | 见下 | 见下 |

`L7=null` 时的细分（这是最容易被误判成 L8 的情况）：
- **L6=true 但结论未采纳知识** → 断点 **L7，cause_code = F**（用了没推动，责任方=agent）
- **L6=false（读了但推理未引用）** → 断点 **L6，cause_code = E**（查到没用，责任方=agent）
- 以上两种都**不是 L8**。L8 只用于「知识链路完全正常」的场景。

## 断点归属规则

断点应反映导致误报的**主要原因**。这里要区分「记录性知识访问」与「主要断点」：

- 如果 agent 读了知识但没用（L6=false），且该知识访问与人工标注的误报原因**无关**
  （如误报原因是"接口非对外暴露"，而读的是无关文档）：
  * 该次知识访问仍按 L6/E 记录在 `l0_l7` 中（这是事实，不能丢）
  * **但主要断点另起一条 L8**，cause_code 从 H/I/J/K 中选最匹配的
  * 在 L8 的 query_content 中说明"本次 L6=false 仅为记录，非误报根因"，
    并写清真正的误报原因
- 如果该知识访问与误报原因**直接相关**（如"该查没查"、"查了错误的知识"、
  "查到了但没用导致误判"），则断点就是那个知识访问级别（L2/L3/L4/L5/L6/L7），
  **不要**再另起 L8
- 判断"是否相关"的标准：知识内容是不是判断该误报所需的知识。
  需要 → 相关；不需要 → 无关（走 L8 另起）

判定规则：
- 逐级判定，不通过的级别即为断点，后续级别填 null
- **L1 判定边界（强制）**：L1 只看"正确结论所需的事实，agent 在本次 session/trace 中是否实际访问过"。
  * 已访问（读过对应文件、执行过对应命令、查过对应知识/记忆）→ L1=false，事实在材料内；后续按 L2-L7 判定是否用对，用错/漏判走 L8。
  * 未访问（材料中没有任何对应访问记录）→ L1=true，断点 L2，cause_code "A"（该查没查）。
  * **不允许**用"仓库里存在该文件"或"理论上可读"来认定已访问；只有 trace 里的实际访问记录才算。
  * 判定"未访问"时必须写明核验范围（检查了哪些 session、哪些工具调用、哪些文件），不能只写"没查到"。
  * **运行时/部署状态必须实际访问**：只有实际读取承载该事实的文件/命令才算访问。读了实际配置（如 config/config.inc.php）、环境变量、compose.yml/Dockerfile、运行中的服务状态 → 算访问；只读模板/默认值（*.dist、*.example）或从代码分支推断 → **不算访问**。若正确结论所需的是实际部署状态而材料中只有模板/推断，L1=true → L2/A。
- **session 中没有知识访问行为时的判定（关键）**：
  - 如果正确结论所需的事实未被访问 → 断点 L2，cause_code "A"
    - 在 l0_l7 数组中新增一条记录，l0_source 填空，l1_need=true，l2_initiated=false，L3-L7 填 null
    - query_content 填"agent 未访问正确结论所需的事实来源（具体说明缺什么事实、检查了哪些范围）"
    - kb_search_query 填一个面向知识库检索的**单一方法论问题**（如"如何验证网络可达性和端口开放状态"），基于 session 分析 agent 避免此误报所需的知识生成。只问方法，不问具体环境事实（端口是否暴露、接口是否部署等知识库无法回答的现状问题）
    - returned_content 填空
  - 如果所需事实已在 trace 中被访问 → L1=false，L2-L7 全部填 null；若 agent 访问了但未用对/未识别，执行 L8 判定。
- 如果 L1-L7 全部通过（L7=positive）或 L1=false（事实已访问且知识链路无问题），但 agent 仍误报，执行 L8 判定：
  - L8 断点表示知识访问链路无问题，但存在其他导致误报的原因
  - 常见场景：推理逻辑错误、验证条件不充分等（注意：验证维度遗漏只有在所需事实**已访问且用错**时才是 L8；未访问属于 L2/A，只读模板/默认值或从代码推断也算未访问）
  - **cause_code 必须从 H/I/J/K 中选最匹配的，不要一律填 H**：
    * **H** — 流程缺陷：重复上报未识别、挖掘方向偏差、未做去重、流程跳步
    * **I** — 调用链中断：找到 sink 但未追踪到 source 入口，或调用链在某处断裂
    * **J** — 模型幻觉：虚构不存在的防护措施、虚构代码行为、凭二手描述推断未读过的源码
    * **K** — 验证否定真漏洞：挖掘判定 CONFIRMED 但验证 agent 否定（仅 FN 场景）
  - breakpoint 填 "L8"
  - 在 l0_l7 数组中新增一条记录，l0_source 填空，query_content 填问题总结，returned_content 填空

## 重复上报的特殊归因规则（重要）

人工标注的原因包含"重复上报"（或"重复"、"已上报"、"已报过"）时，**必须按以下规则归因**：
- 重复上报 = 漏洞真实存在但已作为历史记录上报过（同根因/同链路），agent 不该再报一次
- 这是 agent 挖掘/验证流程的**去重缺陷**，与知识/记忆无关——知识/记忆里有该漏洞的历史记录，agent 可能还读到了，问题在于 agent 未识别"这是已上报过的漏洞"
- **禁止**将重复上报归因到知识/记忆链路（禁止 L2/A、L4/C、L6/E、L7/G）
- 断点应为 **L8，cause_code 填 "H"**（挖掘/验证流程缺陷），query_content 填"重复上报未识别：agent 未比对已上报漏洞清单/历史记录，将已上报过的同根因同链路漏洞再次上报"
- 责任方为 agent，fix_suggestion.target 应为 agent_code 或 agent_prompt（增加上报前去重逻辑），不能是 knowledge
- 如果 L1=false（不需要知识），后续级别全部 null，不产生断点

# 输出格式

压缩模式返回 JSON：
{
  "summary": "结构化摘要，3000字以内。必须包含知识与记忆访问的总结与影响；只能基于证据卡，不得引入证据卡之外的信息",
  "key_findings": ["关键发现1", "关键发现2"],
  "evidence_cards": [
    {
      "evidence_id": "E-<session 前 8 位>-<序号>",
      "event_idx": 0,
      "source": "文件/命令/工具",
      "quote": "原文逐字摘录（保留完整句子，禁止转述、禁止截断）",
      "fact_type": "repo_fact/deployment_fact/knowledge_access/agent_conclusion/omission/counter_evidence"
    }
  ],
  "retention_check": [
    {"item": "配置/部署事实", "status": "preserved/absent", "evidence_ids": ["E-..."]}
  ],
  "l0_l7": [
    {
      "l0_source": "来源标记（如无则空字符串）",
      "l1_need": true/false/null,
      "l2_initiated": true/false/null,
      "l3_accurate": true/false/null,
      "l4_exists": true/false/null,
      "l5_retrieved": true/false/null,
      "l6_used": true/false/null,
      "l7_influenced": "positive/negative/null",
      "breakpoint": "L2/L3/L4/L5/L6/L7/L8/null",
      "cause_code": "A/B/C/D/E/F/G/H/I/J/K/null",
      "evidence_refs": ["支撑本级判定的证据卡 ID；无证据则空数组"],
      "query_content": "agent 实际执行的查询命令或参数（从 session 文本提取，不要概括）",
      "kb_search_query": "面向知识库检索的单一方法论问题（如'如何验证网络可达性和端口开放状态'）。当 breakpoint=L2（agent 该查没查）时，根据 session 分析 agent 避免此误报所需的知识生成；当 breakpoint=L4（查了没得）时，填 agent 本该查询的问题（可能比 agent 实际查的更精准）；其他断点或无断点时填空字符串。只问方法（如何/怎么验证、判断），禁止问环境事实（端口是否暴露、接口是否部署、网关是否隔离、输入是否已过滤），禁止复合问题，禁止堆砌具体 IP/端口/文件名",
      "returned_content": "知识/记忆实际返回的文本内容概括（基于 [知识库返回]/[记忆返回] 标记后的原文，不要推测）",
      "fix_suggestion": "基于本 session 具体问题的修复建议：哪个命令/查询有问题就改哪里。如查询太泛→改为按当前漏洞类型聚焦查询；知识缺失→明确指出知识库缺什么；返回错误→指出返回了什么错误/异常。必须可定位到本 session 的具体位置，禁止空泛建议（如'增加去重逻辑'必须说明在哪个命令/步骤加）"
    }
  ],
  "insufficient_evidence": false,
  "insufficient_reason": "为 true 时说明缺什么事实、检查了哪些范围；否则空字符串"
}

只返回 JSON，不要任何额外文字。"""


_MERGE_PROMPT = """你是漏洞根因分析专家。你将收到一条漏洞的多个 session 的独立压缩摘要，以及人工标注的原因。

该漏洞可能是误报（FP）或漏报（FN）。用户消息中会标明 outcome=FP 或 outcome=FN。
- FP：分析 agent 为什么误报——知识访问问题、推理错误、验证维度遗漏等
- FN：分析 agent 为什么漏报——挖掘链没找到 sink 点、验证链误判为非漏洞、知识缺失导致没查到等

# 事实依据要求

**所有分析必须基于 session 摘要中的实际内容，禁止推测。**
- 每个假设的 evidence 必须引用 session 摘要中的具体事实
- 如果 session 摘要中没有相关信息，直接说明"session 中未涉及此方面"，不要猜测
- query_content 字段：必须填写 agent 实际执行的查询命令，不要概括为通用描述
- kb_search_query 字段：当 breakpoint=L2 或 L4 时必填，其他断点填空字符串。
  **必须是单一的方法论问题**（只问"如何/怎么验证、判断、识别、评估"），一句话一个检索意图。
  知识库存的是方法论与漏洞模式，不是具体客户的部署现状：
  * 禁止问环境事实（某端口是否暴露、某接口是否部署、某网关是否隔离、某输入是否已被上游过滤、某服务是否可达）
  * 禁止把多个问题用逗号拼成复合查询
  * 禁止堆砌具体资产名（IP、端口、文件名、函数名）
  * 正确示例："如何判断路径参数是否已被有效校验"
  * 错误示例："comm_mgr 的 TCP 8888 端口是否对外暴露，file_name 是否已被上游过滤"
- **supporting_breakpoints 字段（重要）**：该假设**直接依据**的断点编号列表。
  * 只能引用上方 `L0-L7 判定` 中实际出现的 `BP-n` 编号，**禁止编造**
  * 一个假设可引用多条；不同假设可以共享同一条
  * 与假设无关的断点不要列进来
  * 如果假设描述的是**非知识访问类**问题（流程缺陷、重复上报未识别、模型幻觉、
    调用链中断等），通常没有可依据的 L0-L7 断点，此时填**空数组 `[]`**。
    空数组是合法值 —— 表示"该假设不基于任何知识访问断点"，不是缺省。
    但如果是"所需事实未访问"导致的 A，必须引用对应的 L2 断点，不能填空数组。
- returned_content 字段：必须概括 session 摘要中记录的实际返回内容，禁止用"可能包含"、"推测"等猜测性语言
- 禁止使用"可能"、"或许"、"推测"等不确定语言描述事实
- 但对"假设"本身可以用概率描述不确定性，这是分析的不确定性，不是事实的不确定性

- **证据卡门槛（强制）**：每个假设必须通过 `evidence_refs` 引用至少一张 session 摘要中实际存在的证据卡 ID。
  * 找不到可引用的证据卡，**禁止输出该假设**；宁可不给假设，也不许猜。
  * `evidence_refs` 只能引用摘要中出现的 `evidence_id`，禁止编造。
  * `evidence` 字段必须逐条对应 `evidence_refs` 中的原文。

- **反证（强制）**：每个假设必须填写 `counter_evidence`。
  * 材料中存在反证 → 说明为什么它不足以推翻该假设；
  * 材料中没有反证 → 写明检查范围（看过哪些 session / 事件），不能只写"未发现"。

- **人工标注只定性质，不作归因证据**：标注笼统（如"误报：其他误报原因"）时，禁止从标注文字推断具体原因；归因只能来自证据卡。

- **证据不足**：如果没有任何假设能引用到证据卡，输出 `insufficient_evidence=true`、`insufficient_reason`，`primary_cause` 填空字符串，不要给 L 级别。

**probability 语义（重要）**：probability 只作展示，**不参与主因选择**。只允许离散值：0.9 / 0.7 / 0.5 / 0.3 / 0.1。

**主因选择（强制）**：必须输出唯一的 `primary_cause` 和 `primary_hypothesis`，按以下顺序：
1. 假设必须至少有一张证据卡；
2. 优先选择证据卡数量更多的假设；
3. 仍并列时，按 cause_code 字母序取第一个；
4. `probability` 不参与选择。
`primary_hypothesis` 必须与 hypotheses 中某一条的 hypothesis 原文完全一致。
其余假设全部列入 `secondary_causes`。

# 任务

## 合并模式 — 多假设分析

将多个 session 的压缩摘要合并为最终结论。**不要只给一个根因，要列出多个可能的根因假设。**

误报/漏报往往是多因素叠加的结果，单一归因会遗漏修复点。你需要从多个角度分析，列出至少 2 个、最多 5 个根因假设，每个假设给出 probability（根因置信度）和对应的修复方案。

### 假设互斥性（重要，违反即错误）

**各假设之间必须是并列的不同原因，不能存在包含/父子关系。** 每个假设必须代表**一个独立、不可再分的缺陷**。

判定标准：若假设 A 成立时假设 B 必然成立，或 A 描述的缺陷范围完全覆盖 B，则 B 是 A 的子项，**禁止同时输出**。

反例（禁止）：
- A："agent 未比对已上报清单，重复上报" + B："agent 执行了去重检查但结果未绑定上报动作"
  → B 是 A「未有效去重」的具体表现，A 已覆盖 B
- A："验证维度遗漏" + B："验证时未检查权限码"
  → B 是 A 的一个具体遗漏项

正确做法（三选一）：
1. **只输出更具体的那条**（可定位到确切修复点时用），把宽泛表述并入其 evidence
2. **只输出更宽泛的那条**，把具体场景写进 fix_suggestion 的 action 中
3. **合并成一条**，用宽泛描述 + 具体修复动作

选择依据：**看哪个能定位到唯一、可执行的修复点**。只保留 1 条也比输出 2 条包含关系好。

自检：逐对比较所有假设，若存在"若 A 成立则 B 必然成立"，必须合并或删除。修复位置（fix_suggestion.location）相同或重叠的两个假设，通常就是包含关系。

### 分析维度

根据 outcome（FP 误报 / FN 漏报）选择对应维度的假设。

每个假设必须标注 cause_code（A-K），与问题单量化体系一致，用于看板呈现和派单。

### cause_code 成因码体系（A-K）

| cause_code | 含义 | 责任方 | 适用场景 |
|------------|------|--------|---------|
| A | 该查没查（召回意识不足，含不知道要查什么） | agent | FP/FN |
| B | 查询太泛（查询不聚焦） | agent | FP/FN |
| C | 查了没得（知识覆盖度不足） | knowledge | FP/FN |
| D | 链路问题（工具失败/超时） | knowledge | FP/FN |
| E | 查到没用（死知识，推理未引用） | agent | FP/FN |
| F | 用了没推动（未影响结论） | agent | FP/FN |
| G | 知识误导（知识内容有误/过时/不适用） | knowledge | FP/FN |
| H | 流程缺陷/其他（挖掘方向偏差、重复上报未识别等 agent 流程问题） | agent | FP/FN |
| I | 调用链中断（找到 sink 未追踪到 source 入口） | agent | FN |
| J | 模型幻觉（虚构不存在的防护措施/漏洞逻辑） | agent | FP/FN |
| K | 验证否定真漏洞（挖掘 CONFIRMED 但验证 agent 否定） | agent | FN |

### 分析维度（按 cause_code 交叉分析）

**FP（误报）常用维度**——为什么 agent 误报了不存在的漏洞：
- A 该查没查【agent】：agent 未查知识库就下结论，需改 prompt 增加知识查询意识
- C 查了没得【knowledge】：知识库缺少业务环境知识/暴露面文档/部署约束/判别方法
- E 查到没用【agent】：agent 查了知识但推理未引用
- G 知识误导【knowledge】：知识内容有误（如声称"框架默认过滤"实际没有）
- J 模型幻觉【agent】：agent 虚构了代码中不存在的防护措施

**FN（漏报）常用维度**——为什么 agent 漏报了真实漏洞：
- A 该查没查【agent】：agent 不知道这类漏洞模式，需改 prompt 增加知识查询意识
- C 查了没得【knowledge】：知识库缺少漏洞模式判定方法
- H 流程缺陷/其他【agent】：挖掘方向偏差（范围/路径未覆盖 sink 点）、重复上报未识别（未比对历史记录）等 agent 流程问题
- I 调用链中断【agent】：找到 sink 但未追踪到 source 入口（数据流不可达）
- G 知识误导【knowledge】：知识/记忆返回内容错误/过时，误导了判定
- J 模型幻觉【agent】：虚构了不存在的防护措施，导致认为不是漏洞
- K 验证否定真漏洞【agent】：挖掘 CONFIRMED 但验证 agent 否定（验证维度遗漏/判定标准过严）

### 重复上报的特殊归因规则（重要）

人工标注的原因包含"重复上报"（或"重复"、"已上报"、"已报过"）时，**必须按以下规则归因**：
- 重复上报 = 漏洞真实存在但已作为历史记录上报过（同根因/同链路），agent 不该再报一次
- 这是 agent 挖掘/验证流程的**去重缺陷**，与知识/记忆无关——知识/记忆里有该漏洞的历史记录，
  agent 可能还读到了，问题在于 agent 未识别"这是已上报过的漏洞"
- **禁止**将重复上报归因到知识/记忆链路（禁止 A 该查没查、C 查了没得、E 查到没用、G 知识误导）
- 断点应为 **L8，cause_code 填 "H"**（挖掘/验证流程缺陷），query_content 填"重复上报未识别：
  agent 未比对已上报漏洞清单/历史记录，将已上报过的同根因同链路漏洞再次上报"
- 责任方为 agent，fix_suggestion.target 应为 agent_code 或 agent_prompt（增加上报前去重逻辑），
  不能是 knowledge/memory

### 责任边界判定

**cause_code 与 responsibility 必须一致（强制约束，防止矛盾）**：

| cause_code | 对应 responsibility |
|------------|-------------------|
| A/B/E/F/H/I/J/K | agent |
| C/D/G | knowledge |
| external_data_source | 仅外部信息缺失场景 |

- 该查没查（A）→ responsibility 必须是 agent，修复是改 prompt 增加查询意识
- 查了没得（C）→ responsibility 必须是 knowledge，修复是补知识库
- 不允许出现 "cause_code=A 但 responsibility=knowledge" 的矛盾组合
- 当"agent 没查知识（A）"且"知识库可能也没有该知识"时，触发 L4 独立验证
  由评测引擎主动查知识库判定：知识存在→A（agent 责任）；知识不存在→C（knowledge 责任）

对每个假设，必须标注 responsibility（与 cause_code 对应表一致），用于派单：
- agent：Agent 改 prompt/code 可解决
- knowledge：知识方补充/修正知识库内容
- external_data_source：提供外部数据源（网关配置/部署架构等）
- 如果 agent_can_resolve=false，必须说明 blocked_by 和 needed_external_data

### 人工标注质量评估

评估人工标注原因的精确度：
- precise：标注精确，可直接定位根因
- imprecise：标注笼统，需追问细化（如"网络不可达"未说明具体是防火墙/网关/内网隔离/认证门槛）
- 如果 imprecise，列出需要追问的具体问题（follow_up_questions）
- **needs_label_confirmation**：如果最终结论取决于人工的真实意图（材料无法判断人说的是"不构成漏洞"还是"设计功能"等），置为 true，并在 follow_up_questions 说明需要确认什么；不要替人补全原因。
- 人工标注只用来确定 FP/FN 和复核背景，**不作为归因证据**。

## 修复建议

针对**所有假设**的修复点，合并输出修复建议列表。一个 case 可能需要多个修复点同时执行才能解决。

每条修复建议必须包含（**结构化字段，用于派单定位**）：
- target：修复责任方，取值：
  * agent_prompt — 修改 agent 的提示词
  * agent_code — 修改 agent 的代码逻辑
  * knowledge — 补充/修改知识库内容
  * memory — 更新/补充记忆文档
  * external_data_source — 提供外部数据源
  * eval_process — 评测流程改进
- agent_type：**具体修改哪个 agent**（target=agent_prompt/agent_code 时必须填写），取值：
  * turing — 挖掘 agent（漏洞挖掘）
  * argo / secmate / dataflow — 其他挖掘 agent
  * webvuln_verify — 验证 agent（Web 漏洞验证）
  * cvuln_verify — 验证 agent（代码漏洞验证）
  * 填空字符串表示不适用
- knowledge_source：**具体修改哪个知识/记忆源**（target=knowledge/memory 时必须填写），取值：
  * knowledge_base — 知识库（漏洞模式知识、判别方法、业务环境知识、部署约束知识）
  * memory_wiki — 记忆/wiki（暴露面清单、不可调用文档、经验总结）
  * 填空字符串表示不适用
- location：具体修改位置（文字描述）：
  * 如果是 agent_prompt/agent_code：哪个 agent 的哪个环节/函数（如"挖掘 agent 的漏洞模式识别阶段 prompt"）
  * 如果是 knowledge：知识库哪类知识（如"漏洞挖掘模式知识 - SQL 注入 sink 判定"）
  * 如果是 memory：记忆里哪个文档（如"暴露面清单 - spportal 接口"）
  * 如果是 external_data_source：需要提供什么数据源
  * 如果是 eval_process：需要改评测流程的什么环节
- action：具体修改内容（如"在挖掘 agent 的 prompt 中增加'检查删除端点权限码'的指令"）
- expected_effect：修改后预期效果（如"挖掘 agent 在审计删除端点时会检查权限码，避免漏报权限提升漏洞"）

## L0-L8 断点判定

- 如果知识访问链路有断点（L2-L7），照常输出
- **L1 判定边界（强制）**：L1 只看"正确结论所需的事实，agent 在本次 session/trace 中是否实际访问过"。
  - 已访问（读过对应文件、执行过对应命令、查过对应知识/记忆）→ L1=false，事实在材料内；后续按 L2-L7 判定是否用对，用错/漏判走 L8。
  - 未访问（材料中没有任何对应访问记录）→ L1=true，断点 L2，cause_code "A"（该查没查）。
  - **不允许**用"仓库里存在该文件"或"理论上可读"来认定已访问；只有 trace 里的实际访问记录才算。
  - 判定"未访问"时必须写明核验范围（检查了哪些 session、哪些工具调用、哪些文件），不能只写"没查到"。
  - **运行时/部署状态必须实际访问**：只有实际读取承载该事实的文件/命令才算访问。读了实际配置（如 config/config.inc.php）、环境变量、compose.yml/Dockerfile、运行中的服务状态 → 算访问；只读模板/默认值（*.dist、*.example）或从代码分支推断 → **不算访问**。若正确结论所需的是实际部署状态而材料中只有模板/推断，L1=true → L2/A。
- **如果 session 中没有知识访问行为**：
  - 正确结论所需的事实未被访问 → 断点 L2，cause_code "A"（该查没查）
    - kb_search_query 填一个面向知识库检索的**单一方法论问题**，基于 session 分析 agent 避免此误报所需的知识生成。只问方法，不问具体环境事实
  - 所需事实已在 trace 中被访问 → L1=false，不产生知识访问断点；若访问了但未用对/未识别，走 L8
- 如果知识访问链路全程通过（L7=positive）**或 L1=false（事实已访问且知识链路无问题）**，但 agent 仍误报，
  必须输出 L8 断点：
  - L8 断点表示知识访问链路无问题，但存在其他非知识访问的原因导致误报/漏报
  - **cause_code 必须从 H/I/J/K 中选最匹配的，不要一律填 H**：
    * **H** — 流程缺陷：重复上报未识别、挖掘方向偏差、未做去重、流程跳步
    * **I** — 调用链中断：找到 sink 但未追踪到 source 入口，或调用链在某处断裂
    * **J** — 模型幻觉：虚构不存在的防护措施、虚构代码行为、凭二手描述推断未读过的源码
    * **K** — 验证否定真漏洞：挖掘判定 CONFIRMED 但验证 agent 否定（仅 FN 场景）
  - breakpoint 填 "L8"
  - query_content 填问题总结（如"验证逻辑不充分：验证条件错误"）
  - l0_source 填空字符串
- L8 仅覆盖知识访问链路确实无问题的场景（L7=positive 或 L1=false）。
  如果 L6/L7 有断点（查到没用、用了没推动、知识误导），断点就在 L6/L7，**不是 L8**
- **注意：验证维度遗漏只有在所需事实已访问且用错时才是 L8；未访问属于 L2/A，不是 L8（只读模板/默认值或从代码推断也算未访问）**

### L7 判定与 cause_code 映射

L7 三种结果的断点与 cause_code **不同**，不要一律跳到 L8：

| L7 取值 | 含义 | 是否断点 | cause_code |
|---------|------|---------|-----------|
| `positive` | 知识正确且推动正确结论 | 不是断点 | 无（继续判 L8） |
| `negative` | 知识错误/过时，且影响结论 | 断点 L7 | **G**（知识误导，责任方=知识方） |
| `null` + L6=true | 知识未推动结论 | 断点 L7 | **F**（用了没推动，责任方=agent） |
| `null` + L6=false | 读了但推理未引用 | 断点 L6 | **E**（查到没用，责任方=agent） |

后三种都**不是 L8**。L8 只用于「知识链路完全正常」的场景。

### 断点归属规则

断点应反映导致误报的**主要原因**。区分「记录性知识访问」与「主要断点」：

- agent 读了知识但没用（L6=false），且该知识访问与人工标注的误报原因**无关**：
  * 该次访问仍按 L6/E 记录（事实不能丢）
  * **主要断点另起一条 L8**，cause_code 从 H/I/J/K 选，
    query_content 说明"本次 L6=false 仅为记录，非误报根因"并写清真正误报原因
- 该知识访问与误报原因**直接相关**（该查没查 / 查错了 / 查到了没用导致误判）：
  断点就是那个知识访问级别（L2-L7），**不要再另起 L8**
- 如果 agent 没查知识（L2=false）但推理需要知识（L1=true）：L2 断点，不是 L8
- 只有「误报原因与知识访问无关（L1=false）」或「知识链路全程通过（L7=positive）」时，才判 L8

# 输出格式

合并模式返回 JSON：
{
  "summary": "合并后的最终摘要，3000字以内",
  "primary_cause": "唯一主因的 cause_code（A-K）；证据不足时填空字符串",
  "primary_hypothesis": "主因假设的原文（必须与 hypotheses 中某一条完全一致）；证据不足时填空字符串",
  "secondary_causes": ["其他假设的 cause_code"],
  "insufficient_evidence": false,
  "insufficient_reason": "为 true 时说明缺什么证据、检查了哪些范围；否则空字符串",
  "audit": [
    {"rule": "primary_unique", "pass": true, "note": ""},
    {"rule": "evidence_grounded", "pass": true, "note": ""},
    {"rule": "counter_evidence_checked", "pass": true, "note": ""}
  ],
  "knowledge_memory_summary": {
    "access_count": "整条链的知识/记忆访问总次数（所有 session 累加）",
    "accesses": [
      {
        "source": "knowledge_base|memory|unknown",
        "query": "agent 查询内容概括",
        "returned": "返回内容概括",
        "used_in_reasoning": true/false,
        "effect": "positive|negative|neutral|none",
        "session_id": "来自哪个 session（如能判断）"
      }
    ],
    "overall_effect": "positive|negative|neutral|none",
    "impact_on_conclusion": "知识/记忆对 agent 最终判定结论的综合影响描述（200字以内）。综合整条链所有 session 的知识访问，说明知识/记忆是否正确推动了结论、误导了结论、还是未影响结论"
  },
  "hypotheses": [
    {
      "hypothesis": "假设描述（如'Agent 将路由定义等同于公网可达'）。必须是独立缺陷，禁止与其他假设存在包含/父子关系",
      "probability": 0.9,  # 仅展示，不参与主因选择；只允许 0.9/0.7/0.5/0.3/0.1
      "responsibility": "agent|knowledge|external_data_source|eval_process",
      "cause_code": "A/B/C/D/E/F/G/H/I/J/K",
      "evidence_refs": ["E-...", "E-..."],  # 必须引用摘要中实际存在的证据卡 ID；无证据不得输出该假设
      "counter_evidence": "材料中的反证；没有反证则写明检查范围（看过哪些 session/事件）",
      "evidence": "session 中的具体事实依据（引用摘要内容，不要推测）",
      "session_id": "该假设主要基于的 session_id（从上方 Session 摘要中引用，可逗号分隔多个；若证据来自多个 session 的合并判断则列全，禁止编造不存在的 session_id）",
      "supporting_breakpoints": ["BP-1", "BP-3"],
      "agent_can_resolve": true/false,
      "blocked_by": "如果 agent_can_resolve=false，说明 Agent 缺少什么（如'网关配置不在代码仓库中'）；如果 true 则填空字符串",
      "needed_external_data": ["如果 agent_can_resolve=false，列出需要的外部数据（如'网关配置'、'Ingress 路由'）；如果 true 则填空数组"],
      "fix_suggestion": {
        "target": "agent_prompt|agent_code|knowledge|memory|external_data_source|eval_process",
        "agent_type": "turing|webvuln_verify|cvuln_verify|...(target=agent_* 时填写，否则空)",
        "knowledge_source": "knowledge_base|memory_wiki(target=knowledge/memory 时填写，否则空)",
        "location": "具体修改位置",
        "action": "具体修改内容",
        "expected_effect": "修改后预期效果"
      }
    }
  ],
  "label_quality": {
    "precision": "precise|imprecise",
    "needs_label_confirmation": false,
    "reason": "评估理由（如'网络不可达未说明具体是防火墙/网关/内网隔离/认证门槛'）",
    "follow_up_questions": ["追问问题1", "追问问题2"]
  },
  "l0_l7": [
    {
      "l0_source": "来源标记",
      "l1_need": true/false/null,
      "l2_initiated": true/false/null,
      "l3_accurate": true/false/null,
      "l4_exists": true/false/null,
      "l5_retrieved": true/false/null,
      "l6_used": true/false/null,
      "l7_influenced": "positive/negative/null",
      "breakpoint": "L2/L3/L4/L5/L6/L7/L8/null",
      "cause_code": "A/B/C/D/E/F/G/H/null",
      "evidence_refs": ["支撑本级判定的证据卡 ID；无证据则空数组"],
      "query_content": "agent 实际执行的查询命令（从摘要中提取原文，不要概括）",
      "kb_search_query": "面向知识库检索的单一方法论问题。当 breakpoint=L2（agent 该查没查）时，根据 session 分析 agent 避免此误报所需的知识生成；当 breakpoint=L4（查了没得）时，填 agent 本该查询的问题；其他断点或无断点时填空字符串。只问方法，禁止问环境事实（端口是否暴露、接口是否部署等），禁止复合问题",
      "returned_content": "知识/记忆实际返回的文本内容概括（基于摘要中的记录，不要推测）"
    }
  ]
}

## knowledge_memory_summary 字段说明

合并模式的 knowledge_memory_summary 是对整条链（所有 session）的知识/记忆访问综合总结：
- 汇总所有 session 的知识/记忆访问次数
- accesses 数组列出每次访问的简要记录（含 session_id 标识来源）
- overall_effect 是综合判断：positive（知识正确推动结论）/ negative（知识误导）/ neutral（访问了但未影响）/ none（无访问）
- impact_on_conclusion 必须基于 session 摘要中的实际事实，说明知识/记忆如何影响了 agent 的最终判定

只返回 JSON，不要任何额外文字。"""


class RootCauseAnalyzer:
    """误报根因分析器 — 挖掘链 + 验证链各自独立压缩，最后合并输出。"""

    def analyze(
        self,
        evaluation_id: str,
        fp_cases: list[dict],
        data_packs: list[DataPack],
        cancel_cb=None,
        project_id: str = "",
    ) -> list[dict]:
        """对每个 FP/FN case 的挖掘 agent session 和验证 agent session 各自做独立压缩 + 合并输出根因分析。

        Args:
            evaluation_id: 评测 ID
            fp_cases: case_matching 结果中 outcome=FP 或 FN 的 case 列表，
                      每项含 case_id, mining_sessions, verify_sessions,
                      vuln_title, description, outcome
            data_packs: DataPack 列表
            cancel_cb: 取消回调
            project_id: 项目 ID（知识库主动验证用，空则跳过 Athena API 查询）

        Returns:
            分析结果列表，每项含：
            - case_id, vuln_title, description, outcome
            - mining: {session_chain, root_cause, fix_suggestion, compressed_summaries, l0_l7_breakpoints, l4_independent_verification}
            - verification: {session_chain, root_cause, fix_suggestion, compressed_summaries, l0_l7_breakpoints, l4_independent_verification}
        """
        # 构建 session_id → events 索引 + session_id → agent_type 映射
        session_events: dict[str, list[RawEvent]] = defaultdict(list)
        session_agent_type: dict[str, str] = {}
        for dp in data_packs:
            for ev in (dp.events or []):
                sid = ev.session_id or ""
                if sid:
                    session_events[sid].append(ev)
                    if sid not in session_agent_type:
                        session_agent_type[sid] = dp.agent_type or ""

        # 从 data_packs 的 session_graph 聚合 parent_map / children_map——
        # 与 DTS 问题单 _query_session_chains 的 _expand_chain 同源同逻辑：
        # case_matching 的 mining/verify 种子 session 展开成完整调用链（祖先+子孙），
        # 保证 debug/case_matching/DTS 三处显示的 session 链一致。
        all_parent_map: dict[str, str] = {}
        all_children_map: dict[str, list[str]] = {}
        for dp in data_packs:
            sg = getattr(dp, "session_graph", None) or {}
            gpm = sg.get("parent_map", {}) if isinstance(sg, dict) else {}
            for sid, pid in gpm.items():
                if sid not in all_parent_map:
                    all_parent_map[sid] = pid
                if pid not in all_children_map:
                    all_children_map[pid] = []
                if sid not in all_children_map[pid]:
                    all_children_map[pid].append(sid)

        # 多 case 并发分析（最多 10 个 case 同时处理）
        # 每个 case 内挖掘链和验证链串行执行，
        # 链内 session 压缩通过 submit_llm_batch 并发（受 LLM gate 控制）
        max_workers = min(len(fp_cases), 10)

        def _run_case(idx_case):
            """分析单个 FP case，返回 (idx, result_dict)。"""
            idx, case = idx_case
            if cancel_cb:
                cancel_cb()

            case_id = case.get("case_id", "")
            vuln_title = case.get("vuln_title", "")
            desc = case.get("description", "")
            summary = case.get("summary", "")
            outcome = case.get("outcome", "FP")
            # 种子 session 展开成完整调用链（祖先+子孙），与 DTS 问题单一致
            mining_chain = self._expand_chain(
                set(case.get("mining_sessions", [])),
                all_parent_map, all_children_map)
            verify_chain = self._expand_chain(
                set(case.get("verify_sessions", [])),
                all_parent_map, all_children_map)
            fp_reason = case.get("human_confirmation_summary", "")

            log("ROOT_CAUSE",
                f"case {case_id}: 开始分析 (outcome={outcome}, "
                f"vuln_title={vuln_title})",
                eval_id=evaluation_id)

            # ── 漏报根因定位：验证否定场景只分析验证链 ──
            # 挖掘 CONFIRMED + 验证否定 → FN，根因在验证 agent 的判定逻辑，
            # 与挖掘 agent 无关。跳过挖掘链 LLM 分析（省成本 + 归因正确）。
            verify_negated = (
                outcome == "FN"
                and case.get("verify_verdict") == "FALSE_POSITIVE"
            )
            if verify_negated:
                log("ROOT_CAUSE",
                    f"case {case_id}: 验证否定真漏洞（挖掘 CONFIRMED + "
                    f"验证否定），根因在验证链，跳过挖掘链分析",
                    eval_id=evaluation_id)
                mining_result = {
                    "session_chain": [],
                    "root_cause": {
                        "category": "mining_ok",
                        "description": "挖掘 agent 已上报 CONFIRMED，"
                                       "验证 agent 否定导致漏报——"
                                       "挖掘链无问题，跳过分析",
                    },
                    "fix_suggestion": [],
                    "compressed_summaries": [],
                    "l0_l7_breakpoints": [],
                }
                verification_result = self._analyze_chain(
                    evaluation_id, case_id, "verification",
                    verify_chain, session_events,
                    vuln_title, desc, fp_reason, outcome, cancel_cb,
                    project_id=project_id,
                )
            else:
                # mining 和 verification 链互相独立，并行分析
                # 用 submit_pool（不占 gate），各链内部 submit_llm_batch/chat_json 自行 acquire gate
                mining_fut = llm_mod.submit_pool(
                    self._analyze_chain,
                    evaluation_id, case_id, "mining",
                    mining_chain, session_events,
                    vuln_title, desc, fp_reason, outcome, cancel_cb,
                    project_id=project_id,
                )
                verification_result = self._analyze_chain(
                    evaluation_id, case_id, "verification",
                    verify_chain, session_events,
                    vuln_title, desc, fp_reason, outcome, cancel_cb,
                    project_id=project_id,
                )
                try:
                    mining_result = mining_fut.result()
                except Exception as e:
                    log("ROOT_CAUSE",
                        f"case {case_id}: mining 链分析失败: {e}",
                        eval_id=evaluation_id)
                    raise

            # 从 session_chain 推导 agent_type（取第一个 session 的 agent_type）
            # FN 漏报 case（sink_not_found）mining_sessions 可能为空——
            # 此时用 case 构造时推导的 agent_type 兜底（orchestrator 从
            # data_packs 推导实际挖掘 agent，见 _mining_agent_type）
            mining_agent_type = ""
            for sid in mining_chain:
                at = session_agent_type.get(sid, "")
                if at:
                    mining_agent_type = at
                    break
            if not mining_agent_type:
                mining_agent_type = case.get("agent_type", "")
            verify_agent_type = ""
            for sid in verify_chain:
                at = session_agent_type.get(sid, "")
                if at:
                    verify_agent_type = at
                    break

            return idx, {
                "case_id": case_id,
                "vuln_title": vuln_title,
                "description": desc,
                "summary": summary,
                "outcome": case.get("outcome", ""),
                "human_confirmation_summary": fp_reason,
                "fn_miss": case.get("fn_miss") or {},
                "mining": {**mining_result, "agent_type": mining_agent_type},
                "verification": {**verification_result, "agent_type": verify_agent_type},
            }

        results: list[dict | None] = [None] * len(fp_cases)

        if max_workers <= 1:
            for i, case in enumerate(fp_cases):
                idx, result = _run_case((i, case))
                results[idx] = result
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_run_case, (i, c)): i
                           for i, c in enumerate(fp_cases)}
                for fut, _ in iter_completed(futures, cancel_cb=cancel_cb):
                    idx, result = fut.result()
                    results[idx] = result

        return [r for r in results if r is not None]

    @staticmethod
    def _expand_chain(
        seeds: set[str],
        all_parent_map: dict[str, str],
        all_children_map: dict[str, list[str]],
    ) -> list[str]:
        """从种子 session 出发，向上找祖先，返回祖先链（根→种子顺序）。

        与 DTS 问题单 _query_session_chains._expand_chain 完全一致——
        保证 case_matching / 根因分析 / DTS 三处展示的 session 链同源同逻辑。

        secmate 的 parent_map 是 finding 派生关系（非调用关系），向下展开
        子孙会把整棵派生树拉进来。只展开祖先链——"这个 finding 是怎么被发现的"。
        """
        chain_ids: set[str] = set()

        # 向上找祖先
        for sid in seeds:
            cur = sid
            while cur and cur in all_parent_map and cur not in chain_ids:
                chain_ids.add(cur)
                cur = all_parent_map[cur]
            if cur and cur not in chain_ids:
                chain_ids.add(cur)  # 根节点

        # 按根→叶子排序：找根节点（parent 不在链中），BFS 往下
        roots = [sid for sid in chain_ids
                 if all_parent_map.get(sid, "") not in chain_ids]
        ordered: list[str] = []
        visited: set[str] = set()
        queue = sorted(roots)
        while queue:
            sid = queue.pop(0)
            if sid in visited:
                continue
            visited.add(sid)
            ordered.append(sid)
            children = [c for c in all_children_map.get(sid, []) if c in chain_ids]
            queue = sorted(children) + queue

        return ordered

    def _analyze_chain(
        self,
        evaluation_id: str,
        case_id: str,
        chain_type: str,
        chain: list[str],
        session_events: dict[str, list[RawEvent]],
        vuln_title: str,
        desc: str,
        fp_reason: str = "",
        outcome: str = "",
        cancel_cb=None,
        project_id: str = "",
    ) -> dict:
        """对一条 session 链做独立压缩 + 合并输出。

        每个 session 独立调 LLM 压缩（不传递前一个摘要），
        收集所有摘要后合并调一次 LLM 输出最终根因。

        chain: 已排好序的 session_id 列表（根→叶子）。
        chain_type: "mining" 或 "verification"，仅用于日志。
        fp_reason: 人工标注的原因，传给 LLM 做根因分析。
        outcome: "FP" 或 "FN"，传给 LLM 区分误报/漏报分析方向。
        project_id: 项目 ID，用于知识库主动验证 L4。
        """
        if not chain:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 无 session，跳过",
                eval_id=evaluation_id)
            return {
                "session_chain": [],
                "root_cause": {
                    "category": "no_session",
                    "description": f"无 {chain_type} session",
                },
                "fix_suggestion": [],
                "compressed_summaries": [],
                "l0_l7_breakpoints": [],
            }

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} session 链 {len(chain)} 个 session",
            eval_id=evaluation_id)

        # ── 第一步：每个 session 独立压缩（并发提交）──
        compressed_summaries: list[dict] = []
        all_breakpoints: list[dict] = []

        def _compress_session(args: tuple) -> dict:
            """压缩单个 session，返回含 step/session_id/summary 等的 dict。

            单个 session 超过 LLM 上下文限制时，按事件分片压缩再合并，
            不截断原始文本。
            """
            i, sid = args
            if cancel_cb:
                cancel_cb()

            events = session_events.get(sid, [])
            session_text = self._format_session_events(sid, events)

            user_content = (
                f"漏洞标题：{vuln_title}\n"
                f"漏洞描述：{desc}\n"
                f"outcome：{outcome or 'FP'}（FP=误报，FN=漏报）\n"
                f"人工标注的原因：{fp_reason or '（未给出）'}\n\n"
                f"Session {i+1}/{len(chain)} (session_id={sid}):\n"
                f"{session_text}"
            )

            messages = [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ]

            # 预检：超过上下文限制时分片压缩
            if llm_mod.would_exceed_context(messages):
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} session {i+1}/{len(chain)} "
                    f"session 过大 (chars={len(session_text)})，分片压缩",
                    eval_id=evaluation_id)
                result = self._compress_session_chunked(
                    evaluation_id, case_id, chain_type, i, sid,
                    events, vuln_title, desc, fp_reason, outcome,
                    chain, cancel_cb,
                )
            else:
                # 输出截断重试：网关随机分发后端，重发同一请求可能命中
                # 上下文更大的后端。重试耗尽后再走输入超限的分片兜底。
                for _trunc_attempt in range(_TRUNCATION_RETRIES + 1):
                    try:
                        result = llm_mod.chat_json(
                            messages,
                            temperature=0,
                            cancel_cb=cancel_cb,
                            max_tokens=llm_mod.get_response_reserve_tokens(),
                            required_keys=["summary"],
                        )
                        break
                    except llm_mod.LLMOutputTruncatedError as e:
                        if _trunc_attempt >= _TRUNCATION_RETRIES:
                            log("ROOT_CAUSE",
                                f"case {case_id}: {chain_type} "
                                f"session {i+1}/{len(chain)} 输出截断，"
                                f"{_TRUNCATION_RETRIES} 次重试后仍失败",
                                eval_id=evaluation_id)
                            log_error(evaluation_id, "ROOT_CAUSE", e)
                            raise
                        log("ROOT_CAUSE",
                            f"case {case_id}: {chain_type} "
                            f"session {i+1}/{len(chain)} 输出截断 "
                            f"(content_len={e.content_len})，"
                            f"重试 {_trunc_attempt+1}/{_TRUNCATION_RETRIES}",
                            eval_id=evaluation_id)
                        time.sleep(_TRUNCATION_RETRY_DELAY)
                    except Exception as e:
                        err_str = str(e)
                        # llm.chat_json 已对输入超限做过多次重试切换后端；
                        # 仍失败说明多次都没命中大上下文后端。此时改为按最保守的
                        # 204800 上下文分片压缩，而不是依赖全局默认值。
                        if llm_mod.is_context_overflow_error(err_str):
                            log("ROOT_CAUSE",
                                f"case {case_id}: {chain_type} "
                                f"session {i+1}/{len(chain)} "
                                f"LLM 输入超限（重试后仍未命中大上下文后端），"
                                f"改按 204800 上下文分片压缩",
                                eval_id=evaluation_id)
                            result = self._compress_session_chunked(
                                evaluation_id, case_id, chain_type, i, sid,
                                events, vuln_title, desc, fp_reason, outcome,
                                chain, cancel_cb, max_ctx_override=204800,
                            )
                        else:
                            log("ROOT_CAUSE",
                                f"case {case_id}: {chain_type} "
                                f"session {i+1}/{len(chain)} LLM 压缩失败",
                                eval_id=evaluation_id)
                            log_error(evaluation_id, "ROOT_CAUSE", e)
                            raise
                        break

            return {
                "session_id": sid,
                "step": i + 1,
                "summary": result.get("summary", ""),
                "key_findings": result.get("key_findings") or [],
                "evidence_cards": result.get("evidence_cards") or [],
                "retention_check": result.get("retention_check") or [],
                "insufficient_evidence": bool(
                    result.get("insufficient_evidence")),
                "insufficient_reason": result.get("insufficient_reason") or "",
                "l0_l7": result.get("l0_l7") or [],
            }

        # 构建任务列表：(step_index, session_id)
        tasks = [(i, sid) for i, sid in enumerate(chain)]

        futures = llm_mod.submit_llm_batch(
            _compress_session, tasks, cancel_cb=cancel_cb)

        for fut in futures:
            try:
                cs = fut.result()
            except Exception as e:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} session 压缩失败: {e}",
                    eval_id=evaluation_id)
                raise

            compressed_summaries.append(cs)

            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} session {cs['step']}/{len(chain)} "
                f"独立压缩完成 (summary {len(cs.get('summary', ''))} 字, "
                f"{len(cs.get('l0_l7') or [])} 条知识访问)",
                eval_id=evaluation_id)

        # 按 step 排序，保证拓扑序
        compressed_summaries.sort(key=lambda x: x["step"])

        # 按 case 总预算截断证据卡（超出按 fact_type 优先级保留）
        card_total, card_truncated = self._enforce_evidence_budget(
            compressed_summaries)
        if card_truncated:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 证据卡超预算，"
                f"截断 {card_truncated} 张（保留 {card_total} 张）",
                eval_id=evaluation_id)

        # 断点在排序之后重建，保证与 _build_bp_registry / merge prompt
        # 的遍历顺序完全一致（同一份 compressed_summaries，同源同序）
        bp_registry = self._build_bp_registry(compressed_summaries)
        ref_by_pos = {(i["session_id"], i["l0_l7_index"]): ref
                      for ref, i in bp_registry.items()}
        for s in compressed_summaries:
            sid = s["session_id"]
            for idx, kp in enumerate(s.get("l0_l7") or []):
                if not isinstance(kp, dict):
                    continue
                brk = kp.get("breakpoint")
                if not brk or brk == "null":
                    continue
                all_breakpoints.append({
                    "session_id": sid,
                    # 链前缀保证跨链唯一（mining/verification 各自从 BP-1 编号）
                    "_bp_ref": self._scoped_ref(
                        ref_by_pos.get((sid, idx), ""), chain_type),
                    **kp,
                })

        # ── 第二步：合并所有 session 摘要，输出最终根因 ──
        merge_user_content = self._build_merge_prompt(
            chain_type, vuln_title, desc, fp_reason, outcome,
            compressed_summaries, bp_registry,
        )

        merge_messages = [
            {"role": "system", "content": _MERGE_PROMPT},
            {"role": "user", "content": merge_user_content},
        ]

        try:
            merge_result = llm_mod.chat_json(
                merge_messages,
                temperature=0,
                cancel_cb=cancel_cb,
                required_keys=["summary"],
            )
        except Exception as e:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 合并压缩失败: {e}",
                eval_id=evaluation_id)
            raise

        merge_summary = merge_result.get("summary", "")
        merge_hypotheses = merge_result.get("hypotheses") or []
        merge_label_quality = merge_result.get("label_quality", {
            "precision": "precise",
            "reason": "",
            "follow_up_questions": [],
        })
        merge_km_summary = merge_result.get("knowledge_memory_summary") or {
            "access_count": 0,
            "accesses": [],
            "overall_effect": "none",
            "impact_on_conclusion": "",
        }

        # 注意：不再收集合并 LLM 输出的 L0-L7 断点（session_id="merge"）。
        # merge 断点是合并阶段对同一知识访问的重复判定，与 session 压缩级断点
        # 内容重复，且修复点无法定位到真实 session。断点只保留 session 级——
        # 它们带真实查询命令与返回内容，可回溯到具体 session。

        # ── 校验假设的 supporting_breakpoints 引用 ──
        # 丢弃不存在的 BP 编号（LLM 可能编造），保留「字段缺失」与「空数组」的区别：
        #   空数组 = LLM 明确表示此假设不基于任何断点
        #   字段缺失 = 协议不完备，后续由因果链回退到 session_id 匹配
        # LLM 看到的是链内编号（BP-1），落库前统一加链前缀转成跨链唯一引用
        _valid_refs = {self._scoped_ref(r, chain_type) for r in bp_registry}
        for h in merge_hypotheses:
            if "supporting_breakpoints" not in h:
                continue
            raw_refs = h.get("supporting_breakpoints") or []
            if not isinstance(raw_refs, list):
                raw_refs = []
            kept, dropped = [], []
            for r in raw_refs:
                if not isinstance(r, str) or not r:
                    continue
                scoped = self._scoped_ref(r, chain_type)
                if scoped in _valid_refs:
                    kept.append(scoped)
                else:
                    dropped.append(r)
            if dropped:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} 假设引用了不存在的断点编号，"
                    f"已丢弃 {dropped}（有效编号共 {len(_valid_refs)} 个）")
            h["supporting_breakpoints"] = kept

        # ── 证据门槛：没有证据卡的假设一律丢弃 ──
        # prompt 已禁止输出无证据假设，这里做程序兜底。
        grounded = []
        for h in merge_hypotheses:
            refs = h.get("evidence_refs") or []
            if isinstance(refs, list) and any(
                    isinstance(r, str) and r for r in refs):
                grounded.append(h)
            else:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} 假设无证据卡，已丢弃: "
                    f"{str(h.get('hypothesis', ''))[:60]}")
        merge_hypotheses = grounded

        # ── 从多假设提取兼容字段（root_cause + fix_suggestion）──
        # 主因按 primary_cause 选取，不看 probability；probability 仅作展示。
        insufficient = bool(merge_result.get("insufficient_evidence"))
        primary_cause = (merge_result.get("primary_cause") or "").strip()
        primary_hypothesis = (
            merge_result.get("primary_hypothesis") or "").strip()
        top_hypothesis = None
        if not insufficient and merge_hypotheses:
            # 优先按主因假设原文精确匹配（cause_code 可能重复，原文唯一）
            if primary_hypothesis:
                top_hypothesis = next(
                    (h for h in merge_hypotheses
                     if h.get("hypothesis") == primary_hypothesis), None)
            if top_hypothesis is None and primary_cause:
                top_hypothesis = next(
                    (h for h in merge_hypotheses
                     if h.get("cause_code") == primary_cause), None)
            if top_hypothesis is None:
                # primary_cause 缺失或与假设不一致：选证据最多者，
                # 并列按 cause_code 字母序（确定性 tie-break）。
                top_hypothesis = sorted(
                    merge_hypotheses,
                    key=lambda h: (-len(h.get("evidence_refs") or []),
                                   str(h.get("cause_code") or "Z")),
                )[0]

        if insufficient:
            merge_root_cause = {
                "category": "insufficient_evidence",
                "description": (merge_result.get("insufficient_reason")
                                or "证据不足，无法判定根因"),
                "human_confirmation_reason": fp_reason,
                "insufficient_evidence": True,
            }
        elif top_hypothesis:
            merge_root_cause = {
                "category": self._hypothesis_to_category(top_hypothesis),
                "description": top_hypothesis.get("hypothesis", "无最终分析结果"),
                "human_confirmation_reason": fp_reason,
                "insufficient_evidence": False,
            }
        else:
            merge_root_cause = {
                "category": "insufficient_evidence",
                "description": "没有任何假设能关联到证据卡，无法判定根因",
                "human_confirmation_reason": fp_reason,
                "insufficient_evidence": True,
            }

        # 以 root_cause 的最终状态为准：无假设/无证据也视为证据不足。
        insufficient = bool(merge_root_cause.get("insufficient_evidence"))

        # fix_suggestion 合并所有假设的修复点
        merge_fix = []
        for h in merge_hypotheses:
            fs = h.get("fix_suggestion")
            if isinstance(fs, dict):
                merge_fix.append(fs)

        # 注意：不再将 hypotheses 的 cause_code 合成为断点（session_id="hypothesis"）。
        # 合成断点是 LLM 假设推理的产物，修复点找不到对应 session 文件，
        # 无法定位到具体修改位置。断点只保留 session 级/merge 级——它们带真实
        # 查询命令与返回内容，修复建议可回溯到具体 session。
        # 假设体系（hypotheses）单独在多假设卡片展示，不进断点统计。

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} 合并压缩完成 "
            f"(summary {len(merge_summary)} 字, "
            f"{len(merge_hypotheses)} 个假设, "
            f"top={merge_root_cause.get('category', '?')})",
            eval_id=evaluation_id)

        # ── 重复上报强制归因修正（代码级兜底，防 LLM 不遵守 prompt 规则）──
        # 人工标注为重复上报时，将所有指向知识/记忆链路的假设（C/E/G/知识责任）
        # 强制修正为 H（挖掘/验证流程去重缺陷，agent 责任）。
        # 重复上报 = 漏洞真实存在但已报过，与知识/记忆无关；知识/记忆有记录
        # 甚至 agent 读到了，问题是 agent 未识别重复性。
        if self._is_duplicate_report(fp_reason):
            corrected = 0
            for h in merge_hypotheses:
                cc = h.get("cause_code", "")
                resp = h.get("responsibility", "")
                if cc in ("C", "E", "G", "D") or resp == "knowledge":
                    h["cause_code"] = "H"
                    h["responsibility"] = "agent"
                    h["hypothesis"] = (
                        "重复上报未识别：agent 未比对已上报漏洞清单/历史记录，"
                        "将已上报过的同根因同链路漏洞再次上报。"
                        + h.get("hypothesis", "")
                    )
                    fs = h.get("fix_suggestion")
                    if isinstance(fs, dict) and fs.get("target") in (
                            "knowledge", "memory"):
                        fs["target"] = "agent_code"
                        fs["action"] = (
                            "增加上报前去重逻辑：agent 在提交漏洞前比对"
                            "已上报漏洞清单/历史确认记录（同根因/同链路），"
                            "识别重复上报并标记为重复，而非作为新漏洞上报。"
                        )
                    corrected += 1
            if corrected:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} 重复上报归因修正："
                    f"{corrected} 个知识链路假设修正为 H/agent"
                    f"（重复上报是流程去重缺陷，非知识问题）")
            # 注意：不改 session 压缩阶段产出的 L2-L7 断点（保留原断点级别）。
            # 重复上报归因 H/L8 只针对 hypothesis 阶段产出的合成 L8 断点
            # （上面循环已改），session 级的 C/E/G/D 断点保留原 breakpoint 级别
            # ——改了会导致 H/L8 断点数膨胀（如 case-20260920-031946 的 mining
            # 5 个 L2-L7 C 断点全部被改成 L8/H，H 总数从合理值膨胀到 357）。

        # ── L4 独立验证（扩展：知识缺失假设也触发）──
        l4_verification = self._verify_l4_independently(
            case_id, chain_type, vuln_title, fp_reason, outcome,
            all_breakpoints, project_id, cancel_cb,
            hypotheses=merge_hypotheses,
            evaluation_id=evaluation_id,
        )

        # ── 假设筛选：只保留有证据卡的假设 ──
        # probability 不再参与筛选；无证据的假设已在上面丢弃。
        # 证据不足的 case 不保留任何假设，避免下游误生成问题单。
        if insufficient:
            merge_hypotheses = []

        # ── 最终状态重算 ──
        # L4/重复上报可能改了 cause_code；报告头部必须与最终假设一致，
        # 不能再沿用 L4 之前算出的 root_cause.category。
        if merge_hypotheses:
            final_top = None
            # L4/重复上报可能改了 cause_code，但对象还是同一个；
            # 优先沿用 L4 之前选定的主因对象。
            if top_hypothesis is not None and top_hypothesis in merge_hypotheses:
                final_top = top_hypothesis
            elif primary_hypothesis:
                final_top = next(
                    (h for h in merge_hypotheses
                     if h.get("hypothesis") == primary_hypothesis), None)
            if final_top is None and primary_cause:
                final_top = next(
                    (h for h in merge_hypotheses
                     if h.get("cause_code") == primary_cause), None)
            if final_top is None:
                final_top = sorted(
                    merge_hypotheses,
                    key=lambda h: (-len(h.get("evidence_refs") or []),
                                   str(h.get("cause_code") or "Z")),
                )[0]
            top_hypothesis = final_top
            merge_root_cause = {
                "category": self._hypothesis_to_category(final_top),
                "description": final_top.get("hypothesis", "无最终分析结果"),
                "human_confirmation_reason": fp_reason,
                "insufficient_evidence": False,
            }
            insufficient = False
        elif insufficient:
            merge_root_cause = {
                "category": "insufficient_evidence",
                "description": (merge_root_cause.get("description")
                                or "证据不足，无法判定根因"),
                "human_confirmation_reason": fp_reason,
                "insufficient_evidence": True,
            }

        # 重算 fix_suggestion（只保留筛选后假设的修复建议）
        merge_fix = []
        for h in merge_hypotheses:
            fs = h.get("fix_suggestion")
            if isinstance(fs, dict):
                merge_fix.append(fs)

        return {
            "session_chain": chain,
            "root_cause": merge_root_cause,
            "hypotheses": merge_hypotheses,
            "primary_cause": (top_hypothesis or {}).get("cause_code", ""),
            "primary_hypothesis": (top_hypothesis or {}).get("hypothesis", ""),
            "audit": merge_result.get("audit") or [],
            "insufficient_evidence": insufficient,
            "label_quality": merge_label_quality,
            "fix_suggestion": merge_fix,
            "compressed_summaries": compressed_summaries,
            "merge_summary": merge_summary,
            "knowledge_memory_summary": merge_km_summary,
            "l0_l7_breakpoints": all_breakpoints,
            "l4_independent_verification": l4_verification,
        }

    @staticmethod
    def _hypothesis_to_category(hypothesis: dict) -> str:
        """从假设的 responsibility 映射到 root_cause.category（兼容旧字段）。"""
        resp = hypothesis.get("responsibility", "")
        cause = hypothesis.get("cause_code", "")
        # cause_code 与 responsibility 对应（A-K 体系）：
        #   A/B/E/F/H/I/J/K → agent 侧
        #   C/D/G → knowledge 侧
        category_map = {
            "A": "reasoning_flaw",       # 该查没查（agent 召回意识不足）
            "B": "query_inaccurate",     # 查询太泛（agent 查询不聚焦）
            "C": "knowledge_gap",        # 查了没得（知识缺失，knowledge 责任）
            "D": "knowledge_error",      # 链路问题（工具失败，knowledge 责任）
            "E": "reasoning_flaw",       # 查到没用（agent 推理未引用）
            "F": "reasoning_flaw",       # 用了没推动（agent 未受影响）
            "G": "knowledge_error",      # 知识误导（knowledge 责任）
            "H": "verification_dimension_missing",  # 流程缺陷/其他 agent 侧
            "I": "reasoning_flaw",       # 调用链中断（agent 数据流分析不足）
            "J": "reasoning_flaw",       # 模型幻觉（agent 推理虚构）
            "K": "verification_dimension_missing",  # 验证否定真漏洞（agent 侧）
        }
        return category_map.get(cause, "reasoning_flaw")

    @staticmethod
    def _enforce_evidence_budget(
        compressed_summaries: list[dict],
    ) -> tuple[int, int]:
        """按 case 总预算截断证据卡，返回 (保留数, 截断数)。

        优先级：部署/配置 > 知识访问 > agent 结论 > 缺失检查 > 反证 > 仓库事实。
        排序是**全局**的（跨 session），避免前面的 session 用低优先级卡片
        挤掉后面 session 的高优先级卡片；同一优先级保持原顺序（稳定）。
        """
        entries: list[tuple[int, int, dict]] = []
        for si, s in enumerate(compressed_summaries):
            for ci, c in enumerate(s.get("evidence_cards") or []):
                if isinstance(c, dict):
                    entries.append((si, ci, c))
        entries.sort(key=lambda e: _EVIDENCE_PRIORITY.get(
            e[2].get("fact_type"), 99))
        keep = {(si, ci) for si, ci, _ in entries[:_EVIDENCE_CARD_BUDGET]}

        total = 0
        truncated = 0
        for si, s in enumerate(compressed_summaries):
            # 索引必须与 entries 一致（entries 用的是原始列表下标），
            # 所以这里不能先过滤非 dict 项——否则 ci 错位，
            # keep 命中错误的卡片，高优先级卡片会被误丢。
            raw = s.get("evidence_cards") or []
            kept = []
            dropped = 0
            for ci, c in enumerate(raw):
                if not isinstance(c, dict):
                    dropped += 1
                    continue
                if (si, ci) not in keep:
                    dropped += 1
                    continue
                kept.append(c)
            s["evidence_cards"] = kept
            s["truncated_evidence"] = dropped
            total += len(kept)
            truncated += dropped
        return total, truncated

    @staticmethod
    def _build_bp_registry(compressed_summaries: list[dict]) -> dict[str, dict]:
        """按 merge prompt 的展示顺序给断点编号（BP-1, BP-2, ...）。

        编号顺序必须与 _build_merge_prompt 的展示顺序完全一致：按
        compressed_summaries 的当前顺序（须已按 step 排序），逐个 session
        逐个 l0_l7 条目递增。只对 breakpoint 非空且不为 "null" 的条目编号。

        注意：本方法每条链各调用一次（mining / verification 分开 merge），
        编号必然重复。落库前必须用 _scoped_ref 拼上链前缀，保证跨链唯一——
        否则因果链汇总时同号断点会互相干扰（实测：verification 的 BP-1
        让 mining 的 BP-1 误判为被引用，过滤失效）。

        Returns:
            {bp_ref: {"session_id", "l0_l7_index", "cause_code", "breakpoint"}}
        """
        registry: dict[str, dict] = {}
        seq = 0
        for s in compressed_summaries:
            sid = s.get("session_id", "")
            for idx, kp in enumerate(s.get("l0_l7") or []):
                if not isinstance(kp, dict):
                    continue
                brk = kp.get("breakpoint")
                if not brk or brk == "null":
                    continue
                seq += 1
                registry[f"BP-{seq}"] = {
                    "session_id": sid,
                    "l0_l7_index": idx,
                    "cause_code": kp.get("cause_code", ""),
                    "breakpoint": brk,
                }
        return registry

    @staticmethod
    def _scoped_ref(bp_ref: str, chain_type: str) -> str:
        """把链内编号转成跨链唯一的引用（MINING-BP-1 / VERIFICATION-BP-1）。"""
        if not bp_ref:
            return ""
        prefix = {"mining": "MINING",
                  "verification": "VERIFICATION"}.get(chain_type, "OTHER")
        return f"{prefix}-{bp_ref}"

    @staticmethod
    def _build_merge_prompt(
        chain_type: str,
        vuln_title: str,
        desc: str,
        fp_reason: str,
        outcome: str,
        compressed_summaries: list[dict],
        bp_registry: dict[str, dict] | None = None,
    ) -> str:
        """构建合并压缩的用户消息。

        bp_registry: 断点编号表，用于给 L0-L7 判定加 BP-n 前缀，
        让 LLM 在假设里引用「supporting_breakpoints」时能精确定位。
        """
        parts = [
            f"漏洞标题：{vuln_title}",
            f"漏洞描述：{desc}",
            f"outcome：{outcome or 'FP'}（FP=误报，FN=漏报）",
            f"人工标注的原因：{fp_reason or '（未给出）'}",
            f"\n以下是 {chain_type} 链中 {len(compressed_summaries)} 个 session "
            f"的独立压缩摘要：\n",
        ]

        # 建立 (session_id, l0_l7_index) → bp_ref 反查，用于打印编号
        ref_by_pos: dict[tuple[str, int], str] = {}
        for ref, info in (bp_registry or {}).items():
            ref_by_pos[(info["session_id"], info["l0_l7_index"])] = ref

        for s in compressed_summaries:
            parts.append(
                f"--- Session {s['step']} (session_id={s['session_id']}) ---"
            )
            parts.append(s.get("summary", ""))
            if s.get("key_findings"):
                parts.append(
                    f"关键发现: {'; '.join(s['key_findings'])}")
            cards = s.get("evidence_cards") or []
            if cards:
                parts.append(
                    "证据卡（假设的 evidence_refs 只能引用下列 evidence_id）:")
                for c in cards:
                    if not isinstance(c, dict):
                        continue
                    parts.append("  - " + json.dumps({
                        "evidence_id": c.get("evidence_id", ""),
                        "event_idx": c.get("event_idx"),
                        "source": c.get("source", ""),
                        "quote": c.get("quote", ""),
                        "fact_type": c.get("fact_type", ""),
                    }, ensure_ascii=False))
            if s.get("insufficient_evidence"):
                parts.append(
                    f"本 session 证据不足：{s.get('insufficient_reason', '')}")
            l0_l7 = s.get("l0_l7") or []
            if l0_l7:
                if bp_registry:
                    # 逐条打印并附链内 BP 编号，供假设的 supporting_breakpoints
                    # 引用（落库时会自动加链前缀转成跨链唯一）
                    parts.append("L0-L7 判定（用下方 BP-n 编号引用）:")
                    for idx, kp in enumerate(l0_l7):
                        if not isinstance(kp, dict):
                            continue
                        ref = ref_by_pos.get((s["session_id"], idx))
                        body = json.dumps(kp, ensure_ascii=False)
                        if ref:
                            parts.append(f"  {ref}: {body}")
                        else:
                            parts.append(f"  (无断点，不编号): {body}")
                else:
                    parts.append(
                        f"L0-L7 判定: {json.dumps(l0_l7, ensure_ascii=False)}")
            parts.append("")

        parts.append(
            "请基于以上所有 session 的独立压缩摘要，合并分析并输出最终结论。"
        )
        return "\n".join(parts)

    @staticmethod
    def _is_duplicate_report(fp_reason: str) -> bool:
        """判断人工标注原因是否为"重复上报"。

        重复上报 = 漏洞真实存在但已作为历史记录上报过（同根因/同链路），
        agent 不该再报一次。这是挖掘/验证流程的去重缺陷，不是知识问题。

        关键词匹配（容忍前缀/后缀/标点差异）：
        - "重复上报" / "重复" / "已上报" / "已报过" / "重复提交"
        - "重复误报"
        """
        if not fp_reason:
            return False
        reason = str(fp_reason).strip()
        if not reason:
            return False
        keywords = (
            "重复上报", "重复提交", "重复误报", "已上报", "已报过",
            "重复发现", "重复报告", "重复",
        )
        return any(kw in reason for kw in keywords)

    def _verify_l4_independently(
        self,
        case_id: str,
        chain_type: str,
        vuln_title: str,
        fp_reason: str,
        outcome: str,
        all_breakpoints: list[dict],
        project_id: str,
        cancel_cb=None,
        hypotheses: list[dict] | None = None,
        evaluation_id: str = "",
    ) -> dict | None:
        """L4 独立验证：当存在 L2/A 断点时，主动搜索知识库验证。

        触发条件（任一满足即触发）：
        - L2 断点（cause_code A，agent 该查没查）
        - 假设 cause_code=A（该查没查）

        只回答一个问题：agent 没查的那个来源里，到底有没有对应知识。
        G（知识/记忆内容错误）不触发 L4，也不允许被 L4 改判为 A。

        闭环逻辑：
        - L2 断点（cause_code A）→ 主动查知识库
          - 知识库有知识（l4=true）→ 责任在 agent，cause_code 保持 A
          - 知识库没有知识（l4=false）→ 责任在知识库，cause_code 改为 C
        """
        has_l2_break = any(
            bp.get("breakpoint") == "L2" for bp in all_breakpoints
        )
        has_a_hypothesis = any(
            h.get("cause_code") == "A" for h in (hypotheses or [])
        )
        if not has_l2_break and not has_a_hypothesis:
            return None

        # ── 重复上报豁免：人工标注为"重复上报"时，不触发 L4 知识库验证 ──
        # 重复上报是 agent 挖掘/验证流程的去重缺陷（漏洞真实存在但已报过），
        # 与知识/记忆无关——知识/记忆里有记录，agent 还读到了，问题在于
        # agent 未识别重复性。若走 L4 验证，知识库必然没有"重复判定"知识，
        # 会把 L2/A 错误修正为 L4/C（知识缺失），归因方向完全错误。
        if self._is_duplicate_report(fp_reason):
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 人工标注为重复上报，"
                f"跳过 L4 知识库验证（重复上报是流程/去重问题，"
                f"与知识/记忆无关，不归因知识链路）")
            return {
                "l4_knowledge_exists": None,
                "candidate_files": 0,
                "matched_files": [],
                "summary": "重复上报——agent 流程去重缺陷，跳过知识库验证",
                "skipped_reason": "duplicate_report",
            }

        # ── 从断点中提取 LLM 分析产出的知识检索问题 ──
        # LLM 在 session 分析时已判定 agent 需要什么知识，并生成 kb_search_query
        # 用它替代从 fp_reason 规则分词，实现"缺什么才问什么"
        kb_search_queries: list[str] = []
        for bp in all_breakpoints:
            q = bp.get("kb_search_query", "").strip()
            if q:
                kb_search_queries.append(q)
        # 去重保持顺序
        seen_q = set()
        kb_search_queries = [q for q in kb_search_queries
                             if not (q in seen_q or seen_q.add(q))]

        # ── 无检索问题：不查知识库 ──
        # LLM 判定有 L2 断点或 A 假设，但没产出 kb_search_query，
        # 说明 LLM 无法确定该查什么——不查 Athena（查了也是白查）。
        if not kb_search_queries:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 检测到"
                f"{'L2 断点' if has_l2_break else ''}"
                f"{'+' if has_l2_break and has_a_hypothesis else ''}"
                f"{'A/该查没查假设' if has_a_hypothesis else ''}，"
                f"但无知识检索问题，跳过 L4 知识库验证")
            return {
                # None=未判定。知识库没被查过，不能返回 False（会被上层
                # 误读成「知识库确实没有该知识」→ 错误归因到知识库）
                "l4_knowledge_exists": None,
                "candidate_files": 0,
                "matched_files": [],
                "summary": "LLM 未产出知识检索问题，无法定向查询知识库",
                "skipped_reason": "no_kb_search_queries",
            }

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} 检测到"
            f"{'L2 断点' if has_l2_break else ''}"
            f"{'+' if has_l2_break and has_a_hypothesis else ''}"
            f"{'A/该查没查假设' if has_a_hypothesis else ''}，"
            f"启动知识库主动验证 L4 (project_id={project_id}, "
            f"queries={kb_search_queries})")

        try:
            from .knowledge_verifier import KnowledgeVerifier
            verifier = KnowledgeVerifier()
            result = verifier.verify(
                vuln_title=vuln_title,
                fp_reason=fp_reason,
                project_id=project_id,
                cancel_cb=cancel_cb,
                evaluation_id=evaluation_id,
                kb_search_queries=kb_search_queries,
            )
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 独立验证完成: "
                f"l4={result.get('l4_knowledge_exists')}, "
                f"candidates={result.get('candidate_files', 0)}")

            # ── 闭环反馈：根据 L4 验证结果修正断点 ──
            l4_exists = result.get("l4_knowledge_exists")
            if l4_exists is None:
                # 未判定：知识库查询失败 / 问题属环境事实类 / 无可用知识源。
                # 此时既不能说「知识库有」（不修正 A），也不能说「知识库没有」
                # （不修正成 C）。保持原断点，并在 L4 结果里标明原因，
                # 让报告能区分「知识库确实缺失」和「知识库没查成」。
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} L4 未判定（{result.get('summary', '')}），"
                    f"断点不做修正")
            elif l4_exists is False:
                # 知识库没有相关知识 → 责任在知识库（覆盖度缺口）
                # L2 断点（该查没查，cause_code A）→ L4 断点（查了没得，cause_code C）
                # 查询超时也按「没有该知识」处理，但带上 query_timeout 标记，
                # 让报告读者知道这是查询没拿到结果，不是知识库确认过没有。
                _timed_out = bool(result.get("query_timeout"))
                _timeout_secs = result.get("query_timeout_secs")
                _timeout_note = (
                    f"（知识库访问 {_timeout_secs}s 超时，未返回结果）"
                    if _timed_out and _timeout_secs else
                    ("（知识库访问超时，未返回结果）" if _timed_out else ""))
                changed = 0
                for bp in all_breakpoints:
                    if bp.get("breakpoint") == "L2" \
                            and bp.get("cause_code") == "A":
                        bp["breakpoint"] = "L4"
                        bp["cause_code"] = "C"
                        bp["l4_exists"] = False
                        if _timed_out:
                            bp["query_timeout"] = True
                            bp["query_timeout_secs"] = _timeout_secs
                        # 改写 query_content 消除矛盾：C（查了没得）的语义是
                        # 知识库缺知识，不能保留 L2 的"agent 未发起访问"表述。
                        # 提取"推理任务需要什么知识"部分，改为知识库缺口的描述。
                        old_qc = bp.get("query_content", "")
                        need_part = old_qc
                        import re as _re
                        m = _re.search(r"[（(](.*?)[)）]", old_qc)
                        if m:
                            need_part = m.group(1).strip()
                            for pre in ("具体说明需要什么知识：",
                                        "需要", "需"):
                                if need_part.startswith(pre):
                                    need_part = need_part[len(pre):].strip()
                                    break
                        bp["query_content"] = (
                            f"知识库缺少该知识（推理任务需要：{need_part}）"
                            f" | L4 独立验证（由测评系统代为发起知识库查询）："
                            f"知识库中未找到能消减此误报的知识{_timeout_note}"
                            f"（{result.get('summary', '')}）"
                        )
                        changed += 1
                if changed:
                    log("ROOT_CAUSE",
                        f"case {case_id}: {chain_type} L4 验证反馈："
                        f"知识库无相关知识，{changed} 个 L2 断点"
                        f"修正为 L4/cause_code C（知识库覆盖度缺口）")
                # knowledge 责任假设：知识确实缺失，假设成立
                # 同步修正 hypotheses：cause_code A→C（该查没查→查了没得），
                # responsibility 保持 knowledge，fix_suggestion.target 保持 knowledge
                for h in (hypotheses or []):
                    if h.get("cause_code") == "A":
                        h["cause_code"] = "C"
                        h["responsibility"] = "knowledge"
                        if _timed_out:
                            h["query_timeout"] = True
                        old_evid = h.get("evidence", "")
                        h["evidence"] = (
                            f"{old_evid} | L4 独立验证（由测评系统代为发起"
                            f"知识库查询）：知识库中未找到"
                            f"能消减此误报的知识{_timeout_note}"
                            f"（{result.get('summary', '')}），"
                            f"按知识缺失处理，责任在知识库（查了没得）"
                        )
                        # 修正 fix_suggestion：若 target=agent_prompt（改 prompt 增加
                        # 查询意识），但知识确实缺失，应改为补知识
                        fs = h.get("fix_suggestion")
                        if isinstance(fs, dict) and fs.get("target") in (
                                "agent_prompt", "agent_code"):
                            fs["target"] = "knowledge"
                            fs["action"] = (
                                f"原建议修改 agent，但 L4 验证发现知识库中"
                                f"无相关知识。改为：补充知识库内容"
                                f"（{fs.get('location', '')}）"
                            )
            elif l4_exists is True:
                # 知识库有知识 → 责任在 agent（该查没查），cause_code 保持 A
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} L4 验证反馈："
                    f"知识库有相关知识，L2 断点保持 cause_code A"
                    f"（agent 该查没查，责任在 agent）")
                # knowledge 责任假设：知识存在但 agent 没查到 → 责任在 agent
                # 只修正 cause_code=A 的假设；G（知识/记忆内容错误）不得被改判。
                for h in (hypotheses or []):
                    if h.get("cause_code") == "A" \
                            and h.get("responsibility") == "knowledge":
                        h["responsibility"] = "agent"
                        h["cause_code"] = "A"
                        old_evid = h.get("evidence", "")
                        h["evidence"] = (
                            f"{old_evid} | L4 独立验证（由测评系统代为发起"
                            f"知识库查询）：知识库中存在"
                            f"相关知识（{result.get('summary', '')}），"
                            f"责任在 agent（该查没查）"
                        )
                        # 修正 fix_suggestion target
                        fs = h.get("fix_suggestion")
                        if isinstance(fs, dict) and fs.get("target") == "knowledge":
                            fs["target"] = "agent_prompt"
                            fs["action"] = (
                                f"原建议补充知识，但 L4 验证发现知识库已有相关知识。"
                                f"改为：{fs.get('action', '')}"
                            )
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} L4 验证反馈："
                    f"knowledge 责任假设修正为 agent"
                    f"（知识库有知识，agent 该查没查）")

            return result
        except Exception as e:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 独立验证失败")
            log_error(evaluation_id, "ROOT_CAUSE", e)
            raise

    def _compress_session_chunked(
        self, evaluation_id: str, case_id: str, chain_type: str,
        step_idx: int, session_id: str,
        events: list[RawEvent], vuln_title: str, desc: str,
        fp_reason: str, outcome: str,
        chain: list[str], cancel_cb=None,
        max_ctx_override: int | None = None,
    ) -> dict:
        """对超大 session 按事件分片压缩，再合并分片摘要。

        策略：
        1. 用本地 DeepSeek V4 tokenizer 计算每片 token 预算
        2. 按事件边界切分（不截断单个事件）
        3. 每片独立调 LLM 压缩
        4. 合并所有分片摘要为最终结果

        max_ctx_override: 强制指定上下文上限（如 400 超限后按 204800 重切）。
        """
        max_ctx = max_ctx_override or llm_mod.get_max_context_tokens() or 1048576
        # 预留输出空间：按上下文窗口的 20% 动态计算（1M→约 21 万，
        # 204800→约 4 万），不能用固定的 4096
        _reserve = llm_mod.get_response_reserve_tokens(max_ctx)
        usable_tokens = max_ctx - _reserve
        # 框架开销：system prompt 全文 + 漏洞标题/描述/outcome/标注原因/session 头
        overhead_tokens = llm_mod.estimate_tokens(
            _SYSTEM_PROMPT + vuln_title + desc + (fp_reason or "")
            + chain_type + session_id + " " * 300)
        # 再留 2% 余量吸收分片拼接时的换行/标签开销
        chunk_token_limit = max(
            int((usable_tokens - overhead_tokens) * 0.98), 1000)

        # 按事件边界切分 session_text
        event_texts = []
        for ev in events:
            et = ev.event_type or "UNKNOWN"
            tool = ev.tool_name or ""
            if et == "REASONING":
                text = _extract_text(ev.output_json)
                if text:
                    event_texts.append(f"[推理] {text}")
            elif et == "TEXT":
                text = _extract_text(ev.output_json)
                if text:
                    event_texts.append(f"[文本] {text}")
            elif et == "TOOL_CALL":
                text = _extract_text(ev.input_json)
                kg_flag = ""
                if ev.is_kg_interaction:
                    kg_flag = " [知识库访问]"
                elif ev.is_memory_interaction:
                    kg_flag = " [记忆访问]"
                event_texts.append(f"[工具调用] {tool}{kg_flag}: {text}")
            elif et == "TOOL_RESULT":
                text = _extract_text(ev.output_json)
                kg_flag = ""
                if ev.is_kg_interaction:
                    kg_flag = " [知识库返回]"
                elif ev.is_memory_interaction:
                    kg_flag = " [记忆返回]"
                event_texts.append(f"[工具返回] {tool}{kg_flag}: {text}")
            elif et == "SESSION_START":
                event_texts.append(f"[会话开始] session={session_id}")

        # 贪心打包事件到分片（按 token 精确计算，不做 chars 估算）
        chunks = []
        current = []
        current_tokens = 0
        for et in event_texts:
            et_tokens = llm_mod.estimate_tokens(et) + 1
            if current_tokens + et_tokens > chunk_token_limit and current:
                chunks.append(current)
                current = []
                current_tokens = 0
            current.append(et)
            current_tokens += et_tokens
        if current:
            chunks.append(current)

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} session {step_idx+1}/{len(chain)} "
            f"分片 {len(chunks)} 片 (每片上限 {chunk_token_limit} tokens, "
            f"{len(events)} 事件)",
            eval_id=evaluation_id)

        # 压缩单个分片；输出被截断时重试（网关随机路由，重试可能落到
        # 上下文更大的后端，输出空间就够了）。
        def _compress_one(chunk_lines, label):
            if cancel_cb:
                cancel_cb()
            chunk_text = "\n".join(chunk_lines)
            user_content = (
                f"漏洞标题：{vuln_title}\n"
                f"漏洞描述：{desc}\n"
                f"outcome：{outcome or 'FP'}（FP=误报，FN=漏报）\n"
                f"人工标注的原因：{fp_reason or '（未给出）'}\n\n"
                f"Session {step_idx+1}/{len(chain)} {label} "
                f"(session_id={session_id}):\n"
                f"{chunk_text}"
            )
            msgs = [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ]
            last_err = None
            for attempt in range(_TRUNCATION_RETRIES + 1):
                try:
                    return llm_mod.chat_json(
                        msgs, temperature=0, cancel_cb=cancel_cb,
                        max_tokens=llm_mod.get_response_reserve_tokens(),
                        required_keys=["summary"])
                except llm_mod.LLMOutputTruncatedError as e:
                    last_err = e
                    if attempt >= _TRUNCATION_RETRIES:
                        break
                    log("ROOT_CAUSE",
                        f"case {case_id}: {chain_type} session {step_idx+1} "
                        f"{label} 输出截断 (content_len={e.content_len})，"
                        f"重试 {attempt+1}/{_TRUNCATION_RETRIES}",
                        eval_id=evaluation_id)
                    time.sleep(_TRUNCATION_RETRY_DELAY)
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} session {step_idx+1} "
                f"{label} 输出截断，{_TRUNCATION_RETRIES} 次重试后仍失败",
                eval_id=evaluation_id)
            raise last_err

        # 并发压缩各分片
        def _compress_chunk(args):
            chunk_idx, chunk_lines = args
            try:
                r = _compress_one(
                    chunk_lines, f"分片 {chunk_idx+1}/{len(chunks)}")
            except Exception as e:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} session {step_idx+1} "
                    f"分片 {chunk_idx+1}/{len(chunks)} 压缩失败",
                    eval_id=evaluation_id)
                log_error(evaluation_id, "ROOT_CAUSE", e)
                raise
            return chunk_idx, r

        chunk_tasks = [(i, c) for i, c in enumerate(chunks)]
        chunk_futures = llm_mod.submit_llm_batch(
            _compress_chunk, chunk_tasks, cancel_cb=cancel_cb)

        chunk_results = {}
        for fut in chunk_futures:
            try:
                cidx, cr = fut.result()
                chunk_results[cidx] = cr
            except Exception as e:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} session {step_idx+1} "
                    f"分片压缩异常: {e}",
                    eval_id=evaluation_id)
                raise

        # 合并分片摘要
        all_summaries = []
        all_key_findings = []
        all_l0_l7 = []
        all_evidence_cards = []
        all_retention = []
        any_insufficient = False
        insufficient_reasons = []
        for cidx in sorted(chunk_results.keys()):
            cr = chunk_results[cidx]
            all_summaries.append(cr.get("summary", ""))
            all_key_findings.extend(cr.get("key_findings") or [])
            all_l0_l7.extend(cr.get("l0_l7") or [])
            all_evidence_cards.extend(cr.get("evidence_cards") or [])
            all_retention.extend(cr.get("retention_check") or [])
            if cr.get("insufficient_evidence"):
                any_insufficient = True
                if cr.get("insufficient_reason"):
                    insufficient_reasons.append(cr["insufficient_reason"])

        # 如果只有一片，直接返回
        if len(chunk_results) == 1:
            return list(chunk_results.values())[0]

        # 多片合并：用 LLM 合并分片摘要
        merge_content = (
            f"漏洞标题：{vuln_title}\n"
            f"漏洞描述：{desc}\n"
            f"outcome：{outcome or 'FP'}\n"
            f"人工标注的原因：{fp_reason or '（未给出）'}\n\n"
            f"以下是 session {session_id} 的 {len(chunks)} 个分片的独立压缩摘要，"
            f"请合并为一份完整的结构化摘要：\n\n"
            + "\n---\n".join(all_summaries)
        )
        merge_msgs = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": merge_content},
        ]
        try:
            merged = llm_mod.chat_json(
                merge_msgs, temperature=0, cancel_cb=cancel_cb,
                required_keys=["summary"])
            # 保留各分片的 l0_l7 和 key_findings
            merged.setdefault("key_findings", all_key_findings)
            merged.setdefault("l0_l7", all_l0_l7)
            merged.setdefault("evidence_cards", all_evidence_cards)
            merged.setdefault("retention_check", all_retention)
            merged.setdefault("insufficient_evidence", any_insufficient)
            merged.setdefault(
                "insufficient_reason",
                "；".join(insufficient_reasons) if insufficient_reasons else "")
            return merged
        except Exception as e:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} session {step_idx+1} "
                f"分片合并失败")
            log_error(evaluation_id, "ROOT_CAUSE", e)
            raise

    def _format_session_events(
        self, session_id: str, events: list[RawEvent],
    ) -> str:
        """格式化 session 的全部事件为文本。"""
        if not events:
            return f"（session {session_id} 无事件）"

        lines = []
        for idx, ev in enumerate(events):
            et = ev.event_type or "UNKNOWN"
            ts = ev.timestamp_ms or 0
            tool = ev.tool_name or ""
            # 事件索引前缀：证据卡必须能回指到具体事件（event_idx）
            p = f"[E{idx}] "

            if et == "REASONING":
                text = _extract_text(ev.output_json)
                if text:
                    lines.append(f"{p}[推理] {text}")
            elif et == "TEXT":
                text = _extract_text(ev.output_json)
                if text:
                    lines.append(f"{p}[文本] {text}")
            elif et == "TOOL_CALL":
                text = _extract_text(ev.input_json)
                # 标记知识访问
                kg_flag = ""
                if ev.is_kg_interaction:
                    kg_flag = " [知识库访问]"
                elif ev.is_memory_interaction:
                    kg_flag = " [记忆访问]"
                lines.append(f"{p}[工具调用] {tool}{kg_flag}: {text}")
                # opencode/turing 格式：tool part 带 state 时 input 和 output
                # 同在一个 TOOL_CALL 事件里（parser._classify 返回 TOOL_CALL）。
                # 只打 input 会让知识库/记忆的返回内容彻底丢失，LLM 只能报
                # 「无法确认返回内容」，进而误判 L4/L6。这里补打 output。
                result_text = _extract_text(ev.output_json)
                if result_text:
                    ret_flag = ""
                    if ev.is_kg_interaction:
                        ret_flag = " [知识库返回]"
                    elif ev.is_memory_interaction:
                        ret_flag = " [记忆返回]"
                    lines.append(
                        f"{p}[工具返回] {tool}{ret_flag}: {result_text}")
            elif et == "TOOL_RESULT":
                text = _extract_text(ev.output_json)
                # 标记知识访问返回
                kg_flag = ""
                if ev.is_kg_interaction:
                    kg_flag = " [知识库返回]"
                elif ev.is_memory_interaction:
                    kg_flag = " [记忆返回]"
                lines.append(f"{p}[工具返回] {tool}{kg_flag}: {text}")
            elif et == "SESSION_START":
                lines.append(f"{p}[会话开始] session={session_id}")

        return "\n".join(lines) if lines else f"（session {session_id} 无有效事件）"


def _extract_text(obj) -> str:
    """从 input_json/output_json 提取文本。"""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for key in ("content", "text", "message", "reasoning",
                     "command", "thinking", "description", "title", "result"):
            val = obj.get(key)
            if val and isinstance(val, str):
                return val
        return json.dumps(obj, ensure_ascii=False)
    return str(obj)
