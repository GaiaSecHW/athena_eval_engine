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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..infra import llm as llm_mod
from ..infra.parallel import iter_completed
from ...infrastructure.log_util import log

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
如果 session 中没有知识访问断点，但存在其他导致误报的问题（如验证维度遗漏、推理逻辑错误、验证不充分等），执行 L8 判定。

# 事实依据要求

**所有分析必须基于 session 中的实际内容，禁止推测。**
- returned_content 字段：必须直接引用或概括 session 中 `[知识库返回]`/`[记忆返回]` 标记后的实际返回文本，禁止用"可能包含"、"推测"等猜测性语言描述返回内容
- query_content 字段：必须填写 agent 实际执行的查询命令或查询参数，从 `[知识库访问]`/`[记忆访问]` 标记后的文本中提取
- summary 和 key_findings 中的每一句话都必须能在 session 文本中找到对应的事实依据，禁止添加 session 中不存在的信息
- 如果知识返回内容为空或无法判断，直接写"返回内容为空"或"无法从 session 文本中确认"，不要猜测

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
| L1 | 需要知识？ | 推理任务是否需要外部知识支撑 | —（不产生断链） | — |
| L2 | 发起访问？ | agent 是否实际调用了知识库/记忆工具 | A 该查没查 | Agent |
| L3 | 查询准确？ | 查询内容是否聚焦当前任务（含具体漏洞类型/框架名/函数名等） | B 查询太泛/不聚焦 | Agent |
| L4 | 知识存在？ | 知识库是否有对应知识（返回内容非空且相关） | C 查了没得 | 知识方 |
| L5 | 成功取回？ | 返回内容是否有效（无 error/timeout/exception） | D 链路问题 | Agent + 知识方 |
| L6 | 被使用？ | agent 推理文本是否引用了知识返回内容 | E 查到没用 | Agent |
| L7 | 影响结论？ | 知识是否影响了判定结论 | F 用了没推动 / G 导致误判 | F: Agent/知识方, G: 知识方 |
| L8 | 其他问题？ | 知识访问链路全程通过（L7=positive）后，agent 仍误报。分析是否存在知识访问之外的问题导致误报 | H 流程缺陷/其他 / I 调用链中断 / J 模型幻觉 / K 验证否定真漏洞 | Agent |

## L6 判定关键规则

L6 判定"agent 推理文本是否引用了知识返回内容"，判定方法：
- 在 session 的 `[推理]` 文本中搜索是否出现了知识返回内容的关键信息（如具体技术名词、建议、模式名等）
- 只有推理文本中明确引用了知识返回内容的具体信息时，L6 才为 true
- 如果 agent 只是读取了知识但推理中未提及返回内容的具体信息，L6 为 false
- **L6=false 时，returned_content 必须如实概括 `[记忆返回]`/`[知识库返回]` 后的实际文本内容，不要添加"可能包含"等推测性描述**

## 断点归属规则

断点应反映导致误报的**主要原因**，不是所有 L6=false 的知识访问都是误报根因。
- 如果 agent 读了知识但没用（L6=false），但这与人工标注的误报原因无关（如误报原因是"接口非对外暴露"），则该知识访问的 L6=false 只是记录，不是主要断点
- 此时主要断点应为 L8（非知识访问维度），从 H/I/J/K 中选最匹配的，
  在 query_content 中填写人工标注的误报原因
- 只有人工标注的误报原因与知识访问直接相关时（如"该查没查"、"查了错误的知识"），才将知识访问断点作为主要断点

判定规则：
- 逐级判定，不通过的级别即为断点，后续级别填 null
- L7 三种结果：positive（正确+一致=正向）、negative（错误+一致=负向，知识方向对但内容有误/过时）、null（不一致=中性，知识未影响结论）
- **session 中没有知识访问行为时的判定（关键）**：
  - 仍要判 L1：推理任务是否需要外部知识支撑？判断标准：agent 面对的推理任务是否需要知识库/记忆中已有的方法、模式、经验来支撑。包括：
    * 验证网络可达性 → 需要接口暴露面知识（业务环境知识）
    * 判断接口暴露面 → 需要不可调用文档（记忆）
    * 评估防护机制有效性 → 需要部署架构约束知识
    * 识别漏洞模式 → 需要漏洞挖掘模式知识
  - 如果 L1=true（需要知识）但 L2=false（agent 没发起访问）→ 断点 L2，cause_code 填 "A"（该查没查）
    - 在 l0_l7 数组中新增一条记录，l0_source 填空，l1_need=true，l2_initiated=false，L3-L7 填 null
    - query_content 填"agent 未发起知识/记忆访问，但推理任务需要知识支撑（具体说明需要什么知识）"
    - returned_content 填空
  - 如果 L1=false（不需要知识），L2-L7 全部填 null，不产生知识访问断点
- 如果 L1-L7 全部通过（L7=positive），但 agent 仍误报，执行 L8 判定：
  - L8 断点表示知识访问链路无问题，但存在其他导致误报的原因
  - 常见场景：推理逻辑错误、验证条件不充分等（注意：验证维度遗漏不一定是 L8——如果遗漏的维度需要知识支撑，应是 L2 断点）
  - cause_code 填 "H"，breakpoint 填 "L8"
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
  "summary": "结构化摘要，3000字以内。必须包含知识与记忆访问的总结与影响",
  "key_findings": ["关键发现1", "关键发现2"],
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
      "query_content": "agent 实际执行的查询命令或参数（从 session 文本提取，不要概括）",
      "returned_content": "知识/记忆实际返回的文本内容概括（基于 [知识库返回]/[记忆返回] 标记后的原文，不要推测）",
      "fix_suggestion": "基于本 session 具体问题的修复建议：哪个命令/查询有问题就改哪里。如查询太泛→改为按当前漏洞类型聚焦查询；知识缺失→明确指出知识库缺什么；返回错误→指出返回了什么错误/异常。必须可定位到本 session 的具体位置，禁止空泛建议（如'增加去重逻辑'必须说明在哪个命令/步骤加）"
    }
  ]
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
- returned_content 字段：必须概括 session 摘要中记录的实际返回内容，禁止用"可能包含"、"推测"等猜测性语言
- 禁止使用"可能"、"或许"、"推测"等不确定语言描述事实
- 但对"假设"本身可以用概率描述不确定性，这是分析的不确定性，不是事实的不确定性

**probability 语义（重要）**：probability 是该假设是**根因的置信度**（0-1），
表示"该假设成为这个 case 真正根因的可能性有多大"。**各假设概率不要求
归一（和不需要等于 1）**——多个假设可以都高（多因素叠加）或都低
（证据不足）。判定依据：
- 0.7-1.0：证据充分，强烈支持该假设是根因
- 0.4-0.6：有部分证据支持，可能是根因之一
- 0.1-0.3：证据不足，可能性较低
- 0.05：微弱可能，作为兜底考虑

# 任务

## 合并模式 — 多假设分析

将多个 session 的压缩摘要合并为最终结论。**不要只给一个根因，要列出多个可能的根因假设。**

误报/漏报往往是多因素叠加的结果，单一归因会遗漏修复点。你需要从多个角度分析，列出至少 2 个、最多 5 个根因假设，每个假设给出 probability（根因置信度）和对应的修复方案。

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
- **如果 session 中没有知识访问行为**：
  - 判 L1：推理任务是否需要知识支撑（如验证网络可达性、判断接口暴露面、评估防护机制等需要知识库中的方法/经验）
  - L1=true 且 L2=false → 断点 L2，cause_code "A"（该查没查）
  - L1=false → 不产生知识访问断点
- 如果知识访问链路全程通过（L7=positive）但 agent 仍误报，必须输出 L8 断点：
  - L8 断点表示知识访问链路无问题，但存在其他非知识访问的原因导致误报/漏报
  - cause_code 从非知识访问维度选（与 A-K 体系一致）：
    * H（流程缺陷/其他）— 挖掘方向偏差、重复上报未识别等 agent 流程问题
    * I（调用链中断）— 找到 sink 未追踪到 source
    * J（模型幻觉）— 虚构不存在的防护/漏洞逻辑
    * K（验证否定真漏洞）— 挖掘 CONFIRMED 但验证否定
  - breakpoint 填 "L8"
  - query_content 填问题总结（如"验证逻辑不充分：验证条件错误"）
  - l0_source 填空字符串
- L8 仅覆盖知识访问链路确实无问题的场景（L7=positive 或 L1=false）
- **注意：验证维度遗漏不一定是 L8**——如果遗漏的验证维度需要知识支撑（如不知道怎么查网络可达性），应判 L2 断点（该查没查），不是 L8

### 断点归属规则

断点应反映导致误报的**主要原因**，不是所有 L6=false 的知识访问都是误报根因。
- 如果 agent 读了知识但没用（L6=false），但这与人工标注的误报原因无关，则该知识访问的 L6=false 只是记录，不是主要断点
- 如果 agent 没查知识（L2=false），但推理任务需要知识支撑（L1=true），这是 L2 断点（该查没查），不是 L8
- 只有人工标注的误报原因与知识访问无关（L1=false）或知识访问链路全程通过（L7=positive）时，才判 L8

# 输出格式

合并模式返回 JSON：
{
  "summary": "合并后的最终摘要，3000字以内",
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
      "hypothesis": "假设描述（如'Agent 将路由定义等同于公网可达'）",
      "probability": 0.4,  # 根因置信度（0-1），不要求归一
      "responsibility": "agent|knowledge|external_data_source|eval_process",
      "cause_code": "A/B/C/D/E/F/G/H/I/J/K",
      "evidence": "session 中的具体事实依据（引用摘要内容，不要推测）",
      "session_id": "该假设主要基于的 session_id（从上方 Session 摘要中引用，可逗号分隔多个；若证据来自多个 session 的合并判断则列全，禁止编造不存在的 session_id）",
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
      "query_content": "agent 实际执行的查询命令（从摘要中提取原文，不要概括）",
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
            else:
                mining_result = self._analyze_chain(
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
        """从种子 session 出发展开完整调用链（祖先 + 子孙），根→叶子顺序。

        与 DTS 问题单 _query_session_chains._expand_chain 完全一致——
        保证 case_matching / 根因分析 / DTS 三处展示的 session 链同源同逻辑。
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

        # 向下找子孙
        queue = list(seeds)
        while queue:
            sid = queue.pop(0)
            for child in all_children_map.get(sid, []):
                if child not in chain_ids:
                    chain_ids.add(child)
                    queue.append(child)

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
            """压缩单个 session，返回含 step/session_id/summary 等的 dict。"""
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

            try:
                result = llm_mod.chat_json(
                    messages,
                    temperature=0,
                    cancel_cb=cancel_cb,
                )
            except Exception as e:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} session {i+1}/{len(chain)} "
                    f"LLM 压缩失败: {str(e)[:200]}",
                    eval_id=evaluation_id)
                result = {
                    "summary": session_text[:3000] if session_text else "",
                    "key_findings": [],
                    "l0_l7": [],
                }

            return {
                "session_id": sid,
                "step": i + 1,
                "summary": result.get("summary", ""),
                "key_findings": result.get("key_findings") or [],
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
                    f"case {case_id}: {chain_type} session 压缩失败: {str(e)[:200]}",
                    eval_id=evaluation_id)
                continue

            compressed_summaries.append(cs)

            # 收集断点
            l0_l7 = cs.get("l0_l7") or []
            for kp in l0_l7:
                if isinstance(kp, dict) and kp.get("breakpoint") \
                        and kp.get("breakpoint") != "null":
                    all_breakpoints.append({
                        "session_id": cs["session_id"],
                        **kp,
                    })

            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} session {cs['step']}/{len(chain)} "
                f"独立压缩完成 (summary {len(cs.get('summary', ''))} 字, "
                f"{len(l0_l7)} 条知识访问)",
                eval_id=evaluation_id)

        # 按 step 排序，保证拓扑序
        compressed_summaries.sort(key=lambda x: x["step"])

        # ── 第二步：合并所有 session 摘要，输出最终根因 ──
        merge_user_content = self._build_merge_prompt(
            chain_type, vuln_title, desc, fp_reason, outcome,
            compressed_summaries,
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
            )
        except Exception as e:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 合并压缩失败: {str(e)[:200]}",
                eval_id=evaluation_id)
            merge_result = {
                "summary": " | ".join(
                    s.get("summary", "") for s in compressed_summaries),
                "hypotheses": [{
                    "hypothesis": f"合并压缩 LLM 调用失败: {str(e)[:200]}",
                    "probability": 1.0,
                    "responsibility": "agent",
                    "cause_code": "H",
                    "evidence": "",
                    "agent_can_resolve": False,
                    "blocked_by": "LLM 调用失败",
                    "needed_external_data": [],
                    "fix_suggestion": {
                        "target": "agent_prompt",
                        "location": "",
                        "action": "",
                        "expected_effect": "",
                    },
                }],
                "label_quality": {
                    "precision": "precise",
                    "reason": "",
                    "follow_up_questions": [],
                },
                "l0_l7": [],
            }

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

        # ── 从多假设提取兼容字段（root_cause + fix_suggestion）──
        # 取最高概率假设作为 root_cause（向后兼容）
        top_hypothesis = max(merge_hypotheses, key=lambda h: h.get("probability", 0)) \
            if merge_hypotheses else None
        merge_root_cause = {
            "category": self._hypothesis_to_category(top_hypothesis) if top_hypothesis else "unknown",
            "description": top_hypothesis.get("hypothesis", "无最终分析结果") if top_hypothesis else "无最终分析结果",
            "human_confirmation_reason": fp_reason,
        } if top_hypothesis else {
            "category": "unknown",
            "description": "无最终分析结果",
        }

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
        )

        # ── 假设可信度筛选 ──
        # 只保留 P>=0.6 的假设；若全部 <0.6，保留 P 最高的那条。
        # top 假设（merge_root_cause 用的）一定被保留，故 merge_root_cause 不变。
        high_conf = [h for h in merge_hypotheses
                     if (h.get("probability") or 0) >= 0.6]
        if high_conf:
            merge_hypotheses = high_conf
        elif merge_hypotheses:
            top_h = max(merge_hypotheses,
                        key=lambda h: h.get("probability") or 0)
            merge_hypotheses = [top_h]
        else:
            merge_hypotheses = []
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
    def _build_merge_prompt(
        chain_type: str,
        vuln_title: str,
        desc: str,
        fp_reason: str,
        outcome: str,
        compressed_summaries: list[dict],
    ) -> str:
        """构建合并压缩的用户消息。"""
        parts = [
            f"漏洞标题：{vuln_title}",
            f"漏洞描述：{desc}",
            f"outcome：{outcome or 'FP'}（FP=误报，FN=漏报）",
            f"人工标注的原因：{fp_reason or '（未给出）'}",
            f"\n以下是 {chain_type} 链中 {len(compressed_summaries)} 个 session "
            f"的独立压缩摘要：\n",
        ]

        for s in compressed_summaries:
            parts.append(
                f"--- Session {s['step']} (session_id={s['session_id']}) ---"
            )
            parts.append(s.get("summary", ""))
            if s.get("key_findings"):
                parts.append(
                    f"关键发现: {'; '.join(s['key_findings'])}")
            if s.get("l0_l7"):
                parts.append(f"L0-L7 判定: {json.dumps(s['l0_l7'], ensure_ascii=False)}")
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
    ) -> dict | None:
        """L4 独立验证：当 L2 断点或 knowledge 责任假设存在时，主动搜索知识库验证。

        触发条件（任一满足即触发）：
        - L2 断点（cause_code A，agent 该查没查）
        - 假设 responsibility=knowledge（知识方责任，知识缺失）

        闭环逻辑：
        - L2 断点（cause_code A）→ 主动查知识库
          - 知识库有知识（l4=true）→ 责任在 agent，cause_code 保持 A
          - 知识库没有知识（l4=false）→ 责任在知识库，cause_code 改为 C
        - 假设 responsibility=knowledge → 主动查知识库
          - 知识库有知识 → 假设不成立（知识存在但 agent 没查到），修正 responsibility=agent
          - 知识库没有知识 → 假设成立（知识确实缺失），保持 responsibility=knowledge
        """
        has_l2_break = any(
            bp.get("breakpoint") == "L2" for bp in all_breakpoints
        )
        has_knowledge_hypothesis = any(
            h.get("responsibility") == "knowledge" for h in (hypotheses or [])
        )
        if not has_l2_break and not has_knowledge_hypothesis:
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

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} 检测到"
            f"{'L2 断点' if has_l2_break else ''}"
            f"{'+' if has_l2_break and has_knowledge_hypothesis else ''}"
            f"{'knowledge 责任假设' if has_knowledge_hypothesis else ''}，"
            f"启动知识库主动验证 L4 (project_id={project_id})")

        try:
            from .knowledge_verifier import KnowledgeVerifier
            verifier = KnowledgeVerifier()
            result = verifier.verify(
                vuln_title=vuln_title,
                fp_reason=fp_reason,
                project_id=project_id,
                cancel_cb=cancel_cb,
            )
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 独立验证完成: "
                f"l4={result.get('l4_knowledge_exists')}, "
                f"candidates={result.get('candidate_files', 0)}")

            # ── 闭环反馈：根据 L4 验证结果修正断点 ──
            l4_exists = result.get("l4_knowledge_exists")
            if l4_exists is False:
                # 知识库没有相关知识 → 责任在知识库（覆盖度缺口）
                # L2 断点（该查没查，cause_code A）→ L4 断点（查了没得，cause_code C）
                changed = 0
                for bp in all_breakpoints:
                    if bp.get("breakpoint") == "L2" \
                            and bp.get("cause_code") == "A":
                        bp["breakpoint"] = "L4"
                        bp["cause_code"] = "C"
                        bp["l4_exists"] = False
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
                            f" | L4 独立验证：知识库中未找到"
                            f"能消减此误报的知识"
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
                        old_evid = h.get("evidence", "")
                        h["evidence"] = (
                            f"{old_evid} | L4 独立验证：知识库中未找到"
                            f"能消减此误报的知识"
                            f"（{result.get('summary', '')}），"
                            f"知识确实缺失，责任在知识库（查了没得）"
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
                for h in (hypotheses or []):
                    if h.get("responsibility") == "knowledge":
                        h["responsibility"] = "agent"
                        h["cause_code"] = "A"
                        old_evid = h.get("evidence", "")
                        h["evidence"] = (
                            f"{old_evid} | L4 独立验证：知识库中存在"
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
                f"case {case_id}: {chain_type} L4 独立验证失败: {str(e)[:200]}")
            return {
                "l4_knowledge_exists": None,
                "matched_files": [],
                "summary": f"验证失败: {str(e)[:200]}",
                "kb_searched": {"athena_api": bool(project_id),
                                "wiki_nfs": True},
                "candidate_files": 0,
                "error": str(e)[:500],
            }

    def _format_session_events(
        self, session_id: str, events: list[RawEvent],
    ) -> str:
        """格式化 session 的全部事件为文本。"""
        if not events:
            return f"（session {session_id} 无事件）"

        lines = []
        for ev in events:
            et = ev.event_type or "UNKNOWN"
            ts = ev.timestamp_ms or 0
            tool = ev.tool_name or ""

            if et == "REASONING":
                text = _extract_text(ev.output_json)
                if text:
                    lines.append(f"[推理] {text}")
            elif et == "TEXT":
                text = _extract_text(ev.output_json)
                if text:
                    lines.append(f"[文本] {text}")
            elif et == "TOOL_CALL":
                text = _extract_text(ev.input_json)
                # 标记知识访问
                kg_flag = ""
                if ev.is_kg_interaction:
                    kg_flag = " [知识库访问]"
                elif ev.is_memory_interaction:
                    kg_flag = " [记忆访问]"
                lines.append(f"[工具调用] {tool}{kg_flag}: {text}")
            elif et == "TOOL_RESULT":
                text = _extract_text(ev.output_json)
                # 标记知识访问返回
                kg_flag = ""
                if ev.is_kg_interaction:
                    kg_flag = " [知识库返回]"
                elif ev.is_memory_interaction:
                    kg_flag = " [记忆返回]"
                lines.append(f"[工具返回] {tool}{kg_flag}: {text}")
            elif et == "SESSION_START":
                lines.append(f"[会话开始] session={session_id}")

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
