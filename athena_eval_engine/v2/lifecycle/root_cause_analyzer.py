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

import glob
import gzip
import hashlib
import json
import os
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..core.causal_levels import (
    CAUSE_LEVEL_RANK as _CAUSE_LEVEL_RANK,
    CAUSE_TO_CATEGORY,
)
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

# _CAUSE_LEVEL_RANK 从 core.causal_levels 导入（单一权威源）。
# 假定线索按置信度降序展示；置信度相同时按最早断裂的 L 级别
# L2(A/B) < L3 < L4(C) < L5(D) < L6(E) < L7(F/G) < L8(H/I/J/K)、
# 证据卡数量、cause_code 做确定性 tie-break。
# 线索之间互不否定，不再选"主因"。

# ── 系统 prompt（固定）──

_SYSTEM_PROMPT = """你是漏洞根因分析专家。你的任务是**压缩**一条漏洞链中的某个 session 原文：把很长的 session 压缩成结构化摘要，同时抽取证据卡、判定 L0-L8。

输入是一条 session 的完整事件流，每行以 [En] 开头。FP（误报）另有人工标注的误报原因；FN（漏报）没有人工标注，以基线漏洞描述作为分析依据。
outcome：FP=agent 报了但实际不是漏洞（误报）；FN=agent 漏报了真实漏洞。
输出不是逐段复述，而是三样东西：
1. 一份 3000 字以内的自包含摘要；
2. 证据卡（原文逐字摘录，供下游合并阶段引用）；
3. 本 session 的 L0-L8 判定。

压缩原则（保留漏洞根因关键信息）：
- 保留：agent 读了什么、执行了什么、返回了什么、推理依据、结论、知识/记忆访问、部署/配置事实、遗漏与矛盾等关键的漏洞相关信息。
- 丢弃：重复输出、无关日志、大段源码（只保留与漏洞根因相关的行）、格式化噪声。
- 摘要必须自包含：没看过原文的人也能理解发生了什么、为什么误报。
- 不得引入原文没有的信息；每条事实都要能由证据卡回指。
- 如果输入是多个分片的摘要（分片压缩后的合并），任务是把它们合并成一份完整摘要，按同样的保留/丢弃原则，不要丢事实。

摘要必须包含以下固定部分，每部分有内容就逐条列出，没有就写"材料中未出现"：
1. 代码/配置事实：写成「文件:行号 → 事实」，不要只写"读了某文件"。
2. 部署/运行事实：端口绑定、环境变量、默认部署取值、暴露面。
3. agent 的判定与自述：最终结论，以及 agent 自己写下的判断依据。
4. **事实与结论的矛盾点**：每条写成「已读到的事实 → agent 的结论」。禁止只写"agent 未识别 XX"而不给出它读到的事实。
5. **影响边界**：影响范围与成立前提。写清楚三件事——影响对象（谁受影响、是否跨用户/跨服务端）、生效前提（依赖哪些配置、环境变量、部署条件）、影响程度（改变或泄露了什么、没有改变或没有泄露什么）。材料中有就必须写。
6. 知识/记忆访问：来源、查询、返回内容、是否被引用。
7. 明确跳过的检查，以及为确认"没做过"而检查过的范围。

以上 7 项是摘要的固定结构，不因篇幅取舍；某项在材料中没有，写"材料中未出现"，不能省略不写。

# 判定流程（严格按顺序，不要跳步）

1. 抽证据卡：原文里出现的事实，逐条落成证据卡。
2. 判 L1→L8：只查下面的决策表，按顺序判，不跳级。
3. 判知识访问相关性：返回内容主张的是否支撑上报漏洞的挖掘发现。
4. 压缩输出：摘要 + 证据卡 + l0_l7。

# Step 1 证据卡

保留清单（原文有就必须保留，原文没有就写"材料中未出现"）：
- agent 读取/执行过的文件与命令，及与判定相关的输出
- 配置文件、默认值、部署/暴露面原文
- 知识/记忆访问：来源、查询、返回、是否被引用
- agent 的判定结论及其依据
- agent 明确跳过的检查、自相矛盾之处
- 与人工标注直接相关的事实、与结论冲突的反证

每张证据卡：
{
  "evidence_id": "E-<session 前 8 位>-<序号>",
  "event_idx": 0,
  "source": "文件/命令/工具",
  "quote": "原文逐字摘录（保留完整句子，禁止转述、禁止截断）",
  "fact_type": "repo_fact/deployment_fact/knowledge_access/agent_conclusion/omission/counter_evidence"
}

fact_type 含义：
- repo_fact：仓库内代码/配置事实
- deployment_fact：部署/运行时/暴露面事实
- knowledge_access：知识/记忆访问及其返回
- agent_conclusion：agent 的结论及其依据
- omission：应出现但未出现的检查/文件/事件（必须写核验范围）
- counter_evidence：与结论冲突的反证

规则：
- 原文每行以 [En] 开头，event_idx 填对应的 n。
- summary 只能基于证据卡，不得引入卡外信息。
- 找不到原文依据的内容，不得写进 summary 或线索。

# 知识/记忆访问的识别

评测引擎已在 session 文本中标记知识/记忆访问行为：
- `[知识库访问]`：agent 通过 athena_ask MCP、bash athena CLI、或 vuln_hunt_submit_knowledge 访问 Athena
- `[知识库返回]`：知识库返回的内容
- `[记忆访问]`：agent 通过 mem.sh CLI 或 cat 读取 wiki .md 文件访问记忆，文件路径包含：memengine/、/app/memory/、compiled_knowledge/
- `[记忆返回]`：记忆返回的内容

规则：
- 只有带上述标记的工具调用才算知识/记忆访问；read/grep/shell 等普通代码检索不算。
- 标记是评测引擎预处理的结果，是权威事实；不要自行把普通工具调用推断为知识访问。
- L0 来源：从标记判断是"知识库"还是"记忆"。
- L2 发起访问：有 `[知识库访问]` 或 `[记忆访问]` 标记即为 true。

# 术语表（统一定义）

- 断点：L1→L8 逐级判定中，第一个不通过的级别；断点级别就是该级别。
- 记录性访问：知识/记忆访问与本次误报无关，只作为事实记录（L6/E），不作为根因。
- 核验范围：为证明"未访问"而检查过的范围，写明读了哪些文件、执行了哪些命令、看了哪些 session。
- 负证据卡：记录"应该存在但没有"的证据卡，必须带核验范围。
- by-design：产品有意设计的行为（如训练靶场的预期漏洞、显式配置开关的效果），不是漏洞。
- verified_finding：记忆/知识中标记为"已验证漏洞"的条目；只代表历史结论，不代表对当前项目一定成立。
- sink 点：漏洞最终触发的位置（文件 + 函数/行号）。
- 调用链：从入口（source）到 sink 点的数据流路径。
- 模型幻觉：agent 虚构了材料中不存在的防护措施、代码行为或漏洞逻辑。
- 验证否定真漏洞：挖掘 agent 判 CONFIRMED，但验证 agent 判"不是漏洞"（仅 FN 场景）。
- 流程缺陷：agent 流程/覆盖/去重上的问题（如重复上报未识别、挖掘方向偏差、流程跳步）。

# Step 2 L1-L8 判定

| 级别 | 问题 | 判定 |
|---|---|---|
| L1 | 正确结论是否需要**外部知识/方法**支撑（如如何验证部署状态、漏洞模式、误报判定准则）？ | 需要 → L1=true；只靠仓库内代码/配置即可完成 → L1=false |
| L2 | agent 是否发起了**知识/记忆访问**（有 `[知识库访问]`/`[记忆访问]` 标记）？ | L1=true 且 L2=false → A（该查没查） |
| L3 | 查询是否聚焦当前任务？ | 太泛 → B |
| L4 | 来源里是否存在对应知识？ | 没有 → C（知识方） |
| L5 | 内容是否成功取回？ | 失败/超时 → D（链路） |
| L6 | 推理是否引用了返回内容？ | 未引用 → E（查到没用） |
| L7 | 知识是否影响了结论？ | negative → G（知识误导）；null+L6=true → F（用了没推动）；null+L6=false → E |
| L8 | 知识链路无问题，但 agent 仍误报 | H 流程缺陷/其他 / I 调用链中断 / J 模型幻觉 / K 验证否定真漏洞 |

L1 边界（仓库内事实 vs 外部事实）：
1. 仓库内事实：源码、配置文件中明确写出来的值（例如编排文件里声明的端口绑定）。
   → L1=false（不需要外部知识，读仓库就知道）。
2. 外部事实：仓库里读不到，必须靠知识库/记忆/部署环境才能知道。
   - 实际运行时配置（如某个环境变量/开关是否开启）
   - 环境变量实际取值
   - 真实网络暴露面
   - 方法论/判定准则（如"如何判断配置开关是否生效"）
   → L1=true（需要知识/方法）。

边界规则（按顺序判定，先满足者生效）：
1. 本 session 内读到了仓库内的部署/配置文件（编排文件、环境变量文件、实际配置文件、启动脚本等），且能据此确定该事实的实际取值 → 仓库内事实 → L1=false；即使同时读了 *.dist/*.example 模板，也以能确定实际值的仓库文件为准。
2. 只读 *.dist/*.example 模板，且仓库内没有任何部署/配置文件能确定实际值（实际值在部署时生成）→ 外部事实 → L1=true，A。
3. 仓库里根本没有该文件（或只有模板）→ 外部事实 → L1=true，A。
4. 文件在 agent 的工作目录里、没有访问限制 → 算仓库内事实；即使 agent 没读，也 L1=false，漏读归 H。
- L1=true 且 L2=false（没有知识/记忆访问）→ L2/A。
- L1=true 且 L2=true → 继续 L3-L7。
- L1=false → 走 L8 验证维度；如果 agent 读到了仓库事实但用错 → H。

A/H 判定顺序（强制，先判 H，再判 A）——仅适用于 L2=false 的 session：
1. 本 session 材料中已有足以得出正确结论的事实（agent 已读到的文件、工具返回或推理原文里出现），而 agent 的结论与它矛盾 → L1=false，L8/H。已读到却用错属于流程/验证缺陷，不是知识缺失。
2. 只有材料中不存在足以得出正确结论的事实时，才判 L1=true，再按 L2 判定 A。
3. 判 L1=true 时，"还有某个外部事实（如部署期环境变量）没有被核实"不能作为理由；只要已有事实足以否定该结论，就归 H。

L2=true 时的不变量（强制，优先于上面的 A/H 顺序）：
- 发生了知识/记忆访问（L2=true）→ 默认 L1=true，必须按 L2-L7 逐级判，不得用"已有仓库事实"改判 L1=false。
- L2=true 且 L6=true → 断点必为 L7（G 或 F），禁止判 L8/H。
- L2=true 时唯一允许 L1=false 的情形：该访问是记录性访问，与本次误报无关，L6=false，且已在证据中说明无关。

L1/L2 证据门槛（强制）：
- 判 L1=true 必须写明需要哪条外部知识/方法（1-3 条），并说明为什么仓库内文件无法确定它。
- "任务提示里说明可以查询知识库"只说明可访问，不构成 L1=true 的依据。
- 判 L2=false 必须确认 session 中没有 `[知识库访问]`/`[记忆访问]` 标记。
- 判 H 必须引用一张证据卡，展示 agent 已读到仓库事实但结论与事实矛盾。

L7 规则：
- L6=true 且返回内容错误/过时/by-design，且被用作上报依据 → L7=negative，cause_code=G。
- L6=true 但结论未采纳 → L7=null，断点 L7，cause_code=F。
- L6=false（读了但推理未引用）→ 断点 L6，cause_code=E。
- 以上都不是 L8。L8 只在以下情况使用：L7=positive；L1=false 且 L2=false（不需要知识且未发起访问，问题在非知识维度）；或知识访问为记录性且与误报无关（L6=false，已说明无关）。重复上报按专门规则直接判 L8/H。

L7=negative 的证据门槛（强制）：
- 必须同时引用：① 记忆/知识返回内容原文；② agent 推理中引用该内容的原文。
- 如果返回内容与上报漏洞是同一组件 + 同一行为，且 agent 引用了它 → 必须 L7=negative/G，禁止 l7=null。
- 缺任一条引用 → 不能判 G；L6=true 判 F（用了没推动），L6=false 判 E（查到没用）。

知识访问相关性（逐项比对，禁止凭感觉）：
1. 从上报漏洞标题/描述提取两个要素：
   - 组件：文件名/函数名/接口名
   - 行为：如"无认证可重置数据库"
2. 对知识/记忆返回内容逐条检查：
   - 同时出现组件和行为 → 同一个漏洞结论 → 直接相关。
     - agent 引用了该内容（L6=true）且内容错误/过时/by-design → L7/negative/G。
     - agent 未引用 → L6/E。
   - 只出现组件或只出现行为，或讲的是其他问题 → 不是同一个结论 → 记录性访问，可另起 L8。
3. 人工标注笼统（如"误报：其他误报原因"）时，不能作为"与误报无关"的依据。
4. 有 [知识库访问]/[记忆访问] 且返回非空时，必须先判 L2-L7，不得直接跳到 L8。

验证 session 的 A/H 二选一（强制）：
- 没有发起知识/记忆访问（L2=false），且任务需要外部知识/方法（L1=true）→ L2/A（该查没查）。
- 发起了知识/记忆访问（L2=true），但没用到目标事实、或用了错误内容 → 按 L6/E、L7/F/G 判定，不判 A。
- L1=false（事实在仓库内可读），agent 读到了但用错 → L8/H。
- 不允许把"没查知识"判成 H，也不允许把"查了用错"判成 A。

重复上报：
- 人工标注含"重复上报/已上报/已报过/重复" → 断点 L8/H，禁止归到知识链路。
- query_content 写"重复上报未识别：agent 未比对已上报清单/历史记录"。

# 类别证据要求（不满足不得给该 cause_code）

| cause | 最低证据（必须来自证据卡原文） |
|---|---|
| A | ① 写明需要哪条外部知识/方法（1-3 条），并说明仓库内文件为何无法确定它；② 确认本次 session 中没有 [知识库访问]/[记忆访问] 标记。任务提示允许查询知识库不构成依据。缺任一条不得给 A。**压缩阶段已判 L2/A 断点的 session 是 A 的直接证据——不得用后见之明把 A 断点改判为 H**（后见之明=已知正确答案后构造出"本可推出正确结论"的事实链——若该链的关键事实不在 session 材料中，归 A 不归 H）。 |
| B | agent 实际查询命令原文 + 不聚焦的具体理由 |
| C | 同源查询命令 + 返回为空/无相关内容的原文 |
| D | 返回错误/超时的原文 |
| E | 返回内容原文 + 推理中未引用该内容的依据 |
| F | 返回内容原文 + 引用但结论未采纳的依据 |
| G | 返回内容原文（含与上报漏洞相同的组件/行为）+ agent 引用该内容的推理原文 |
| H | 流程/验证维度问题证据（已读事实但结论矛盾、重复上报未识别、挖掘方向偏差等）。**证据层级匹配规则同样适用于验证复核**：上报结论的前提（如可达性/可利用性）只引用代码声明类证据（注解/配置注释），验证未退回待确认仍予以确认——属验证维度缺陷；反之挖掘侧同款错误（拿代码声明当部署事实）属挖掘维度缺陷。**「漏做检查」只在检查所需信息已在 session 材料中出现时才是 H；检查所需信息不在材料中（如框架执行语义、部署配置、生产过滤规则），agent 需要查询知识库获取——属 A（该查没查），不是 H**。 |
| I | sink 命中证据 + 调用链断点的证据 |
| J | agent 虚构内容原文 + 材料中不存在该内容的证据 |
| K | 挖掘 CONFIRMED 结论 + 验证否定的结论 |

不满足 → 不得给该 cause_code；改判为满足证据要求的类别，或标 insufficient_evidence。

# 置信度（confidence）

confidence 表示"证据对当前线索的支撑程度"，不是"根因可能性"：
- 0.9：所需证据齐全且 quote 已在原文核实，无反证；
- 0.7：所需证据齐全，但有已解释的反证；
- 0.5：证据部分相关，只能作为次要线索；
- 0.3：证据薄弱，不应输出；
- 0.1：猜测，禁止输出。
confidence >= 0.6 的线索展示；<0.6 的不展示（若没有任何一条 >=0.6，只展示置信度最高的一条）；<0.5 的线索直接丢弃。

# Step 3 输出

下面的 schema 是字段示意，不是可直接复制的 JSON；输出时每个字段只取一个值，不要把 `A/B/C` 或 `true/false` 整串抄进去；必须是合法 JSON。

{
  "summary": "结构化摘要，3000字以内，必须覆盖证据卡所有非空项",
  "key_findings": ["..."],
  "evidence_cards": [ ... ],
  "retention_check": [{"item": "影响边界", "status": "preserved/absent", "evidence_ids": ["E-..."]}],
  "l0_l7": [
    {
      "l0_source": "知识库/记忆/空",
      "l1_need": true/false/null,
      "l2_initiated": true/false/null,
      "l3_accurate": true/false/null,
      "l4_exists": true/false/null,
      "l5_retrieved": true/false/null,
      "l6_used": true/false/null,
      "l7_influenced": "positive/negative/null",
      "breakpoint": "L2/L3/L4/L5/L6/L7/L8/none",
      "cause_code": "A/B/C/D/E/F/G/H/I/J/K/null",
      "confidence": 0.9,
      "evidence_refs": ["E-..."],
      "query_content": "agent 实际执行的查询命令或参数；非知识断点填问题总结",
      "kb_search_query": "breakpoint=L2/L4 时填一个方法论问题，否则空",
      "returned_content": "实际返回内容概括，无则空",
      "fix_suggestion": "按缺陷类别给出的通用修复规则（元规则，非本 case 专属）"
    }
  ],
  "insufficient_evidence": false,
  "insufficient_reason": ""
}

# 字段说明（输入 + 输出）

输入：
- [En]：事件索引；evidence_cards.event_idx 填对应的 n。
- outcome：FP=误报；FN=漏报。
- 程序核对：知识/记忆记录在返回后的引用次数、与上报漏洞的关键词重合，是 L6/L7 的事实依据。引用次数 >0 时 L6 必须为 true，不得判"未引用"。
- session_id / Session i/N：当前 session 的 ID 和在链中的位置。

输出：
- summary：压缩后的自包含摘要。
- key_findings：关键发现列表。
- evidence_cards：证据卡，字段见 Step 1。
- retention_check：7 个固定部分的核查结果；item 取固定部分名称（代码/配置事实、部署/运行事实、agent 判定与自述、事实与结论的矛盾点、影响边界、知识/记忆访问、跳过的检查），preserved=材料中有且已保留，absent=材料中没有；evidence_ids 填对应证据卡。7 项必须全部出现。
- l0_l7：本 session 的逐级判定，字段如下：
  - l0_source：知识来源（知识库/记忆/空）
  - l1_need：true=需要知识支撑；false=不需要；null=不适用（与字段名一致）
  - l2_initiated：是否发起知识/记忆访问
  - l3_accurate：查询是否聚焦
  - l4_exists：来源里是否有对应知识
  - l5_retrieved：是否成功取回
  - l6_used：推理是否引用返回内容
  - l7_influenced：positive/negative/null
  - breakpoint：第一个不通过的级别；本 session 无缺陷时填 none，不得留空或填 null
  - cause_code：A-K
  - confidence：证据支撑度（0.1-0.9）
  - evidence_refs：支撑本判定的证据卡 ID
  - query_content：知识访问填实际查询命令；非知识断点填问题总结
  - kb_search_query：L2/L4 时填一个检索问题（方法论或环境事实均可）
  - returned_content：知识/记忆返回内容；无则空
  - fix_suggestion：本 session 的修复建议（通用元规则，按缺陷类别写；不点名具体漏洞类型/参数/入口——case 专属事实属于知识库补充）
- insufficient_evidence / insufficient_reason：整个 session 无法给出有证据的判定时使用。

# 硬约束
- 没有证据卡的结论不输出。
- 禁止推测；材料里没有的写"材料中未出现"。
- 每个 session 必须输出 l0_l7，且每条的 breakpoint 必须显式给出：有缺陷填 L2-L8，无缺陷填 none，禁止省略或填 null。
- kb_search_query 问方法论或环境事实均可（环境事实=项目特有的环境信息/业务知识，如网关暴露面约定、部署架构、内部 API 标记——属知识库分类中的环境信息/纠偏知识/负结论），禁止复合问题。
- 只返回 JSON，不要额外文字。

# 示例
例1 记忆返回 verified_finding，主张与上报漏洞相同，agent 引用后确认 → L7/negative/G。
例2 本次 session 只读模板文件（*.dist/*.example），没读实际配置文件，且仓库内没有任何部署/配置文件能确定实际值 → L1=true，L2/A；即使其他 session 读过部署描述文件，也不能算本次已访问。
例3 agent 读了部署描述文件，看到服务只绑定回环地址，却仍判外部可达 → L8/H。
例4 session 里没有任何知识访问，且所需事实不能从代码/配置读到 → L2/A；如果事实已在材料中但用错 → L8/H。

# 自检
- 摘要的 7 个固定部分是否齐全（缺项写"材料中未出现"）？
- 每条矛盾点是否写成「事实 → 结论」？
- 影响边界（范围 + 成立前提）是否列出？
- 证据卡覆盖保留清单的所有非空项？
- 有知识访问的 session 是否都出了 L2-L7？
- L6=true 且内容错误时是否判了 L7/G？
- L8 是否只在知识链路正常时出现？
- summary 是否只基于证据卡？

只返回 JSON。"""


def _hypothesis_fit(h: dict) -> float:
    """线索排序分：标注匹配度（annotation_fit）优先，缺省回退证据支撑度。

    旧数据/LLM 未输出 annotation_fit 时回退 confidence，排序行为与
    旧版一致（证据支撑度降序）。
    """
    try:
        return float(h.get("annotation_fit",
                            h.get("confidence", 0.5)) or 0.5)
    except (TypeError, ValueError):
        return 0.5


def _annotation_line(fp_reason: str, outcome: str) -> str:
    """人工标注提示行。

    FP（误报）才有人工标注；FN（漏报）来自开发态基线，
    不存在"漏报原因"的人工标注，分析以基线漏洞描述为依据。
    """
    if str(outcome or "FP").upper() == "FN":
        return "人工标注：无（漏报没有人工标注；以基线漏洞描述为分析依据）"
    return f"人工标注的误报原因：{fp_reason or '（未给出）'}"


_MERGE_PROMPT = """你是漏洞根因分析专家。输入是一条漏洞链涉及的多个 session 摘要、证据卡和 L0-L7 断点。输出根因假定线索和修复建议。

outcome：FP=误报；FN=漏报。
输入中的断点编号为 BP-n；线索的 supporting_breakpoints 只能引用这些编号。

# 术语表（统一定义）

- 挖掘 agent 职责：**发现所有风险点**（召回优先、宽进——多报风险点不构成缺陷；FP 的把关责任在验证侧）。挖掘的错只有两种形态：把待验证的前提（如可达性）写成事实断言上报；漏报真实风险点。
- 验证 agent 职责：**证明风险可利用**（举证责任在验证——可达性/可利用性未证明时只能输出待确认/退回，确认即失职；上报前提只引用代码声明类证据而验证未退回，属验证维度缺陷）。
- 假定线索：一个独立、不可再分的根因猜测；2-5 条，互斥。线索不是结论，可以多条并存。
- 互斥：不能有包含/父子关系；若 A 成立必然导致 B，只保留一条。
- 反证：材料中与线索冲突的事实；没有反证要写明检查范围。
- 置信度：证据对该线索的支撑程度（0.1-0.9）。线索按置信度降序展示。
- BP-n：输入中 L0-L7 断点的编号。

# L0-L7 断点含义（用于理解输入，不重新判级）

断点 = 某个 session 在 L1→L8 逐级判定中第一个不通过的级别。输入中每条断点带 BP-n 编号，字段包括 breakpoint、cause_code、query_content、returned_content。

| 级别 | 含义 | cause_code |
|---|---|---|
| L1 | 是否需要知识支撑（l1_need=true 表示需要） | — |
| L2 | agent 是否发起知识/记忆访问 | A 该查没查 |
| L3 | 查询是否聚焦当前任务 | B 查询太泛 |
| L4 | 来源里是否存在对应知识 | C 查了没得 |
| L5 | 内容是否成功取回 | D 链路问题 |
| L6 | 推理是否引用返回内容 | E 查到没用 |
| L7 | 知识是否影响结论 | F 用了没推动 / G 知识误导 |
| L8 | 知识链路正常，问题在其他维度 | H 流程缺陷/其他 / I 调用链 / J 幻觉 / K 验证否定 |

- `supporting_breakpoints` 填线索直接依据的 BP-n；只填输入中实际出现的编号。
- 不要重新判 L0-L8，也不要修改断点的级别或 cause_code。

# 判定流程（严格按顺序）

1. 读输入：只使用已给的证据卡和 L0-L7 断点，不要重新判 L0-L8。
2. 生成线索：2-5 个互斥线索，每个必须有 evidence_refs 和 counter_evidence。
   - 若输入断点为 L2/A，但该断点的证据或反证显示 agent 在同一 session 已读到足以否定其结论的事实，则不得产出 A 线索，按 L8/H 表述（已读到却用错属流程/验证缺陷）。
3. 输出。线索按置信度降序展示，LLM 不需要选主因——不存在"主因"这个概念。

# Step 1 证据门槛
- 每个线索的 evidence_refs 只能引用输入中实际存在的 evidence_id。
- 找不到证据卡 → 禁止输出该线索；宁可少给，不许猜。
- evidence 字段必须逐条对应 evidence_refs。
- 证据不足（没有任何线索能引用证据卡）→ insufficient_evidence=true，不要输出线索，不要给 L 级别。

# Step 2 反证
- 每个线索必须填 counter_evidence。
- 材料有反证 → 说明为何不足以推翻；没有反证 → 写明检查范围（看过哪些 session/事件）。

# Step 3 线索要求
- 2-5 个，互斥，不能有包含/父子关系。
- 每个线索一个独立缺陷，能定位到唯一修复点。
- 「未查询知识库」「未核实暴露面」等**同一缺失只保留一条线索**——换措辞重复描述同一缺陷算违反互斥，不得输出多条。
- cause_code / responsibility 必须符合下表。
- 人工标注（FP 才有）是**对照基准**：它定义正确判定（误报的真实成因），由问题单页面顶部统一展示，**线索叙述不得整段复述标注原文**（页面已展示，复述即重复）。每条线索只写两段：**agent 判定**（引证据卡：读了什么、据此判了什么）→ **差距**（agent 缺了什么知识/数据/步骤，导致判定偏离人工判定）。差距中可用短语引用人工判定的关键结论（如「与人工判定的『终端不可达』相反」），不整段抄。漏报（FN）没有人工标注，以基线漏洞描述为对照基准，同样按此格式。

# Step 4 展示顺序（程序执行，LLM 不需要选）
- 线索按**标注匹配度（annotation_fit）降序**展示：最能解释人工标注的在前。
- 标注匹配度相同时按**证据支撑度（confidence）降序**。
- 再相同时按最早断裂的 L 级别：L2/L3(A/B) < L4(C) < L5(D) < L6(E) < L7(F/G) < L8(H/I/J/K)。
- 再按证据卡数量降序；最后按 cause_code 字母序。
- probability 只展示，不参与排序。
- LLM 不需要输出 primary_cause / primary_hypothesis / secondary_causes，这些字段由程序填写。

# cause_code 表
| code | 含义 | 责任方 | L 级别 |
|---|---|---|---|
| A | 该查没查 | agent | L2 |
| B | 查询太泛 | agent | L3 |
| C | 查了没得 | knowledge | L4 |
| D | 链路问题 | knowledge | L5 |
| E | 查到没用 | agent | L6 |
| F | 用了没推动 | agent | L7 |
| G | 知识误导 | knowledge | L7 |
| H | 流程缺陷/其他 | agent | L8 |
| I | 调用链中断 | agent | L8 |
| J | 模型幻觉 | agent | L8 |
| K | 验证否定真漏洞 | agent | L8 |

responsibility 取值：
- agent：改 prompt/code 可解决
- knowledge：补充/修正知识内容。**知识库与知识记忆作为一个知识供给整体考虑，服务对象就是挖掘 agent 与验证 agent**（记忆部分数据即来源于知识库），只管**项目特有的**非通用知识，按知识库分类：**业务知识**（业务威胁/作业/纠偏）、**漏洞挖掘知识**（判例模式/历史库/安全假设/挖掘方法/负结论）、**经验类知识**（PoC-EXP/利用手法/成败经验）、**环境信息**、**脚手架**；**通用知识由模型提供，缺通用知识不归 knowledge、归 agent（模型本应具备）**。缺项目特有知识归 knowledge，不归 external_data_source；写入落点细节用 knowledge_source 区分
- external_data_source：仅当所需事实连知识整体都无法承载（需实时部署数据/运行时状态）时使用
- eval_process：评测流程改进

responsibility 一致性（强制）：
- responsibility=agent 的线索必须 agent_can_resolve=true 且 blocked_by 为空；写不出可落地的 agent 侧修复动作时不得给 agent。
- blocked_by 非空或 agent_can_resolve=false 时，responsibility 必须是 knowledge/external_data_source/eval_process 之一。

重复上报：标注含"重复上报/已上报/已报过" → 所有知识链路线索改 H/agent，禁止 A/C/E/G。

# 类别证据要求（不满足不得给该 cause_code）

| cause | 最低证据（必须来自 evidence_refs 指向的证据卡原文） |
|---|---|
| A | ① 写明需要哪条外部知识/方法（1-3 条），并说明仓库内文件为何无法确定它；② 确认本次 session 中没有 [知识库访问]/[记忆访问] 标记。任务提示允许查询知识库不构成依据。缺任一条不得给 A。**压缩阶段已判 L2/A 断点的 session 是 A 的直接证据——不得用后见之明把 A 断点改判为 H**（后见之明=已知正确答案后构造出"本可推出正确结论"的事实链——若该链的关键事实不在 session 材料中，归 A 不归 H）。 |
| B | agent 实际查询命令原文 + 不聚焦的理由 |
| C | 同源查询命令 + 返回为空/无相关内容 |
| D | 返回错误/超时原文 |
| E | 返回内容原文 + 推理未引用 |
| F | 返回内容原文 + 引用但结论未采纳 |
| G | 返回内容原文（含与上报漏洞相同的组件/行为）+ agent 引用该内容的推理原文 |
| H | 流程/验证维度问题证据（已读事实但结论矛盾、重复上报未识别、挖掘方向偏差等）。**证据层级匹配规则同样适用于验证复核**：上报结论的前提（如可达性/可利用性）只引用代码声明类证据（注解/配置注释），验证未退回待确认仍予以确认——属验证维度缺陷；反之挖掘侧同款错误（拿代码声明当部署事实）属挖掘维度缺陷。**「漏做检查」只在检查所需信息已在 session 材料中出现时才是 H；检查所需信息不在材料中（如框架执行语义、部署配置、生产过滤规则），agent 需要查询知识库获取——属 A（该查没查），不是 H**。 |
| I | sink 命中证据 + 调用链断点证据 |
| J | agent 虚构内容原文 + 材料中不存在的证据 |
| K | 挖掘 CONFIRMED + 验证否定 |

不满足 → 不得给该 cause_code；改判为满足证据要求的类别，或把该线索标为证据不足。

G 的证据必须同时包含：① 记忆/知识返回内容原文；② agent 推理中引用该内容的原文。缺一不可，否则不能给 G。

# 置信度（confidence）

confidence 表示"证据对当前线索的支撑程度"，不是"根因可能性"：
- 0.9：所需证据齐全且 quote 已验证，无反证；
- 0.7：所需证据齐全，但有已解释的反证；
- 0.5：证据部分相关，只能作为次要线索；
- 0.3：证据薄弱，不应输出；
- 0.1：猜测，禁止输出。
confidence >= 0.6 的线索展示；<0.6 的不展示（若没有任何一条 >=0.6，只展示置信度最高的一条）；<0.5 的线索直接丢弃。

probability：根因可能性，仅展示，不参与排序。
confidence：证据对线索的支撑程度，用于展示门槛与排序（>=0.6 展示）。两者不要混用。

# fix_suggestion 填写规则
- target=agent_prompt/agent_code 时，agent_type 必填（turing/argo/secmate/dataflow/webvuln_verify/cvuln_verify）。
- target=knowledge/memory 时，knowledge_source 必填（knowledge_base/memory_wiki）。
- **action 必须是通用元规则**：按缺陷类别写适用于全部同类 case 的规则（如证据分级、断言门槛、上报前必须核实的前提类别）。
  禁止 case 专属规则——不得点名具体漏洞类型/参数/入口/文件名（每张单加一条专属规则，提示词会无限膨胀）。
  本 case 的具体事实（如某入口在商用版本已裁剪、某方法实际做了转义）属于项目知识——写 target=knowledge 的建议：知识库补充该项目事实。
- location 写角色级位置（如「挖掘 agent 上报前检查规则」）。agent 提示词/代码是外部产品，平台无法定位到具体文件——禁止伪装成已知文件路径。
- 如果 agent_can_resolve=false，必须写 blocked_by 和 needed_external_data。

# 输出格式

下面的 schema 是字段示意，不是可直接复制的 JSON；输出时每个字段只取一个值，不要把 `A/B/C` 或 `true/false` 整串抄进去；必须是合法 JSON。
{
  "summary": "合并摘要，3000字以内",
  "insufficient_evidence": false,
  "insufficient_reason": "",
  "audit": [{"rule": "...", "pass": true, "note": ""}],
  "knowledge_memory_summary": {
    "access_count": 0,
    "accesses": [{"source": "knowledge_base/memory/unknown", "query": "...", "returned": "...", "used_in_reasoning": true, "effect": "positive/negative/neutral/none", "session_id": "..."}],
    "overall_effect": "positive/negative/neutral/none",
    "impact_on_conclusion": "..."
  },
  "hypotheses": [
    {
      "hypothesis": "线索描述",
      "probability": 0.9,
      "responsibility": "agent/knowledge/external_data_source/eval_process",
      "cause_code": "A/B/C/D/E/F/G/H/I/J/K",
      "confidence": 0.9,
      "annotation_fit": 0.8,
      "evidence_refs": ["E-..."],
      "counter_evidence": "反证，或检查范围",
      "evidence": "逐条对应 evidence_refs 的原文依据（单个字符串；多条依据用分号分隔，禁止输出数组）",
      "session_id": "主要依据的 session_id",
      "supporting_breakpoints": ["BP-1"],
      "agent_can_resolve": true,
      "blocked_by": "",
      "needed_external_data": [],
      "fix_suggestion": {
        "target": "agent_prompt/agent_code/knowledge/memory/external_data_source/eval_process",
        "agent_type": "turing/argo/secmate/dataflow/webvuln_verify/cvuln_verify/空",
        "knowledge_source": "knowledge_base/memory_wiki/空",
        "location": "具体修改位置",
        "action": "具体修改内容",
        "expected_effect": "修改后预期效果"
      }
    }
  ],
  "label_quality": {
    "precision": "precise/imprecise",
    "needs_label_confirmation": false,
    "reason": "...",
    "follow_up_questions": ["..."]
  }
}

# 字段说明（输入 + 输出）

输入：
- Session i/N (session_id)：第 i 个 session 的摘要块，N 是链中 session 总数。
- 关键发现：该 session 的关键事实列表。
- 证据卡：evidence_id（唯一 ID）、event_idx（事件索引）、source（文件/命令/工具）、quote（原文）、fact_type（repo_fact=仓库代码/配置事实；deployment_fact=部署/运行时/暴露面事实；knowledge_access=知识/记忆访问；agent_conclusion=agent 结论；omission=应出现但未出现；counter_evidence=反证）。
- L0-L7 判定：每条断点带 BP-n 编号，字段如下：
  - l0_source：知识来源（知识库/记忆/空）
  - l1_need：true=需要知识支撑；false=不需要；null=不适用
  - l2_initiated：是否发起知识/记忆访问
  - l3_accurate：查询是否聚焦
  - l4_exists：来源里是否有对应知识
  - l5_retrieved：是否成功取回
  - l6_used：推理是否引用返回内容
  - l7_influenced：positive/negative/null
  - breakpoint：断点级别
  - cause_code：A-K
  - query_content：查询命令或问题总结
  - returned_content：知识/记忆返回内容
  - kb_search_query：L2/L4 的检索问题
- 本 session 证据不足：该 session 没有任何可引用证据。

输出：
- summary：合并摘要。
- insufficient_evidence / insufficient_reason：无线索能引用证据卡时使用。
- audit：逐条自检；rule=检查项，pass=true/false，note=说明。
- knowledge_memory_summary：
  - access_count：整条链知识/记忆访问次数
  - accesses：每次访问；source=knowledge_base/memory/unknown，query=查询，returned=返回，used_in_reasoning=是否引用，effect=positive/negative/neutral/none，session_id=来源 session
  - overall_effect：整体影响
  - impact_on_conclusion：对结论的影响说明
- hypotheses：每个线索包含：
  - hypothesis：线索描述
  - probability：根因可能性，仅展示
  - responsibility：agent/knowledge/external_data_source/eval_process
  - cause_code：A-K
  - confidence：**证据支撑度**（引用的证据卡对该线索的支撑程度；<0.6 不展示、<0.5 丢弃——过滤用）
  - annotation_fit：**标注匹配度**（该线索解释人工标注的程度：FP=解释误报的真实成因，FN=解释漏报的真实缺口；**排序用**。复述标注原文不算匹配——要解释成因；与标注无关的过程线索（如验证侧事故）匹配度应低）
  - evidence_refs：引用的证据卡 ID
  - counter_evidence：反证或检查范围
  - evidence：逐条对应 evidence_refs 的依据
  - session_id：主要依据的 session
  - supporting_breakpoints：依据的 BP-n
  - agent_can_resolve：agent 改 prompt/code 能否解决
  - blocked_by：不能解决时缺什么
  - needed_external_data：不能解决时需要的外部数据
  - fix_suggestion：target/agent_type/knowledge_source/location/action/expected_effect
- label_quality：
  - precision：precise/imprecise
  - needs_label_confirmation：结论是否取决于人工真实意图
  - reason：评估理由
  - follow_up_questions：需要确认的问题

# label_quality 判定标准（强制）

precision 评估的是**标注文本本身**的质量，不是分析方能否验证它：
- imprecise：标注文本自身有缺陷——空泛无机制、自相矛盾、下拉标签与补充说明不符、无法复现判定。reason 必须引用标注原文并指出具体缺陷；follow_up_questions 必须非空；needs_label_confirmation 必须为 true。
- precise：标注把误报/漏报机制说清楚了——即使其前提是材料外事实、无法从 session 材料验证。
- 「标注前提无法从材料验证」（如部署事实不在工作区）→ precision=precise 且 needs_label_confirmation=true，并在 follow_up_questions 列出待确认问题。**禁止把"无法验证"判为 imprecise**。

# 硬约束
- 只使用输入中已有的证据卡和断点，不重新判 L0-L8。
- 没有 evidence_refs 的线索不输出。
- 线索按 confidence 降序展示；probability 不参与排序。
- 证据不足时不给结论。
- 只返回 JSON。

# 示例
例1 输入断点里有一条 L7/G（记忆内容误导），同时有一条 L8/H（未识别设计意图）→ 输出两条线索，按各自 confidence 排序。
例2 输入断点里有 L2/A（未访问实际配置）和 L8/H → 输出两条线索，按各自 confidence 排序。
例3 没有任何线索能引用证据卡 → insufficient_evidence=true。

# 自检
- 每个线索都有 evidence_refs 和 counter_evidence？
- 每条线索的 confidence 是否与证据强度一致？
- annotation_fit 是否按「解释人工标注的程度」打分？与标注成因无关的过程线索（如验证侧事故）匹配度应低；只复述标注原文不算匹配。
- 是否有 L2/A 线索却只输出了 H？
- **A/H 一致性**：压缩阶段已判 L2/A 断点的 session，merge 顶层是否为 A？若为 H，H 线索的关键事实是否真的在 session 材料中？凭后见之明构造的"本可推出正确结论"事实链，若关键事实不在材料中，应改判 A。
- **「漏做检查」归属**：H 线索中的"漏做检查"，检查所需信息是否已在 session 材料中？不在材料中（需查知识库获取框架行为/部署配置）→ 属 A 不属 H。
- 证据不足时是否没有硬给结论？
- blocked_by 非空或 agent_can_resolve=false 的线索，responsibility 是否不为 agent？
- 线索叙述中的事实断言（如「X 仍指向 Y」「不存在 Z」）是否都被 evidence_refs 引用的证据卡原文支持？与自己的证据卡矛盾的断言必须删除或改写。
- 是否有两条线索描述同一缺失（如都是"未查询知识库"）？只保留一条。
- 每条线索是否都包含「agent 判定 → 差距」且未整段复述人工标注原文？
- label_quality.precision=imprecise 的理由是否引用了标注原文并指出文本自身缺陷？"无法从材料验证标注前提"是否已改记 needs_label_confirmation=true 而非 imprecise？
"""


# ── per-case 根因缓存 ──
# 布局：{reports_dir}/_root_cause_cache/{任务 ID}/{case 文件}.json.gz
# ——按平台任务 ID 分目录，不同任务的 case 互不干扰（同名 case_id 不
# 会串到别的任务）；任务已结束、trace 冻结，人工标注只增不改——重跑
# （如标注变化后重新发起测评）时老 case 直接复用既有根因（断点/责任方/
# L4 判定原样保留，不翻案——已按旧根因修复误报的人不会看到根因变化），
# 只对新增确认（缓存未命中）的 case 跑 LLM 分析。
# key = case 标注输入指纹（case_id/outcome/标题/描述/摘要/人工确认
# 摘要/验证否定标记/agent 类型）+ 分析器版本号。
# prompt 或判定逻辑变化时必须递增版本号，否则缓存仍是旧逻辑结果。
# v2：A/H 归因漂移修复（漏做检查归属 + 后见之明防护 + A/H 一致性
# 自检，改压缩与 merge 两处 prompt）。
# v3：fix_suggestion 元规则约束（压缩与 merge 两处 prompt：action 按
# 缺陷类别写通用规则，禁止 case 专属规则；项目事实归知识库；
# location 角色级定位，不伪装文件路径）。
_RCA_CACHE_VERSION = 3


def _rca_cache_dir() -> str:
    from ...config_loader import get_reports_dir
    return os.path.join(get_reports_dir(), "_root_cause_cache")


def _safe_task_id(task_id: str) -> str:
    """任务 ID → 子目录名（非法字符替换，空 → _unknown）。"""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(task_id or ""))[:120] or "_unknown"


def _rca_task_cache_dir(task_id: str) -> str:
    return os.path.join(_rca_cache_dir(), _safe_task_id(task_id))


def _rca_cache_path(case: dict, task_id: str = "") -> str:
    """缓存文件路径：{任务 ID}/{safe_case_id}_{outcome}_v{版本}_{指纹16}.json.gz

    gzip 存储：缓存内容是纯文本 JSON（压缩摘要/根因/断点/L4 明细），
    实测整体压缩率约 4 倍（126KB/case → ~30KB），reports PVC 只有
    5Gi，不压缩在大规模 case 下会撑满。
    """
    case_id = str(case.get("case_id") or "")
    outcome = str(case.get("outcome") or "")
    digest_input = "\x1f".join([
        case_id, outcome,
        str(case.get("vuln_title") or ""),
        str(case.get("description") or ""),
        str(case.get("summary") or ""),
        str(case.get("human_confirmation_summary") or ""),
        str(case.get("verify_verdict") or ""),
        str(case.get("agent_type") or ""),
    ])
    digest = hashlib.md5(digest_input.encode("utf-8")).hexdigest()[:16]
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", case_id)[:120] or "nocase"
    return os.path.join(
        _rca_task_cache_dir(task_id),
        f"{safe_id}_{outcome}_v{_RCA_CACHE_VERSION}_{digest}.json.gz")


def _rca_cache_load(case: dict, task_id: str = "") -> dict | None:
    """命中返回缓存的分析结果；未命中/损坏返回 None（回退新分析）。

    优先读 gzip 新格式（.json.gz），回退旧明文格式（.json）——旧文件
    仍可复用，下次重算时才转成新格式。
    """
    gz_path = _rca_cache_path(case, task_id)
    for path, is_gz in ((gz_path, True), (gz_path[:-3], False)):
        if not os.path.isfile(path):
            continue
        try:
            if is_gz:
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            if isinstance(data, dict) and \
                    data.get("case_id") == str(case.get("case_id") or ""):
                return data
        except Exception:
            pass
    return None


def _rca_cache_save(case: dict, result: dict, task_id: str = "") -> None:
    """写入 per-case 分析结果（gzip + 临时文件原子替换；失败不阻断）。"""
    path = _rca_cache_path(case, task_id)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        with gzip.open(tmp, "wt", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as e:
        log("ROOT_CAUSE", f"根因缓存写入失败（不阻断）: {e}")


def _safe_case_id(case_id: str) -> str:
    """缓存文件名前缀：非法字符替换 + 截断（与 _rca_cache_path 同一规则）。"""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(case_id or ""))[:120] or "nocase"


def cleanup_case_cache(task_id: str, case_ids: list[str]) -> int:
    """删除指定任务下指定 case 的根因缓存（所有版本/标注指纹）。

    返回删除文件数。用于评测真正删除后的孤儿回收——仅当这些 case_id
    已不再被任何问题单引用时调用。重跑（retry）不走这里，缓存继续复用。
    """
    task_dir = _rca_task_cache_dir(task_id)
    if not case_ids or not os.path.isdir(task_dir):
        return 0
    removed = 0
    for case_id in case_ids:
        # *.json* 同时覆盖新 gzip 格式（.json.gz）与旧明文格式（.json）
        pattern = os.path.join(task_dir, f"{_safe_case_id(case_id)}_*.json*")
        for path in glob.glob(pattern):
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
    if removed:
        log("ROOT_CAUSE", f"清理根因缓存 {removed} 个文件"
                          f"（任务 {task_id or '_unknown'}，"
                          f"{len(case_ids)} 个已删除 case）")
    return removed


def purge_task_cache(task_id: str) -> int:
    """清空任务全部 per-case 根因缓存（全量重跑用），返回删除文件数。

    增量重跑复用标注未变 case 的既有根因结论（不重复消耗 LLM）；
    全量重跑先清空该任务缓存——重跑时全部 case 走当前 prompt 重新
    LLM 分析。只清本任务目录，其他任务缓存不受影响。
    """
    import shutil
    task_dir = _rca_task_cache_dir(task_id)
    if not os.path.isdir(task_dir):
        return 0
    n = sum(len(files) for _, _, files in os.walk(task_dir))
    try:
        shutil.rmtree(task_dir)
    except OSError as e:
        log("ROOT_CAUSE", f"清空任务根因缓存失败 task={task_id or '_unknown'}: {e}")
        return 0
    log("ROOT_CAUSE", f"已清空任务 {task_id or '_unknown'} 根因缓存"
                      f"（{n} 个文件，全量重跑）")
    return n


_cache_swept = False


def _sweep_old_cache_versions() -> None:
    """清理死缓存文件，每进程只扫一次。

    两类死数据（当前代码永远不会读取）：
    - 旧版本文件（版本号 < 当前）：prompt/判定逻辑变更后残留，
      平均 126KB/case，不清理会在 reports PVC（5Gi）上持续累积；
    - 缓存根目录下的平铺文件：新布局按任务 ID 分目录，根目录文件
      无论版本号都已不可达（历史布局遗留）。
    """
    global _cache_swept
    if _cache_swept:
        return
    _cache_swept = True
    cache_dir = _rca_cache_dir()
    if not os.path.isdir(cache_dir):
        return
    removed = 0
    for root, _dirs, files in os.walk(cache_dir):
        at_root = os.path.abspath(root) == os.path.abspath(cache_dir)
        for name in files:
            if not at_root:
                m = re.search(r"_v(\d+)_", name)
                if not m or int(m.group(1)) >= _RCA_CACHE_VERSION:
                    continue
            try:
                os.remove(os.path.join(root, name))
                removed += 1
            except OSError:
                pass
    if removed:
        log("ROOT_CAUSE", f"清理死缓存 {removed} 个文件"
                          f"（当前版本 v{_RCA_CACHE_VERSION}，含历史平铺布局）")


class RootCauseAnalyzer:
    """误报根因分析器 — 挖掘链 + 验证链各自独立压缩，最后合并输出。"""

    def analyze(
        self,
        evaluation_id: str,
        fp_cases: list[dict],
        data_packs: list[DataPack],
        cancel_cb=None,
        project_id: str = "",
        task_id: str = "",
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
            task_id: 平台任务 ID——per-case 根因缓存按任务 ID 分目录存放

        Returns:
            分析结果列表，每项含：
            - case_id, vuln_title, description, outcome
            - mining: {session_chain, root_cause, fix_suggestion, compressed_summaries, l0_l7_breakpoints, l4_independent_verification}
            - verification: {session_chain, root_cause, fix_suggestion, compressed_summaries, l0_l7_breakpoints, l4_independent_verification}
        """
        # 旧版本缓存（prompt 变更前）永不再被读取，首次分析时一次性回收
        _sweep_old_cache_versions()

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
            # 人工标注只属于误报（FP）：漏报是开发态基线里未被上报的真实漏洞，
            # 没有"漏报原因"这种人工标注，以基线漏洞描述为分析依据。
            fp_reason = (case.get("human_confirmation_summary", "")
                         if str(outcome).upper() == "FP" else "")

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

        # per-case 根因缓存：trace 冻结 + 标注输入未变的 case 直接复用
        # 既有分析（根因/断点/责任方/L4 判定原样保留，重跑不翻案），
        # 只对新增确认（缓存未命中）的 case 跑 LLM。
        to_analyze: list[tuple[int, dict]] = []
        for i, case in enumerate(fp_cases):
            hit = _rca_cache_load(case, task_id)
            if hit is not None:
                results[i] = hit
            else:
                to_analyze.append((i, case))
        reused = len(fp_cases) - len(to_analyze)
        if fp_cases and reused:
            log("ROOT_CAUSE",
                f"根因缓存命中 {reused}/{len(fp_cases)} 个 case"
                f"（标注输入未变，复用既有根因），新分析 {len(to_analyze)} 个",
                eval_id=evaluation_id)

        def _run_and_save(idx_case):
            idx, result = _run_case(idx_case)
            _rca_cache_save(fp_cases[idx], result, task_id)
            return idx, result

        max_workers = min(len(to_analyze), 10)
        if to_analyze:
            if max_workers <= 1:
                for i, case in to_analyze:
                    idx, result = _run_case((i, case))
                    _rca_cache_save(fp_cases[idx], result, task_id)
                    results[idx] = result
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(_run_and_save, (i, c)): i
                               for i, c in to_analyze}
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
        fp_reason: 人工标注的误报原因（仅 FP 提供；FN 为空，以基线漏洞描述为分析依据）。
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
            trace_texts[sid] = session_text

            # 程序核对知识/记忆记录的引用情况，作为 L6 判定的事实依据——
            # 模型会漏看返回后的引用（同一 trace 两次跑出 L6=true / false）。
            citation_hint, cited_ids = self._knowledge_citation_facts(
                session_text, vuln_title, desc)

            user_content = (
                f"漏洞标题：{vuln_title}\n"
                f"漏洞描述：{desc}\n"
                f"outcome：{outcome or 'FP'}（FP=误报，FN=漏报）\n"
                + _annotation_line(fp_reason, outcome) + "\n"
                + (f"\n{citation_hint}\n" if citation_hint else "")
                + f"\nSession {i+1}/{len(chain)} (session_id={sid}):\n"
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

            l0_l7 = result.get("l0_l7") or []
            # L6 兜底：程序已核实记录 ID 在返回后被引用，L6 必为 true。
            # 只在 session 内恰好一条知识访问时生效，避免多条访问错配。
            if cited_ids:
                accessed = [kp for kp in l0_l7 if isinstance(kp, dict)
                            and str(kp.get("l2_initiated")).lower() == "true"]
                if len(accessed) == 1 and str(
                        accessed[0].get("l6_used")).lower() != "true":
                    accessed[0]["l6_used"] = True
                    log("ROOT_CAUSE",
                        f"case {case_id}: {chain_type} session {sid[:8]} "
                        f"L6 兜底修正 false→true（引用记录 {cited_ids[:3]}）",
                        eval_id=evaluation_id)

            return {
                "session_id": sid,
                "step": i + 1,
                "summary": result.get("summary", ""),
                "key_findings": result.get("key_findings") or [],
                "evidence_cards": self._verified_evidence_cards(
                    result.get("evidence_cards") or [], session_text,
                    case_id, chain_type, sid),
                "retention_check": result.get("retention_check") or [],
                "insufficient_evidence": bool(
                    result.get("insufficient_evidence")),
                "insufficient_reason": result.get("insufficient_reason") or "",
                "l0_l7": l0_l7,
            }

        # 构建任务列表：(step_index, session_id)
        tasks = [(i, sid) for i, sid in enumerate(chain)]

        # 本链实际喂给 LLM 的 session 文本（内容寻址快照用）
        trace_texts: dict[str, str] = {}

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

        # 落盘本次分析实际使用的 session 文本（内容寻址），
        # 用于两次评测对比「输入是否变了」以及离线复现。
        input_fingerprint = self._write_trace_snapshot(
            evaluation_id, case_id, chain_type, chain, trace_texts)

        # 断点不变量程序兜底：L2/L6 已确定时，级别和 cause_code 不由模型自由选择。
        # 必须在 _build_bp_registry 之前执行，保证合并提示词看到的是同一份结果。
        for s in compressed_summaries:
            for kp in (s.get("l0_l7") or []):
                if isinstance(kp, dict):
                    self._normalize_breakpoint(kp, case_id, chain_type)

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
                if not brk or brk in ("null", "none"):
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
        # 漏报没有人工标注，quality 评估无依据，不输出也不进统计。
        merge_label_quality = (merge_result.get("label_quality", {
            "precision": "precise",
            "reason": "",
            "follow_up_questions": [],
        }) if str(outcome).upper() != "FN" else {})

        # ── label_quality 矛盾守卫 ──
        # imprecise 必须有文本缺陷论证 + 待确认问题 + 需人工确认；
        # LLM 常把「标注前提在材料外无法验证」误判成 imprecise（本应是
        # precise + needs_label_confirmation=true）。矛盾形态一律降级
        # 回 precise+待确认，防止无依据 imprecise 污染问题单与统计。
        merge_label_quality = self._enforce_label_quality(
            merge_label_quality, case_id=case_id, chain_type=chain_type,
            evaluation_id=evaluation_id)
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

        # ── 校验线索的 supporting_breakpoints 引用 ──
        # 丢弃不存在的 BP 编号（LLM 可能编造），保留「字段缺失」与「空数组」的区别：
        #   空数组 = LLM 明确表示此线索不基于任何断点
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
                    f"case {case_id}: {chain_type} 线索引用了不存在的断点编号，"
                    f"已丢弃 {dropped}（有效编号共 {len(_valid_refs)} 个）")
            h["supporting_breakpoints"] = kept

        # ── 证据门槛：引用必须指向真实存在的证据卡；置信度 <0.5 丢弃 ──
        valid_card_ids = {
            c.get("evidence_id")
            for s in compressed_summaries
            for c in (s.get("evidence_cards") or [])
            if isinstance(c, dict) and c.get("evidence_id")
        }
        grounded = []
        for h in merge_hypotheses:
            refs = h.get("evidence_refs") or []
            kept = [r for r in refs
                    if isinstance(r, str) and r in valid_card_ids]
            dropped = [r for r in refs if r not in kept]
            h["evidence_refs"] = kept
            try:
                conf = float(h.get("confidence", 0.7))
            except (TypeError, ValueError):
                conf = 0.0
            h["confidence"] = conf
            if dropped:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} 线索引用了不存在的证据卡，"
                    f"已丢弃 {dropped}")
            if kept and conf >= 0.5:
                grounded.append(h)
            else:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} 线索证据不足/置信度过低，"
                    f"已丢弃: {str(h.get('hypothesis', ''))[:60]} "
                    f"(refs={len(kept)}, confidence={conf})")
        merge_hypotheses = grounded

        # ── 近重复线索去重 ──
        # merge prompt 要求线索互斥，但 LLM 常把同一缺失换措辞输出多条。
        merge_hypotheses = self._dedup_near_duplicate_hypotheses(
            merge_hypotheses, case_id=case_id, chain_type=chain_type,
            evaluation_id=evaluation_id)

        # 只有置信度 >=0.7 的线索参与顶层展示摘要的选取
        primary_pool = [h for h in merge_hypotheses
                        if h.get("confidence", 0.7) >= 0.7]

        # ── 从多线索提取兼容字段（root_cause + fix_suggestion）──
        # 顶层摘要取置信度最高的线索；probability 仅作展示，不参与排序。
        # 只有置信度 >=0.7 且有真实证据卡的线索才参与。
        insufficient = (bool(merge_result.get("insufficient_evidence"))
                        or not primary_pool)
        top_hypothesis = None
        if not insufficient and primary_pool:
            # 链级展示取标注匹配度最高的一条假定线索（缺省回退证据支撑度）；
            # 并列时按证据支撑度、最早断裂 L、证据卡数量、cause_code 做确定性
            # tie-break。
            # 不使用 LLM 自由选择的 primary_hypothesis——它会在 A/H 之间漂移。
            # 最终重算（下方）会在 L4/重复上报修正后再次排序，此处仅作初步选择。
            top_hypothesis = sorted(
                primary_pool,
                key=lambda h: (
                    -_hypothesis_fit(h),
                    -float(h.get("confidence", 0) or 0),
                    _CAUSE_LEVEL_RANK.get(
                        str(h.get("cause_code") or ""), 99),
                    -len(h.get("evidence_refs") or []),
                    str(h.get("cause_code") or "Z"),
                ),
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
                "description": "没有任何线索能关联到证据卡，无法判定根因",
                "human_confirmation_reason": fp_reason,
                "insufficient_evidence": True,
            }

        # 以 root_cause 的最终状态为准：无线索/无证据也视为证据不足。
        insufficient = bool(merge_root_cause.get("insufficient_evidence"))

        # fix_suggestion 合并所有线索的修复点
        merge_fix = []
        for h in merge_hypotheses:
            fs = h.get("fix_suggestion")
            if isinstance(fs, dict):
                merge_fix.append(fs)

        # 注意：不再将 hypotheses 的 cause_code 合成为断点（session_id="hypothesis"）。
        # 合成断点是 LLM 线索推理的产物，修复点找不到对应 session 文件，
        # 无法定位到具体修改位置。断点只保留 session 级/merge 级——它们带真实
        # 查询命令与返回内容，修复建议可回溯到具体 session。
        # 线索体系（hypotheses）单独在多线索卡片展示，不进断点统计。

        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} 合并压缩完成 "
            f"(summary {len(merge_summary)} 字, "
            f"{len(merge_hypotheses)} 个线索, "
            f"top={merge_root_cause.get('category', '?')})",
            eval_id=evaluation_id)

        # ── 重复上报强制归因修正（代码级兜底，防 LLM 不遵守 prompt 规则）──
        # 人工标注为重复上报时，将所有指向知识/记忆链路的线索（C/E/G/知识责任）
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
                    f"{corrected} 个知识链路线索修正为 H/agent"
                    f"（重复上报是流程去重缺陷，非知识问题）")
            # 注意：不改 session 压缩阶段产出的 L2-L7 断点（保留原断点级别）。
            # 重复上报归因 H/L8 只针对 hypothesis 阶段产出的合成 L8 断点
            # （上面循环已改），session 级的 C/E/G/D 断点保留原 breakpoint 级别
            # ——改了会导致 H/L8 断点数膨胀（如 case-20260920-031946 的 mining
            # 5 个 L2-L7 C 断点全部被改成 L8/H，H 总数从合理值膨胀到 357）。

        # ── L4 独立验证（扩展：知识缺失线索也触发）──
        l4_verification = self._verify_l4_independently(
            case_id, chain_type, vuln_title, fp_reason, outcome,
            all_breakpoints, project_id, cancel_cb,
            hypotheses=merge_hypotheses,
            evaluation_id=evaluation_id,
        )

        # ── 系统验证结论 → 证据卡 ──
        # 类机制：评测系统代为执行的验证结论（L4 检索，及未来任何程序化
        # 核查）统一落成「系统验证」证据卡，进入 compressed_summaries
        # 证据卡池——线索用 evidence_refs 正常引用，页面与其他证据卡
        # 统一渲染；不再各自往 evidence 字段拼文本（点补丁）。
        l4_card = self._build_system_verification_card(
            l4_verification or {}, chain_type)
        if l4_card:
            compressed_summaries.append({
                "session_id": "system-verification",
                "summary": f"L4 独立验证结论（{chain_type}链，"
                           f"评测系统代为检索知识库）",
                "evidence_cards": [l4_card],
            })

        # ── L4 闭环应用 ──
        # 验证结果不再只记录不使用：agent 没查的那个来源里到底有没有知识，
        # 直接决定 A/C 归因方向——有知识（l4=true）→ 责任在 agent（该查没查，
        # 保持 A）；无知识（l4=false）→ 责任在知识库（改 C/knowledge）。
        # 幂等性：l4 结果随 case 快照固化（l4_independent_verification 字段），
        # 下游消费的是本次运行的固化值，不因外部检索波动而漂移。
        self._apply_l4_closed_loop(
            merge_hypotheses, l4_verification,
            case_id=case_id, chain_type=chain_type,
            evaluation_id=evaluation_id,
            card_id=l4_card.get("evidence_id", ""))

        # ── 线索一致性守卫 ──
        # LLM 常产出自相矛盾的线索（responsibility=agent + agent_can_resolve=false
        # + blocked_by 非空）：既要求 agent 修，又承认 agent 修不了。代码级兜底，
        # 防止矛盾线索带着高 confidence 进入顶层排序。
        self._enforce_hypothesis_consistency(
            merge_hypotheses, case_id=case_id, chain_type=chain_type,
            evaluation_id=evaluation_id)

        # ── 线索筛选：只保留有证据卡的线索 ──
        # probability 不再参与筛选；无证据的线索已在上面丢弃。
        # 证据不足的 case 不保留任何线索，避免下游误生成问题单。
        if insufficient:
            merge_hypotheses = []

        # ── 最终状态重算 ──
        # L4/重复上报可能改了 cause_code；报告头部必须与最终线索一致，
        # 不能再沿用 L4 之前算出的 root_cause.category。
        if primary_pool:
            # 重算按最终 cause_code 与置信度排序，不沿用修正前的 top_hypothesis
            # 做 tie-break——重复上报修正可能把 C(L4) 降级为 H(L8)，原 top
            # 的 rank 变了，再用它做 tie-break 会给被降级的线索不当优势。
            # 置信度相同时按最早 L、证据数、cause_code，完全确定性。
            final_top = sorted(
                primary_pool,
                key=lambda h: (
                    -_hypothesis_fit(h),
                    -float(h.get("confidence", 0) or 0),
                    _CAUSE_LEVEL_RANK.get(
                        str(h.get("cause_code") or ""), 99),
                    -len(h.get("evidence_refs") or []),
                    str(h.get("cause_code") or "Z"),
                ),
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

        # 重算 fix_suggestion（只保留筛选后线索的修复建议）
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
            "input_fingerprint": input_fingerprint,
        }

    @staticmethod
    def _knowledge_citation_facts(
        session_text: str, vuln_title: str, desc: str,
    ) -> tuple[str, list[str]]:
        """核对知识/记忆返回记录在返回之后是否被引用。

        模型会漏看引用，导致同一 trace 两次跑出 L6=true/false
        （E/L6 与 G/L7 之间翻转）。这里把可核实的事实写进输入。

        Returns:
            (提示文本, 被引用的记录 ID 列表)
        """
        starts = [m.start() for m in re.finditer(r"(?m)^\[E\d+\] ", session_text)]
        if not starts:
            return "", []
        starts.append(len(session_text))

        title_tokens = set(re.findall(
            r"[A-Za-z_][A-Za-z0-9_.\-]{3,}",
            f"{vuln_title or ''} {desc or ''}"))

        lines: list[str] = []
        cited: list[str] = []
        for a, b in zip(starts, starts[1:]):
            block = session_text[a:b]
            marker = ("[记忆返回]" if "[记忆返回]" in block
                      else "[知识库返回]" if "[知识库返回]" in block else "")
            if not marker:
                continue
            ids = list(dict.fromkeys(
                re.findall(r"\bid:\s*([A-Za-z0-9_\-]{3,})", block)))
            if not ids:
                continue
            tail = session_text[b:]
            # 按记录切分，关键词重合按单条记录计算，避免整块误标
            for chunk in re.split(r"\n\s*-\s*id:\s*", block)[1:]:
                m = re.match(r"([A-Za-z0-9_\-]{3,})", chunk)
                if not m:
                    continue
                rid = m.group(1)
                tm = re.search(r"\n\s*type:\s*([A-Za-z_]+)", chunk)
                shared = sorted(t for t in title_tokens if t in chunk)
                cnt = len(re.findall(rf"\b{re.escape(rid)}\b", tail))
                if cnt:
                    cited.append(rid)
                parts = [f"{marker.strip('[]')}记录 {rid}"]
                if tm:
                    parts.append(f"type={tm.group(1)}")
                parts.append(f"返回后被引用 {cnt} 次")
                if shared:
                    parts.append(f"与上报的漏洞标题/描述共享关键词 {shared[:5]}")
                lines.append("- " + "；".join(parts))

        if not lines:
            return "", []
        hint = ("程序核对（事实，L6/L7 判定必须以此为准，不得凭印象判断是否引用）：\n"
                + "\n".join(lines))
        return hint, list(dict.fromkeys(cited))

    @staticmethod
    def _write_trace_snapshot(
        evaluation_id: str,
        case_id: str,
        chain_type: str,
        chain: list[str],
        trace_texts: dict[str, str],
    ) -> dict:
        """把本链实际喂给 LLM 的 session 文本写成内容寻址快照。

        文件名带 chain 级 sha256 前 12 位：同一份输入重跑命中同一文件，
        不覆盖、不增长；输入变了就生成新文件，能直接看出"这次输入不同"。
        快照只存文本 + 指纹，不参与判定，不是结果缓存。

        Returns:
            {"case_hash", "prompt_hash", "sessions": [{session_id, chars, sha256}]}
        """
        h = hashlib.sha256()
        sessions: list[dict] = []
        for sid in chain:
            text = trace_texts.get(sid, "")
            sh = hashlib.sha256(text.encode("utf-8")).hexdigest()
            h.update(sid.encode("utf-8"))
            h.update(sh.encode("utf-8"))
            sessions.append({"session_id": sid, "chars": len(text),
                             "sha256": sh, "text": text})
        case_hash = h.hexdigest()
        prompt_hash = hashlib.sha256(
            (_SYSTEM_PROMPT + _MERGE_PROMPT).encode("utf-8")).hexdigest()

        fingerprint = {
            "case_hash": case_hash,
            "prompt_hash": prompt_hash,
            "sessions": [{k: s[k] for k in ("session_id", "chars", "sha256")}
                         for s in sessions],
        }
        # 快照全文落盘由 system_config.trace_snapshot 控制；
        # 指纹始终记录，关闭时仍可对比两次评测的输入是否一致。
        from ..core import runtime_flags
        if not runtime_flags.get_flag("trace_snapshot"):
            fingerprint["snapshot_written"] = False
            return fingerprint
        written = False
        try:
            from ...config_loader import get_reports_dir
            path = os.path.join(
                get_reports_dir(),
                f"{evaluation_id}_trace_{case_id}_{chain_type}_"
                f"{case_hash[:12]}.json")
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({
                        "evaluation_id": evaluation_id,
                        "case_id": case_id,
                        "chain_type": chain_type,
                        **fingerprint,
                        "sessions": sessions,
                    }, f, ensure_ascii=False)
                log("ROOT_CAUSE", f"trace 快照: {path}")
            written = True
        except Exception as e:
            log("ROOT_CAUSE", f"trace 快照写入失败 case={case_id}: {e}",
                eval_id=evaluation_id)
        fingerprint["snapshot_written"] = written
        return fingerprint

    @staticmethod
    def _hypothesis_to_category(hypothesis: dict) -> str:
        """从 cause_code 映射到 root_cause.category（单一权威源）。"""
        cause = hypothesis.get("cause_code", "")
        return CAUSE_TO_CATEGORY.get(cause, "reasoning_flaw")

    @staticmethod
    def _normalize_breakpoint(kp: dict, case_id: str = "", chain_type: str = "") -> None:
        """按 L1/L2/L6 的不变量修正断点，消除模型自相矛盾的判级。

        不变量（与提示词一致，程序兜底）：
        - L2=false + L1=true → L2/A。
        - L2=true → L1=true（唯一例外是记录性访问，其 L6=false 不在此修正）。
        - L2=true + L6=true + L7=negative → L7/G。
        - L2=true + L6=true + L7=null   → L7/F。

        只修正自相矛盾的组合，不改写证据完整、判级自洽的结果。
        """
        def _flag(v) -> bool | None:
            if isinstance(v, bool):
                return v
            s = str(v).strip().lower()
            if s == "true":
                return True
            if s == "false":
                return False
            return None

        l1 = _flag(kp.get("l1_need"))
        l2 = _flag(kp.get("l2_initiated"))
        l6 = _flag(kp.get("l6_used"))
        l7 = str(kp.get("l7_influenced") or "").strip().lower() or "null"

        new_brk, new_cause = kp.get("breakpoint"), kp.get("cause_code", "")
        new_l1 = kp.get("l1_need")

        if l2 is False and l1 is True:
            new_brk, new_cause = "L2", "A"
        elif l2 is True and l6 is True:
            new_l1 = True
            if l7 == "negative":
                new_brk, new_cause = "L7", "G"
            elif l7 == "null":
                new_brk, new_cause = "L7", "F"

        if (new_brk, new_cause, new_l1) != (
                kp.get("breakpoint"), kp.get("cause_code", ""), kp.get("l1_need")):
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 断点不变量修正 "
                f"L1={kp.get('l1_need')} L2={kp.get('l2_initiated')} "
                f"L6={kp.get('l6_used')} L7={kp.get('l7_influenced')}: "
                f"{kp.get('breakpoint')}/{kp.get('cause_code')} → "
                f"{new_brk}/{new_cause}")
        kp["l1_need"] = new_l1
        kp["breakpoint"] = new_brk
        kp["cause_code"] = new_cause

    @staticmethod
    def _normalize_quote_text(s: str) -> str:
        return re.sub(r"\s+", " ", str(s or "")).strip()

    @classmethod
    def _quote_is_grounded(cls, quote: str, norm_text: str) -> bool:
        """证据卡 quote 必须能在本 session 原文中逐字找到。

        先尝试整段（前 120 字）；失败再逐行检查（长度 >=12），
        容忍 quote 合并了多行原文，但不接受完全编造的内容。
        """
        raw = str(quote or "").replace("…", "").strip()
        if not raw:
            return False
        full = cls._normalize_quote_text(raw)
        if full and full[:120] in norm_text:
            return True
        for line in raw.splitlines():
            part = cls._normalize_quote_text(line)
            if len(part) >= 12 and part in norm_text:
                return True
        return False

    @classmethod
    def _verified_evidence_cards(
        cls, cards, session_text: str, case_id: str,
        chain_type: str, sid: str,
    ) -> list:
        """丢弃 quote 在原文中找不到的证据卡。"""
        norm_text = cls._normalize_quote_text(session_text)
        kept, dropped = [], []
        for c in cards or []:
            if not isinstance(c, dict):
                continue
            if cls._quote_is_grounded(c.get("quote"), norm_text):
                kept.append(c)
            else:
                dropped.append(c.get("evidence_id", ""))
        if dropped:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} session {sid[:8]} "
                f"证据卡 quote 未在原文中找到，已丢弃: {dropped}")
        return kept

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
                if not brk or brk in ("null", "none"):
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
        让 LLM 在线索里引用「supporting_breakpoints」时能精确定位。
        """
        parts = [
            f"漏洞标题：{vuln_title}",
            f"漏洞描述：{desc}",
            f"outcome：{outcome or 'FP'}（FP=误报，FN=漏报）",
            _annotation_line(fp_reason, outcome),
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
                    "证据卡（线索的 evidence_refs 只能引用下列 evidence_id）:")
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
                    # 逐条打印并附链内 BP 编号，供线索的 supporting_breakpoints
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
        - 线索 cause_code=A（该查没查）

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
        # LLM 判定有 L2 断点或 A 线索，但没产出 kb_search_query，
        # 说明 LLM 无法确定该查什么——不查 Athena（查了也是白查）。
        if not kb_search_queries:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 检测到"
                f"{'L2 断点' if has_l2_break else ''}"
                f"{'+' if has_l2_break and has_a_hypothesis else ''}"
                f"{'A/该查没查线索' if has_a_hypothesis else ''}，"
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
            f"{'A/该查没查线索' if has_a_hypothesis else ''}，"
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

            # L4 结果在本链内立即闭环应用（_apply_l4_closed_loop），
            # 并随 case 快照固化（l4_independent_verification 字段）——
            # 下游消费固化值，不因外部检索波动导致重复分析漂移。
            # 断点（session 级 L0-L7）不改：断点是事实记录，
            # 归因修正是 hypotheses 层的职责（与重复上报守卫同模式）。
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 结果将闭环应用到线索 "
                f"(l4={result.get('l4_knowledge_exists')})")

            return result
        except Exception as e:
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 独立验证失败")
            log_error(evaluation_id, "ROOT_CAUSE", e)
            raise

    @staticmethod
    def _build_system_verification_card(
        l4_verification: dict, chain_type: str,
    ) -> dict:
        """把系统验证结论建成「系统验证」证据卡。

        类机制：评测系统代为执行的验证结论（L4 独立检索，及未来任何
        程序化核查）统一落成 fact_type=系统验证 的证据卡，进入
        compressed_summaries 证据卡池——线索用 evidence_refs 正常引用，
        页面与其他证据卡统一渲染，不再各自往 evidence 字段拼文本。
        """
        l4 = l4_verification.get("l4_knowledge_exists")
        if l4 is None:
            return {}
        # 方向：旧数据无 direction 时，命中默认正向（与既有闭环行为一致）
        direction = str(l4_verification.get("l4_knowledge_direction")
                        or ("positive" if l4 else "none"))
        hit_titles = [
            str(m.get("title") or "").strip()
            for m in (l4_verification.get("matched_files") or [])
            if isinstance(m, dict) and m.get("title")]
        dir_label = {
            "positive": "命中正向知识（能引导正确判定）",
            "negative": "命中负向知识（会把判定引向错误——知识库需修正/下架该内容）",
            "mixed": "正负向知识并存（既有引导正确判定的内容，也有误导内容）",
            "none": "未找到相关知识",
        }.get(direction, "方向未判定")
        quote = (
            f"L4 独立验证（{chain_type}链，评测系统代为检索知识库）："
            + dir_label
        )
        if l4 and hit_titles:
            quote += "——" + "；".join(hit_titles[:3])
        summary = str(l4_verification.get("summary") or "").strip()
        if summary:
            quote += f"（{summary}）"
        return {
            "evidence_id": f"E-L4-VERIFY-{chain_type}",
            "fact_type": "系统验证",
            "source": "L4 独立检索",
            "event_idx": None,
            "quote": quote,
            "session_id": "",
        }

    @staticmethod
    def _evidence_text(value) -> str:
        """线索 evidence 归一成字符串：LLM 偶尔把 evidence 输出成数组。"""
        if isinstance(value, list):
            return "；".join(
                str(v).strip() for v in value if str(v or "").strip())
        return str(value or "").strip()

    def _apply_l4_closed_loop(
        self,
        hypotheses: list[dict],
        l4_verification: dict | None,
        case_id: str = "",
        chain_type: str = "",
        evaluation_id: str = "",
        card_id: str = "",
    ) -> None:
        """L4 闭环：用独立验证结果修正 A 类线索的归因方向。

        闭环逻辑（与 _verify_l4_independently 的设计意图一致），三态：
        - 命中正向知识（l4=true，direction=positive/None）→ 查了就对了 →
          责任在 agent（该查没查），cause_code 保持 A，且必须
          agent_can_resolve=true、无 blocked_by。
        - 命中负向知识（l4=true，direction=negative）→ agent 即使查了也会
          被误导 → 首要修复是知识库**修正/下架**该内容（与"缺失→补充"
          是两种不同的知识问题）→ 责任在 knowledge。
        - 没有知识（l4=false）→ 查了也没用 → 知识**供给缺口**（补充），
          cause_code 改 C/knowledge。
        - l4_knowledge_exists=None（未查/跳过/查询失败）→ 不修改。
        mixed（正负并存）按正向处理（查了有机会拿到正确知识），
        卡内容如实标注并存。

        各结论都以「系统验证」证据卡（card_id）引用进线索的
        evidence_refs——与普通证据卡同一体系，不拼文本。

        只修正 hypotheses 层，不改 session 级 L0-L7 断点（断点是事实记录，
        与重复上报守卫同模式）。
        """
        if not hypotheses or not isinstance(l4_verification, dict):
            return
        l4 = l4_verification.get("l4_knowledge_exists")
        if l4 is None:
            return
        # 方向：旧数据无 direction 时，命中默认正向（与既有行为一致）
        direction = str(l4_verification.get("l4_knowledge_direction")
                        or ("positive" if l4 else "none"))
        negative = l4 is True and direction == "negative"

        for h in hypotheses:
            if str(h.get("cause_code") or "") != "A":
                continue
            if card_id and card_id not in (h.get("evidence_refs") or []):
                h.setdefault("evidence_refs", []).append(card_id)
            if negative:
                # 命中的是负向知识：agent 查了会被误导——首要修复是
                # 知识库修正/下架，而非补充（与"缺失"区分）
                h["cause_code"] = "C"
                h["responsibility"] = "knowledge"
                h["agent_can_resolve"] = False
                h["blocked_by"] = ("知识库存在误导性知识（L4 命中会把判定"
                                   "引向错误的内容），需修正/下架")
                ev = self._evidence_text(h.get("evidence"))
                h["evidence"] = (
                    ev + ("；" if ev else "")
                    + f"{card_id}：L4 命中负向知识——agent 即使查询也会被"
                      f"误导，首要修复是修正/下架知识内容"
                )
                fs = h.get("fix_suggestion")
                if isinstance(fs, dict) and fs.get("target") in (
                        "agent_prompt", "agent_code"):
                    fs["target"] = "knowledge"
                    fs["knowledge_source"] = "knowledge_base"
                    fs["action"] = (
                        "修正/下架知识库中的误导性内容（L4 命中会把判定"
                        "引向错误的知识），" + str(fs.get("action") or "")
                    ).rstrip("，")
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} L4 闭环：命中负向知识，"
                    f"A 线索修正为 C/knowledge（修正而非补充）: "
                    f"{str(h.get('hypothesis', ''))[:60]}",
                    eval_id=evaluation_id)
            elif l4:
                # 知识库有知识 → A 保持 agent 责任，且 agent 可解决
                h["responsibility"] = "agent"
                h["agent_can_resolve"] = True
                h["blocked_by"] = ""
                h["needed_external_data"] = []
                ev = self._evidence_text(h.get("evidence"))
                h["evidence"] = (
                    ev + ("；" if ev else "")
                    + f"{card_id}：该查的知识存在（L4 独立检索命中），"
                      f"agent 未发起查询"
                )
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} L4 闭环：知识库有知识，"
                    f"A 线索保持 agent 责任（agent_can_resolve=true），"
                    f"L4 证据卡已引用: "
                    f"{str(h.get('hypothesis', ''))[:60]}",
                    eval_id=evaluation_id)
            else:
                # 知识库无知识 → 查了也没用，责任转知识库（C）
                h["cause_code"] = "C"
                h["responsibility"] = "knowledge"
                h["agent_can_resolve"] = False
                h["blocked_by"] = "知识库缺少对应业务/环境知识（L4 独立检索未命中）"
                ev = self._evidence_text(h.get("evidence"))
                h["evidence"] = (
                    ev + ("；" if ev else "")
                    + f"{card_id}：知识库主动检索未找到对应知识，"
                      f"查了也没用，责任在知识供给"
                )
                fs = h.get("fix_suggestion")
                if isinstance(fs, dict) and fs.get("target") in (
                        "agent_prompt", "agent_code"):
                    fs["target"] = "knowledge"
                    fs["knowledge_source"] = "knowledge_base"
                    fs["action"] = (
                        "补充知识库内容：沉淀该误报场景所需的业务/环境知识"
                        "（如项目部署架构约定、暴露面语义），"
                        + str(fs.get("action") or "补充知识库内容")
                    )
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} L4 闭环：知识库无对应知识，"
                    f"A 线索修正为 C/knowledge: "
                    f"{str(h.get('hypothesis', ''))[:60]}",
                    eval_id=evaluation_id)

    def _enforce_hypothesis_consistency(
        self,
        hypotheses: list[dict],
        case_id: str = "",
        chain_type: str = "",
        evaluation_id: str = "",
    ) -> None:
        """线索一致性守卫：responsibility 与 blocked_by/agent_can_resolve 一致。

        LLM 常产出自相矛盾的线索——responsibility=agent 却
        agent_can_resolve=false / blocked_by 非空（既要求 agent 修，又承认
        agent 修不了）。守卫规则：

        - responsibility=agent → agent_can_resolve 必须为 true；
          blocked_by 必须为空。违反时以 agent_can_resolve/blocked_by 为准
          （它们反映"能否解决"的事实），按 fix_suggestion.target 重写责任方：
          target=eval_process → eval_process；target=knowledge/memory →
          knowledge；其余 → external_data_source。
        - responsibility≠agent（knowledge/eval_process/external_data_source）
          不动——这些责任方允许 agent_can_resolve=false。
        """
        target_to_resp = {
            "eval_process": "eval_process",
            "knowledge": "knowledge",
            "memory": "knowledge",
        }
        for h in hypotheses:
            if str(h.get("responsibility") or "") != "agent":
                continue
            blocked = bool(str(h.get("blocked_by") or "").strip())
            can_resolve = h.get("agent_can_resolve")
            if not blocked and can_resolve is not False:
                continue
            fs = h.get("fix_suggestion")
            target = str((fs or {}).get("target") or "")
            new_resp = target_to_resp.get(target, "external_data_source")
            old_resp = h.get("responsibility")
            h["responsibility"] = new_resp
            if can_resolve is not False:
                h["agent_can_resolve"] = False
            if isinstance(fs, dict) and fs.get("target") in (
                    "agent_prompt", "agent_code"):
                fs["target"] = new_resp
                fs["agent_type"] = ""
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 一致性守卫：线索"
                f" responsibility {old_resp}→{new_resp}"
                f"（blocked_by 非空/agent_can_resolve=false 与 agent 责任矛盾）: "
                f"{str(h.get('hypothesis', ''))[:60]}",
                eval_id=evaluation_id)

    @staticmethod
    def _enforce_label_quality(
        lq: dict | None,
        case_id: str = "",
        chain_type: str = "",
        evaluation_id: str = "",
    ) -> dict | None:
        """label_quality 矛盾守卫：imprecise 必须有论证。

        imprecise = 标注文本自身缺陷，必须有 follow_up_questions 非空 +
        needs_label_confirmation=true。LLM 常把「标注前提在材料外无法验证」
        误判成 imprecise（本应是 precise + needs_label_confirmation=true），
        且 reason 填成误报成因复述、follow_up 留空。矛盾形态一律降级回
        precise+待确认，防止无依据 imprecise 污染问题单与 label_quality
        统计。
        """
        if not isinstance(lq, dict) or lq.get("precision") != "imprecise":
            return lq
        fus = lq.get("follow_up_questions") or []
        needs = lq.get("needs_label_confirmation")
        if fus and needs is True:
            return lq  # 形态完整，保留 imprecise
        fixed = dict(lq)
        fixed["precision"] = "precise"
        fixed["needs_label_confirmation"] = True
        log("ROOT_CAUSE",
            f"case {case_id}: {chain_type} label_quality 矛盾守卫："
            f"imprecise 缺论证（follow_up={len(fus)}, "
            f"needs_confirmation={needs}），降级回 precise+待确认: "
            f"{str(lq.get('reason', ''))[:80]}",
            eval_id=evaluation_id)
        return fixed

    @staticmethod
    def _dedup_near_duplicate_hypotheses(
        hypotheses: list[dict],
        case_id: str = "",
        chain_type: str = "",
        evaluation_id: str = "",
    ) -> list[dict]:
        """近重复线索去重：同一证据基础上的同一缺陷只保留置信度最高者。

        merge prompt 要求线索互斥，但 LLM 常把同一缺失换措辞输出多条
        （如 A「未查询知识库确认注解语义」+ H「未查询网关暴露面知识」）。
        判定标准：同一 session + 同一组断点 + 同一责任方 = 同一证据基础。
        无 session/断点定位的线索不参与去重（无证据基础可比）。
        丢弃均打日志留痕，可审计。
        """
        keep: dict[tuple, dict] = {}
        out: list[dict] = []
        for h in hypotheses:
            sid = str(h.get("session_id") or "")
            bps = tuple(sorted(str(b) for b in
                               (h.get("supporting_breakpoints") or [])))
            resp = str(h.get("responsibility") or "")
            if not sid or not bps:
                out.append(h)
                continue
            key = (sid, bps, resp)
            prev = keep.get(key)
            if prev is None:
                keep[key] = h
                out.append(h)
                continue
            if (_hypothesis_fit(h), float(h.get("confidence", 0) or 0)) > \
                    (_hypothesis_fit(prev),
                     float(prev.get("confidence", 0) or 0)):
                # 新线索排序分更高：替换已保留者
                drop, keep_val = prev, h
                out.remove(prev)
                keep[key] = h
                out.append(h)
            else:
                # 已保留者排序分更高：丢弃当前线索（尚未入列表，无需移除）
                drop, keep_val = h, prev
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} 近重复线索去重：丢弃"
                f"[{drop.get('cause_code')}] "
                f"{str(drop.get('hypothesis', ''))[:60]}，保留"
                f"[{keep_val.get('cause_code')}] "
                f"{str(keep_val.get('hypothesis', ''))[:60]}"
                f"（session={sid}, BP={list(bps)}, resp={resp}）",
                eval_id=evaluation_id)
        return out

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
                + _annotation_line(fp_reason, outcome) + "\n\n"
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
                        msgs, cancel_cb=cancel_cb,
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
            + _annotation_line(fp_reason, outcome) + "\n\n"
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
                merge_msgs, cancel_cb=cancel_cb,
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
