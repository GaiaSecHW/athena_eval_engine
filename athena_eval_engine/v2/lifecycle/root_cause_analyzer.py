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
import re
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

# 主因按最早断裂的 L 级别选择：L2(A/B) < L3 < L4(C) < L5(D) < L6(E)
# < L7(F/G) < L8(H/I/J/K)。级别越小越优先，避免 A 与 H 同时存在时
# 因证据卡数量波动导致主因翻转。
_CAUSE_LEVEL_RANK = {
    "A": 2, "B": 3, "C": 4, "D": 5,
    "E": 6, "F": 7, "G": 7,
    "H": 8, "I": 8, "J": 8, "K": 8,
}

# ── 系统 prompt（固定）──

_SYSTEM_PROMPT = """你是漏洞根因分析专家。你的任务是**压缩**一条漏洞链中的某个 session 原文：把很长的 session 压缩成结构化摘要，同时抽取证据卡、判定 L0-L8。

输入是一条 session 的完整事件流，每行以 [En] 开头；另有人工标注的误报/漏报原因。
outcome：FP=agent 报了但实际不是漏洞（误报）；FN=agent 漏报了真实漏洞。
输出不是逐段复述，而是三样东西：
1. 一份 3000 字以内的自包含摘要；
2. 证据卡（原文逐字摘录，供下游合并阶段引用）；
3. 本 session 的 L0-L8 判定。

压缩原则：
- 保留：agent 读了什么、执行了什么、返回了什么、推理依据、结论、知识/记忆访问、部署/配置事实、遗漏与矛盾等关键的漏洞相关信息。
- 丢弃：重复输出、无关日志、大段源码（只保留与判定相关的行）、格式化噪声。
- 摘要必须自包含：没看过原文的人也能理解发生了什么、为什么误报。
- 不得引入原文没有的信息；每条事实都要能由证据卡回指。
- 如果输入是多个分片的摘要（分片压缩后的合并），任务是把它们合并成一份完整摘要，按同样的保留/丢弃原则，不要丢事实。

# 判定流程（严格按顺序，不要跳步）

1. 抽证据卡：原文里出现的事实，逐条落成证据卡。
2. 判 L1→L8：只查下面的决策表，按顺序判，不跳级。
3. 判知识访问相关性：返回内容主张的是否就是被上报的同一个漏洞。
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
- 找不到原文依据的内容，不得写进 summary 或假设。

# 知识/记忆访问的识别

评测引擎已在 session 文本中标记知识/记忆访问行为：
- `[知识库访问]`：agent 通过 athena_ask MCP、bash athena CLI、或 vuln_hunt_submit_knowledge 访问 Athena
- `[知识库返回]`：知识库返回的内容
- `[记忆访问]`：agent 通过 mem.sh CLI 或 cat 读取 wiki .md 文件访问记忆
- `[记忆返回]`：记忆返回的内容

规则：
- 只有带上述标记的工具调用才算知识/记忆访问；read/grep/shell 等普通代码检索不算。
- 标记是评测引擎预处理的结果，是权威事实；不要自行把普通工具调用推断为知识访问。
- L0 来源：从标记判断是"知识库"还是"记忆"。
- L2 发起访问：有 `[知识库访问]` 或 `[记忆访问]` 标记即为 true。

# 术语表（统一定义）

- 断点：L1→L8 逐级判定中，第一个不通过的级别；断点级别就是该级别。
- 记录性访问：知识/记忆访问与本次误报无关，只作为事实记录（L6/E），不作为主因。
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
| L8 | 知识链路无问题，但 agent 仍误报 | H 流程缺陷 / I 调用链中断 / J 模型幻觉 / K 验证否定真漏洞 |

L1 边界（仓库内事实 vs 外部事实）：
1. 仓库内事实：源码、配置文件中明确写出来的值（例如 compose.yml 里的 ports: 127.0.0.1:4280:80）。
   → L1=false（不需要外部知识，读仓库就知道）。
2. 外部事实：仓库里读不到，必须靠知识库/记忆/部署环境才能知道。
   - 实际运行时配置（DISABLE_AUTHENTICATION 是否开启）
   - 环境变量实际取值
   - 真实网络暴露面
   - 方法论/判定准则（如"如何判断配置开关是否生效"）
   → L1=true（需要知识/方法）。

边界规则：
- 文件在 agent 的工作目录里、没有访问限制 → 算仓库内事实；即使 agent 没读，也 L1=false，漏读归 H。
- 只读 *.dist/*.example 模板、实际值在部署时生成 → 实际值仍是外部事实 → L1=true，A。
- 仓库里根本没有该文件（或只有模板）→ 外部事实 → L1=true，A。
- L1=true 且 L2=false（没有知识/记忆访问）→ L2/A。
- L1=true 且 L2=true → 继续 L3-L7。
- L1=false → 走 L8 验证维度；如果 agent 读到了仓库事实但用错 → H。

L1/L2 证据门槛（强制）：
- 判 L1=true 必须写明需要哪条外部知识/方法（1-3 条）。
- 判 L2=false 必须确认 session 中没有 `[知识库访问]`/`[记忆访问]` 标记。
- 判 H 必须引用一张证据卡，展示 agent 已读到仓库事实但结论与事实矛盾。

L7 规则：
- L6=true 且返回内容错误/过时/by-design，且被用作上报依据 → L7=negative，cause_code=G。
- L6=true 但结论未采纳 → L7=null，断点 L7，cause_code=F。
- L6=false（读了但推理未引用）→ 断点 L6，cause_code=E。
- 以上都不是 L8。L8 只在以下情况使用：L7=positive；L1=false（不需要知识，问题在非知识维度）；或知识访问为记录性且与误报无关（L6=false，已说明无关）。重复上报按专门规则直接判 L8/H。

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
| A | 负证据卡：所需事实 + 核验范围（读了哪些文件/命令），范围内无对应访问记录 |
| B | agent 实际查询命令原文 + 不聚焦的具体理由 |
| C | 同源查询命令 + 返回为空/无相关内容的原文 |
| D | 返回错误/超时的原文 |
| E | 返回内容原文 + 推理中未引用该内容的依据 |
| F | 返回内容原文 + 引用但结论未采纳的依据 |
| G | 返回内容原文（含与上报漏洞相同的组件/行为）+ agent 引用该内容的推理原文 |
| H | 已访问该事实的证据（文件/命令/原文）+ 结论与事实矛盾的证据 |
| I | sink 命中证据 + 调用链断点的证据 |
| J | agent 虚构内容原文 + 材料中不存在该内容的证据 |
| K | 挖掘 CONFIRMED 结论 + 验证否定的结论 |

不满足 → 不得给该 cause_code；改判为满足证据要求的类别，或标 insufficient_evidence。

# 置信度（confidence）

confidence 表示"证据对当前结论的支撑程度"，不是"根因可能性"：
- 0.9：所需证据齐全且 quote 已在原文核实，无反证；
- 0.7：所需证据齐全，但有已解释的反证；
- 0.5：证据部分相关，只能作为次要判断，不能做主因；
- 0.3：证据薄弱，不应输出；
- 0.1：猜测，禁止输出。
主因要求 confidence >= 0.7；0.5<=confidence<0.7 只能作为次要结论，不参与主因；<0.5 的结论直接丢弃。

# Step 3 输出

下面的 schema 是字段示意，不是可直接复制的 JSON；输出时每个字段只取一个值，不要把 `A/B/C` 或 `true/false` 整串抄进去；必须是合法 JSON。

{
  "summary": "结构化摘要，3000字以内，必须覆盖证据卡所有非空项",
  "key_findings": ["..."],
  "evidence_cards": [ ... ],
  "retention_check": [{"item": "配置/部署事实", "status": "preserved/absent", "evidence_ids": ["E-..."]}],
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
      "breakpoint": "L2/L3/L4/L5/L6/L7/L8/null",
      "cause_code": "A/B/C/D/E/F/G/H/I/J/K/null",
      "confidence": 0.9,
      "evidence_refs": ["E-..."],
      "query_content": "agent 实际执行的查询命令或参数；非知识断点填问题总结",
      "kb_search_query": "breakpoint=L2/L4 时填一个方法论问题，否则空",
      "returned_content": "实际返回内容概括，无则空",
      "fix_suggestion": "定位到本 session 的具体修复建议"
    }
  ],
  "insufficient_evidence": false,
  "insufficient_reason": ""
}

# 字段说明（输入 + 输出）

输入：
- [En]：事件索引；evidence_cards.event_idx 填对应的 n。
- outcome：FP=误报；FN=漏报。
- session_id / Session i/N：当前 session 的 ID 和在链中的位置。

输出：
- summary：压缩后的自包含摘要。
- key_findings：关键发现列表。
- evidence_cards：证据卡，字段见 Step 1。
- retention_check：保留清单核查；item=清单项名称，preserved=原文有且已保留，absent=原文没有；evidence_ids 填对应证据卡。
- l0_l7：本 session 的逐级判定，字段如下：
  - l0_source：知识来源（知识库/记忆/空）
  - l1_need：true=需要知识支撑；false=不需要；null=不适用（与字段名一致）
  - l2_initiated：是否发起知识/记忆访问
  - l3_accurate：查询是否聚焦
  - l4_exists：来源里是否有对应知识
  - l5_retrieved：是否成功取回
  - l6_used：推理是否引用返回内容
  - l7_influenced：positive/negative/null
  - breakpoint：第一个不通过的级别
  - cause_code：A-K
  - confidence：证据支撑度（0.1-0.9）
  - evidence_refs：支撑本判定的证据卡 ID
  - query_content：知识访问填实际查询命令；非知识断点填问题总结
  - kb_search_query：L2/L4 时填一个方法论检索问题
  - returned_content：知识/记忆返回内容；无则空
  - fix_suggestion：本 session 的修复建议
- insufficient_evidence / insufficient_reason：整个 session 无法给出有证据的判定时使用。

# 硬约束
- 没有证据卡的结论不输出。
- 禁止推测；材料里没有的写"材料中未出现"。
- kb_search_query 只问方法论，不问环境事实，禁止复合问题。
- 只返回 JSON，不要额外文字。

# 示例
例1 记忆返回 verified_finding，主张与上报漏洞相同，agent 引用后确认 → L7/negative/G。
例2 本次 session 只读 config.inc.php.dist、没读实际 config/config.inc.php → L1=true，L2/A；即使其他 session 读过 compose.yml，也不能算本次已访问。
例3 agent 读了 compose.yml，看到 127.0.0.1:4280:80，却仍判 path_reachable=true → L8/H。
例4 session 里没有任何知识访问，且所需事实不能从代码/配置读到 → L2/A；如果事实已在材料中但用错 → L8/H。

# 自检
- 证据卡覆盖保留清单的所有非空项？
- 有知识访问的 session 是否都出了 L2-L7？
- L6=true 且内容错误时是否判了 L7/G？
- L8 是否只在知识链路正常时出现？
- summary 是否只基于证据卡？

只返回 JSON。"""


_MERGE_PROMPT = """你是漏洞根因分析专家。输入是一条漏洞链涉及的多个 session 摘要、证据卡和 L0-L7 断点。输出根因假设、唯一主因和修复建议。

outcome：FP=误报；FN=漏报。
输入中的断点编号为 BP-n；假设的 supporting_breakpoints 只能引用这些编号。

# 术语表（统一定义）

- 假设：一个独立、不可再分的根因；2-5 个，互斥。
- 互斥：不能有包含/父子关系；若 A 成立必然导致 B，只保留一条。
- 反证：材料中与假设冲突的事实；没有反证要写明检查范围。
- 主因：按最早断裂 L 级别选出的唯一假设。
- primary_hypothesis：主因假设原文，必须与某条假设完全一致。
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
| L8 | 知识链路正常，问题在其他维度 | H 流程 / I 调用链 / J 幻觉 / K 验证否定 |

- `supporting_breakpoints` 填假设直接依据的 BP-n；只填输入中实际出现的编号。
- 不要重新判 L0-L8，也不要修改断点的级别或 cause_code。

# 判定流程（严格按顺序）

1. 读输入：只使用已给的证据卡和 L0-L7 断点，不要重新判 L0-L8。
2. 生成假设：2-5 个互斥假设，每个必须有 evidence_refs 和 counter_evidence。
3. 选主因：按最早断裂的 L 级别选唯一 primary_cause / primary_hypothesis。
4. 输出。

# Step 1 证据门槛
- 每个假设的 evidence_refs 只能引用输入中实际存在的 evidence_id。
- 找不到证据卡 → 禁止输出该假设；宁可少给，不许猜。
- evidence 字段必须逐条对应 evidence_refs。
- 证据不足（没有任何假设能引用证据卡）→ insufficient_evidence=true，primary_cause 空，不要给 L 级别。

# Step 2 反证
- 每个假设必须填 counter_evidence。
- 材料有反证 → 说明为何不足以推翻；没有反证 → 写明检查范围（看过哪些 session/事件）。

# Step 3 假设要求
- 2-5 个，互斥，不能有包含/父子关系。
- 每个假设一个独立缺陷，能定位到唯一修复点。
- cause_code / responsibility 必须符合下表。
- 人工标注只定 FP/FN 和复核背景，不作为归因证据；标注笼统时禁止从标注文字推断原因。

# Step 4 主因选择（强制）
- 按最早断裂的 L 级别：L2/L3(A/B) < L4(C) < L5(D) < L6(E) < L7(F/G) < L8(H/I/J/K)。
- 同级按证据卡数量降序；再按 cause_code 字母序。
- probability 只展示，不参与选择。
- primary_hypothesis 必须与某条假设原文完全一致。

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
- knowledge：补充/修正知识库内容
- external_data_source：需要外部数据源（网关配置/部署架构等）
- eval_process：评测流程改进

重复上报：标注含"重复上报/已上报/已报过" → 所有知识链路假设改 H/agent，禁止 A/C/E/G。

# 类别证据要求（不满足不得给该 cause_code）

| cause | 最低证据（必须来自 evidence_refs 指向的证据卡原文） |
|---|---|
| A | 负证据卡：所需事实 + 核验范围，范围内无对应访问记录 |
| B | agent 实际查询命令原文 + 不聚焦的理由 |
| C | 同源查询命令 + 返回为空/无相关内容 |
| D | 返回错误/超时原文 |
| E | 返回内容原文 + 推理未引用 |
| F | 返回内容原文 + 引用但结论未采纳 |
| G | 返回内容原文（含与上报漏洞相同的组件/行为）+ agent 引用该内容的推理原文 |
| H | 已访问该事实的证据 + 结论与事实矛盾的证据 |
| I | sink 命中证据 + 调用链断点证据 |
| J | agent 虚构内容原文 + 材料中不存在的证据 |
| K | 挖掘 CONFIRMED + 验证否定 |

不满足 → 不得给该 cause_code；改判为满足证据要求的类别，或把该假设标为证据不足。

G 的证据必须同时包含：① 记忆/知识返回内容原文；② agent 推理中引用该内容的原文。缺一不可，否则不能给 G。

# 置信度（confidence）

confidence 表示"证据对当前假设的支撑程度"，不是"根因可能性"：
- 0.9：所需证据齐全且 quote 已验证，无反证；
- 0.7：所需证据齐全，但有已解释的反证；
- 0.5：证据部分相关，只能作为次要假设，不能做主因；
- 0.3：证据薄弱，不应输出；
- 0.1：猜测，禁止输出。
主因要求 confidence >= 0.7；0.5<=confidence<0.7 只能作为次要假设，不参与主因；<0.5 的假设直接丢弃。

probability：根因可能性，仅展示，不参与选择。
confidence：证据对假设的支撑程度，用于门控（>=0.7 才能做主因）。两者不要混用。

# fix_suggestion 填写规则
- target=agent_prompt/agent_code 时，agent_type 必填（turing/argo/secmate/dataflow/webvuln_verify/cvuln_verify）。
- target=knowledge/memory 时，knowledge_source 必填（knowledge_base/memory_wiki）。
- action 必须能定位到具体位置，禁止空泛建议。
- 如果 agent_can_resolve=false，必须写 blocked_by 和 needed_external_data。

# 输出格式

下面的 schema 是字段示意，不是可直接复制的 JSON；输出时每个字段只取一个值，不要把 `A/B/C` 或 `true/false` 整串抄进去；必须是合法 JSON。
{
  "summary": "合并摘要，3000字以内",
  "primary_cause": "A-K 或空",
  "primary_hypothesis": "与某条假设原文一致，或空",
  "secondary_causes": ["..."],
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
      "hypothesis": "假设描述",
      "probability": 0.9,
      "responsibility": "agent/knowledge/external_data_source/eval_process",
      "cause_code": "A/B/C/D/E/F/G/H/I/J/K",
      "confidence": 0.9,
      "evidence_refs": ["E-..."],
      "counter_evidence": "反证，或检查范围",
      "evidence": "逐条对应 evidence_refs 的原文依据",
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
- primary_cause：唯一主因的 cause_code。
- primary_hypothesis：主因假设原文。
- secondary_causes：其余假设的 cause_code。
- insufficient_evidence / insufficient_reason：无假设能引用证据卡时使用。
- audit：逐条自检；rule=检查项，pass=true/false，note=说明。
- knowledge_memory_summary：
  - access_count：整条链知识/记忆访问次数
  - accesses：每次访问；source=knowledge_base/memory/unknown，query=查询，returned=返回，used_in_reasoning=是否引用，effect=positive/negative/neutral/none，session_id=来源 session
  - overall_effect：整体影响
  - impact_on_conclusion：对结论的影响说明
- hypotheses：每个假设包含：
  - hypothesis：假设描述
  - probability：根因可能性，仅展示
  - responsibility：agent/knowledge/external_data_source/eval_process
  - cause_code：A-K
  - confidence：证据支撑度，主因要求 >=0.7
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

# 硬约束
- 只使用输入中已有的证据卡和断点，不重新判 L0-L8。
- 没有 evidence_refs 的假设不输出。
- 主因按最早 L 级别选，不看 probability。
- 证据不足时不给结论。
- 只返回 JSON。

# 示例
例1 输入断点里有一条 L7/G（记忆内容误导），同时有一条 L8/H（未识别设计意图）→ 主因 G（L7 早于 L8）。
例2 输入断点里有 L2/A（未访问实际配置）和 L8/H → 主因 A（L2 早于 L8）。
例3 没有任何假设能引用证据卡 → insufficient_evidence=true。

# 自检
- 每个假设都有 evidence_refs 和 counter_evidence？
- 主因是否按最早 L 级别选？
- 是否有 L2/A 假设却把主因给了 L8？
- 证据不足时是否没有硬给结论？
"""


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
                "evidence_cards": self._verified_evidence_cards(
                    result.get("evidence_cards") or [], session_text,
                    case_id, chain_type, sid),
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
                    f"case {case_id}: {chain_type} 假设引用了不存在的证据卡，"
                    f"已丢弃 {dropped}")
            if kept and conf >= 0.5:
                grounded.append(h)
            else:
                log("ROOT_CAUSE",
                    f"case {case_id}: {chain_type} 假设证据不足/置信度过低，"
                    f"已丢弃: {str(h.get('hypothesis', ''))[:60]} "
                    f"(refs={len(kept)}, confidence={conf})")
        merge_hypotheses = grounded
        # 只有置信度 >=0.7 的假设才能参与主因选择
        primary_pool = [h for h in merge_hypotheses
                        if h.get("confidence", 0.7) >= 0.7]

        # ── 从多假设提取兼容字段（root_cause + fix_suggestion）──
        # 主因按最早断裂的 L 级别选取，不看 probability；probability 仅作展示。
        # 只有置信度 >=0.7 且有真实证据卡的假设才参与主因选择。
        insufficient = (bool(merge_result.get("insufficient_evidence"))
                        or not primary_pool)
        primary_hypothesis = (
            merge_result.get("primary_hypothesis") or "").strip()
        top_hypothesis = None
        if not insufficient and primary_pool:
            # 主因按最早断裂的 L 级别选择（L2/A 优先于 L7/G、L8/H），
            # 同级按证据卡数量降序，再按 cause_code 字母序。
            # 不使用 LLM 自由选择的 primary_hypothesis 作为主判据——
            # 它会在 A/H 之间漂移；LLM 的选择只作为同级同证据数的 tie-break。
            llm_primary = next(
                (h for h in primary_pool
                 if primary_hypothesis
                 and h.get("hypothesis") == primary_hypothesis), None)
            top_hypothesis = sorted(
                primary_pool,
                key=lambda h: (
                    _CAUSE_LEVEL_RANK.get(
                        str(h.get("cause_code") or ""), 99),
                    -len(h.get("evidence_refs") or []),
                    0 if h is llm_primary else 1,
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
        if primary_pool:
            # 重算时仍按最早断裂的 L 级别选主因；原主因对象只作同级 tie-break。
            final_top = sorted(
                primary_pool,
                key=lambda h: (
                    _CAUSE_LEVEL_RANK.get(
                        str(h.get("cause_code") or ""), 99),
                    -len(h.get("evidence_refs") or []),
                    0 if h is top_hypothesis else 1,
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
            "D": "link_error",           # 链路问题（工具失败/超时/解析错误）
            "E": "reasoning_flaw",       # 查到没用（agent 推理未引用）
            "F": "reasoning_flaw",       # 用了没推动（agent 未受影响）
            "G": "knowledge_error",      # 知识误导（knowledge 责任）
            "H": "process_flaw",  # 流程缺陷/其他 agent 侧
            "I": "reasoning_flaw",       # 调用链中断（agent 数据流分析不足）
            "J": "reasoning_flaw",       # 模型幻觉（agent 推理虚构）
            "K": "verification_dimension_missing",  # 验证否定真漏洞（agent 侧）
        }
        return category_map.get(cause, "reasoning_flaw")

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

            # L4 只记录知识库覆盖度，不修改断点、假设或主因。
            # 外部知识库的检索/判定每次都可能不同；若允许它改判 A↔C，
            # 同一份 trace 重复分析会得到不同结论。
            log("ROOT_CAUSE",
                f"case {case_id}: {chain_type} L4 仅记录 "
                f"(l4={result.get('l4_knowledge_exists')})，"
                f"不修改断点/假设/主因")

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
