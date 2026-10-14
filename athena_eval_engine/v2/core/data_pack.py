"""DataPack — 标准化数据包（中间层）。

parser 输出 DataPack，下游模块只消费 DataPack，不直接调用 parser。
设计参考 docs/v2-architecture-design.md §3。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    events: list                       # list[RawEvent]
    session_graph: dict                # session 关系图（parent_id 边）
    session_meta: dict                 # session 元数据（token/step/time）

    # session 阶段标注（业务阶段归类，详见 docs/agent-session-phase-classification.md）
    session_phase_labels: dict         # session_id -> 业务阶段（第一层+第二层程序标注）
    session_phase_source: dict         # session_id -> 标注来源标识符（task_type/agent_name/persona/analysisType/worker_type/tool_name）

    # Facts（resolver 从 events 提取）——用 Any 避免循环 import
    outcome_fact: Any | None = None    # OutcomeFact | None
    knowledge_fact: Any | None = None  # KnowledgeInteractionFact | None
    tool_action_fact: Any | None = None  # ToolActionFact | None
    resource_fact: Any | None = None   # ResourceFact | None

    # 基线
    benchmark_item: Any | None = None   # BenchmarkItem | None
