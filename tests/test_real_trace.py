"""真实 Turing trace 适配测试 — opencode.db（§1 R1 真数据）。

验证 parser 对真实 opencode 格式（part 无 type 列、tool part 含 state、tokens 在 step-finish）可用。
"""
from __future__ import annotations
from pathlib import Path
import pytest

from athena_eval_engine.workers.turing_trace_parser import TuringTraceParser
from athena_eval_engine.workers.resolvers import (
    OutcomeResolverImpl, KnowledgeResolverImpl, ToolActionResolverImpl, ResourceResolverImpl,
)
from athena_eval_engine.domain.task_run import TaskRun, BenchmarkItem
from athena_eval_engine.domain.enums import Condition, ConditionSource, ExpectedLabel

REAL_DB = Path(__file__).parent / "fixtures" / "real_turing" / "opencode.db"
pytestmark = pytest.mark.skipif(not REAL_DB.exists(), reason="真实 opencode.db 未拉取")


EVAL_CONFIG = {
    "access_rules": {"skill_names": ["wiki-mount", "general-pre", "secocto-context-init", "preprocess"],
                     "path_patterns": ["wiki", "compiled_knowledge"],
                     "command_patterns": [r"source secocto.*wiki", "compiled_knowledge"]},
    "delivery_rules": {"path_patterns": ["/wiki/", "/compiled_knowledge/"],
                       "reject_patterns": [r"^not found$", r"^No wiki mount",
                                           r"^Error: .*permission denied", r"^Permission denied"]},
    "token_schema": {"reasoning_in_output": True, "cache_excluded": True},
}


def test_real_trace_parses_and_resolves():
    """真实 opencode.db：parser 产出 RawEvent，4 Resolver 产出 Fact，无崩溃。"""
    parser = TuringTraceParser()
    ts = {"trace_id": "real-1", "source_uri": str(REAL_DB), "turing_session_id": "ses_real"}
    events = list(parser.parse(ts))
    session = parser.load_session(ts)
    session["_events_ts"] = [e.timestamp_ms for e in events]

    # 至少有大量事件
    assert len(events) > 100, f"真实 trace 应有大量事件，实际 {len(events)}"
    types = {}
    for e in events:
        types[e.event_type] = types.get(e.event_type, 0) + 1
    print("event type 分布:", types)
    assert "TOOL_CALL" in types, "真实 trace 应有 tool 事件"

    # session tokens 从 step-finish 累计
    assert (session.get("tokens_input") or 0) > 0, f"tokens_input 应从 step-finish 累计: {session.get('tokens_input')}"
    assert (session.get("tokens_output") or 0) > 0

    # Resolvers（无 benchmark target → UNDETERMINED，但不崩溃）
    tr = TaskRun(task_run_id="tr-real", evaluation_id="EVREAL", task_id="T-real",
                 trace_id="real-1", condition=Condition.KG, condition_source=ConditionSource.MANIFEST,
                 trace_valid=True, runtime_valid=True, benchmark_item_id="BI-real")
    bench = BenchmarkItem("BI-real", "BS", "T-real", ExpectedLabel.VULNERABLE, target_finding_id="F-real")
    oc = OutcomeResolverImpl().resolve(tr, bench, events)
    kn = KnowledgeResolverImpl(EVAL_CONFIG).resolve(tr, events)
    ta = ToolActionResolverImpl(EVAL_CONFIG).resolve(tr, events, "1.0")
    rs = ResourceResolverImpl(EVAL_CONFIG).resolve(tr, session)

    # outcome 多半 UNDETERMINED（无 F-real finding），但不崩
    assert oc.outcome.value in ("SUCCESS", "FAIL", "UNDETERMINED")
    # behavior 有 tool 计数
    assert ta.total_tool_calls > 0, "真实 trace 应有 tool 调用"
    print("action 分布:", ta.action_distribution)
    # resource 有 effective_tokens + steps
    assert rs.effective_tokens is not None and rs.effective_tokens > 0
    assert rs.steps is not None and rs.steps > 0
    print(f"effective_tokens={rs.effective_tokens} steps={rs.steps} duration_ms={rs.duration_ms}")
