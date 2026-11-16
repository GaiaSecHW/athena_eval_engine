# Hook 1：远程 Case 分析接口

## 1. 定位

Hook 1 把 eval-engine 中「输入一个 case + 它的 session trace，输出 case 级根因分析」
从本地 `RootCauseAnalyzer` 抽象成可替换端口：

```text
                         ┌──────────────────────────────┐
                         │ eval-engine orchestrator      │
                         │ _stage_root_cause()          │
                         └──────────────┬───────────────┘
                                        │ CaseAnalysisPort.analyze()
                 ┌──────────────────────┼──────────────────────┐
                 │                      │                      │
          ┌──────▼──────┐       ┌───────▼────────┐      ┌──────▼──────┐
          │ local       │       │ remote         │      │ shadow      │
          │ RootCause   │       │ HTTP adapter   │      │ local 权威  │
          │ Analyzer    │       │ + fallback     │      │ 远程仅对比  │
          └─────────────┘       └───────┬────────┘      └─────────────┘
                                        │
                              ┌─────────▼──────────┐
                              │ 远程进化引擎        │
                              │ 异步 job + artifact│
                              └────────────────────┘
```

默认 `case_analysis.mode=local`，完全不改变现有分析行为。

## 2. 接口

```text
POST   /v1/case-analysis-jobs
GET    /v1/case-analysis-jobs/{job_id}
GET    /v1/case-analysis-jobs/{job_id}/result
DELETE /v1/case-analysis-jobs/{job_id}
GET    /v1/artifacts/{analysis_id}.json
GET    /healthz
GET    /readyz
```

鉴权：配置 token 后，除健康检查外均要求 `Authorization: Bearer <token>`。
幂等：`POST` 携带 `Idempotency-Key`；同 key 返回同一个 job。

## 3. 创建请求

```json
{
  "schema_version": "1.0",
  "request_id": "EV-001:case-001",
  "evaluation_id": "EV-001",
  "case": {
    "case_id": "case-001",
    "task_id": "task-001",
    "outcome": "FP",
    "vuln_title": "...",
    "description": "...",
    "summary": "...",
    "human_confirmation_summary": "...",
    "expected_label": "VULNERABLE",
    "verify_verdict": "",
    "verify_negated": false,
    "fn_miss": {},
    "mining_sessions": ["sess-001"],
    "verification_sessions": ["sess-002"]
  },
  "chains": {
    "mining": {
      "agent_type": "turing",
      "seed_session_ids": ["sess-001"],
      "session_chain": ["sess-000", "sess-001"]
    },
    "verification": {
      "agent_type": "webvuln_verify",
      "seed_session_ids": ["sess-002"],
      "session_chain": ["sess-002"]
    }
  },
  "session_graph": {"parent_map": {"sess-001": "sess-000"}},
  "sessions": [
    {
      "session_id": "sess-001",
      "agent_type": "turing",
      "session_meta": {},
      "events": [
        {
          "event_id": "evt-001",
          "event_type": "TOOL_CALL",
          "timestamp_ms": 1760000000000,
          "message_id": "msg-001",
          "part_id": "part-001",
          "step_no": 3,
          "tool_name": "bash",
          "input_json": {"command": "cat FileController.java"},
          "output_json": null,
          "raw_type": "tool_call",
          "parse_status": "OK",
          "is_kg_interaction": false,
          "is_memory_interaction": true,
          "is_memory_write": false,
          "call_id": "call-001"
        }
      ]
    }
  ],
  "context": {"project_id": "P-001"},
  "options": {
    "chain_expansion": "engine",
    "include_audit": true,
    "include_l4_verification": true,
    "include_knowledge_memory_summary": true,
    "deadline_seconds": 900,
    "language": "zh-CN"
  }
}
```

关键约定：

- `chains.*.session_chain` 由 engine 按本地同源规则展开；远程不得重新解释链。
- `sessions` 包含链上全部 session 的完整 events，不做数据截断。
- `human_confirmation_summary` 仅 FP 有意义；FN 以基线漏洞描述为分析依据。
- `outcome=FN` 且 `verify_verdict=FALSE_POSITIVE` 时，engine 会把
  `chains.mining.session_chain` 置空并标记 `skipped=true`：挖掘已
  `CONFIRMED`、验证否定导致漏报，根因只在验证链。

## 4. Job 状态

创建响应：

```json
{
  "job_id": "job-001",
  "status": "queued",
  "poll_url": "/v1/case-analysis-jobs/job-001",
  "result_url": "/v1/case-analysis-jobs/job-001/result"
}
```

状态：`queued|pending|running` 为进行中，`succeeded|completed` 为成功，
`failed|error|cancelled` 为失败。成功时 `GET job` 返回 `result`。

## 5. 结果

```json
{
  "schema_version": "1.0",
  "analysis_id": "ana-001",
  "case_id": "case-001",
  "outcome": "FP",
  "mining": {
    "status": "ok",
    "session_chain": ["sess-000", "sess-001"],
    "agent_type": "turing",
    "root_cause": {
      "category": "reasoning_flaw",
      "description": "..."
    },
    "primary_hypothesis_id": "MINING-H1",
    "hypotheses": [],
    "l0_l7_breakpoints": [],
    "fix_suggestion": [],
    "label_quality": {},
    "insufficient_evidence": false
  },
  "verification": {
    "status": "ok",
    "session_chain": ["sess-002"],
    "agent_type": "webvuln_verify",
    "root_cause": {"category": "process_flaw", "description": "..."},
    "primary_hypothesis_id": "VERIFICATION-H1",
    "hypotheses": [],
    "l0_l7_breakpoints": [],
    "fix_suggestion": [],
    "label_quality": {},
    "insufficient_evidence": false
  },
  "detail_ref": {
    "uri": "http://remote-evolution-engine-mock:8080/v1/artifacts/ana-001.json",
    "sha256": "...",
    "content_type": "application/json"
  },
  "provenance": {
    "analyzer_version": "remote-x.y",
    "prompt_version": "prompt-v1",
    "model": "..."
  }
}
```

### 5.1 hypothesis 结构

```json
{
  "hypothesis_id": "VERIFICATION-H1",
  "hypothesis": "验证阶段缺少影响门槛判定",
  "probability": 0.9,
  "confidence": 0.9,
  "responsibility": "agent",
  "cause_code": "H",
  "evidence_refs": ["E-abc12345-1"],
  "counter_evidence": "...",
  "evidence": "...",
  "session_id": "sess-002",
  "supporting_breakpoints": ["VERIFICATION-BP-1"],
  "agent_can_resolve": true,
  "blocked_by": "",
  "needed_external_data": [],
  "fix_suggestion": {
    "target": "agent_prompt",
    "agent_type": "webvuln_verify",
    "location": "...",
    "action": "...",
    "expected_effect": "..."
  }
}
```

### 5.2 breakpoint 结构

```json
{
  "ref": "VERIFICATION-BP-1",
  "session_id": "sess-002",
  "l0_source": "空",
  "l1_need": true,
  "l2_initiated": false,
  "l3_accurate": null,
  "l4_exists": null,
  "l5_retrieved": null,
  "l6_used": null,
  "l7_influenced": null,
  "breakpoint": "L2",
  "cause_code": "A",
  "confidence": 0.7,
  "evidence_refs": ["E-abc12345-1"],
  "query_content": "...",
  "returned_content": "",
  "fix_suggestion": "..."
}
```

## 6. Detail artifact

大字段放 artifact，job 结果只携带 `detail_ref`。artifact 按链分组：

```json
{
  "schema_version": "1.0",
  "case_id": "case-001",
  "compressed_summaries": {
    "mining": [],
    "verification": [
      {
        "session_id": "sess-002",
        "step": 1,
        "summary": "...",
        "key_findings": [],
        "evidence_cards": [
          {
            "evidence_id": "E-abc12345-1",
            "event_idx": 10,
            "source": "read FileController.java",
            "quote": "完整原文引用",
            "fact_type": "repo_fact"
          }
        ],
        "retention_check": [],
        "insufficient_evidence": false,
        "insufficient_reason": "",
        "l0_l7": []
      }
    ]
  },
  "merge_summary": {"mining": "", "verification": "..."},
  "knowledge_memory_summary": {"mining": {}, "verification": {}},
  "l4_independent_verification": {"mining": {}, "verification": {}},
  "audit": {"mining": [], "verification": []}
}
```

适配器也兼容不分组写法：`compressed_summaries` 为数组、其他字段为单值；
数组按 `chain_type` / `session_id` 过滤。

## 7. engine 侧校验

远程结果在进入 `CausalChainAnalyzer` 之前必须通过：

- `case_id` / `outcome` 与请求一致；
- `schema_version` 为 `1.0`；
- `session_chain` 必须是 engine 请求链的子集，最终仍使用 engine 链；
- `cause_code` ∈ A-K，`breakpoint` ∈ L2-L8；
- `confidence` ∈ [0,1]；
- `hypotheses[].evidence_refs` 能在 detail 的 evidence cards 找到；
- `supporting_breakpoints` 能在同链断点 ref 找到；
- 有 hypotheses 时 `primary_hypothesis_id` 必须存在且指向其中一条；
- `insufficient_evidence=true` 时不得携带可生成 DTS 的 hypotheses；
- `detail_ref.sha256` 必须存在；artifact 下载失败或 sha256 不匹配视为远程失败。

任一校验失败都走与网络失败相同的回退路径。

## 8. 失败与回退

```text
远程失败 / 超时 / 契约非法
        │
        ├─ fallback.enabled=true
        │      ├─ 记录 warning（source=case_analysis_remote）
        │      └─ 仅失败 case 回退本地 RootCauseAnalyzer
        │
        └─ fallback.enabled=false
               └─ 抛 CaseAnalysisRemoteError，评测失败
```

回退是 per-case 的：10 个 case 中 1 个远程失败，只对那 1 个回退，其余仍用远程。
报告 `data_quality_warnings` 中可见失败原因，不会静默降级。

## 9. 配置

```yaml
case_analysis:
  mode: local              # local | remote | shadow
  remote:
    base_url: "http://remote-evolution-engine-mock.secflow-ns.svc:8080"
    api_prefix: "/v1"
    token: ""
    # 单个 case 的总预算：创建 + 轮询 + 结果 + artifact。
    # 生产建议不低于 600 秒；默认 900 秒（15 分钟）。
    # 单次 HTTP 请求最多 60 秒，所有重试共享同一个 case 总预算。
    timeout_seconds: 900
    poll_interval_seconds: 2
    max_concurrency: 10
    detail_mode: artifact
    detail_required: true
    fallback:
      enabled: true
      mode: local
  shadow:
    authoritative: local
```

环境变量覆盖：

```text
EVAL_CASE_ANALYSIS_MODE
EVAL_CASE_ANALYSIS_BASE_URL
EVAL_CASE_ANALYSIS_API_PREFIX
EVAL_CASE_ANALYSIS_TOKEN
EVAL_CASE_ANALYSIS_TIMEOUT
EVAL_CASE_ANALYSIS_POLL_INTERVAL
EVAL_CASE_ANALYSIS_MAX_CONCURRENCY
EVAL_CASE_ANALYSIS_DETAIL_MODE
EVAL_CASE_ANALYSIS_DETAIL_REQUIRED
EVAL_CASE_ANALYSIS_FALLBACK_ENABLED
EVAL_CASE_ANALYSIS_FALLBACK_MODE
EVAL_CASE_ANALYSIS_SHADOW_AUTHORITATIVE
```

## 10. 联调脚本

```bash
# 直接验证远程 HTTP 契约
python scripts/smoke_remote_case_analysis.py \
  --base-url http://remote-evolution-engine-mock:8080 \
  --request-file scripts/fixtures/remote_case_analysis_request.json

# 验证 eval-engine 适配器 + 契约校验 + DTS 兼容
EVAL_CASE_ANALYSIS_MODE=remote \
EVAL_CASE_ANALYSIS_BASE_URL=http://remote-evolution-engine-mock:8080 \
python scripts/smoke_case_analysis_adapter.py \
  --request-file scripts/fixtures/remote_case_analysis_request.json
```
