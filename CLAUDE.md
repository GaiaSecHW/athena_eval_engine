# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Athena Eval Engine (知识图谱2.0 安全评测引擎) — evaluates whether a knowledge graph (KG) helps an AI agent find vulnerabilities. The same task is run twice (KG enabled vs No-KG control group), and 10 metrics (M1–M10) quantify the KG's impact on accuracy, behavior, and cost. The pipeline is: **Trace → Fact → Pair → Metric → Report**.

The codebase is entirely in Python (≥3.10), uses FastAPI for the API, MySQL for persistence, and calls an OpenAI-compatible LLM endpoint for AI analysis. All comments and domain concepts are in Chinese.

## Commands

```bash
# Install (dev)
python -m venv .venv && .venv/Scripts/activate
pip install -e ".[test]"

# Run API server (dev, port 8090)
python -m uvicorn athena_eval_engine.api.routes.evaluations:app --host 0.0.0.0 --port 8090

# Run all tests
pytest

# Run a single test file / test
pytest tests/test_metrics.py
pytest tests/test_metrics.py::test_known_effect_kg_recovers_half

# Run only trace-to-fact fixture tests (no MySQL needed)
pytest tests/test_trace_to_fact.py

# Docker build & run
docker build -t athena-eval-engine .
docker run -p 8090:8090 athena-eval-engine

# Port-forward k8s services for local dev (MySQL, Platform API, Schedule API, V-Bench API)
bash port-forward.sh
```

## Environment & Configuration

- Config is loaded from `config.yaml` (path overridable via `EVAL_CONFIG_FILE` env var). In k8s, a ConfigMap mounts `config.yaml`.
- Every config key also has an env var override (`EVAL_MYSQL_HOST`, `EVAL_LLM_BASE_URL`, `EVAL_LLM_MODEL`, `VBENCH_API_URL`, `PROJECT_API`, `SCHEDULE_API`, `DATA_ROOT`, `PLATFORM_TOKEN`, etc.) — see `config_loader.py`.
- **Tests require a live MySQL** for `test_api.py`, `test_persistence.py`, `test_web.py`, and `test_real_trace.py`. The fixture-based `test_trace_to_fact.py` and `test_metrics.py` run purely in-memory (no DB).
- The venv uses Windows paths (`.venv/Scripts/python.exe`).

## Architecture

### Pipeline (7 phases in `evaluation_service.py:run()`)

The orchestrator runs synchronously inside a background thread (ThreadPoolExecutor, max 3 concurrent). It uses **short-lived MySQL connections** — slow operations (trace parsing, LLM calls) never hold a DB connection, to survive remote firewall resets. A `_db_query()` wrapper retries on connection loss (2013/2006) with exponential backoff.

1. **VALIDATE/INGEST** (`create()`) — Freeze snapshot, insert benchmark items (with case descriptions from V-Bench API), create evaluation row.
2. **PARSING** — Parallel trace parsing (ThreadPoolExecutor, up to 4 workers). Each trace: parser → RawEvents, then 4 resolvers + AI matcher run in parallel per trace. `retry` path: if facts already exist in DB, skips re-parsing and loads from DB.
3. **RESOLVING** — Facts written to MySQL in a single batch (idempotent on duplicate keys).
4. **PAIRING** — `TaskPairMatcherImpl` matches KG/No-KG task runs by `(evaluation_id, task_id)`. `PairDerivedFactComputer` computes JSD, ΔToken, ΔSteps, ΔTime, PairTransition.
5. **CALCULATING** — `run_all_metrics()` computes M1–M10 with parallel bootstrap (numpy releases GIL). Statistical tests: GT-stratified paired bootstrap (M1/M4), paired bootstrap (M2/M3/M7/M8–M10), Wilson CI (M5/M6), McNemar (M2/M3 joint), Wilcoxon (M8–M10).
6. **REPORTING** — `assemble()` builds report model; `ai_narrative()`, `ai_per_case_kg_analysis()`, `ai_vuln_analysis()` call LLM for narrative conclusions. All LLM calls have rule-based fallbacks if the LLM is unavailable.
7. **FINALIZE** — Write report to `evaluation_report` table, set status to COMPLETED.

### State Machine (`orchestration/state_machine.py`)

Strict whitelist of transitions (CREATED → VALIDATING → INGESTING → PARSING → RESOLVING → PAIRING → CALCULATING → STATISTICAL_ANALYSIS → DIAGNOSING → REPORTING → FINALIZING → COMPLETED). Non-whitelist transitions are rejected. FAILED/CANCELLED can resume to VALIDATING.

### Layered Structure

- **`domain/`** — Pure business logic, no I/O. `enums.py` (mirrors `schema.sql` CHECK constraints), `raw_event.py` (canonical event), `task_run.py` (TaskRun/BenchmarkItem), `facts/` (OutcomeFact, KnowledgeInteractionFact, ToolActionFact, ResourceFact, PairDerivedFact), `metrics/` (M1–M10 + `run_all_metrics`), `statistics/engine.py` (bootstrap/McNemar/Wilson/Wilcoxon), `diagnostics/` (rule-based anomaly detection).
- **`workers/`** — Trace parsers and resolvers. `turing_trace_parser.py` (SQLite opencode.db → RawEvent), `argo_trace_parser.py` (Claude Code JSONL → RawEvent), `resolvers.py` (4 resolvers: Outcome, Knowledge, ToolAction, Resource), `ai_matcher.py` (LLM-based finding→benchmark matching), `pairing.py` (pair matching + derived fact computation).
- **`application/`** — Orchestration. `evaluation_service.py` (the main `create()`/`run()`/`get_status()`/`get_report()`), `platform_service.py` (project/task discovery, kubectl exec for trace files in dev), `report_assembler.py` (report model + LLM narrative).
- **`infrastructure/`** — External integrations. `database.py` (pymysql, `connect()`, `ensure_schema()`), `llm.py` (OpenAI-compatible client with retry, `chat()`/`chat_json()`), `vbench_client.py` (benchmark baseline data).
- **`persistence/repositories/fact_repo.py`** — All SQL INSERT functions (one per fact type + metric/statistical result).
- **`api/routes/`** — FastAPI endpoints. `evaluations.py` (main app), `web.py` (dashboard), `platform.py`, `benchmark_system.py`.
- **`db_writer.py`** — Standalone subprocess script for writing facts to MySQL (bypasses main process connection issues).

### Key Domain Concepts

- **Condition**: KG (knowledge graph enabled) vs NOGK (control) vs UNKNOWN.
- **RawEvent** (§8.2): Canonical event from trace parsing. `is_kg_interaction` flag set by parser determines KG interactions (resolvers don't hardcode tool names).
- **Facts**: 4 fact types extracted per task run — OutcomeFact (vuln found?), KnowledgeInteractionFact (KG accessed/delivered?), ToolActionFact (tool call distribution), ResourceFact (tokens/steps/duration).
- **PairView**: KG+No-KG pair with outcomes + derived deltas. Input to metric calculations.
- **Metrics M1–M10**: ΔBA (accuracy), IR (improvement rate), RR (regression rate), ΔFNR, KAR (knowledge access rate), KDR (knowledge delivery rate), JSD (behavior shift), ΔToken, ΔSteps, ΔTime. NA + reason_code when denominators are zero (never output 0).
- **Canonical Actions**: KG > FINDING > CODE > SHELL > OTHER (priority order for tool classification).

### Trace Formats

Two parsers exist:
- **TuringTraceParser**: Reads SQLite (`opencode.db`) with `session` + `part` tables. Schema Gate blocks if required tables missing.
- **ArgoTraceParser**: Reads Claude Code JSONL session files (directory of `.jsonl` files). Selected when `source_uri` is a directory or ends with `.jsonl`.

Parser selection happens in `_get_parser()` in `evaluation_service.py`.

### Test Fixtures

- `tests/fixtures/01-12_*` — Single-trace fixtures (SQLite `trace.db` + `expected.json`). Cover TP/FP/FN/TN, wiki mount, token reasoning, step mismatch, time invalid.
- `tests/fixtures/13-16_*` — Pair fixtures (KG `kg.db` + No-KG `nogk.db` + `expected.json`). Cover no-tool-call, fingerprint mismatch, recovered pair.
- `tests/fixtures/fetched/` — Real trace data from production (opencode.db, JSONL sessions). Used by `test_real_trace.py`.
- `tests/fixture_builder.py` — Discovers and lists fixture directories.

### NA Contract

When a metric cannot be calculated (zero denominator, no stratum, insufficient bootstrap replicates), it returns `calculation_status=NA` with a `reason_code` (e.g., `NO_STRATUM`, `NO_VALID_DENOMINATOR`, `BOOTSTRAP_UNSTABLE`). NA rows never carry an estimate value. This is a core invariant — do not output 0 or None-as-zero for metrics.
