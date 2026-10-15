# CLAUDE.md

This file provides guidance to AI coding agents when working with code in this repository.

See **AGENTS.md** for the authoritative project documentation — architecture, commands, domain concepts, trace formats, and testing guidance.

## Quick Reference

```bash
# Install (dev)
python -m venv .venv && .venv/Scripts/activate
pip install -e ".[test]"

# Run API server (dev, port 8090, health 8091)
python -m uvicorn athena_eval_engine.api.routes.evaluations:app --host 0.0.0.0 --port 8090

# Run tests
pytest tests/test_metrics.py          # pure in-memory, no DB needed
pytest tests/test_trace_to_fact.py    # fixture-based, no DB needed

# Docker
docker build -t athena-eval-engine .
docker run -p 8090:8090 athena-eval-engine
```

The codebase is Python ≥3.10, FastAPI, MySQL, OpenAI-compatible LLM. All comments and domain concepts are in Chinese.
