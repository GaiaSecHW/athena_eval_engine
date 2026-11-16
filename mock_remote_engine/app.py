"""Remote evolution engine mock — FastAPI 异步 job 服务。

仅用于联调 Hook 1 契约，不是生产实现。默认从
``MOCK_FIXTURE_DIR/cluster_sample.json`` 读取集群真实样本；没有命中时
基于请求中的真实 events 做确定性分析。
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response

from .mock_analyzer import analyze_request, load_fixture
from .schemas import CaseAnalysisRequest, JobResponse


log = logging.getLogger("mock_remote_engine")
logging.basicConfig(level=os.environ.get("MOCK_LOG_LEVEL", "INFO"))

app = FastAPI(title="Remote Evolution Engine Mock", version="1.0")

_lock = threading.Lock()
_jobs: dict[str, dict[str, Any]] = {}
_idempotency: dict[str, str] = {}
_artifacts: dict[str, bytes] = {}
_executor = ThreadPoolExecutor(
    max_workers=int(os.environ.get("MOCK_MAX_WORKERS", "4")),
    thread_name_prefix="mock-analysis",
)
_fixture: dict[str, Any] | None = None


@dataclass
class Job:
    job_id: str
    case_id: str
    status: str = "queued"
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    analysis_id: str = ""
    idempotency_key: str = ""
    scenario: str = "normal"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


def _get_fixture() -> dict:
    global _fixture
    with _lock:
        if _fixture is None:
            _fixture = load_fixture()
        return _fixture


def reset_store() -> None:
    """测试辅助：清空 job / artifact / fixture 缓存。"""
    global _fixture
    with _lock:
        _jobs.clear()
        _idempotency.clear()
        _artifacts.clear()
        _fixture = None


def _require_token(request: Request) -> None:
    expected = os.environ.get("MOCK_TOKEN", "")
    if not expected:
        return
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="invalid bearer token")


def _public_job(job: Job, request: Request) -> dict[str, Any]:
    if isinstance(job, dict):
        job = Job(**job)
    body = {
        "job_id": job.job_id,
        "status": job.status,
        "case_id": job.case_id,
        "poll_url": f"/v1/case-analysis-jobs/{job.job_id}",
        "result_url": f"/v1/case-analysis-jobs/{job.job_id}/result",
    }
    if job.result is not None:
        body["result"] = job.result
    if job.error is not None:
        body["error"] = job.error
    return body


def _scenario(request: Request) -> str:
    return (request.headers.get("X-Mock-Scenario") or
            os.environ.get("MOCK_SCENARIO", "normal")).strip().lower()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "jobs": len(_jobs)}


@app.post("/v1/case-analysis-jobs")
def create_job(
    body: CaseAnalysisRequest,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    _require_token(request)
    payload = body.model_dump()
    case_id = str((payload.get("case") or {}).get("case_id", ""))
    if not case_id:
        raise HTTPException(status_code=400, detail="case.case_id 不能为空")
    key = idempotency_key or str(payload.get("request_id", "")) or case_id
    with _lock:
        existing_id = _idempotency.get(key)
        if existing_id and existing_id in _jobs:
            return _public_job(_jobs[existing_id], request)
        job = Job(
            job_id="job-" + uuid.uuid4().hex[:16],
            case_id=case_id,
            idempotency_key=key,
            scenario=_scenario(request),
        )
        _jobs[job.job_id] = job.__dict__
        _idempotency[key] = job.job_id
        _prune_jobs()
    _executor.submit(_run_job, job.job_id, payload, str(request.base_url).rstrip("/"))
    with _lock:
        return _public_job(Job(**_jobs[job.job_id]), request)


@app.get("/v1/case-analysis-jobs/{job_id}")
def get_job(job_id: str, request: Request) -> dict[str, Any]:
    _require_token(request)
    with _lock:
        raw = _jobs.get(job_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="job not found")
        return _public_job(Job(**raw), request)


@app.get("/v1/case-analysis-jobs/{job_id}/result")
def get_result(job_id: str, request: Request) -> dict[str, Any]:
    _require_token(request)
    with _lock:
        raw = _jobs.get(job_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="job not found")
        job = Job(**raw)
        if job.status not in ("succeeded", "completed", "success", "done"):
            raise HTTPException(status_code=409, detail=f"job status={job.status}")
        return job.result or {}


@app.delete("/v1/case-analysis-jobs/{job_id}")
def delete_job(job_id: str, request: Request) -> dict:
    _require_token(request)
    with _lock:
        raw = _jobs.pop(job_id, None)
        if raw is None:
            raise HTTPException(status_code=404, detail="job not found")
        if raw.get("analysis_id"):
            _artifacts.pop(raw["analysis_id"], None)
        key = raw.get("idempotency_key")
        if key and _idempotency.get(key) == job_id:
            _idempotency.pop(key, None)
    return {"deleted": True, "job_id": job_id}


@app.get("/v1/artifacts/{analysis_id}")
def get_artifact(analysis_id: str, request: Request) -> Response:
    _require_token(request)
    if analysis_id.endswith(".json"):
        analysis_id = analysis_id[:-5]
    with _lock:
        raw = _artifacts.get(analysis_id)
    if raw is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    return Response(content=raw, media_type="application/json")


def _run_job(job_id: str, payload: dict, base_url: str) -> None:
    try:
        with _lock:
            raw = _jobs.get(job_id)
            if raw is None:
                return
            raw["status"] = "running"
            raw["updated_at"] = time.time()
            scenario = raw.get("scenario", "normal")
        delay = float(os.environ.get("MOCK_JOB_DELAY_SECONDS", "0.2"))
        if scenario == "slow":
            delay = max(delay, float(os.environ.get("MOCK_SLOW_SECONDS", "2")))
        if delay > 0:
            time.sleep(delay)
        if scenario == "fail":
            raise RuntimeError("mock scenario=fail")
        if scenario == "running_forever":
            return

        result, detail = analyze_request(payload, _get_fixture())
        if scenario == "insufficient":
            for chain_type in ("mining", "verification"):
                chain = result.setdefault(chain_type, {})
                chain["status"] = "insufficient_evidence"
                chain["insufficient_evidence"] = True
                chain["hypotheses"] = []
                chain["primary_hypothesis_id"] = ""
                chain["l0_l7_breakpoints"] = []
                chain["root_cause"] = {
                    "category": "insufficient_evidence",
                    "description": "mock scenario=insufficient",
                }
            detail = {
                "schema_version": "1.0",
                "case_id": result.get("case_id", ""),
                "compressed_summaries": {"mining": [], "verification": []},
                "merge_summary": {"mining": "", "verification": ""},
                "knowledge_memory_summary": {"mining": {}, "verification": {}},
                "l4_independent_verification": {"mining": {}, "verification": {}},
                "audit": {"mining": [], "verification": []},
            }
        if scenario == "invalid":
            chain = {}
            for chain_type in ("mining", "verification"):
                candidate = result.get(chain_type) or {}
                if candidate.get("session_chain"):
                    chain = candidate
                    break
            hyps = chain.get("hypotheses") or []
            if hyps:
                hyps[0]["cause_code"] = "Z"
            else:
                chain["hypotheses"] = [{
                    "hypothesis_id": "BAD-H1",
                    "cause_code": "Z",
                    "confidence": 0.9,
                    "evidence_refs": [],
                }]
                chain["primary_hypothesis_id"] = "BAD-H1"

        analysis_id = "ana-" + uuid.uuid4().hex[:16]
        artifact_bytes = json.dumps(
            detail, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), default=str,
        ).encode("utf-8")
        with _lock:
            _artifacts[analysis_id] = artifact_bytes

        result["analysis_id"] = analysis_id
        if scenario != "missing_detail":
            artifact_id = "does-not-exist" if scenario == "detail_404" else analysis_id
            result["detail_ref"] = {
                "uri": f"{base_url}/v1/artifacts/{artifact_id}.json",
                "sha256": __import__("hashlib").sha256(artifact_bytes).hexdigest(),
                "content_type": "application/json",
            }
        with _lock:
            raw = _jobs.get(job_id)
            if raw is not None:
                raw.update({
                    "status": "succeeded",
                    "result": result,
                    "analysis_id": analysis_id,
                    "updated_at": time.time(),
                })
    except Exception as exc:
        log.exception("mock job %s failed", job_id)
        with _lock:
            raw = _jobs.get(job_id)
            if raw is not None:
                raw.update({
                    "status": "failed",
                    "error": {"code": "mock_failure", "message": str(exc)},
                    "updated_at": time.time(),
                })


def _prune_jobs(max_jobs: int = 500) -> None:
    if len(_jobs) <= max_jobs:
        return
    ordered = sorted(_jobs.items(), key=lambda kv: kv[1].get("created_at", 0))
    for job_id, raw in ordered[:len(_jobs) - max_jobs]:
        _jobs.pop(job_id, None)
        if raw.get("analysis_id"):
            _artifacts.pop(raw["analysis_id"], None)
        key = raw.get("idempotency_key")
        if key:
            _idempotency.pop(key, None)
