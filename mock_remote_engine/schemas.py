"""Mock 远程进化引擎的请求模型（宽松，避免拒绝真实 trace 的额外字段）。"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CaseAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "1.0"
    request_id: str = ""
    evaluation_id: str = ""
    case: dict[str, Any] = Field(default_factory=dict)
    chains: dict[str, Any] = Field(default_factory=dict)
    session_graph: dict[str, Any] = Field(default_factory=dict)
    sessions: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)


class JobResponse(BaseModel):
    job_id: str
    status: str
    case_id: str = ""
    poll_url: str = ""
    result_url: str = ""
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
