"""Case 级根因分析端口（Hook 1）。

该模块把原 ``RootCauseAnalyzer.analyze()`` 封装成可替换端口：

- ``local``：完全保持原有本地分析行为；
- ``remote``：把 case + session trace 发到远程进化引擎，engine 只负责
  输入组装、契约校验和本地字段补齐；
- ``shadow``：本地结果为准，同时调用远程做对比，差异写数据质量告警。

远程不可用、超时、返回非法数据时，按 case 回退本地。回退不是静默降级：
每次回退都会写入 ``pipeline_warnings``，最终出现在报告的
``data_quality_warnings`` 中。若显式关闭回退，则直接抛异常，评测失败。
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol

from ..core.causal_levels import (
    ALL_CAUSES,
    ALL_LEVELS,
    CAUSE_TO_LEVEL,
)
from ..core.data_pack import DataPack
from ..core.raw_event import RawEvent
from ..infra import pipeline_warnings as _pw
from ..infra.log_util import log
from ..infra.parallel import iter_completed
from .root_cause_analyzer import RootCauseAnalyzer


_ALLOWED_RESPONSIBILITIES = {
    "agent", "knowledge", "external_data_source", "eval_process",
}
_TERMINAL_OK = {"succeeded", "completed", "success", "done"}
_TERMINAL_BAD = {"failed", "error", "cancelled", "canceled"}
_RUNNING = {"queued", "pending", "running", "created", "accepted"}


class CaseAnalysisError(RuntimeError):
    """Case 分析端口错误基类。"""


class CaseAnalysisRemoteError(CaseAnalysisError):
    """远程进化引擎不可用、超时或返回失败。"""


class CaseAnalysisContractError(CaseAnalysisRemoteError):
    """远程返回结果不符合契约。"""


@dataclass(frozen=True)
class CaseAnalysisSettings:
    """Hook 1 运行配置。"""

    mode: str = "local"
    base_url: str = ""
    api_prefix: str = "/v1"
    token: str = ""
    timeout_seconds: float = 900.0
    poll_interval_seconds: float = 2.0
    max_concurrency: int = 10
    detail_mode: str = "artifact"
    detail_required: bool = True
    fallback_enabled: bool = True
    fallback_mode: str = "local"
    shadow_authoritative: str = "local"

    @classmethod
    def from_config(cls) -> "CaseAnalysisSettings":
        from ... import config_loader as cfg

        return cls(
            mode=cfg.CASE_ANALYSIS_MODE,
            base_url=cfg.CASE_ANALYSIS_BASE_URL,
            api_prefix=cfg.CASE_ANALYSIS_API_PREFIX,
            token=cfg.CASE_ANALYSIS_TOKEN,
            timeout_seconds=cfg.CASE_ANALYSIS_TIMEOUT_SECONDS,
            poll_interval_seconds=cfg.CASE_ANALYSIS_POLL_INTERVAL_SECONDS,
            max_concurrency=cfg.CASE_ANALYSIS_MAX_CONCURRENCY,
            detail_mode=cfg.CASE_ANALYSIS_DETAIL_MODE,
            detail_required=cfg.CASE_ANALYSIS_DETAIL_REQUIRED,
            fallback_enabled=cfg.CASE_ANALYSIS_FALLBACK_ENABLED,
            fallback_mode=cfg.CASE_ANALYSIS_FALLBACK_MODE,
            shadow_authoritative=cfg.CASE_ANALYSIS_SHADOW_AUTHORITATIVE,
        )


class CaseAnalysisPort(Protocol):
    """Hook 1 端口协议，签名与 RootCauseAnalyzer.analyze() 保持一致。"""

    def analyze(
        self,
        evaluation_id: str,
        cases: list[dict],
        data_packs: list[DataPack],
        cancel_cb=None,
        project_id: str = "",
    ) -> list[dict]: ...


class LocalCaseAnalysisAdapter:
    """本地分析适配器（原有逻辑，默认路径）。"""

    def __init__(self, analyzer: RootCauseAnalyzer | None = None):
        self._analyzer = analyzer or RootCauseAnalyzer()

    def analyze(
        self,
        evaluation_id: str,
        cases: list[dict],
        data_packs: list[DataPack],
        cancel_cb=None,
        project_id: str = "",
    ) -> list[dict]:
        if not cases:
            return []
        return self._analyzer.analyze(
            evaluation_id, cases, data_packs,
            cancel_cb=cancel_cb, project_id=project_id,
        )


class CaseAnalysisRequestBuilder:
    """从 DataPack 构建远程请求；链展开规则与本地分析器同源。"""

    def __init__(self, data_packs: list[DataPack]):
        self._session_events: dict[str, list[RawEvent]] = {}
        self._session_agent_type: dict[str, str] = {}
        self._parent_map: dict[str, str] = {}
        self._children_map: dict[str, list[str]] = {}
        for dp in data_packs or []:
            for ev in (dp.events or []):
                sid = ev.session_id or ""
                if not sid:
                    continue
                self._session_events.setdefault(sid, []).append(ev)
                if sid not in self._session_agent_type:
                    self._session_agent_type[sid] = dp.agent_type or ""
            graph = getattr(dp, "session_graph", None) or {}
            parent_map = (graph.get("parent_map", {})
                          if isinstance(graph, dict) else {})
            for sid, pid in parent_map.items():
                if sid not in self._parent_map:
                    self._parent_map[sid] = pid
                if pid not in self._children_map:
                    self._children_map[pid] = []
                if sid not in self._children_map[pid]:
                    self._children_map[pid].append(sid)

    def build(
        self,
        *,
        evaluation_id: str,
        case: dict,
        project_id: str = "",
        deadline_seconds: float = 900.0,
    ) -> dict:
        case_id = str(case.get("case_id", ""))
        mining_seeds = set(case.get("mining_sessions", []) or [])
        verify_seeds = set(case.get("verify_sessions", []) or [])
        mining_chain = RootCauseAnalyzer._expand_chain(
            mining_seeds, self._parent_map, self._children_map)
        verify_chain = RootCauseAnalyzer._expand_chain(
            verify_seeds, self._parent_map, self._children_map)
        verify_negated = (
            str(case.get("outcome", "")).upper() == "FN"
            and str(case.get("verify_verdict", "")) == "FALSE_POSITIVE"
        )
        if verify_negated:
            # 与 RootCauseAnalyzer 保持一致：挖掘已 CONFIRMED、验证否定导致
            # FN 时，根因在验证链，不把 mining 链送去远程重复分析。
            mining_chain = []

        mining_agent = self._agent_type(mining_chain, case.get("agent_type", ""))
        verify_agent = self._agent_type(verify_chain, "")
        sessions = [
            self._session_payload(sid)
            for sid in dict.fromkeys(mining_chain + verify_chain)
        ]
        parent_map = {
            sid: self._parent_map[sid]
            for sid in dict.fromkeys(mining_chain + verify_chain)
            if sid in self._parent_map
        }
        return {
            "schema_version": "1.0",
            "request_id": f"{evaluation_id}:{case_id}",
            "evaluation_id": evaluation_id,
            "case": {
                "case_id": case_id,
                "task_id": str(case.get("task_id", "")),
                "outcome": str(case.get("outcome", "")),
                "vuln_title": str(case.get("vuln_title", "")),
                "description": str(case.get("description", "")),
                "summary": str(case.get("summary", "")),
                "human_confirmation_summary": str(
                    case.get("human_confirmation_summary", "")),
                "expected_label": str(case.get("expected_label", "")),
                "verify_verdict": str(case.get("verify_verdict", "")),
                "verify_negated": verify_negated,
                "fn_miss": case.get("fn_miss") or {},
                "mining_sessions": sorted(mining_seeds),
                "verification_sessions": sorted(verify_seeds),
            },
            "chains": {
                "mining": {
                    "agent_type": mining_agent,
                    "seed_session_ids": sorted(mining_seeds),
                    "session_chain": mining_chain,
                    "skipped": verify_negated,
                    "skip_reason": (
                        "outcome=FN 且 verify_verdict=FALSE_POSITIVE；"
                        "根因在验证链" if verify_negated else ""),
                },
                "verification": {
                    "agent_type": verify_agent,
                    "seed_session_ids": sorted(verify_seeds),
                    "session_chain": verify_chain,
                },
            },
            "session_graph": {"parent_map": parent_map},
            "sessions": sessions,
            "context": {"project_id": project_id},
            "options": {
                "chain_expansion": "engine",
                "include_audit": True,
                "include_l4_verification": True,
                "include_knowledge_memory_summary": True,
                "deadline_seconds": deadline_seconds,
                "language": "zh-CN",
            },
        }

    def _agent_type(self, chain: list[str], fallback: str) -> str:
        for sid in chain:
            agent = self._session_agent_type.get(sid, "")
            if agent:
                return agent
        return fallback or ""

    def _session_payload(self, sid: str) -> dict:
        events: list[dict] = []
        for idx, ev in enumerate(self._session_events.get(sid, [])):
            item = dataclasses.asdict(ev)
            item["event_index"] = idx
            events.append(item)
        return {
            "session_id": sid,
            "agent_type": self._session_agent_type.get(sid, ""),
            "session_meta": {},
            "events": events,
        }


class _UrllibHttpClient:
    """最小 JSON HTTP 客户端；仅本端口使用，避免改变全局 http_client 行为。"""

    def __init__(self, token: str = ""):
        self._token = token

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict | None = None,
        headers: dict | None = None,
        timeout: float = 60.0,
        attempts: int = 1,
    ) -> tuple[Any, bytes, int]:
        body = None
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "athena-eval-engine/case-analysis-port",
        }
        if self._token:
            request_headers["Authorization"] = f"Bearer {self._token}"
        if headers:
            request_headers.update(headers)
        if json_body is not None:
            body = json.dumps(
                json_body, ensure_ascii=False, default=str,
            ).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        last_error: Exception | None = None
        for attempt in range(attempts):
            req = urllib.request.Request(
                url, data=body, headers=request_headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                    status = getattr(resp, "status", 200)
                parsed = json.loads(raw.decode("utf-8")) if raw else None
                return parsed, raw, status
            except urllib.error.HTTPError as exc:
                raw = exc.read() if hasattr(exc, "read") else b""
                snippet = raw.decode("utf-8", errors="replace")[:1000]
                retryable = exc.code >= 500 or exc.code in (408, 425, 429)
                last_error = CaseAnalysisRemoteError(
                    f"{method} {url} HTTP {exc.code}: {snippet}")
                if retryable and attempt + 1 < attempts:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise last_error from exc
            except (urllib.error.URLError, TimeoutError, socket.timeout,
                    OSError, UnicodeDecodeError, ValueError) as exc:
                last_error = CaseAnalysisRemoteError(
                    f"{method} {url} 请求失败: {exc}")
                if attempt + 1 < attempts:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise last_error from exc
        raise last_error or CaseAnalysisRemoteError(f"{method} {url} 请求失败")


class RemoteCaseAnalysisAdapter:
    """远程进化引擎适配器。"""

    def __init__(
        self,
        settings: CaseAnalysisSettings,
        *,
        fallback_adapter: CaseAnalysisPort | None = None,
        http_client: _UrllibHttpClient | None = None,
    ):
        self._settings = settings
        if settings.fallback_enabled and settings.fallback_mode != "local":
            raise ValueError(
                f"不支持的 case_analysis fallback_mode={settings.fallback_mode}")
        self._fallback = fallback_adapter or LocalCaseAnalysisAdapter()
        self._http = http_client or _UrllibHttpClient(settings.token)

    def analyze(
        self,
        evaluation_id: str,
        cases: list[dict],
        data_packs: list[DataPack],
        cancel_cb=None,
        project_id: str = "",
    ) -> list[dict]:
        if not cases:
            return []
        if not self._settings.base_url:
            return self._all_local_or_raise(
                evaluation_id, cases, data_packs, cancel_cb,
                project_id, reason="未配置远程进化引擎 base_url",
            )

        builder = CaseAnalysisRequestBuilder(data_packs)
        max_workers = max(
            1, min(int(self._settings.max_concurrency or 1), len(cases)))
        results: list[dict | None] = [None] * len(cases)
        failed: list[tuple[int, dict, Exception]] = []

        def _run(idx_case: tuple[int, dict]) -> tuple[int, dict]:
            idx, case = idx_case
            if cancel_cb:
                cancel_cb()
            payload = builder.build(
                evaluation_id=evaluation_id,
                case=case,
                project_id=project_id,
                deadline_seconds=self._settings.timeout_seconds,
            )
            result = self._analyze_case(payload, case, cancel_cb=cancel_cb)
            if cancel_cb:
                cancel_cb()
            return idx, result

        if max_workers <= 1:
            for idx, case in enumerate(cases):
                try:
                    out_idx, result = _run((idx, case))
                    results[out_idx] = result
                except CaseAnalysisRemoteError as exc:
                    failed.append((idx, case, exc))
                except Exception:
                    raise
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(_run, (idx, case)): idx
                    for idx, case in enumerate(cases)
                }
                for fut, _ in iter_completed(futures, cancel_cb=cancel_cb):
                    idx = futures[fut]
                    try:
                        out_idx, result = fut.result()
                        results[out_idx] = result
                    except CaseAnalysisRemoteError as exc:
                        failed.append((idx, cases[idx], exc))
                    except Exception:
                        raise

        if failed:
            for _, case, exc in failed:
                cid = str(case.get("case_id", ""))
                _pw.add(
                    evaluation_id, "case_analysis_remote",
                    "remote_case_failed", "warning",
                    f"case {cid} 远程进化引擎分析失败"
                    + ("，已回退本地" if self._settings.fallback_enabled
                       else "，未启用回退")
                    + f"：{exc}",
                    case_id=cid,
                )
                log("CASE_ANALYSIS",
                    f"case {cid} 远程分析失败: {exc}",
                    eval_id=evaluation_id)

            if not self._settings.fallback_enabled:
                first = failed[0][2]
                raise CaseAnalysisRemoteError(
                    f"{len(failed)}/{len(cases)} 个 case 远程分析失败，"
                    f"且 fallback 已关闭；首个错误: {first}") from first

            if self._settings.fallback_mode != "local":
                raise CaseAnalysisRemoteError(
                    f"不支持的 fallback_mode={self._settings.fallback_mode}；"
                    "目前只支持 local")
            failed_cases = [case for _, case, _ in failed]
            local_results = self._fallback.analyze(
                evaluation_id, failed_cases, data_packs,
                cancel_cb=cancel_cb, project_id=project_id,
            )
            by_case = {
                str(item.get("case_id", "")): item
                for item in local_results
                if isinstance(item, dict)
            }
            for idx, case, _ in failed:
                cid = str(case.get("case_id", ""))
                item = by_case.get(cid)
                if item is None:
                    raise CaseAnalysisRemoteError(
                        f"case {cid} 远程失败后本地回退未返回结果")
                results[idx] = item

        if any(item is None for item in results):
            raise CaseAnalysisRemoteError(
                "远程 case 分析内部结果缺失；拒绝返回不完整结果")
        return results

    def _all_local_or_raise(
        self, evaluation_id: str, cases: list[dict],
        data_packs: list[DataPack], cancel_cb, project_id: str, reason: str,
    ) -> list[dict]:
        if not self._settings.fallback_enabled:
            raise CaseAnalysisRemoteError(reason)
        for case in cases:
            cid = str(case.get("case_id", ""))
            _pw.add(
                evaluation_id, "case_analysis_remote",
                "remote_unavailable", "warning",
                f"case {cid} 远程进化引擎不可用，已回退本地：{reason}",
                case_id=cid,
            )
        log("CASE_ANALYSIS", f"{reason}，全部回退本地", eval_id=evaluation_id)
        return self._fallback.analyze(
            evaluation_id, cases, data_packs,
            cancel_cb=cancel_cb, project_id=project_id,
        )

    def _analyze_case(self, payload: dict, case: dict, cancel_cb=None) -> dict:
        deadline = time.monotonic() + max(
            0.1, float(self._settings.timeout_seconds))
        request_key = _sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        )
        idem_key = _sha256(
            f"{payload.get('evaluation_id')}:{payload.get('case', {}).get('case_id')}:"
            f"{request_key}"
        )[:40]
        job = self._create_job(payload, idem_key, deadline, cancel_cb)
        job_id = str(job.get("job_id", ""))
        if not job_id:
            raise CaseAnalysisContractError("创建 job 响应缺少 job_id")

        result = self._wait_for_job(job, job_id, cancel_cb, deadline)
        detail = self._fetch_detail(result, deadline, cancel_cb)
        self._ensure_deadline(deadline)
        return self._assemble_case(
            case=case, payload=payload, result=result, detail=detail,
        )

    def _create_job(
        self, payload: dict, idem_key: str, deadline: float, cancel_cb=None,
    ) -> dict:
        url = self._api_url("/case-analysis-jobs")
        obj, _, _ = self._request_with_deadline(
            "POST", url, json_body=payload,
            headers={
                "Idempotency-Key": idem_key,
                "X-Request-Id": str(payload.get("request_id", "")),
            },
            deadline=deadline,
            attempts=2,
            cancel_cb=cancel_cb,
        )
        if not isinstance(obj, dict):
            raise CaseAnalysisContractError("创建 job 响应不是 JSON object")
        return obj

    def _wait_for_job(
        self, job: dict, job_id: str, cancel_cb, deadline: float,
    ) -> dict:
        current = job
        poll_url = current.get("poll_url") or \
            self._api_url(f"/case-analysis-jobs/{job_id}")
        while True:
            if cancel_cb:
                cancel_cb()
            status = str(current.get("status", "")).lower()
            if status in _TERMINAL_OK:
                result = current.get("result")
                if isinstance(result, dict):
                    return result
                result_url = current.get("result_url")
                if result_url:
                    obj, _, _ = self._request_with_deadline(
                        "GET", self._resolve_url(result_url),
                        deadline=deadline,
                        attempts=2,
                        cancel_cb=cancel_cb,
                    )
                    if not isinstance(obj, dict):
                        raise CaseAnalysisContractError(
                            "result_url 返回不是 JSON object")
                    return obj
                raise CaseAnalysisContractError(
                    f"job {job_id} 已完成但缺少 result")
            if status in _TERMINAL_BAD:
                error = current.get("error") or {}
                raise CaseAnalysisRemoteError(
                    f"job {job_id} 状态 {status}: {error}")
            if status not in _RUNNING:
                raise CaseAnalysisContractError(
                    f"job {job_id} 返回未知状态 {status!r}")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._delete_job(job_id)
                raise CaseAnalysisRemoteError(
                    f"job {job_id} 轮询超时（{self._settings.timeout_seconds}s）")
            self._sleep(min(self._settings.poll_interval_seconds, remaining),
                        cancel_cb)
            obj, _, _ = self._request_with_deadline(
                "GET", self._resolve_url(poll_url),
                deadline=deadline,
                attempts=2,
                cancel_cb=cancel_cb,
            )
            if not isinstance(obj, dict):
                raise CaseAnalysisContractError("轮询响应不是 JSON object")
            current = obj

    def _fetch_detail(
        self, result: dict, deadline: float, cancel_cb=None,
    ) -> dict:
        mode = (self._settings.detail_mode or "artifact").lower()
        if mode == "inline":
            detail = result.get("detail") or result.get("detail_content")
            if isinstance(detail, dict):
                return detail
            if self._settings.detail_required:
                raise CaseAnalysisContractError("inline detail 缺失")
            return {}
        if mode != "artifact":
            raise CaseAnalysisContractError(
                f"不支持的 detail_mode={self._settings.detail_mode}")

        ref = result.get("detail_ref")
        if not ref:
            if self._settings.detail_required:
                raise CaseAnalysisContractError("结果缺少 detail_ref")
            return {}
        if not isinstance(ref, dict) or not ref.get("uri"):
            raise CaseAnalysisContractError("detail_ref 缺少 uri")
        obj, raw, _ = self._request_with_deadline(
            "GET", self._resolve_url(str(ref["uri"])),
            deadline=deadline,
            attempts=2,
            cancel_cb=cancel_cb,
        )
        expected = str(ref.get("sha256", "") or "").strip().lower()
        if not expected:
            raise CaseAnalysisContractError("detail_ref 缺少 sha256")
        if _sha256_bytes(raw).lower() != expected:
            raise CaseAnalysisContractError("detail_ref sha256 校验失败")
        if not isinstance(obj, dict):
            raise CaseAnalysisContractError("detail artifact 不是 JSON object")
        return obj

    def _delete_job(self, job_id: str) -> None:
        try:
            self._http.request(
                "DELETE", self._api_url(f"/case-analysis-jobs/{job_id}"),
                timeout=2.0, attempts=1,
            )
        except Exception:
            pass

    def _request_with_deadline(
        self,
        method: str,
        url: str,
        *,
        deadline: float,
        json_body: dict | None = None,
        headers: dict | None = None,
        attempts: int = 2,
        cancel_cb=None,
    ) -> tuple[Any, bytes, int]:
        """执行 HTTP 请求，所有重试共享同一个 case 总 deadline。"""
        last_error: Exception | None = None
        for attempt in range(max(1, attempts)):
            timeout = self._remaining_timeout(deadline, cap=60.0)
            try:
                return self._http.request(
                    method, url, json_body=json_body, headers=headers,
                    timeout=timeout, attempts=1,
                )
            except CaseAnalysisRemoteError as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if attempt + 1 >= attempts or remaining <= 0:
                    raise
                self._sleep(min(0.5 * (attempt + 1), remaining), cancel_cb)
        raise last_error or CaseAnalysisRemoteError(f"{method} {url} 请求失败")

    def _remaining_timeout(self, deadline: float, *, cap: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CaseAnalysisRemoteError(
                f"case 分析总超时（{self._settings.timeout_seconds}s）")
        return max(0.01, min(cap, remaining))

    def _ensure_deadline(self, deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise CaseAnalysisRemoteError(
                f"case 分析总超时（{self._settings.timeout_seconds}s）")

    def _assemble_case(
        self, *, case: dict, payload: dict, result: dict, detail: dict,
    ) -> dict:
        case_id = str(case.get("case_id", ""))
        schema_version = result.get("schema_version")
        if schema_version != "1.0":
            raise CaseAnalysisContractError(
                f"不支持的 result.schema_version={schema_version!r}")
        if "case_id" not in result or str(result.get("case_id", "")) != case_id:
            raise CaseAnalysisContractError(
                f"result.case_id={result.get('case_id')!r} 与请求 {case_id!r} 不一致")
        remote_outcome = result.get("outcome")
        local_outcome = str(case.get("outcome", ""))
        if remote_outcome is None or str(remote_outcome) != local_outcome:
            raise CaseAnalysisContractError(
                f"result.outcome={remote_outcome!r} 与请求 {local_outcome!r} 不一致")

        if not isinstance(detail, dict):
            raise CaseAnalysisContractError("detail 不是 JSON object")
        if detail:
            detail_schema = detail.get("schema_version")
            if detail_schema not in (None, "1.0"):
                raise CaseAnalysisContractError(
                    f"不支持的 detail.schema_version={detail_schema!r}")
            detail_case_id = detail.get("case_id")
            if detail_case_id not in (None, "") and str(detail_case_id) != case_id:
                raise CaseAnalysisContractError(
                    f"detail.case_id={detail_case_id!r} 与请求 {case_id!r} 不一致")

        outcome = local_outcome
        fp_reason = (str(case.get("human_confirmation_summary", ""))
                     if outcome.upper() == "FP" else "")
        verify_negated = (
            outcome.upper() == "FN"
            and str(case.get("verify_verdict", "")) == "FALSE_POSITIVE"
        )
        provenance = result.get("provenance") or {}
        if not isinstance(provenance, dict):
            raise CaseAnalysisContractError("result.provenance 不是 object")
        chains_out: dict[str, dict] = {}
        for chain_type in ("mining", "verification"):
            local_chain = list(
                ((payload.get("chains") or {}).get(chain_type) or {}).get(
                    "session_chain") or []
            )
            local_agent = str(
                ((payload.get("chains") or {}).get(chain_type) or {}).get(
                    "agent_type") or ""
            )
            if chain_type == "mining" and not local_agent:
                local_agent = str(case.get("agent_type", "") or "")
            raw = result.get(chain_type)
            if not isinstance(raw, dict):
                raise CaseAnalysisContractError(
                    f"result 缺少 {chain_type} 分析段")
            if not local_chain:
                remote_chain = raw.get("session_chain")
                if remote_chain not in (None, []):
                    raise CaseAnalysisContractError(
                        f"{chain_type} 请求链为空，但远程返回了 session_chain")
                if raw.get("hypotheses") or raw.get("l0_l7_breakpoints"):
                    raise CaseAnalysisContractError(
                        f"{chain_type} 请求链为空，但远程返回了分析结论")
                root_cause = (
                    {
                        "category": "mining_ok",
                        "description": (
                            "挖掘 agent 已上报 CONFIRMED，验证 agent 否定导致"
                            "漏报——挖掘链无问题，跳过分析"),
                    }
                    if chain_type == "mining" and verify_negated else None
                )
                chains_out[chain_type] = self._empty_chain(
                    chain_type, local_agent, provenance,
                    root_cause=root_cause)
                continue
            chains_out[chain_type] = self._validate_chain(
                chain_type=chain_type,
                raw=raw,
                local_chain=local_chain,
                agent_type=local_agent,
                fp_reason=fp_reason,
                detail=self._chain_detail(detail, chain_type, local_chain),
                provenance=provenance,
                payload=payload,
            )

        return {
            "case_id": case_id,
            "vuln_title": str(case.get("vuln_title", "")),
            "description": str(case.get("description", "")),
            "summary": str(case.get("summary", "")),
            "outcome": outcome,
            "human_confirmation_summary": fp_reason,
            "fn_miss": case.get("fn_miss") or {},
            "mining": chains_out["mining"],
            "verification": chains_out["verification"],
        }

    def _validate_chain(
        self, *, chain_type: str, raw: dict, local_chain: list[str],
        agent_type: str, fp_reason: str, detail: dict, provenance: dict,
        payload: dict,
    ) -> dict:
        status = str(raw.get("status", "ok")).lower()
        if status not in {"ok", "insufficient_evidence"}:
            raise CaseAnalysisContractError(
                f"{chain_type}.status 非法: {status!r}")
        raw_insufficient = raw.get("insufficient_evidence", False)
        if isinstance(raw_insufficient, bool):
            insufficient = raw_insufficient
        elif str(raw_insufficient).strip().lower() in ("true", "false"):
            insufficient = str(raw_insufficient).strip().lower() == "true"
        else:
            raise CaseAnalysisContractError(
                f"{chain_type}.insufficient_evidence 不是 bool: "
                f"{raw_insufficient!r}")
        if status == "insufficient_evidence":
            insufficient = True

        remote_chain = raw.get("session_chain")
        if remote_chain is not None:
            if not isinstance(remote_chain, list):
                raise CaseAnalysisContractError(
                    f"{chain_type}.session_chain 不是 list")
            extra = [str(s) for s in remote_chain if str(s) not in local_chain]
            if extra:
                raise CaseAnalysisContractError(
                    f"{chain_type}.session_chain 含请求链外 session: "
                    f"{extra[:5]}")

        evidence_ids = self._evidence_ids(detail)
        breakpoints, bp_refs = self._validate_breakpoints(
            chain_type, raw.get("l0_l7_breakpoints"), local_chain)
        hypotheses = self._validate_hypotheses(
            chain_type, raw.get("hypotheses"), local_chain,
            bp_refs, detail, evidence_ids)
        if insufficient and hypotheses:
            raise CaseAnalysisContractError(
                f"{chain_type} insufficient_evidence=true 但仍返回 hypotheses")

        primary_id = str(raw.get("primary_hypothesis_id", "") or "")
        primary_cause = ""
        primary_text = ""
        if hypotheses:
            ids = {h["hypothesis_id"] for h in hypotheses}
            if not primary_id:
                raise CaseAnalysisContractError(
                    f"{chain_type} 有 hypotheses 但 primary_hypothesis_id 为空")
            if primary_id not in ids:
                raise CaseAnalysisContractError(
                    f"{chain_type}.primary_hypothesis_id={primary_id!r} 不存在")
            primary = next(h for h in hypotheses
                           if h["hypothesis_id"] == primary_id)
            primary_cause = primary.get("cause_code", "")
            primary_text = primary.get("hypothesis", "")
        elif primary_id:
            raise CaseAnalysisContractError(
                f"{chain_type} 无 hypotheses 但 primary_hypothesis_id 非空")

        root_cause = raw.get("root_cause")
        if root_cause is None:
            root_cause = {}
        if not isinstance(root_cause, dict):
            raise CaseAnalysisContractError(
                f"{chain_type}.root_cause 不是 object")
        root_cause = dict(root_cause)
        if insufficient:
            root_cause.setdefault("category", "insufficient_evidence")
            root_cause.setdefault("description", "证据不足，无法判定根因")
        elif not root_cause:
            raise CaseAnalysisContractError(
                f"{chain_type}.root_cause 缺失且非证据不足")
        root_cause["human_confirmation_reason"] = fp_reason
        root_cause["insufficient_evidence"] = insufficient

        fix_suggestion = raw.get("fix_suggestion") or []
        if isinstance(fix_suggestion, dict):
            fix_suggestion = [fix_suggestion]
        if not isinstance(fix_suggestion, list):
            raise CaseAnalysisContractError(
                f"{chain_type}.fix_suggestion 不是 list")

        label_quality = raw.get("label_quality") or {}
        if not isinstance(label_quality, dict):
            raise CaseAnalysisContractError(
                f"{chain_type}.label_quality 不是 object")

        summaries = detail.get("compressed_summaries") or []
        merge_summary = detail.get("merge_summary") or ""
        knowledge_summary = detail.get("knowledge_memory_summary") or {}
        l4 = detail.get("l4_independent_verification") or {}
        audit = detail.get("audit") or []
        if not isinstance(summaries, list):
            raise CaseAnalysisContractError(
                f"detail.{chain_type}.compressed_summaries 不是 list")
        if not isinstance(merge_summary, str):
            raise CaseAnalysisContractError(
                f"detail.{chain_type}.merge_summary 不是 string")
        if not isinstance(knowledge_summary, dict):
            raise CaseAnalysisContractError(
                f"detail.{chain_type}.knowledge_memory_summary 不是 object")
        if not isinstance(l4, dict):
            raise CaseAnalysisContractError(
                f"detail.{chain_type}.l4_independent_verification 不是 object")
        if not isinstance(audit, list):
            raise CaseAnalysisContractError(
                f"detail.{chain_type}.audit 不是 list")

        return {
            "session_chain": local_chain,
            "root_cause": root_cause,
            "hypotheses": hypotheses,
            "primary_hypothesis_id": primary_id,
            "primary_cause": primary_cause,
            "primary_hypothesis": primary_text,
            "audit": audit,
            "insufficient_evidence": insufficient,
            "label_quality": label_quality,
            "fix_suggestion": fix_suggestion,
            "compressed_summaries": summaries,
            "merge_summary": merge_summary,
            "knowledge_memory_summary": knowledge_summary,
            "l0_l7_breakpoints": breakpoints,
            "l4_independent_verification": l4,
            "input_fingerprint": self._fingerprint(
                chain_type, local_chain, payload, provenance),
            "agent_type": agent_type,
        }

    def _validate_breakpoints(
        self, chain_type: str, raw_breakpoints: Any, local_chain: list[str],
    ) -> tuple[list[dict], set[str]]:
        if raw_breakpoints is None:
            return [], set()
        if not isinstance(raw_breakpoints, list):
            raise CaseAnalysisContractError(
                f"{chain_type}.l0_l7_breakpoints 不是 list")
        out: list[dict] = []
        refs: set[str] = set()
        for idx, item in enumerate(raw_breakpoints):
            if not isinstance(item, dict):
                raise CaseAnalysisContractError(
                    f"{chain_type}.l0_l7_breakpoints[{idx}] 不是 object")
            cause = str(item.get("cause_code", "") or "")
            if cause not in ALL_CAUSES:
                raise CaseAnalysisContractError(
                    f"{chain_type} 断点 cause_code 非法: {cause!r}")
            level = str(item.get("breakpoint", "") or "")
            if level not in ALL_LEVELS:
                raise CaseAnalysisContractError(
                    f"{chain_type} 断点级别非法: {level!r}")
            expected_level = CAUSE_TO_LEVEL.get(cause, "")
            if expected_level and level != expected_level:
                raise CaseAnalysisContractError(
                    f"{chain_type} 断点 cause_code={cause} 应映射 {expected_level}，"
                    f"实际为 {level}")
            sid = str(item.get("session_id", "") or "")
            if sid and sid not in local_chain:
                raise CaseAnalysisContractError(
                    f"{chain_type} 断点 session_id 不在链中: {sid}")
            ref = str(item.get("ref") or item.get("_bp_ref")
                      or f"{chain_type.upper()}-BP-{idx + 1}")
            if ref in refs:
                raise CaseAnalysisContractError(
                    f"{chain_type} 断点 ref 重复: {ref}")
            refs.add(ref)
            bp = dict(item)
            bp["_bp_ref"] = ref
            out.append(bp)
        return out, refs

    def _validate_hypotheses(
        self, chain_type: str, raw_hypotheses: Any, local_chain: list[str],
        bp_refs: set[str], detail: dict,
        evidence_ids: set[str] | None = None,
    ) -> list[dict]:
        if raw_hypotheses is None:
            return []
        if not isinstance(raw_hypotheses, list):
            raise CaseAnalysisContractError(
                f"{chain_type}.hypotheses 不是 list")
        if evidence_ids is None:
            evidence_ids = self._evidence_ids(detail)
        out: list[dict] = []
        seen_ids: set[str] = set()
        for idx, item in enumerate(raw_hypotheses):
            if not isinstance(item, dict):
                raise CaseAnalysisContractError(
                    f"{chain_type}.hypotheses[{idx}] 不是 object")
            cause = str(item.get("cause_code", "") or "")
            if cause not in ALL_CAUSES:
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索 cause_code 非法: {cause!r}")
            try:
                confidence = float(item.get("confidence", 0))
            except (TypeError, ValueError) as exc:
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索 confidence 非数字") from exc
            if not 0.0 <= confidence <= 1.0:
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索 confidence 越界: {confidence}")
            responsibility = str(item.get("responsibility", "") or "")
            if responsibility and responsibility not in _ALLOWED_RESPONSIBILITIES:
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索 responsibility 非法: {responsibility!r}")
            evidence_refs = item.get("evidence_refs") or []
            if not isinstance(evidence_refs, list):
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索 evidence_refs 不是 list")
            missing = [str(r) for r in evidence_refs
                       if str(r) not in evidence_ids]
            if missing:
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索引用不存在的证据卡: {missing[:5]}")
            supporting = item.get("supporting_breakpoints") or []
            if not isinstance(supporting, list):
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索 supporting_breakpoints 不是 list")
            bad_bp = [str(r) for r in supporting
                      if str(r) not in bp_refs]
            if bad_bp:
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索引用不存在的断点: {bad_bp[:5]}")
            session_id = str(item.get("session_id", "") or "")
            if session_id:
                for sid in (s.strip() for s in session_id.split(",")):
                    if sid and sid not in local_chain:
                        raise CaseAnalysisContractError(
                            f"{chain_type} 线索 session_id 不在链中: {sid}")
            hyp = dict(item)
            hyp["hypothesis_id"] = str(
                item.get("hypothesis_id") or
                f"{chain_type.upper()}-H{idx + 1}")
            if hyp["hypothesis_id"] in seen_ids:
                raise CaseAnalysisContractError(
                    f"{chain_type} 线索 hypothesis_id 重复: "
                    f"{hyp['hypothesis_id']}")
            seen_ids.add(hyp["hypothesis_id"])
            hyp["confidence"] = confidence
            if "probability" not in hyp:
                hyp["probability"] = confidence
            out.append(hyp)
        return out

    @staticmethod
    def _evidence_ids(detail: dict) -> set[str]:
        ids: set[str] = set()
        for summary in detail.get("compressed_summaries") or []:
            if not isinstance(summary, dict):
                continue
            for card in summary.get("evidence_cards") or []:
                if not isinstance(card, dict):
                    continue
                eid = card.get("evidence_id") or card.get("id")
                if eid:
                    ids.add(str(eid))
        return ids

    @staticmethod
    def _chain_detail(
        detail: dict, chain_type: str, local_chain: list[str],
    ) -> dict:
        if not isinstance(detail, dict):
            return {}
        nested = detail.get("chains")
        if isinstance(nested, dict) and isinstance(nested.get(chain_type), dict):
            return dict(nested[chain_type])

        result = dict(detail)
        for key in (
            "merge_summary", "knowledge_memory_summary",
            "l4_independent_verification", "audit",
        ):
            value = result.get(key)
            if isinstance(value, dict) and any(
                    k in value for k in ("mining", "verification")):
                result[key] = value.get(chain_type, {} if key != "audit" else [])
        summaries = result.get("compressed_summaries")
        if isinstance(summaries, dict) and any(
                k in summaries for k in ("mining", "verification")):
            summaries = summaries.get(chain_type, [])
        if isinstance(summaries, list):
            chain_ids = set(local_chain)
            filtered = []
            for item in summaries:
                if not isinstance(item, dict):
                    continue
                item_chain = str(item.get("chain_type", "") or "")
                item_sid = str(item.get("session_id", "") or "")
                if item_chain and item_chain != chain_type:
                    continue
                if item_sid and chain_ids and item_sid not in chain_ids:
                    continue
                filtered.append(item)
            result["compressed_summaries"] = filtered
        return result

    @staticmethod
    def _empty_chain(
        chain_type: str, agent_type: str, provenance: dict,
        *, root_cause: dict | None = None,
    ) -> dict:
        return {
            "session_chain": [],
            "root_cause": root_cause or {
                "category": "no_session",
                "description": f"无 {chain_type} session",
            },
            "hypotheses": [],
            "primary_hypothesis_id": "",
            "primary_cause": "",
            "primary_hypothesis": "",
            "audit": [],
            "insufficient_evidence": False,
            "label_quality": {},
            "fix_suggestion": [],
            "compressed_summaries": [],
            "merge_summary": "",
            "knowledge_memory_summary": {},
            "l0_l7_breakpoints": [],
            "l4_independent_verification": {},
            "input_fingerprint": {
                "sessions": [],
                "source": "remote",
                "snapshot_written": False,
                "analyzer_version": str(
                    provenance.get("analyzer_version", "") or ""),
            },
            "agent_type": agent_type,
        }

    @staticmethod
    def _fingerprint(
        chain_type: str, chain: list[str], payload: dict, provenance: dict,
    ) -> dict:
        sessions_by_id = {
            str(item.get("session_id", "")): item
            for item in payload.get("sessions") or []
            if isinstance(item, dict)
        }
        h = hashlib.sha256()
        sessions_out: list[dict] = []
        for sid in chain:
            events = (sessions_by_id.get(sid) or {}).get("events") or []
            text = json.dumps(
                events, ensure_ascii=False, sort_keys=True, default=str)
            sh = _sha256(text)
            h.update(sid.encode("utf-8"))
            h.update(sh.encode("utf-8"))
            sessions_out.append({
                "session_id": sid,
                "chars": len(text),
                "sha256": sh,
            })
        return {
            "case_hash": h.hexdigest(),
            "prompt_hash": (
                _sha256(str(provenance.get("prompt_version", "")))
                if provenance.get("prompt_version") else ""),
            "sessions": sessions_out,
            "source": "remote",
            "snapshot_written": False,
            "analyzer_version": str(provenance.get("analyzer_version", "") or ""),
            "chain_type": chain_type,
        }

    def _api_url(self, path: str) -> str:
        prefix = "/" + (self._settings.api_prefix.strip("/") or "v1")
        return f"{self._settings.base_url.rstrip('/')}{prefix}/{path.lstrip('/')}"

    def _resolve_url(self, url: str) -> str:
        lowered = url.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return url
        return f"{self._settings.base_url.rstrip('/')}/{url.lstrip('/')}"

    @staticmethod
    def _sleep(seconds: float, cancel_cb=None) -> None:
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            if cancel_cb:
                cancel_cb()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.25, remaining))


class ShadowCaseAnalysisAdapter:
    """Shadow 模式：本地结果权威，远程结果只用于比对并写告警。"""

    def __init__(
        self, local: CaseAnalysisPort, remote: CaseAnalysisPort,
    ):
        self._local = local
        self._remote = remote

    def analyze(
        self,
        evaluation_id: str,
        cases: list[dict],
        data_packs: list[DataPack],
        cancel_cb=None,
        project_id: str = "",
    ) -> list[dict]:
        local_results = self._local.analyze(
            evaluation_id, cases, data_packs,
            cancel_cb=cancel_cb, project_id=project_id,
        )
        try:
            remote_results = self._remote.analyze(
                evaluation_id, cases, data_packs,
                cancel_cb=cancel_cb, project_id=project_id,
            )
        except Exception as exc:
            if cancel_cb:
                cancel_cb()
            _pw.add(
                evaluation_id, "case_analysis_remote",
                "shadow_failed", "warning",
                f"shadow 远程分析失败，保留本地结果：{exc}",
            )
            log("CASE_ANALYSIS", f"shadow 远程分析失败: {exc}",
                eval_id=evaluation_id)
            return local_results

        mismatches = _compare_results(local_results, remote_results)
        if mismatches:
            _pw.add(
                evaluation_id, "case_analysis_remote",
                "shadow_mismatch", "warning",
                "shadow 远程与本地结果不一致："
                + "；".join(mismatches[:10])
                + (" 等" if len(mismatches) > 10 else ""),
            )
            log("CASE_ANALYSIS",
                f"shadow 差异 {len(mismatches)} 个 case",
                eval_id=evaluation_id)
        return local_results


def _compare_results(local: list[dict], remote: list[dict]) -> list[str]:
    remote_by_id = {
        str(item.get("case_id", "")): item for item in remote
        if isinstance(item, dict)
    }
    out: list[str] = []
    for item in local:
        cid = str(item.get("case_id", ""))
        other = remote_by_id.get(cid)
        if other is None:
            out.append(f"{cid}: 远程缺少结果")
            continue
        for chain_type in ("mining", "verification"):
            a = item.get(chain_type) or {}
            b = other.get(chain_type) or {}
            ac = str(a.get("primary_cause", "") or "")
            bc = str(b.get("primary_cause", "") or "")
            if ac != bc:
                out.append(f"{cid}.{chain_type}: 本地 {ac or '-'} / 远程 {bc or '-'}")
    return out


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_case_analysis_adapter(
    settings: CaseAnalysisSettings | None = None,
    *,
    local_adapter: CaseAnalysisPort | None = None,
    http_client: _UrllibHttpClient | None = None,
) -> CaseAnalysisPort:
    """按配置构建 Hook 1 适配器。默认返回完全不变的本地实现。"""
    settings = settings or CaseAnalysisSettings.from_config()
    local = local_adapter or LocalCaseAnalysisAdapter()
    mode = (settings.mode or "local").lower()
    if mode == "local":
        return local
    if settings.fallback_enabled and settings.fallback_mode != "local":
        raise ValueError(
            f"不支持的 case_analysis fallback_mode={settings.fallback_mode}")
    if mode == "remote":
        return RemoteCaseAnalysisAdapter(
            settings, fallback_adapter=local, http_client=http_client)
    if mode == "shadow":
        if settings.shadow_authoritative != "local":
            raise ValueError(
                "shadow.authoritative 目前只支持 local")
        remote = RemoteCaseAnalysisAdapter(
            dataclasses.replace(settings, fallback_enabled=False),
            fallback_adapter=local, http_client=http_client)
        return ShadowCaseAnalysisAdapter(local, remote)
    raise ValueError(f"不支持的 case_analysis mode={settings.mode!r}")
