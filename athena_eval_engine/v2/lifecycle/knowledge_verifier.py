"""知识库主动验证器 — 当 agent 没查知识（L2=false）时，主动搜索知识库验证 L4。

场景：
  L0-L7 分析判定 L2 断点（agent 该查没查）时，评测引擎无法确认知识库里到底有没有相关知识。
  本模块模拟 agent 的知识查询行为：根据误报原因构造查询，去知识库搜索是否有相关知识。

两个知识来源（与 agent 的访问方式一致）：
  1. 知识库（Athena API）：
     - POST /api/athena/projects/{project_id}/retrieve → 提交检索任务（与 agent 同款端点）
     - GET /api/athena/projects/{project_id}/retrieve/tasks/{task_id} → 轮询检索结果
     - 需要 project_id（从评测 manifest 获取）
     - /retrieve 端点有 auto-ensure 机制：项目未注册时自动从平台 API 拉取创建货架
  2. 记忆/wiki（NFS .md 文件）：
     - /data/files/secocto-evo/compiled_knowledge/ 下的 .md 文件
     - agent 直接 cat 读，eval-engine pod 可直接访问
     - AGENTS.md 含 Fast Memory Index 表

流程：
  1. 从 vuln_title + human_confirmation_summary 提取查询关键词
  2. 查 Athena API retrieve → 检索结果（语义检索，与 agent 同款）
  3. 查 NFS compiled_knowledge → 候选 wiki 文件
  4. 读取候选文件内容摘要
  5. LLM 判定候选文件是否真正包含解决误报所需的知识
  6. 返回 L4 判定 + 证据
"""
from __future__ import annotations

import json
import os
import re
import threading
import urllib.parse
import urllib.request
from typing import Any

from ...config_loader import DATA_ROOT
from ..infra.log_util import log, log_error
from ..infra import llm as llm_mod

# ── 记忆/wiki NFS 路径 ──
_WIKI_ROOT = os.path.join(DATA_ROOT, "secocto-evo", "compiled_knowledge")
_AGENTS_MD = os.path.join(_WIKI_ROOT, "AGENTS.md")

# ── Athena API ──
# k8s 环境变量自动注入：ATHENA_API_SERVICE_HOST + ATHENA_API_SERVICE_PORT_HTTP
# fallback 用 Service DNS 域名（ClusterIP 在服务重建后会变，域名稳定）
_ATHENA_HOST = os.environ.get("ATHENA_API_SERVICE_HOST", "athena-api.secflow-ns.svc.cluster.local")
_ATHENA_PORT = os.environ.get("ATHENA_API_SERVICE_PORT_HTTP", "8000")
_ATHENA_BASE = f"http://{_ATHENA_HOST}:{_ATHENA_PORT}"

# ── 候选文件上限 ──
_MAX_CANDIDATES = 20

# ── Athena /retrieve 单项目并发上限 ──
_ATHENA_MAX_CONCURRENCY = 8

# ── 跨 case 全局信号量：按 project_id 限制 Athena /retrieve 并发 ──
# 多个 case 可能同时触发 L4 验证，各自开线程查同一 project_id，
# 总并发可能超过 Athena 单项目 8 的限制。用 per-project 信号量兜底。
_project_sems: dict[str, threading.Semaphore] = {}
_project_sems_lock = threading.Lock()

# ── seen_docs 去重锁（_search_athena_api_logged 内部使用）──
seen_docs_lock = threading.Lock()

# ── 单个 .md 文件读取前 N 行 ──
_MD_PREVIEW_LINES = 40

# ── API 超时 + 重试 ──
_API_TIMEOUT = 10           # 单次 HTTP 请求超时
_RETRIEVE_POLL_TIMEOUT = 1200  # 检索轮询超时（Athena 后端慢查询实测可达 20 分钟）
_RETRIEVE_POLL_INTERVAL = 2  # 轮询间隔（秒）
_ATHENA_RETRIES = 3          # Athena API 查询重试次数（连接错误重试）
_ATHENA_RETRY_DELAY = 1      # 重试间隔（秒）

# LLM 判定 prompt
_VERIFY_PROMPT = """你是知识库内容判定专家。

# 任务
判断知识库中是否有能消减某个误报的知识。

你将收到：
1. 漏洞类型
2. 人工标注的误报原因（说明为什么这是误报）
3. 从知识库中检索到的候选文章列表（来源 + 文件路径 + 标题 + 摘要 + 内容预览）

请判断这些候选文章中，是否有能帮助 agent 避免这个误报的知识。

# 判定标准

"能消减误报"的标准：知识内容直接涉及误报原因中提到的验证维度或判定条件。
- 如果误报原因是"网络不可达"，知识应包含网络可达性验证方法
- 如果误报原因是"输入已校验"，知识应包含输入校验有效性评估
- 如果误报原因是"接口非对外暴露"，知识应包含接口暴露面评估方法
- 如果误报原因是"已有防护机制"，知识应包含防护机制有效性验证

"不能消减误报"的情况：
- 文章只讲漏洞挖掘方法（怎么挖），不讲误报判别（怎么排除）
- 文章涉及漏洞类型但与误报原因无关
- 文章是通用安全知识，没有针对误报场景的具体指导

# 输出格式
只返回 JSON：
{
  "knowledge_exists": true/false,
  "matched_files": [
    {
      "path": "文件路径",
      "title": "文件标题",
      "relevance": "high/medium/low",
      "reason": "为什么这个文件能或不能消减误报（结合误报原因具体说明）"
    }
  ],
  "summary": "总体判断：知识库是否有覆盖此误报场景的知识，100字以内"
}

只返回 JSON，不要任何额外文字。"""


class KnowledgeVerifier:
    """知识库主动验证器。

    当 agent 没查知识（L2=false）时，主动搜索知识库和记忆/wiki 验证 L4（知识存在？）。
    """

    def verify(
        self,
        vuln_title: str,
        fp_reason: str,
        project_id: str = "",
        cancel_cb=None,
        evaluation_id: str = "",
        kb_search_queries: list[str] | None = None,
    ) -> dict:
        """主动搜索知识库 + 记忆/wiki，验证是否有解决该误报所需的知识。

        透明化：返回结果含 query_log 字段，记录查询过程的每一步——
        提取的关键词、Athena API 请求、wiki 搜索路径、每步返回的候选数，
        让用户能看到"评测引擎去知识库问了什么问题"。

        Args:
            vuln_title: 漏洞标题
            fp_reason: 人工标注的误报原因
            project_id: 项目 ID（Athena API 查询用，空则跳过 API 查询）
            cancel_cb: 取消回调
            kb_search_queries: LLM 从 session 分析产出的知识检索问题，
                              为空则不查知识库（LLM 判定无需查询）

        Returns:
            {
                "l4_knowledge_exists": true/false,
                "matched_files": [...],
                "summary": "总体判断",
                "kb_searched": {"athena_api": bool, "wiki_nfs": bool},
                "candidate_files": int,
                "query_log": [{
                    "step": str,        # 步骤名
                    "action": str,      # 动作描述
                    "detail": str,      # 具体内容（URL/路径/关键词）
                    "result": str,      # 结果摘要
                    "count": int,       # 命中数量
                }, ...],
            }
        """
        # 查询过程日志——透明化每一步
        query_log: list[dict] = []

        # 1. 确定查询关键词
        # 用 LLM 从 session 分析产出的知识检索问题（"缺什么才问什么"）
        # 没有检索问题 = LLM 判定不需要查知识库，直接返回
        keywords = kb_search_queries or []
        query_log.append({
            "step": "检索问题提取",
            "action": "使用 LLM 从 session 分析产出的知识检索问题",
            "detail": f"检索问题: {keywords}",
            "result": f"{len(keywords)} 个检索问题: {', '.join(keywords) if keywords else '（无）'}",
            "count": len(keywords),
        })
        if not keywords:
            log("KB_VERIFY",
                f"无知识检索问题，跳过知识库验证 "
                f"(vuln_title={vuln_title}, fp_reason={fp_reason})")
            result = self._empty_result()
            result["query_log"] = query_log
            result["summary"] = "LLM 分析未产出知识检索问题，无需查询知识库"
            return result

        log("KB_VERIFY",
            f"关键词: {keywords} (vuln_title={vuln_title}, "
            f"fp_reason={fp_reason}, project_id={project_id})")

        candidates: list[dict] = []

        # 2. 查 Athena API /retrieve（与 agent 同款端点）
        if project_id:
            api_candidates, api_log = self._search_athena_api_logged(
                project_id, keywords, evaluation_id=evaluation_id,
                cancel_cb=cancel_cb)
            candidates.extend(api_candidates)
            query_log.extend(api_log)
            log("KB_VERIFY", f"Athena API: {len(api_candidates)} 候选")
        else:
            query_log.append({
                "step": "Athena API 搜索",
                "action": "跳过（无 project_id）",
                "detail": "project_id 为空，跳过 Athena API 查询",
                "result": "未查询",
                "count": 0,
            })

        # 3. 查 NFS compiled_knowledge (wiki/记忆)
        wiki_candidates, wiki_log = self._search_wiki_logged(keywords)
        candidates.extend(wiki_candidates)
        query_log.extend(wiki_log)
        log("KB_VERIFY", f"Wiki NFS: {len(wiki_candidates)} 候选")

        # 去重（按 path）
        seen_paths = set()
        unique_candidates = []
        for c in candidates:
            path = c.get("path", "")
            if path and path not in seen_paths:
                seen_paths.add(path)
                unique_candidates.append(c)
        candidates = unique_candidates[:_MAX_CANDIDATES]

        query_log.append({
            "step": "去重",
            "action": f"按 path 去重（上限 {_MAX_CANDIDATES}）",
            "detail": f"去重前 {len(candidates) + len(seen_paths)} 个候选",
            "result": f"去重后 {len(unique_candidates)} 个候选",
            "count": len(unique_candidates),
        })

        if not candidates:
            _searched_api = bool(project_id)
            _searched_wiki = os.path.isdir(_WIKI_ROOT)
            # 两个数据源都没查过 → 未判定（None），不能返回 False 误报「知识缺失」
            _l4 = False if (_searched_api or _searched_wiki) else None
            result = {
                "l4_knowledge_exists": _l4,
                "matched_files": [],
                "summary": ("知识库和记忆/wiki 中均未找到与误报原因相关的知识"
                            if _l4 is not None else
                            "无可用知识源（未提供 project_id 且 wiki 目录不存在），未查询"),
                "kb_searched": {
                    "athena_api": _searched_api,
                    "wiki_nfs": _searched_wiki,
                },
                "candidate_files": 0,
            }
            result["query_log"] = query_log
            return result

        # 4. 读取候选文件内容摘要
        for c in candidates:
            if not c.get("content_preview"):
                c["content_preview"] = self._read_content(c)

        query_log.append({
            "step": "读取候选文件",
            "action": f"读取 {len(candidates)} 个候选文件内容摘要（前 {_MD_PREVIEW_LINES} 行）",
            "detail": "; ".join(c.get("path", "") for c in candidates[:10]),
            "result": f"已读取 {len(candidates)} 个文件",
            "count": len(candidates),
        })

        # 5. LLM 判定
        query_log.append({
            "step": "LLM 判定",
            "action": f"用 LLM 判定 {len(candidates)} 个候选文件是否含消减误报的知识",
            "detail": f"漏洞标题: {vuln_title}; 误报原因: {fp_reason}",
            "result": "等待 LLM 判定...",
            "count": len(candidates),
        })

        result = self._llm_verify(vuln_title, fp_reason, candidates, cancel_cb,
                                  evaluation_id=evaluation_id)
        result["kb_searched"] = {
            "athena_api": bool(project_id),
            "wiki_nfs": os.path.isdir(_WIKI_ROOT),
        }
        result["candidate_files"] = len(candidates)
        result["query_log"] = query_log

        log("KB_VERIFY",
            f"LLM 判定完成: l4={result.get('l4_knowledge_exists')}, "
            f"matched={len(result.get('matched_files', []))}")

        return result

    # ── Athena API 搜索（/retrieve 端点，与 agent 同款）──

    def _search_athena_api(
        self, project_id: str, keywords: list[str],
    ) -> list[dict]:
        """通过 Athena API /retrieve 搜索知识。

        API: POST /api/athena/projects/{project_id}/retrieve → 提交检索任务
             GET /api/athena/projects/{project_id}/retrieve/tasks/{task_id} → 轮询结果
        与 agent 使用的端点完全一致，走 auto-ensure 机制。
        """
        candidates, _ = self._search_athena_api_logged(project_id, keywords)
        return candidates

    def _search_athena_api_logged(
        self, project_id: str, keywords: list[str],
        evaluation_id: str = "",
        cancel_cb=None,
    ) -> tuple[list[dict], list[dict]]:
        """Athena API 检索（带查询日志）。

        用 /retrieve 端点（与 agent 同款）。并发提交+轮询，单项目并发上限 8。
        跨 case 用 per-project 信号量控制全局并发，避免同一 project_id
        的多个 case 各开 8 线程导致总并发超过 Athena 单项目限制。
        """
        import time as _time
        from concurrent.futures import ThreadPoolExecutor, as_completed

        submit_url = f"{_ATHENA_BASE}/api/athena/projects/{project_id}/retrieve"

        # 获取或创建 per-project 信号量（跨 case 共享）
        with _project_sems_lock:
            sem = _project_sems.get(project_id)
            if sem is None:
                sem = threading.Semaphore(_ATHENA_MAX_CONCURRENCY)
                _project_sems[project_id] = sem

        def _submit_and_poll(kw: str) -> tuple[str, str | None, dict | None, str | None]:
            """提交 → 轮询到完成 → 返回。整个生命周期持有 per-project 信号量。"""
            sem.acquire()
            try:
                # 提交
                task_id = None
                last_err = None
                for attempt in range(_ATHENA_RETRIES):
                    try:
                        payload = json.dumps({"message": kw}).encode("utf-8")
                        req = urllib.request.Request(
                            submit_url,
                            data=payload,
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        resp = urllib.request.urlopen(req, timeout=_API_TIMEOUT)
                        data = json.loads(resp.read())
                        task_id = data.get("retrieval_task_id")
                        if task_id:
                            break
                    except Exception as e:
                        last_err = e
                        if attempt < _ATHENA_RETRIES - 1:
                            _time.sleep(_ATHENA_RETRY_DELAY)
                if not task_id:
                    return kw, None, None, str(last_err) if last_err else "unknown"

                # 轮询到完成或超时
                poll_url = (f"{_ATHENA_BASE}/api/athena/projects/{project_id}"
                            f"/retrieve/tasks/{task_id}")
                poll_start = _time.time()
                _last_poll_err = None
                while _time.time() - poll_start < _RETRIEVE_POLL_TIMEOUT:
                    if cancel_cb:
                        cancel_cb()
                    try:
                        req = urllib.request.Request(poll_url)
                        resp = urllib.request.urlopen(req, timeout=_API_TIMEOUT)
                        poll_data = json.loads(resp.read())
                        status = poll_data.get("status", "")
                        if status in ("completed", "failed"):
                            return kw, task_id, poll_data, None
                    except Exception as e:
                        # 轮询期间的瞬时错误继续重试，但要记录，不能静默吞掉
                        _last_poll_err = e
                        log("KB_VERIFY",
                            f"Athena 轮询异常 (kw={kw}, task_id={task_id}): "
                            f"{type(e).__name__}: {e}")
                    _time.sleep(_RETRIEVE_POLL_INTERVAL)
                # 超时：带上最后一次轮询错误，便于区分「服务慢」和「持续报错」
                if _last_poll_err is not None:
                    return kw, task_id, None, f"timeout; last poll error: {_last_poll_err}"
                return kw, task_id, None, "timeout"
            finally:
                sem.release()

        # 并发提交+轮询，单 case 内并发上限 8，跨 case 也受 per-project 信号量约束
        max_workers = min(len(keywords), _ATHENA_MAX_CONCURRENCY)
        raw_results: list[tuple[str, str | None, dict | None, str | None]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_submit_and_poll, kw): kw for kw in keywords}
            for fut in as_completed(futures):
                raw_results.append(fut.result())

        # 按原始顺序排序
        kw_order = {kw: i for i, kw in enumerate(keywords)}
        raw_results.sort(key=lambda r: kw_order.get(r[0], 0))

        candidates: list[dict] = []
        seen_docs: set[str] = set()
        log_entries: list[dict] = []

        for kw, task_id, poll_data, error in raw_results:
            if task_id is None:
                log("KB_VERIFY", f"Athena /retrieve 提交失败 (kw={kw}): {error}")
                from ..infra.pipeline_warnings import add as _add_warning
                _add_warning(evaluation_id, "kb_verify", "athena_api_failed", "warning",
                             f"Athena /retrieve 提交失败 (kw={kw}): {error}")
                log_entries.append({
                    "step": "Athena API 搜索",
                    "action": f"POST {submit_url}",
                    "detail": f"关键词: {kw}",
                    "result": f"提交失败（{_ATHENA_RETRIES}次重试后）: {error}",
                    "count": 0,
                })
                continue

            poll_url = (f"{_ATHENA_BASE}/api/athena/projects/{project_id}"
                        f"/retrieve/tasks/{task_id}")

            if error == "timeout" or (error or "").startswith("timeout;"):
                log("KB_VERIFY", f"Athena /retrieve 轮询超时 (kw={kw}, task_id={task_id}, "
                                 f"timeout={_RETRIEVE_POLL_TIMEOUT}s, detail={error})")
                from ..infra.pipeline_warnings import add as _add_warning
                _add_warning(evaluation_id, "kb_verify", "athena_api_timeout", "warning",
                             f"Athena /retrieve 轮询超时 (kw={kw}): timeout={_RETRIEVE_POLL_TIMEOUT}s, detail={error}")
                log_entries.append({
                    "step": "Athena API 搜索",
                    "action": f"POST {submit_url} → GET {poll_url}",
                    "detail": f"关键词: {kw}, task_id={task_id}",
                    "result": f"轮询超时（{_RETRIEVE_POLL_TIMEOUT}s）: {error}",
                    "count": 0,
                })
                continue

            if poll_data is None or poll_data.get("status") != "completed":
                err = (poll_data.get("error_summary") or poll_data.get("error_class") or "unknown") if poll_data else "no response"
                log("KB_VERIFY", f"Athena /retrieve 检索失败 (kw={kw}, task_id={task_id}): {err}")
                log_entries.append({
                    "step": "Athena API 搜索",
                    "action": f"POST {submit_url} → GET {poll_url}",
                    "detail": f"关键词: {kw}, task_id={task_id}",
                    "result": f"检索失败: {err}",
                    "count": 0,
                })
                continue

            # 解析检索结果
            content = poll_data.get("content", "")
            recall = poll_data.get("recall") or {}
            retrieve_results = recall.get("results", []) if isinstance(recall, dict) else []

            new_docs: list[str] = []
            for r in retrieve_results:
                doc_path = r.get("document_path") or r.get("path") or ""
                snippet = r.get("content") or r.get("snippet") or r.get("context") or ""
                title = r.get("title") or (doc_path.split("/")[-1].replace(".md", "") if doc_path else "")

                if doc_path:
                    with seen_docs_lock:
                        if doc_path in seen_docs:
                            continue
                        seen_docs.add(doc_path)
                    new_docs.append(doc_path)
                    candidates.append({
                        "source": "athena_api",
                        "path": doc_path,
                        "title": title,
                        "abstract": snippet,
                        "keywords": kw,
                        "content_preview": snippet,
                        "hit_fields": ["retrieve"],
                    })

                    if len(candidates) >= _MAX_CANDIDATES:
                        break

            # 如果没有 structured results 但有 content，把 content 作为候选
            if not retrieve_results and content:
                candidates.append({
                    "source": "athena_api",
                    "path": f"retrieve/{task_id}",
                    "title": f"检索结果: {kw}",
                    "abstract": content,
                    "keywords": kw,
                    "content_preview": content,
                    "hit_fields": ["retrieve"],
                })

            match_count = len(retrieve_results) if retrieve_results else (1 if content else 0)
            log_entries.append({
                "step": "Athena API 搜索",
                "action": f"POST {submit_url} → GET {poll_url}",
                "detail": f"关键词: {kw}, task_id={task_id}",
                "result": (f"检索完成，返回 {match_count} 个结果，"
                           f"命中 {len(new_docs)} 个文档"
                           + (f": {', '.join(d.split('/')[-1] for d in new_docs[:3])}"
                              if new_docs else "")),
                "count": len(new_docs),
            })

            if len(candidates) >= _MAX_CANDIDATES:
                break

        return candidates, log_entries

    # ── Wiki/记忆 NFS 搜索 ──

    def _search_wiki(self, keywords: list[str]) -> list[dict]:
        """搜索 NFS compiled_knowledge 目录的 .md 文件。"""
        candidates, _ = self._search_wiki_logged(keywords)
        return candidates

    def _search_wiki_logged(self, keywords: list[str]) -> tuple[list[dict], list[dict]]:
        """Wiki/记忆 NFS 搜索（带查询日志）。

        记录 Fast Memory Index 条目数、匹配结果、逐文件扫描了哪些目录。
        """
        log_entries: list[dict] = []

        if not os.path.isdir(_WIKI_ROOT):
            log_entries.append({
                "step": "Wiki/记忆 NFS 搜索",
                "action": f"检查目录 {_WIKI_ROOT}",
                "detail": "目录不存在",
                "result": "跳过 wiki 搜索",
                "count": 0,
            })
            return [], log_entries

        log_entries.append({
            "step": "Wiki/记忆 NFS 搜索",
            "action": f"搜索目录 {_WIKI_ROOT}",
            "detail": f"关键词: {', '.join(keywords)}",
            "result": "开始搜索",
            "count": 0,
        })

        # 1. 读 Fast Memory Index
        index_entries = self._load_fast_memory_index()
        log_entries.append({
            "step": "Wiki/记忆 NFS 搜索",
            "action": f"读 Fast Memory Index（{_AGENTS_MD}）",
            "detail": f"AGENTS.md {'存在' if index_entries else '不存在或为空'}",
            "result": f"解析到 {len(index_entries)} 个索引条目",
            "count": len(index_entries),
        })

        candidates = self._match_index(keywords, index_entries)
        log_entries.append({
            "step": "Wiki/记忆 NFS 搜索",
            "action": "关键词匹配 Fast Memory Index",
            "detail": f"关键词: {', '.join(keywords)}",
            "result": f"索引匹配到 {len(candidates)} 个候选",
            "count": len(candidates),
        })

        # 2. 索引匹配不足时逐文件扫描
        if len(candidates) < 3:
            exclude = {c.get("path") for c in candidates}
            scan_dirs = ("vulns", "topics", "products", "experiences", "overlays")
            log_entries.append({
                "step": "Wiki/记忆 NFS 搜索",
                "action": "逐文件扫描（索引匹配不足 3，回退扫描）",
                "detail": f"扫描子目录: {', '.join(scan_dirs)}",
                "result": "开始逐文件扫描...",
                "count": 0,
            })
            extra = self._scan_files_direct(keywords, exclude)
            candidates.extend(extra[:_MAX_CANDIDATES - len(candidates)])
            log_entries.append({
                "step": "Wiki/记忆 NFS 搜索",
                "action": "逐文件扫描完成",
                "detail": f"扫描子目录: {', '.join(scan_dirs)}",
                "result": f"逐文件扫描追加 {len(extra)} 个候选",
                "count": len(extra),
            })

        return candidates[:_MAX_CANDIDATES], log_entries

    def _load_fast_memory_index(self) -> list[dict]:
        """读取 AGENTS.md，解析 Fast Memory Index 表。"""
        if not os.path.isfile(_AGENTS_MD):
            return []

        try:
            with open(_AGENTS_MD, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        entries: list[dict] = []
        in_table = False
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("| Title") and "Fastpath" in stripped:
                in_table = True
                continue
            if not in_table:
                continue
            if stripped.startswith("|") and set(stripped.replace("|", "").replace("-", "").strip()) <= set():
                continue
            if not stripped.startswith("|"):
                in_table = False
                continue

            cols = [c.strip() for c in stripped.split("|")]
            cols = [c for c in cols if c != ""]
            if len(cols) < 5:
                continue

            entries.append({
                "title": cols[0],
                "abstract": cols[1] if len(cols) > 1 else "",
                "keywords": cols[2] if len(cols) > 2 else "",
                "scope": cols[3] if len(cols) > 3 else "",
                "fastpath": cols[4] if len(cols) > 4 else "",
                "confidence": cols[5] if len(cols) > 5 else "",
            })

        return entries

    def _match_index(
        self, keywords: list[str], index_entries: list[dict],
    ) -> list[dict]:
        """用关键词匹配 Fast Memory Index 条目。"""
        matched: list[dict] = []

        for entry in index_entries:
            title = entry.get("title", "")
            abstract = entry.get("abstract", "")
            kw_str = entry.get("keywords", "")
            fastpath = entry.get("fastpath", "")

            if "test" in title.lower() or "测试" in title:
                continue

            title_lower = title.lower()
            abstract_lower = abstract.lower()
            kw_lower = kw_str.lower()

            hit_fields = []
            hit_count = 0

            for kw in keywords:
                kw_l = kw.lower()
                if kw_l in title_lower:
                    hit_count += 3
                    if "title" not in hit_fields:
                        hit_fields.append("title")
                if kw_l in abstract_lower:
                    hit_count += 2
                    if "abstract" not in hit_fields:
                        hit_fields.append("abstract")
                if kw_l in kw_lower:
                    hit_count += 2
                    if "keywords" not in hit_fields:
                        hit_fields.append("keywords")

            if hit_count > 0:
                path = os.path.join(
                    _WIKI_ROOT,
                    fastpath.replace("compiled_knowledge/", "", 1),
                ) if fastpath else ""
                if path and not os.path.isabs(path):
                    path = os.path.join(_WIKI_ROOT, path)

                matched.append({
                    "source": "wiki_nfs",
                    "title": title,
                    "abstract": abstract,
                    "keywords": kw_str,
                    "path": path,
                    "hit_fields": hit_fields,
                    "content_preview": "",
                })

        matched.sort(key=lambda x: sum([
            (3 if "title" in x.get("hit_fields", []) else 0),
            (2 if "abstract" in x.get("hit_fields", []) else 0),
            (2 if "keywords" in x.get("hit_fields", []) else 0),
        ]), reverse=True)

        return matched[:_MAX_CANDIDATES]

    def _scan_files_direct(
        self, keywords: list[str], exclude: set[str] | None = None,
    ) -> list[dict]:
        """逐文件扫描 wiki 目录，关键词匹配 .md 文件。"""
        exclude = exclude or set()
        subdirs = ("vulns", "topics", "products", "experiences", "overlays")
        matched: list[dict] = []

        for subdir in subdirs:
            dir_path = os.path.join(_WIKI_ROOT, subdir)
            if not os.path.isdir(dir_path):
                continue

            for fname in os.listdir(dir_path):
                if not fname.endswith(".md"):
                    continue
                fpath = os.path.join(dir_path, fname)
                if not os.path.isfile(fpath) or fpath in exclude:
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        lines = []
                        for _ in range(_MD_PREVIEW_LINES):
                            line = f.readline()
                            if not line:
                                break
                            lines.append(line)
                except Exception:
                    continue

                preview = "".join(lines)
                title = self._extract_md_title(fname, lines)
                fname_lower = fname.lower()
                title_lower = (title or "").lower()
                preview_lower = preview.lower()

                hit_in_name = any(kw.lower() in fname_lower for kw in keywords)
                hit_in_title = any(kw.lower() in title_lower for kw in keywords)
                hit_in_content = any(kw.lower() in preview_lower for kw in keywords)

                if hit_in_name or hit_in_title or hit_in_content:
                    matched.append({
                        "source": "wiki_nfs",
                        "title": title,
                        "abstract": preview,
                        "keywords": "",
                        "path": fpath,
                        "hit_fields": [
                            *(["name"] if hit_in_name else []),
                            *(["title"] if hit_in_title else []),
                            *(["content"] if hit_in_content else []),
                        ],
                        # content_preview 由后续 _read_content 读取完整内容填充，
                        # 搜索阶段不截断存储
                    })

                if len(matched) >= _MAX_CANDIDATES:
                    break
            if len(matched) >= _MAX_CANDIDATES:
                break

        return matched

    # ── 通用工具 ──

    @staticmethod
    def _extract_md_title(filename: str, lines: list[str]) -> str:
        """从 .md 文件提取标题。"""
        in_frontmatter = False
        for line in lines:
            stripped = line.strip()
            if stripped == "---":
                in_frontmatter = not in_frontmatter
                continue
            if in_frontmatter:
                m = re.match(r'^title:\s*(.+)$', stripped)
                if m:
                    return m.group(1).strip().strip('"\'')
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("# ") and not stripped.startswith("## "):
                return stripped[2:].strip()
        return filename.replace(".md", "").replace("-", " ").replace("_", " ")

    def _read_content(self, candidate: dict) -> str:
        """读取候选文件内容摘要。

        Athena API 来源：已在搜索阶段读取（content_preview 已填充）
        Wiki NFS 来源：直接读文件
        """
        source = candidate.get("source", "")
        path = candidate.get("path", "")

        if source == "athena_api":
            # context 已在搜索阶段直接用作 content_preview，无需再读文件
            return candidate.get("content_preview", "") or candidate.get("abstract", "")
        elif source == "wiki_nfs" and path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception:
                return ""
        return candidate.get("abstract", "")

    # ── LLM 判定 ──

    def _llm_verify(
        self,
        vuln_title: str,
        fp_reason: str,
        candidates: list[dict],
        cancel_cb=None,
        evaluation_id: str = "",
    ) -> dict:
        """LLM 判定候选文章是否真正包含解决误报所需的知识。

        候选文章内容不截断——截断会导致关键知识被丢弃，L4 判定错误。
        如果所有候选内容合计超过 LLM 上下文限制，分批送 LLM 判定后合并。
        """
        def _build_messages(batch: list[dict]) -> list[dict]:
            files_desc = []
            for i, c in enumerate(batch):
                hit_str = "、".join(c.get("hit_fields", [])) or "无"
                source_label = "知识库API" if c.get("source") == "athena_api" else "记忆Wiki"
                files_desc.append(
                    f"文章{i+1}:\n"
                    f"  来源: {source_label}\n"
                    f"  路径: {c.get('path', '')}\n"
                    f"  标题: {c.get('title', '')}\n"
                    f"  摘要: {c.get('abstract', '')}\n"
                    f"  关键词: {c.get('keywords', '')}\n"
                    f"  匹配方式: {hit_str}\n"
                    f"  内容预览:\n{c.get('content_preview', '')}\n"
                )
            user_content = (
                f"漏洞标题: {vuln_title}\n\n"
                f"人工标注的误报原因: {fp_reason}\n\n"
                f"知识库候选文章 ({len(batch)} 个):\n\n"
                f"{''.join(files_desc)}\n\n"
                f"请判断这些文章中是否有能消减这个误报的知识。"
                f"重点关注：文章内容是否直接涉及误报原因中提到的验证维度。"
            )
            return [
                {"role": "system", "content": _VERIFY_PROMPT},
                {"role": "user", "content": user_content},
            ]

        # 预检：全部候选合计是否超限
        all_msgs = _build_messages(candidates)
        if not llm_mod.would_exceed_context(all_msgs):
            # 未超限：一次性送 LLM
            try:
                result = llm_mod.chat_json(
                    all_msgs, temperature=0, cancel_cb=cancel_cb,
                    required_keys=["knowledge_exists"])
            except Exception as e:
                log("KB_VERIFY", "LLM 判定失败")
                log_error(evaluation_id, "KB_VERIFY", e)
                raise
            return {
                "l4_knowledge_exists": result.get("knowledge_exists", False),
                "matched_files": result.get("matched_files") or [],
                "summary": result.get("summary", ""),
            }

        # 超限：分批送 LLM，每批预检不超限
        log("KB_VERIFY",
            f"候选文章内容合计超限，分批 LLM 判定 ({len(candidates)} 个候选)")
        batches = []
        current_batch = []
        for c in candidates:
            trial = current_batch + [c]
            if llm_mod.would_exceed_context(_build_messages(trial)) and current_batch:
                batches.append(current_batch)
                current_batch = [c]
            else:
                current_batch = trial
        if current_batch:
            batches.append(current_batch)

        all_matched = []
        any_knowledge_exists = False
        summaries = []
        for bi, batch in enumerate(batches):
            if cancel_cb:
                cancel_cb()
            batch_msgs = _build_messages(batch)
            try:
                r = llm_mod.chat_json(
                    batch_msgs, temperature=0, cancel_cb=cancel_cb,
                    required_keys=["knowledge_exists"])
            except Exception as e:
                log("KB_VERIFY", f"分批 {bi+1}/{len(batches)} LLM 判定失败")
                log_error(evaluation_id, "KB_VERIFY", e)
                raise
            if r.get("knowledge_exists", False):
                any_knowledge_exists = True
            all_matched.extend(r.get("matched_files") or [])
            summaries.append(r.get("summary", ""))

        return {
            "l4_knowledge_exists": any_knowledge_exists,
            "matched_files": all_matched,
            "summary": f"分批判定（{len(batches)} 批）: " + "; ".join(summaries),
        }

    @staticmethod
    def _empty_result() -> dict:
        """未实际查询知识库时的返回值。

        l4_knowledge_exists=None 表示「未判定」——不能返回 False，
        否则上层会误读成「知识库确实没有该知识」，进而把责任错归到知识库
        （用户取消/未产出检索问题等场景下知识库根本没被查过）。
        """
        return {
            "l4_knowledge_exists": None,
            "matched_files": [],
            "summary": "未查询知识库",
            "kb_searched": {"athena_api": False, "wiki_nfs": False},
            "candidate_files": 0,
        }
