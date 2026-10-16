"""知识库主动验证器 — 当 agent 没查知识（L2=false）时，主动搜索知识库验证 L4。

场景：
  L0-L7 分析判定 L2 断点（agent 该查没查）时，评测引擎无法确认知识库里到底有没有相关知识。
  本模块模拟 agent 的知识查询行为：根据误报原因构造查询，去知识库搜索是否有相关知识。

两个知识来源（与 agent 的访问方式一致）：
  1. 知识库（Athena API）：
     - GET /api/athena/projects/{project_id}/knowledge/concepts?query=xxx → 概念搜索
     - GET /api/athena/projects/{project_id}/knowledge/file?path=xxx → 读文件内容
     - 需要 project_id（从评测 manifest 获取）
     - 知识库内容在 /data/projects/{project_id}/知识货架/ 下
  2. 记忆/wiki（NFS .md 文件）：
     - /data/files/secocto-evo/compiled_knowledge/ 下的 .md 文件
     - agent 直接 cat 读，eval-engine pod 可直接访问
     - AGENTS.md 含 Fast Memory Index 表

流程：
  1. 从 vuln_title + human_confirmation_summary 提取查询关键词
  2. 查 Athena API knowledge/concepts → 候选知识文件
  3. 查 NFS compiled_knowledge → 候选 wiki 文件
  4. 读取候选文件内容摘要
  5. LLM 判定候选文件是否真正包含解决误报所需的知识
  6. 返回 L4 判定 + 证据
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any

from ...config_loader import DATA_ROOT
from ...infrastructure.log_util import log
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

# ── 单个 .md 文件读取前 N 行 ──
_MD_PREVIEW_LINES = 40

# ── API 超时 ──
_API_TIMEOUT = 10

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
    ) -> dict:
        """主动搜索知识库 + 记忆/wiki，验证是否有解决该误报所需的知识。

        Args:
            vuln_title: 漏洞标题
            fp_reason: 人工标注的误报原因
            project_id: 项目 ID（Athena API 查询用，空则跳过 API 查询）
            cancel_cb: 取消回调

        Returns:
            {
                "l4_knowledge_exists": true/false,
                "matched_files": [{path, title, source, relevance, reason}],
                "summary": "总体判断",
                "kb_searched": {"athena_api": bool, "wiki_nfs": bool},
                "candidate_files": int,
            }
        """
        # 1. 提取查询关键词
        keywords = self._extract_keywords(vuln_title, fp_reason)
        if not keywords:
            log("KB_VERIFY", f"无法提取关键词: vuln_title={vuln_title}, fp_reason={fp_reason}")
            return self._empty_result()

        log("KB_VERIFY",
            f"关键词: {keywords} (vuln_title={vuln_title[:50]}, "
            f"fp_reason={fp_reason[:50]}, project_id={project_id})")

        candidates: list[dict] = []

        # 2. 查 Athena API knowledge/concepts
        if project_id:
            api_candidates = self._search_athena_api(project_id, keywords)
            candidates.extend(api_candidates)
            log("KB_VERIFY", f"Athena API: {len(api_candidates)} 候选")

        # 3. 查 NFS compiled_knowledge (wiki/记忆)
        wiki_candidates = self._search_wiki(keywords)
        candidates.extend(wiki_candidates)
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

        if not candidates:
            return {
                "l4_knowledge_exists": False,
                "matched_files": [],
                "summary": "知识库和记忆/wiki 中均未找到与误报原因相关的知识",
                "kb_searched": {
                    "athena_api": bool(project_id),
                    "wiki_nfs": os.path.isdir(_WIKI_ROOT),
                },
                "candidate_files": 0,
            }

        # 4. 读取候选文件内容摘要
        for c in candidates:
            if not c.get("content_preview"):
                c["content_preview"] = self._read_content(c)

        # 5. LLM 判定
        result = self._llm_verify(vuln_title, fp_reason, candidates, cancel_cb)
        result["kb_searched"] = {
            "athena_api": bool(project_id),
            "wiki_nfs": os.path.isdir(_WIKI_ROOT),
        }
        result["candidate_files"] = len(candidates)

        log("KB_VERIFY",
            f"LLM 判定完成: l4={result.get('l4_knowledge_exists')}, "
            f"matched={len(result.get('matched_files', []))}")

        return result

    # ── 关键词提取 ──

    def _extract_keywords(self, vuln_title: str, fp_reason: str) -> list[str]:
        """从误报原因和漏洞类型提取知识查询关键词。

        优先从 fp_reason 提取验证维度关键词（如"网络可达性"、"输入校验"），
        这些关键词能查到"为什么是误报"的知识。
        vuln_title 关键词作为补充（如"SSRF"），查到的是"怎么挖漏洞"的知识，
        对误报消减参考价值较低。
        """
        keywords: list[str] = []

        # ── 优先从误报原因提取 ──
        # fp_reason 中的关键词指向"为什么是误报"，能查到误报消减知识
        if fp_reason:
            reason = re.sub(r'^(误报[：:])?\s*(其他误报原因[：:])?\s*', '', fp_reason)
            # 按标点和空格分词
            segments = re.split(r'[，,。.；;！!？?\s]+', reason)
            for seg in segments:
                seg = seg.strip()
                if len(seg) >= 2:
                    keywords.append(seg)

        # ── 从漏洞类型提取（补充）──
        if vuln_title:
            vuln_lower = vuln_title.lower()
            vuln_keywords = [
                "sql注入", "xss", "ssrf", "csrf", "dos", "rce",
                "命令注入", "路径穿越", "文件上传", "反序列化",
                "信息泄露", "越权", "认证绕过", "权限提升",
            ]
            for kw in vuln_keywords:
                if kw in vuln_lower or kw in vuln_title:
                    if kw not in keywords:
                        keywords.append(kw)

        # 去重，保留顺序
        seen = set()
        unique = []
        for kw in keywords:
            if kw not in seen:
                seen.add(kw)
                unique.append(kw)
        return unique

    # ── Athena API 搜索 ──

    def _search_athena_api(
        self, project_id: str, keywords: list[str],
    ) -> list[dict]:
        """通过 Athena API knowledge/concepts 搜索知识。

        API: GET /api/athena/projects/{project_id}/knowledge/concepts?query=xxx
        返回 matches[]，每个含 aliases + mentions[]（含 document_path + context）
        """
        candidates: list[dict] = []
        seen_docs: set[str] = set()

        for kw in keywords:
            try:
                url = (f"{_ATHENA_BASE}/api/athena/projects/{project_id}"
                       f"/knowledge/concepts?" +
                       urllib.parse.urlencode({"query": kw}))
                req = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=_API_TIMEOUT)
                data = json.loads(resp.read())
            except Exception as e:
                log("KB_VERIFY", f"Athena API 查询失败 (kw={kw}): {str(e)[:150]}")
                continue

            for match in data.get("matches", []):
                aliases = match.get("aliases", [])
                for mention in match.get("mentions", []):
                    doc_path = mention.get("document_path", "")
                    context = mention.get("context", "")
                    if not doc_path or doc_path in seen_docs:
                        continue
                    seen_docs.add(doc_path)

                    # 立即读取文件内容（project_id 在此上下文中可用）
                    content = self._read_athena_file(project_id, doc_path)

                    candidates.append({
                        "source": "athena_api",
                        "path": doc_path,
                        "title": doc_path.split("/")[-1].replace(".md", ""),
                        "abstract": context[:200],
                        "keywords": ", ".join(aliases),
                        "content_preview": content,
                        "hit_fields": ["concepts"],
                    })

                    if len(candidates) >= _MAX_CANDIDATES:
                        return candidates

        return candidates

    def _read_athena_file(
        self, project_id: str, doc_path: str,
    ) -> str:
        """通过 Athena API knowledge/file 读取文件内容。"""
        try:
            url = (f"{_ATHENA_BASE}/api/athena/projects/{project_id}"
                   f"/knowledge/file?" +
                   urllib.parse.urlencode({"path": doc_path}))
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=_API_TIMEOUT)
            data = json.loads(resp.read())
            return str(data.get("content", ""))[:2000]
        except Exception as e:
            log("KB_VERIFY", f"Athena API 读文件失败 ({doc_path}): {str(e)[:150]}")
            return ""

    # ── Wiki/记忆 NFS 搜索 ──

    def _search_wiki(self, keywords: list[str]) -> list[dict]:
        """搜索 NFS compiled_knowledge 目录的 .md 文件。

        模拟 agent 的访问方式：先读 AGENTS.md 的 Fast Memory Index，
        关键词匹配 index 的 title/abstract/keywords 列 → 候选文章。
        索引匹配不足时回退到逐文件扫描。
        """
        if not os.path.isdir(_WIKI_ROOT):
            return []

        # 1. 读 Fast Memory Index
        index_entries = self._load_fast_memory_index()
        candidates = self._match_index(keywords, index_entries)

        # 2. 索引匹配不足时逐文件扫描
        if len(candidates) < 3:
            exclude = {c.get("path") for c in candidates}
            extra = self._scan_files_direct(keywords, exclude)
            candidates.extend(extra[:_MAX_CANDIDATES - len(candidates)])

        return candidates[:_MAX_CANDIDATES]

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

        matched.sort(key=lambda x: sum(
            3 if "title" in x.get("hit_fields", []) else 0 +
            2 if "abstract" in x.get("hit_fields", []) else 0 +
            2 if "keywords" in x.get("hit_fields", []) else 0
        ), reverse=True)

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
                        "abstract": preview[:200],
                        "keywords": "",
                        "path": fpath,
                        "hit_fields": [
                            *(["name"] if hit_in_name else []),
                            *(["title"] if hit_in_title else []),
                            *(["content"] if hit_in_content else []),
                        ],
                        "content_preview": preview[:2000],
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
            # 搜索阶段已通过 _read_athena_file 读取，直接返回
            return candidate.get("content_preview", "") or candidate.get("abstract", "")
        elif source == "wiki_nfs" and path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = []
                    for _ in range(_MD_PREVIEW_LINES):
                        line = f.readline()
                        if not line:
                            break
                        lines.append(line)
                return "".join(lines)[:2000]
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
    ) -> dict:
        """LLM 判定候选文章是否真正包含解决误报所需的知识。"""
        files_desc = []
        for i, c in enumerate(candidates):
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
                f"  内容预览:\n{c.get('content_preview', '')[:500]}\n"
            )

        user_content = (
            f"漏洞标题: {vuln_title}\n\n"
            f"人工标注的误报原因: {fp_reason}\n\n"
            f"知识库候选文章 ({len(candidates)} 个):\n\n"
            f"{''.join(files_desc)}\n\n"
            f"请判断这些文章中是否有能消减这个误报的知识。"
            f"重点关注：文章内容是否直接涉及误报原因中提到的验证维度。"
        )

        messages = [
            {"role": "system", "content": _VERIFY_PROMPT},
            {"role": "user", "content": user_content},
        ]

        try:
            result = llm_mod.chat_json(
                messages,
                temperature=0,
                cancel_cb=cancel_cb,
            )
        except Exception as e:
            log("KB_VERIFY", f"LLM 判定失败: {str(e)[:200]}")
            return {
                "l4_knowledge_exists": bool(candidates),
                "matched_files": [
                    {
                        "path": c.get("path", ""),
                        "title": c.get("title", ""),
                        "relevance": "medium",
                        "reason": "LLM 判定失败，关键词匹配降级",
                    }
                    for c in candidates
                ],
                "summary": f"LLM 判定失败，降级为关键词匹配（{len(candidates)} 个候选）",
            }

        return {
            "l4_knowledge_exists": result.get("knowledge_exists", False),
            "matched_files": result.get("matched_files") or [],
            "summary": result.get("summary", ""),
        }

    @staticmethod
    def _empty_result() -> dict:
        return {
            "l4_knowledge_exists": False,
            "matched_files": [],
            "summary": "无法提取查询关键词或知识库不可访问",
            "kb_searched": {"athena_api": False, "wiki_nfs": False},
            "candidate_files": 0,
        }
