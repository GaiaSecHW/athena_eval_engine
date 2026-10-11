"""知识盘点模块 — 覆盖度 + 质量标注。

数据来源：
- 知识库 API（athena-api，k8s 内 svc 访问）：全量文件清单 + 目录树 + 单条文档全文 + 效果统计
- 记忆 NFS 目录（/app/memory/）：init.json + 各子目录知识条目

覆盖度判定：
1. 调知识库 API 拉全量文件清单 + 结构化目录
2. 读记忆 NFS 目录，按 type/level 分类统计
3. 从 data_packs 的 benchmark_item 获取被测漏洞类型列表
4. 用知识文档的 topic 字段和文件名关键词匹配漏洞类型
5. 对比：基线有的漏洞类型在知识库/记忆中有没有对应知识

质量判定：
1. 从知识文档 frontmatter 读取 验证状态 / topic / 层级 字段
2. 对 Trace 中实际访问过的知识，用 LLM 对比基线漏洞信息判定正确性（Prompt 5）
3. 质量标签：correct / outdated / incomplete

输出写入 {reports_dir}/{evaluation_id}_inventory.json
"""
from __future__ import annotations

import json
import os
import re
import glob as _glob
from typing import Any

import urllib.request
from urllib.error import URLError, HTTPError

from ..infra.llm import chat_json, is_enabled as llm_is_enabled
from ...infrastructure.log_util import log

# ── 配置 ──────────────────────────────────────────────

# 知识库 API（k8s 内 svc 访问）
KNOWLEDGE_API_HOST = os.environ.get(
    "KNOWLEDGE_API_HOST", "athena-api.secflow-ns.svc.cluster.local"
)
KNOWLEDGE_API_PORT = int(os.environ.get("KNOWLEDGE_API_PORT", "8000"))

# 记忆 NFS 目录
MEMORY_ROOT = os.environ.get("MEMORY_ROOT", "/app/memory")

# L7 confidence 阈值（confidence < 此值 → 标记为无法确认）
_L7_CONFIDENCE_THRESHOLD = float(
    os.environ.get("L7_CONFIDENCE_THRESHOLD", "0.6")
)

# HTTP 请求超时（秒）— 知识库 API 可能返回大文件
_HTTP_TIMEOUT = 30.0

# ── 漏洞类型关键词映射（用于从知识文档 topic/文件名匹配漏洞类型）──
# 知识文档的 topic 字段或文件名可能含这些关键词
_VULN_TYPE_KEYWORDS: dict[str, list[str]] = {
    "SQL注入": ["sql", "sqli", "sql注入", "sql_injection"],
    "XSS": ["xss", "跨站脚本", "cross_site_script"],
    "命令注入": ["command_injection", "命令注入", "rce", "os_command", "cmd_injection"],
    "路径穿越": ["path_traversal", "路径穿越", "directory_traversal", "lfi"],
    "SSRF": ["ssrf", "server_side_request"],
    "反序列化": ["deserialization", "反序列化", "unserialize", "deserial"],
    "XXE": ["xxe", "xml_external"],
    "文件上传": ["file_upload", "文件上传", "upload"],
    "信息泄露": ["info_leak", "信息泄露", "sensitive_data", "info_disclosure"],
    "权限绕过": ["auth_bypass", "权限绕过", "access_control", "broken_access"],
    "CSRF": ["csrf", "跨站请求"],
    "逻辑漏洞": ["logic", "业务逻辑", "逻辑漏洞"],
    "缓冲区溢出": ["buffer_overflow", "缓冲区溢出", "bof"],
    "内存破坏": ["memory_corruption", "内存破坏", "heap", "stack_overflow"],
}


class KnowledgeInventory:
    """知识盘点：覆盖度 + 质量标注。

    覆盖度：知识库 API + 记忆 NFS 目录 → 按漏洞类型匹配 → 覆盖/缺失
    质量：frontmatter 验证状态 + LLM 对 Trace 中访问过的知识判定正确性
    """

    def __init__(self, llm_client=None):
        """初始化。

        Args:
            llm_client: 可选的 LLM 客户端。None 时使用 v2 infra llm 模块。
                        传入的对象需有 chat_json(messages, **kwargs) -> dict 方法。
        """
        self.llm = llm_client

    # ── 主入口 ──────────────────────────────────────────

    def run_inventory(
        self,
        evaluation_id: str,
        data_packs: list,
        reports_dir: str,
    ) -> dict:
        """执行知识盘点，返回 inventory 结果 dict。

        Args:
            evaluation_id: 评测 ID
            data_packs: list[DataPack]，从中提取 benchmark_item 漏洞类型
                       和 Trace 中实际访问过的知识内容
            reports_dir: 报告输出目录

        Returns:
            inventory 结果 dict（见模块 docstring）
        """
        log("INVENTORY", f"开始知识盘点 evaluation_id={evaluation_id}")

        # 1. 从 data_packs 提取基线漏洞类型 + Trace 中访问过的知识
        baseline_vuln_types = self._extract_baseline_vuln_types(data_packs)
        accessed_knowledge_items = self._extract_accessed_knowledge(data_packs)
        project_id = self._extract_project_id(data_packs)

        log(
            "INVENTORY",
            f"基线漏洞类型 {len(baseline_vuln_types)} 种，"
            f"Trace 中访问知识 {len(accessed_knowledge_items)} 条，"
            f"project_id={project_id}",
        )

        # 2. 调知识库 API 拉全量清单
        kb_coverage = self._fetch_knowledge_base_coverage(project_id)

        # 3. 读记忆 NFS 目录
        memory_coverage = self._fetch_memory_coverage()

        # 4. 覆盖度判定：基线漏洞类型 vs 知识库/记忆
        coverage = self._assess_coverage(
            baseline_vuln_types, kb_coverage, memory_coverage
        )

        # 5. 质量标注
        quality = self._assess_quality(
            kb_coverage.get("knowledge_items", []),
            accessed_knowledge_items,
        )

        # 6. 组装结果
        result = {
            "evaluation_id": evaluation_id,
            "coverage": coverage,
            "quality": quality,
            "memory_coverage": {
                "total_dirs": memory_coverage.get("total_dirs", 0),
                "covered_dirs": memory_coverage.get("covered_dirs", 0),
                "dirs": memory_coverage.get("dirs", []),
            },
            "kb_stats": kb_coverage.get("stats", {}),
        }

        # 7. 写入文件
        out_path = os.path.join(reports_dir, f"{evaluation_id}_inventory.json")
        os.makedirs(reports_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        log("INVENTORY", f"盘点结果写入 {out_path}")

        return result

    # ── 从 data_packs 提取信息 ──────────────────────────

    def _extract_baseline_vuln_types(self, data_packs: list) -> list[str]:
        """从 data_packs 的 benchmark_item 中提取被测漏洞类型列表。"""
        vuln_types: set[str] = set()
        for dp in data_packs:
            bench = getattr(dp, "benchmark_item", None)
            if bench is None:
                continue
            # benchmark_item 可能是 dataclass 或 dict
            vt = None
            if hasattr(bench, "vulnerability_type"):
                vt = bench.vulnerability_type
            elif hasattr(bench, "vuln_type"):
                vt = bench.vuln_type
            elif isinstance(bench, dict):
                vt = bench.get("vulnerability_type") or bench.get("vuln_type")
            if vt:
                vuln_types.add(str(vt))
        return sorted(vuln_types)

    def _extract_project_id(self, data_packs: list) -> str | None:
        """从 data_packs 中提取 project_id（用于调知识库 API）。"""
        for dp in data_packs:
            # DataPack 有 task_id，从 task_id 或 session_meta 推导 project_id
            session_meta = getattr(dp, "session_meta", None)
            if isinstance(session_meta, dict):
                pid = session_meta.get("project_id")
                if pid:
                    return str(pid)
            # 从 task_id 间接获取不了 project_id，需要外部传入
            # 但 data_pack 可能有额外属性
            pid = getattr(dp, "project_id", None)
            if pid:
                return str(pid)
        # 回退：从环境变量
        return os.environ.get("KNOWLEDGE_API_PROJECT_ID")

    def _extract_accessed_knowledge(self, data_packs: list) -> list[dict]:
        """从 data_packs 的 KnowledgeInteractionFact 中提取实际访问过的知识条目。

        返回 list[dict]，每条含：
        - knowledge_id: 知识标识（文件路径或查询关键词）
        - query_content: 查询内容
        - returned_content: 返回内容摘要
        - task_run_id: 来源 task_run
        - vuln_type: 关联的漏洞类型（如有）
        """
        accessed: list[dict] = []
        for dp in data_packs:
            kf = getattr(dp, "knowledge_fact", None)
            if kf is None:
                continue

            task_run_id = getattr(dp, "task_run_id", "")
            bench = getattr(dp, "benchmark_item", None)
            vuln_type = None
            if bench:
                if hasattr(bench, "vulnerability_type"):
                    vuln_type = bench.vulnerability_type
                elif hasattr(bench, "vuln_type"):
                    vuln_type = bench.vuln_type
                elif isinstance(bench, dict):
                    vuln_type = bench.get("vulnerability_type") or bench.get("vuln_type")

            # 知识库交互
            interactions = getattr(kf, "interactions", None) or []
            for inter in interactions:
                if not isinstance(inter, dict):
                    continue
                accessed.append({
                    "knowledge_id": inter.get("command", inter.get("tool", "")),
                    "query_content": str(inter.get("command", "")),
                    "returned_content": str(inter.get("output_preview", ""))[:2000],
                    "task_run_id": task_run_id,
                    "vuln_type": str(vuln_type) if vuln_type else None,
                    "source_system": "knowledge_base",
                })

            # 记忆交互
            memory_interactions = getattr(kf, "memory_interactions", None) or []
            for inter in memory_interactions:
                if not isinstance(inter, dict):
                    continue
                accessed.append({
                    "knowledge_id": inter.get("command", inter.get("tool", "")),
                    "query_content": str(inter.get("command", "")),
                    "returned_content": str(inter.get("output_preview", ""))[:2000],
                    "task_run_id": task_run_id,
                    "vuln_type": str(vuln_type) if vuln_type else None,
                    "source_system": "memory",
                })

        return accessed

    # ── 知识库 API 调用 ──────────────────────────────────

    def _fetch_knowledge_base_coverage(self, project_id: str | None) -> dict:
        """调知识库 API 拉全量清单。

        端点（ClusterIP 10.108.227.89:8000，k8s 内通过 svc 访问）：
        1. GET /api/athena/projects/{pid}/knowledge/tree — 全量文件清单
        2. GET /api/athena/projects/{pid}/knowledge/index?dir={dir} — 目录下知识条目
        3. GET /api/athena/projects/{pid}/knowledge/file?path={path} — 知识内容（含 frontmatter）
        4. GET /api/athena/projects/{pid} — 项目信息（counts: A/B/C/raw, knowledge_enabled）
        5. GET /api/athena/management/analytics/projects/{pid} — 效果统计

        从端点 1+2 获取全量知识清单，按漏洞类型分类。
        """
        if not project_id:
            log("INVENTORY", "无 project_id，跳过知识库 API 调用")
            return {"knowledge_items": [], "stats": {}, "error": "no_project_id"}

        base_url = f"http://{KNOWLEDGE_API_HOST}:{KNOWLEDGE_API_PORT}"
        knowledge_items: list[dict] = []
        stats: dict = {}

        # 端点 1: 全量文件清单
        tree_url = f"{base_url}/api/athena/projects/{project_id}/knowledge/tree"
        tree_items = self._http_get_json(tree_url)
        if tree_items and "items" in tree_items:
            for item in tree_items["items"]:
                knowledge_items.append({
                    "path": item.get("path", ""),
                    "size": item.get("size", 0),
                    "modified_at": item.get("modified_at"),
                    "source": "knowledge_tree",
                })
            log("INVENTORY", f"知识库 tree 端点返回 {len(knowledge_items)} 条")

        # 端点 2: 根目录结构（directories + documents）
        index_url = f"{base_url}/api/athena/projects/{project_id}/knowledge/index"
        index_data = self._http_get_json(index_url)
        directories = []
        if index_data and "directories" in index_data:
            directories = index_data["directories"]
            # 对每个子目录再查 index 获取文档列表
            for d in directories:
                dpath = d.get("path", "")
                if not dpath:
                    continue
                sub_url = (
                    f"{base_url}/api/athena/projects/{project_id}"
                    f"/knowledge/index?dir={dpath}"
                )
                sub_data = self._http_get_json(sub_url)
                if sub_data and "documents" in sub_data:
                    for doc in sub_data["documents"]:
                        doc_path = doc.get("path", "")
                        knowledge_items.append({
                            "path": doc_path,
                            "dir": dpath,
                            "name": doc.get("name", ""),
                            "source": "knowledge_index",
                        })

        # 端点 3: 对关键文档获取 frontmatter（用于质量判定）
        # 只获取有 path 的文档，限制数量避免过多 API 调用
        seen_paths: set[str] = set()
        enriched_items: list[dict] = []
        for item in knowledge_items:
            path = item.get("path", "")
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            file_url = (
                f"{base_url}/api/athena/projects/{project_id}"
                f"/knowledge/file?path={path}"
            )
            file_data = self._http_get_json(file_url)
            if file_data and "content" in file_data:
                frontmatter = self._parse_frontmatter(file_data["content"])
                enriched = dict(item)
                enriched["frontmatter"] = frontmatter
                enriched["content_preview"] = file_data["content"][:500]
                enriched_items.append(enriched)
            else:
                enriched_items.append(item)

        # 端点 4: 项目信息
        proj_url = f"{base_url}/api/athena/projects/{project_id}"
        proj_info = self._http_get_json(proj_url)
        if proj_info:
            stats["project_info"] = {
                "knowledge_enabled": proj_info.get("knowledge_enabled"),
                "counts": proj_info.get("counts", {}),
                "layer": proj_info.get("layer"),
            }

        # 端点 5: 效果统计
        eff_url = (
            f"{base_url}/api/athena/management/analytics/projects/{project_id}"
        )
        eff_data = self._http_get_json(eff_url)
        if eff_data and "effectiveness" in eff_data:
            stats["effectiveness"] = eff_data["effectiveness"]

        log(
            "INVENTORY",
            f"知识库 API 共获取 {len(enriched_items)} 条知识条目，"
            f"含 frontmatter {sum(1 for i in enriched_items if 'frontmatter' in i)} 条",
        )

        return {
            "knowledge_items": enriched_items,
            "stats": stats,
        }

    def _http_get_json(self, url: str) -> dict | None:
        """HTTP GET 返回 JSON。失败时 log 警告并返回 None。"""
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            log("INVENTORY", f"HTTP {e.code} from {url}: {str(e)[:200]}")
            return None
        except (URLError, TimeoutError, OSError) as e:
            log("INVENTORY", f"HTTP 请求失败 {url}: {str(e)[:200]}")
            return None

    @staticmethod
    def _parse_frontmatter(content: str) -> dict:
        """解析 Markdown frontmatter（--- 包裹的 YAML）。

        frontmatter 格式：
        ---
        name: xxx
        topic: [SQL注入, XSS]
        验证状态: 已验证
        层级: L2
        ---

        返回 dict。不依赖 PyYAML，用简单 key: value 解析。
        """
        fm: dict[str, Any] = {}
        # 匹配 --- 包裹的 frontmatter
        m = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if not m:
            return fm
        body = m.group(1)
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # key: value
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                # 去掉引号
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                elif val.startswith("'") and val.endswith("'"):
                    val = val[1:-1]
                # 解析 YAML 数组 [a, b, c]
                if val.startswith("[") and val.endswith("]"):
                    inner = val[1:-1].strip()
                    if inner:
                        items = [
                            x.strip().strip("\"'")
                            for x in inner.split(",")
                            if x.strip()
                        ]
                        fm[key] = items
                    else:
                        fm[key] = []
                else:
                    fm[key] = val
        return fm

    # ── 记忆 NFS 目录 ──────────────────────────────────

    def _fetch_memory_coverage(self) -> dict:
        """读记忆 NFS 目录 /app/memory/ 下的 init.json，获取记忆覆盖度。

        init.json 包含：
        - source: 来源标识
        - entries: 知识条目列表
        - 每个 entry 含 vulnerability_type 等字段

        记忆目录结构：
        /app/memory/{task_id}/init.json
        或 /app/memory/{dir}/init.json
        """
        if not os.path.isdir(MEMORY_ROOT):
            log("INVENTORY", f"记忆目录不存在: {MEMORY_ROOT}")
            return {"total_dirs": 0, "covered_dirs": 0, "dirs": []}

        # 遍历 MEMORY_ROOT 下的子目录，查找 init.json
        init_files = _glob.glob(
            os.path.join(MEMORY_ROOT, "*", "init.json")
        )
        # 也搜索更深一级
        init_files.extend(
            _glob.glob(os.path.join(MEMORY_ROOT, "*", "*", "init.json"))
        )

        dirs_info: list[dict] = []
        covered_dirs = 0

        for init_path in init_files:
            dir_name = os.path.basename(os.path.dirname(init_path))
            try:
                with open(init_path, "r", encoding="utf-8") as f:
                    init_data = json.load(f)
            except Exception as e:
                log("INVENTORY", f"读取 init.json 失败 {init_path}: {str(e)[:100]}")
                continue

            source = init_data.get("source", "")
            entries = init_data.get("entries", [])

            # 统计条目数和覆盖的漏洞类型
            entry_count = len(entries)
            vuln_types_in_dir: set[str] = set()
            for entry in entries:
                if isinstance(entry, dict):
                    vt = (
                        entry.get("vulnerability_type")
                        or entry.get("vuln_type")
                        or entry.get("topic")
                    )
                    if vt:
                        if isinstance(vt, list):
                            for v in vt:
                                vuln_types_in_dir.add(str(v))
                        else:
                            vuln_types_in_dir.add(str(vt))

            dirs_info.append({
                "dir": dir_name,
                "source": source,
                "entry_count": entry_count,
                "vuln_types": sorted(vuln_types_in_dir),
                "init_path": init_path,
            })
            if entry_count > 0:
                covered_dirs += 1

        log(
            "INVENTORY",
            f"记忆目录扫描完成: {len(init_files)} 个 init.json, "
            f"{covered_dirs} 个含知识条目",
        )

        return {
            "total_dirs": len(init_files),
            "covered_dirs": covered_dirs,
            "dirs": dirs_info,
        }

    # ── 覆盖度判定 ──────────────────────────────────────

    def _assess_coverage(
        self,
        baseline_vuln_types: list[str],
        kb_coverage: dict,
        memory_coverage: dict,
    ) -> dict:
        """覆盖度判定：基线漏洞类型 vs 知识库/记忆。

        逻辑：
        1. 对每个基线漏洞类型，在知识库知识条目中搜索匹配（topic + 文件名关键词）
        2. 在记忆目录中搜索匹配
        3. 有匹配 → covered，无匹配 → uncovered
        """
        kb_items = kb_coverage.get("knowledge_items", [])
        mem_dirs = memory_coverage.get("dirs", [])

        # 预处理知识库条目：提取可搜索的文本
        kb_searchable: list[dict] = []
        for item in kb_items:
            path = item.get("path", "").lower()
            name = item.get("name", "").lower()
            fm = item.get("frontmatter", {})
            topics = fm.get("topic", [])
            if isinstance(topics, str):
                topics = [topics]
            topics_lower = [str(t).lower() for t in topics]
            kb_searchable.append({
                "path": item.get("path", ""),
                "text": " ".join([path, name] + topics_lower),
                "topics": topics,
            })

        # 预处理记忆条目
        mem_searchable: list[dict] = []
        for d in mem_dirs:
            for vt in d.get("vuln_types", []):
                mem_searchable.append({
                    "dir": d.get("dir", ""),
                    "vuln_type": vt,
                    "text": str(vt).lower(),
                })

        covered: list[str] = []
        uncovered: list[str] = []

        for vt in baseline_vuln_types:
            vt_lower = vt.lower()
            # 漏洞类型关键词
            keywords = _VULN_TYPE_KEYWORDS.get(vt, [vt_lower])

            # 搜索知识库
            kb_matches = []
            for ks in kb_searchable:
                if any(kw in ks["text"] for kw in keywords):
                    kb_matches.append(ks["path"])
                elif vt_lower in ks["text"]:
                    kb_matches.append(ks["path"])

            # 搜索记忆
            mem_matches = []
            for ms in mem_searchable:
                if any(kw in ms["text"] for kw in keywords):
                    mem_matches.append(ms["dir"])
                elif vt_lower in ms["text"]:
                    mem_matches.append(ms["dir"])

            if kb_matches or mem_matches:
                covered.append(vt)
            else:
                uncovered.append(vt)

        total = len(baseline_vuln_types)
        covered_count = len(covered)
        coverage_rate = covered_count / total if total > 0 else 0.0

        return {
            "total_vuln_types": total,
            "covered_vuln_types": covered_count,
            "uncovered_vuln_types": uncovered,
            "coverage_rate": round(coverage_rate, 4),
            "covered_details": {
                vt: {
                    "kb_paths": list(set(
                        ks["path"]
                        for ks in kb_searchable
                        for kw in _VULN_TYPE_KEYWORDS.get(vt, [vt.lower()])
                        if kw in ks["text"]
                    )),
                    "mem_dirs": list(set(
                        ms["dir"]
                        for ms in mem_searchable
                        for kw in _VULN_TYPE_KEYWORDS.get(vt, [vt.lower()])
                        if kw in ms["text"]
                    )),
                }
                for vt in covered
            },
        }

    # ── 质量标注 ────────────────────────────────────────

    def _assess_quality(
        self,
        knowledge_items: list[dict],
        accessed_items: list[dict],
    ) -> list[dict]:
        """质量标注。

        对 Trace 中访问过的知识，用 LLM 判定知识内容正确性。
        对未访问的知识，从 frontmatter 的验证状态字段标注。

        Args:
            knowledge_items: 知识库全量知识条目（含 frontmatter）
            accessed_items: Trace 中实际访问过的知识条目

        Returns:
            list[dict]，每条含 knowledge_id, vuln_type, quality_label,
            accessed_in_eval, quality_evidence
        """
        quality_results: list[dict] = []

        # 1. 对未访问的知识，从 frontmatter 的验证状态字段标注
        accessed_ids = {
            item.get("knowledge_id", "") for item in accessed_items
        }

        for item in knowledge_items:
            path = item.get("path", "")
            fm = item.get("frontmatter", {})
            topics = fm.get("topic", [])
            if isinstance(topics, str):
                topics = [topics]
            vuln_type = topics[0] if topics else ""

            # 从 frontmatter 判定质量
            validation_status = str(fm.get("验证状态", fm.get("validation_status", "")))
            if validation_status in ("已验证", "verified", "validated"):
                label = "correct"
                evidence = f"frontmatter 验证状态={validation_status}"
            elif validation_status in ("未验证", "unverified"):
                label = "incomplete"
                evidence = f"frontmatter 验证状态={validation_status}，未经基线验证"
            elif validation_status in ("过时", "outdated", "deprecated"):
                label = "outdated"
                evidence = f"frontmatter 验证状态={validation_status}"
            else:
                # 无验证状态字段，不标注（不输出）
                continue

            quality_results.append({
                "knowledge_id": path,
                "vuln_type": vuln_type,
                "quality_label": label,
                "accessed_in_eval": path in accessed_ids,
                "quality_evidence": evidence,
            })

        # 2. 对 Trace 中访问过的知识，用 LLM 判定正确性
        if accessed_items and self._llm_available():
            llm_results = self._llm_quality_assessment(accessed_items)
            quality_results.extend(llm_results)
        elif accessed_items and not self._llm_available():
            # LLM 不可用时，对访问过的知识标注为 incomplete（无法判定）
            for acc in accessed_items:
                quality_results.append({
                    "knowledge_id": acc.get("knowledge_id", ""),
                    "vuln_type": acc.get("vuln_type", ""),
                    "quality_label": "incomplete",
                    "accessed_in_eval": True,
                    "quality_evidence": "LLM 不可用，无法判定知识正确性",
                })

        return quality_results

    def _llm_available(self) -> bool:
        """检查 LLM 是否可用。"""
        if self.llm is not None:
            return True
        try:
            return llm_is_enabled()
        except Exception:
            return False

    def _llm_quality_assessment(self, accessed_items: list[dict]) -> list[dict]:
        """用 LLM 对 Trace 中访问过的知识判定正确性。

        使用 Prompt 5（L7 知识正确性判定），对每条访问过的知识：
        - 输入：知识返回内容 + 基线漏洞信息
        - 输出：knowledge_correct, direction_consistent, confidence, reason
        - 质量标签映射：
          - knowledge_correct=true → correct
          - knowledge_correct=false → outdated（知识过时或不适用）
          - confidence < 阈值 → incomplete（无法确认）
        """
        results: list[dict] = []

        system_prompt = (
            "你是知识内容质量判定员。判断知识返回内容是否正确、是否过时或不适用于当前漏洞。\n\n"
            "# 判定维度\n\n"
            "## 知识正确性（knowledge_correct）\n"
            "对比知识返回内容与基线漏洞信息，判断知识是否正确：\n"
            "- correct=true：知识描述的漏洞模式、sink 函数等与基线漏洞信息一致\n"
            "- correct=false：知识内容存在以下问题之一：\n"
            "  - 知识描述的漏洞模式与基线漏洞类型不符\n"
            "  - 知识指向的 sink 函数与基线 sink 不匹配\n"
            "  - 知识内容过时（如描述的函数已在新版本中修复）\n"
            "  - 知识内容不适用于当前项目的技术栈或代码结构\n\n"
            "## 置信度（confidence）\n"
            "0.0-1.0：<0.6 表示信息不足无法可靠判断\n\n"
            "只返回 JSON：\n"
            '{"knowledge_correct": true/false, "confidence": 0.0-1.0, '
            '"reason": "500字以内中文，结论先行，说明判断依据"}'
        )

        for item in accessed_items:
            knowledge_content = item.get("returned_content", "")
            vuln_type = item.get("vuln_type", "")
            query_content = item.get("query_content", "")
            knowledge_id = item.get("knowledge_id", "")

            if not knowledge_content or not vuln_type:
                results.append({
                    "knowledge_id": knowledge_id,
                    "vuln_type": vuln_type,
                    "quality_label": "incomplete",
                    "accessed_in_eval": True,
                    "quality_evidence": "知识返回内容或漏洞类型为空，无法判定",
                })
                continue

            user_content = (
                f"知识返回内容:\n{knowledge_content}\n\n"
                f"查询内容: {query_content}\n\n"
                f"基线漏洞信息:\n"
                f"漏洞类型: {vuln_type}\n\n"
                f"判断知识是否正确、是否过时或不适用于当前漏洞，给出置信度。"
            )

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ]

            try:
                result = self._call_llm_json(messages, reasoning_effort="high")
            except Exception as e:
                log(
                    "INVENTORY",
                    f"LLM 质量判定失败 knowledge_id={knowledge_id}: "
                    f"{str(e)[:200]}",
                )
                results.append({
                    "knowledge_id": knowledge_id,
                    "vuln_type": vuln_type,
                    "quality_label": "incomplete",
                    "accessed_in_eval": True,
                    "quality_evidence": f"LLM 调用失败: {str(e)[:200]}",
                })
                continue

            knowledge_correct = result.get("knowledge_correct")
            confidence = result.get("confidence", 0.0)
            reason = result.get("reason", "")

            # 映射质量标签
            if confidence < _L7_CONFIDENCE_THRESHOLD:
                label = "incomplete"
                evidence = f"LLM 置信度={confidence} < 阈值{_L7_CONFIDENCE_THRESHOLD}，无法确认。{reason}"
            elif knowledge_correct is True:
                label = "correct"
                evidence = f"LLM 判定正确（confidence={confidence}）。{reason}"
            elif knowledge_correct is False:
                label = "outdated"
                evidence = f"LLM 判定过时/不适用（confidence={confidence}）。{reason}"
            else:
                label = "incomplete"
                evidence = f"LLM 无法判定 knowledge_correct={knowledge_correct}。{reason}"

            results.append({
                "knowledge_id": knowledge_id,
                "vuln_type": vuln_type,
                "quality_label": label,
                "accessed_in_eval": True,
                "quality_evidence": evidence[:1000],
            })

        return results

    def _call_llm_json(self, messages: list[dict], **kwargs) -> dict:
        """调用 LLM 返回 JSON。

        优先用注入的 llm_client，回退到 v2 infra llm 模块。
        """
        if self.llm is not None:
            # 注入的客户端可能有不同接口
            if hasattr(self.llm, "chat_json"):
                return self.llm.chat_json(messages, **kwargs)
            elif hasattr(self.llm, "chat"):
                raw = self.llm.chat(messages, **kwargs)
                return json.loads(raw) if isinstance(raw, str) else raw
            else:
                raise RuntimeError("llm_client 没有 chat_json/chat 方法")
        else:
            return chat_json(messages, **kwargs)
