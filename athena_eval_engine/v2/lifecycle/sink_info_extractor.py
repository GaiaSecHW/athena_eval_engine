"""Sink 信息提取器 — 用 LLM 从基线 case 描述中提取结构化 sink 点。

基线 case 的 source_file 字段只有文件路径，source_function/source_line
通常为空（locator 只有文件路径）。但 description（原始漏洞报告）中
包含完整的 sink 点信息：文件路径、函数名、行号。

本模块用 LLM 从 description 中提取结构化 sink 信息：
- sink 文件路径列表（可能有多个文件）
- sink 函数名列表（方法全限定名或简单名）
- sink 行号列表（行号或行号区间）

提取后的结构化数据交给 SinkSearchScanner 做精确匹配：
不再只按文件 basename 匹配，而是检查 trace event 中是否出现了
sink 函数名（agent 读到了 sink 点的函数，而不只是读了文件的其他部分）。

行号作为辅助验证——trace event 中可能不直接出现行号，
但如果 event 的 output 中有 sink 函数附近的内容，可间接确认。
"""
from __future__ import annotations

from ..infra import llm as llm_mod
from ...infrastructure.log_util import log

_PROMPT_SYSTEM = """你是漏洞 sink 点提取器。给你一个漏洞的完整描述，请从中提取出 sink 点的结构化信息。

sink 点是漏洞的最终触发位置——漏洞被利用时执行的代码位置。
通常在漏洞描述的"调用链"、"数据流"、"证据"等部分中。

需要提取：
1. sink_files: sink 点涉及的源文件路径列表（Java/Python/C 等源文件）
   - 只提取漏洞触发链中的文件，不要提取测试文件或配置文件
   - 如果描述中有完整路径，提取完整路径；如果只有文件名，提取文件名
2. sink_functions: sink 点的函数/方法名列表
   - 方法名可能写为 ClassName.methodName() 或 methodName() 或 ClassName#methodName
   - 提取完整的方法引用（含类名前缀优先）
   - 只提取 sink 点的函数，不要提取入口函数或调用链上游的函数
3. sink_lines: sink 点的行号列表
   - 格式为行号数字（如 1022）或行号区间字符串（如 "1022-1042"）
   - 只提取 sink 点的行号，不要提取调用链其他位置的行号

注意：
- 漏洞描述可能很长，包含大量上下文。只提取 sink 点信息，不提取入口点信息
- sink 点是漏洞链的终点——数据最终到达并造成危害的代码位置
- 如果描述中没有明确的 sink 信息，返回空列表

只返回 JSON：
{
  "sink_files": ["file1.java", "file2.py"],
  "sink_functions": ["ClassName.methodName", "otherMethod"],
  "sink_lines": ["1022", "1040-1050"],
  "sink_description": "简要描述 sink 点是什么",
  "confidence": 0.0-1.0
}
"""


def _build_user_content(case: dict) -> str:
    """构建 LLM 输入：漏洞标题 + 描述 + 已知 source_file。"""
    parts: list[str] = []

    title = case.get("vuln_title") or case.get("title") or ""
    if title:
        parts.append(f"漏洞标题：{title}")

    description = case.get("description") or ""
    if description:
        parts.append(f"漏洞描述：\n{description}")

    source_file = case.get("source_file") or ""
    if source_file:
        parts.append(f"已知 sink 文件路径（locator）：{source_file}")

    summary = case.get("summary") or ""
    if summary:
        parts.append(f"漏洞摘要：{summary}")

    return "\n\n".join(parts)


class SinkInfoExtractor:
    """用 LLM 从基线 case 描述中提取结构化 sink 点信息。"""

    def extract(self, case: dict, cancel_cb=None) -> dict:
        """从单个 case 提取结构化 sink 信息。

        Args:
            case: 基线 case 详情，需含 description/vuln_title/source_file
            cancel_cb: 取消回调

        Returns:
            {
                "sink_files": [str],      # sink 文件路径列表
                "sink_functions": [str],  # sink 函数名列表
                "sink_lines": [str],      # sink 行号/区间列表
                "sink_description": str,   # sink 点描述
                "confidence": float,       # 提取置信度
                "source_file_raw": str,    # 原始 source_file（locator 提取的）
            }
        """
        description = case.get("description") or ""
        if not description:
            log("SINK_EXTRACT",
                f"case {case.get('case_id', '')} 无 description，跳过提取")
            return self._empty_result(case)

        user_content = _build_user_content(case)
        if not user_content.strip():
            log("SINK_EXTRACT",
                f"case {case.get('case_id', '')} 无可提取内容")
            return self._empty_result(case)

        messages = [
            {"role": "system", "content": _PROMPT_SYSTEM},
            {"role": "user", "content": user_content},
        ]

        try:
            kwargs = {"temperature": 0, "reasoning_effort": "none"}
            if cancel_cb:
                kwargs["cancel_cb"] = cancel_cb
            result = llm_mod.chat_json(messages, **kwargs)
        except Exception as e:
            log("SINK_EXTRACT",
                f"case {case.get('case_id', '')} LLM 提取失败: {e}")
            return self._empty_result(case)

        sink_files = result.get("sink_files") or []
        sink_functions = result.get("sink_functions") or []
        sink_lines = result.get("sink_lines") or []
        sink_desc = result.get("sink_description") or ""
        confidence = float(result.get("confidence") or 0)

        # 如果 LLM 没提取到 sink_files 但原始 source_file 有值，用它兜底
        source_file_raw = case.get("source_file") or ""
        if not sink_files and source_file_raw:
            sink_files = [source_file_raw]

        log("SINK_EXTRACT",
            f"case {case.get('case_id', '')}: "
            f"files={len(sink_files)}, funcs={len(sink_functions)}, "
            f"lines={len(sink_lines)}, conf={confidence:.2f}")

        return {
            "sink_files": sink_files,
            "sink_functions": sink_functions,
            "sink_lines": sink_lines,
            "sink_description": sink_desc,
            "confidence": confidence,
            "source_file_raw": source_file_raw,
        }

    def extract_batch(
        self,
        cases: dict[str, dict],
        cancel_cb=None,
    ) -> dict[str, dict]:
        """批量提取多个 case 的 sink 信息。

        Args:
            cases: {case_id: case_detail}
            cancel_cb: 取消回调

        Returns:
            {case_id: sink_info_dict}
        """
        results: dict[str, dict] = {}
        for cid, cd in cases.items():
            if cancel_cb:
                cancel_cb()
            sink_info = self.extract(cd, cancel_cb=cancel_cb)
            results[cid] = sink_info
        return results

    @staticmethod
    def _empty_result(case: dict) -> dict:
        """返回空结果。"""
        return {
            "sink_files": [case.get("source_file") or ""]
            if case.get("source_file") else [],
            "sink_functions": [],
            "sink_lines": [],
            "sink_description": "",
            "confidence": 0.0,
            "source_file_raw": case.get("source_file") or "",
        }
