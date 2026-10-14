"""本地 token 计算器 — 使用 DeepSeek V4 tokenizer 精确计算 token 数。

用于 LLM 匹配前动态分批，确保 prompt 不超 token 上限。

tokenizer 文件以分卷压缩形式存储在 deepseek_v4_tokenizer/ 目录下
（tokenizer_files.zip.part00 ~ part19），首次使用时自动拼接解压到内存。

使用 HuggingFace `tokenizers` 库（轻量 Rust 库，不依赖 transformers/torch）。
"""
from __future__ import annotations

import io
import json
import os
import zipfile
from functools import lru_cache

_TOKENIZER_DIR = os.path.join(os.path.dirname(__file__), "deepseek_v4_tokenizer")
_tokenizer = None


def _reconstruct_tokenizer_files() -> dict[str, bytes]:
    """从分卷压缩文件中重建 tokenizer 文件。

    读取 tokenizer_files.zip.part00 ~ part19，拼接后解压，
    返回 {filename: content_bytes} 字典。
    """
    parts = sorted(
        f for f in os.listdir(_TOKENIZER_DIR)
        if f.startswith("tokenizer_files.zip.part")
    )
    if not parts:
        raise FileNotFoundError(
            f"未找到 tokenizer 分卷文件，请检查 {_TOKENIZER_DIR} 目录"
        )

    # 拼接所有分卷
    buf = io.BytesIO()
    for part in parts:
        with open(os.path.join(_TOKENIZER_DIR, part), "rb") as f:
            buf.write(f.read())
    buf.seek(0)

    # 解压
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(buf, "r") as zf:
        for name in zf.namelist():
            files[name] = zf.read(name)
    return files


@lru_cache(maxsize=1)
def _get_tokenizer():
    """延迟加载 tokenizer（首次调用时加载，后续复用）。

    使用 tokenizers.Tokenizer.from_file() 加载标准 tokenizer.json，
    不依赖 transformers/torch。
    """
    global _tokenizer
    if _tokenizer is None:
        from tokenizers import Tokenizer

        files = _reconstruct_tokenizer_files()
        tok_json = files.get("tokenizer.json")
        if not tok_json:
            raise FileNotFoundError("tokenizer.json not found in split volumes")
        _tokenizer = Tokenizer.from_buffer(tok_json)
    return _tokenizer


def count_tokens(text: str) -> int:
    """计算文本的 token 数。"""
    if not text:
        return 0
    tok = _get_tokenizer()
    return len(tok.encode(text).ids)


def count_messages_tokens(messages: list[dict]) -> int:
    """计算 LLM messages（system + user）的 token 数。

    messages: [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
    """
    # 拼接所有 message 内容，用分隔符区分
    parts = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        parts.append(f"<|{role}|>{content}")
    full_text = "".join(parts) + "<|assistant|>"
    return count_tokens(full_text)


def fit_batch_by_token(items: list[str], max_tokens: int,
                       reserve_tokens: int = 4096) -> list[list[int]]:
    """按 token 上限将文本列表分批。

    Args:
        items: 文本列表
        max_tokens: 模型最大上下文 token 数
        reserve_tokens: 预留给 system prompt + 输出 + 格式的 token 数

    Returns:
        [[idx, idx, ...], [idx, ...], ...] 每批的 item 索引列表
    """
    budget = max_tokens - reserve_tokens
    if budget <= 0:
        # 无法分批，每批 1 条
        return [[i] for i in range(len(items))]

    batches: list[list[int]] = []
    current: list[int] = []
    current_tokens = 0

    for i, text in enumerate(items):
        t = count_tokens(text)
        if current and current_tokens + t > budget:
            batches.append(current)
            current = []
            current_tokens = 0
        current.append(i)
        current_tokens += t

    if current:
        batches.append(current)

    return batches
