"""Parser 共享工具函数。

各 trace parser 的 extract_findings 方法共用的通用逻辑。
平台特定逻辑不应放在此处，应留在各 parser 内部。
"""
from __future__ import annotations
import json


def _extract_json_objects_from_text(text: str) -> list[dict]:
    """Extract JSON objects from text containing ```json blocks.

    Uses json.JSONDecoder().raw_decode() to handle JSON values that
    contain backticks (e.g., `` `memcpy_s` `` in string values), which
    would break regex-based extraction that looks for closing ``` markers.
    """
    decoder = json.JSONDecoder()
    results: list[dict] = []
    search_start = 0
    marker = '```json'
    while True:
        idx = text.find(marker, search_start)
        if idx == -1:
            break
        brace_idx = text.find('{', idx + len(marker))
        if brace_idx == -1:
            break
        try:
            obj, end_pos = decoder.raw_decode(text, brace_idx)
            if isinstance(obj, dict):
                results.append(obj)
            search_start = end_pos
        except json.JSONDecodeError:
            search_start = idx + len(marker)
    return results


def _try_repair_backslash_quote(text: str) -> dict | None:
    """修复 JSON 转义错误 + 花括号补全。

    Step 1: 修复 \\" 转义错误（escaped backslash + unescaped quote → escaped quote）。
    Step 2: 花括号补全（在 repaired 文本上统计深度并补全缺失的 }）。
    """
    decoder = json.JSONDecoder()
    repaired = text
    # Step 1: 修复 \\" 转义错误
    for _ in range(50):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            if (e.pos >= 3
                    and repaired[e.pos - 1] == '"'
                    and repaired[e.pos - 3:e.pos - 1] == '\\\\'):
                repaired = repaired[:e.pos - 3] + '\\' + repaired[e.pos - 1:]
            else:
                break
    # Step 2: 花括号补全
    depth = 0
    in_str = False
    esc = False
    for ch in repaired:
        if esc:
            esc = False
            continue
        if ch == '\\':
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
    if depth > 0:
        fixed = repaired + '}' * depth
        try:
            obj = json.loads(fixed)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
    return None


def parse_json_lenient(text: str) -> dict | None:
    """尽力解析单个 JSON 对象，四层策略递进。

    1. json.loads（严格解析）
    2. raw_decode（从首个 { 解析，容忍尾部额外内容）
    3. 花括号补全（补全缺失的闭合 }，修复被截断的 JSON）
    4. \\" 转义修复（修复 escaped backslash + unescaped quote）

    Agent 输出的 JSON 可能：尾部带额外文字、被 max_tokens 截断、缺少闭合括号、转义错误。
    """
    if not text:
        return None
    text = text.strip()
    # 策略 1: 严格解析
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    # 策略 2: raw_decode（容忍尾部内容）
    decoder = json.JSONDecoder()
    start = text.find('{')
    if start >= 0:
        try:
            obj, _ = decoder.raw_decode(text, start)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    # 策略 3: 花括号补全
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if esc:
            esc = False
            continue
        if ch == '\\':
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
    if depth > 0:
        fixed = text + '}' * depth
        try:
            obj = json.loads(fixed)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
    # 策略 4: \\" 转义修复
    return _try_repair_backslash_quote(text)


def extract_json_payloads(text: str, keywords: list[str] | None = None) -> list[dict]:
    """从文本中提取 JSON 对象，多层策略递进。

    策略：
    1. ```json 代码块（raw_decode + 花括号补全兜底）
    2. 关键词+花括号匹配（搜索 keywords，找到外层 JSON 对象）
    3. 裸 raw_decode（从每个顶层 { 尝试解析）

    Args:
        text: 包含 JSON 的文本
        keywords: 策略 2 的搜索关键词列表（如 ['"verdict"', '"findings"']），
                  None 时跳过策略 2
    """
    if not text:
        return []

    results: list[dict] = []
    seen: set[str] = set()

    def _add(obj: dict) -> None:
        sig = json.dumps(obj, sort_keys=True, ensure_ascii=False)
        if sig not in seen:
            seen.add(sig)
            results.append(obj)

    # 策略 1: ```json 代码块
    for obj in _extract_json_objects_from_text(text):
        _add(obj)
    # 策略 1b: ```json 块用花括号补全兜底
    marker = '```json'
    search_start = 0
    while True:
        idx = text.find(marker, search_start)
        if idx == -1:
            break
        brace_idx = text.find('{', idx + len(marker))
        if brace_idx == -1:
            search_start = idx + len(marker)
            continue
        close_idx = text.find('```', brace_idx)
        if close_idx < 0:
            close_idx = len(text)
        json_str = text[brace_idx:close_idx]
        obj = parse_json_lenient(json_str)
        if obj:
            _add(obj)
        search_start = close_idx + 3

    if results:
        return results

    # 策略 2: 关键词+花括号匹配
    if keywords:
        # 预计算所有顶层 { 的位置（depth=0）
        top_level_opens: list[int] = []
        depth = 0
        in_str = False
        esc = False
        for j, ch in enumerate(text):
            if esc:
                esc = False
                continue
            if ch == '\\':
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == '{':
                if depth == 0:
                    top_level_opens.append(j)
                depth += 1
            elif ch == '}':
                depth -= 1

        for keyword in keywords:
            kw_search = 0
            while True:
                idx = text.find(keyword, kw_search)
                if idx < 0:
                    break
                # 找到关键词之前的最后一个顶层 {
                brace_start = -1
                for tb in top_level_opens:
                    if tb <= idx:
                        brace_start = tb
                    else:
                        break
                if brace_start < 0:
                    kw_search = idx + 1
                    continue
                # 花括号匹配找到外层 JSON
                d = 0
                in_s = False
                esc2 = False
                end_idx = -1
                for j in range(brace_start, len(text)):
                    ch = text[j]
                    if esc2:
                        esc2 = False
                        continue
                    if ch == '\\':
                        esc2 = True
                        continue
                    if ch == '"':
                        in_s = not in_s
                        continue
                    if in_s:
                        continue
                    if ch == '{':
                        d += 1
                    elif ch == '}':
                        d -= 1
                        if d == 0:
                            end_idx = j + 1
                            break
                if end_idx > 0:
                    obj = parse_json_lenient(text[brace_start:end_idx])
                    if obj:
                        _add(obj)
                    kw_search = max(end_idx, idx + len(keyword))
                else:
                    close_idx = text.find('```', brace_start)
                    if close_idx < 0:
                        close_idx = len(text)
                    json_str = text[brace_start:close_idx]
                    obj = parse_json_lenient(json_str)
                    if obj:
                        _add(obj)
                    kw_search = max(close_idx + 3, idx + len(keyword))

    if results:
        return results

    # 策略 3: 裸 raw_decode（从每个顶层 { 尝试）
    decoder = json.JSONDecoder()
    for i in top_level_opens if keywords else range(len(text)):
        ch = text[i] if keywords else text[i]
        if ch != '{':
            continue
        try:
            obj, _ = decoder.raw_decode(text, i)
            if isinstance(obj, dict):
                _add(obj)
        except json.JSONDecodeError:
            pass

    return results


def attach_event_indices(findings: dict[str, dict], events: list) -> None:
    """为每个 finding 关联提交事件索引（用于后续提取挖掘过程上下文）。

    在 events 中搜索包含该 finding_id 的事件，记录其索引。
    各 parser 的 extract_findings 末尾调用此函数。
    """
    for fid, f in findings.items():
        if "_event_idx" not in f:
            for i, e in enumerate(events):
                combined = str(e.input_json or "") + str(e.output_json or "")
                if fid and fid != "?" and fid in combined:
                    f["_event_idx"] = i
                    break
            else:
                f["_event_idx"] = 0
