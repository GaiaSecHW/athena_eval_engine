"""CVulnVerify parser 专用工具函数。

从老代码 ``workers/parse_utils.py`` 拷贝 CVulnVerify parser 用到的函数：
- ``_extract_json_objects_from_text`` — 从 ```json 代码块提取 JSON 对象
- ``parse_json_lenient`` — 尽力解析单个 JSON 对象（四层策略）
- ``_try_repair_backslash_quote`` — JSON 转义修复 + 结构补全（parse_json_lenient 策略 4）
- ``_escape_control_chars_in_strings`` — 字符串值中字面控制字符转义
- ``attach_event_indices`` — 为 finding 关联提交事件索引
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


def _escape_control_chars_in_strings(text: str) -> str:
    """将 JSON 字符串值中的字面控制字符转义。"""
    _escape_map = {
        '\n': '\\n', '\r': '\\r', '\t': '\\t',
        '\b': '\\b', '\f': '\\f',
    }
    out: list[str] = []
    in_str = False
    esc = False
    for ch in text:
        if esc:
            esc = False
            out.append(ch)
            continue
        if ch == '\\':
            esc = True
            out.append(ch)
            continue
        if ch == '"':
            in_str = not in_str
            out.append(ch)
            continue
        if in_str and ord(ch) < 0x20:
            out.append(_escape_map.get(ch, f'\\u{ord(ch):04x}'))
        else:
            out.append(ch)
    return ''.join(out)


def _try_repair_backslash_quote(text: str) -> dict | None:
    """修复 JSON 常见错误 + 结构补全。

    Step 0: 修复字符串值中的字面控制字符（原始换行符/制表符 → 转义）。
    Step 1: 修复 \\" 转义错误（escaped backslash + unescaped quote → escaped quote）。
    Step 1b: 修复无效 escape（backslash + 非 JSON 转义字符）。
    Step 2: 结构修复（在错误位置插入缺失的分隔符/闭合符）。
    Step 2b: 修复未转义引号（"Expecting ',' delimiter" 由未转义 " 导致）。
    Step 3: 花括号+方括号补全（在 repaired 文本上统计深度并补全缺失的 } 和 ]）。
    """
    _valid_escapes = set('"\\/bfnrtu')
    decoder = json.JSONDecoder()
    # Step 0: 修复字符串值中的字面控制字符
    repaired = _escape_control_chars_in_strings(text)
    # Step 1: 修复 \\" 转义错误 + Step 1b: 修复无效 \escape
    for _ in range(100):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            if (e.pos >= 3
                    and repaired[e.pos - 1] == '"'
                    and repaired[e.pos - 3:e.pos - 1] == '\\\\'):
                repaired = repaired[:e.pos - 3] + '\\' + repaired[e.pos - 1:]
                continue
            if (e.msg.startswith("Invalid \\escape")
                    and e.pos < len(repaired)
                    and repaired[e.pos] == '\\'
                    and e.pos + 1 < len(repaired)
                    and repaired[e.pos + 1] not in _valid_escapes):
                repaired = repaired[:e.pos] + '\\' + repaired[e.pos:]
                continue
            break
    # Step 2: 结构修复（在错误位置插入缺失的分隔符/闭合符）
    for _ in range(50):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            if e.msg.startswith("Expecting ',' delimiter") or e.msg.startswith("Expecting ':' delimiter"):
                fixes = []
                if e.msg.startswith("Expecting ',' delimiter"):
                    fixes = [
                        repaired[:e.pos] + ',' + repaired[e.pos:],
                        repaired[:e.pos] + ']' + repaired[e.pos:],
                        repaired[:e.pos] + ']}' + repaired[e.pos:],
                        repaired[:e.pos] + ']},' + repaired[e.pos:],
                    ]
                elif e.msg.startswith("Expecting ':' delimiter"):
                    fixes = [
                        repaired[:e.pos] + ':' + repaired[e.pos:],
                    ]
                for fixed in fixes:
                    try:
                        obj, _ = decoder.raw_decode(fixed)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                for extra_brackets in [']', ']]', ']]]', ']', ']}', ']]}']:
                    fixed = repaired[:e.pos] + extra_brackets + repaired[e.pos:]
                    try:
                        obj, _ = decoder.raw_decode(fixed)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                break
            else:
                break
    # Step 2b: 修复未转义引号（"Expecting ',' delimiter" 由未转义 " 导致）
    for _ in range(50):
        try:
            obj, _ = decoder.raw_decode(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError as e:
            if not e.msg.startswith("Expecting ',' delimiter"):
                break
            i = e.pos - 1
            while i >= 0 and repaired[i] in ' \t\n\r':
                i -= 1
            if i < 0 or repaired[i] != '"':
                break
            if i > 0 and repaired[i - 1] == '\\':
                break
            repaired = repaired[:i] + '\\"' + repaired[i + 1:]
            continue
    brace_depth = 0
    bracket_depth = 0
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
            brace_depth += 1
        elif ch == '}':
            brace_depth -= 1
        elif ch == '[':
            bracket_depth += 1
        elif ch == ']':
            bracket_depth -= 1
    if brace_depth > 0 or bracket_depth > 0:
        suffix = ']' * max(bracket_depth, 0) + '}' * max(brace_depth, 0)
        fixed = repaired + suffix
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
    4. \\" 转义修复 + 结构修复 + 花括号方括号补全

    Agent 输出的 JSON 可能：尾部带额外文字、被 max_tokens 截断、缺少闭合括号、转义错误、缺逗号、缺 ]。
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
