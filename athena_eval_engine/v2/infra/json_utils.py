"""JSON 序列化工具 — dataclass → dict，numpy → Python 原生类型。

从 orchestrator 和 assembler 两处重复实现中提取。
"""
from __future__ import annotations

import dataclasses
import json
import sys


def json_default(obj):
    """json.dump default — dataclass → dict，numpy → Python 原生类型。"""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    # numpy 标量
    for mod_name, convs in (
        ("numpy", (
            ("float64", float), ("float32", float),
            ("int64", int), ("int32", int),
            ("float_", float), ("int_", int),
        )),
    ):
        mod = sys.modules.get(mod_name)
        if mod is not None and isinstance(obj, mod.ndarray):
            return obj.tolist()
        if mod is not None:
            for attr, conv in convs:
                t = getattr(mod, attr, None)
                if t is not None and isinstance(obj, t):
                    return conv(obj)
    if isinstance(obj, (set, tuple)):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def json_dump(obj, f, **kw):
    """json.dump 包装：用 json_default 替代 default=str。"""
    kw.setdefault("ensure_ascii", False)
    kw.setdefault("indent", 2)
    json.dump(obj, f, default=json_default, **kw)


def json_dumps(obj, **kw):
    """json.dumps 包装：用 json_default 替代 default=str。"""
    kw.setdefault("ensure_ascii", False)
    return json.dumps(obj, default=json_default, **kw)
