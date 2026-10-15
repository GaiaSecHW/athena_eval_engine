"""统一并发配置 — 所有线程池大小的单一数据源。

用法:
    from ..infrastructure.concurrency import get, set_val, get_all, set_all

    pool = ThreadPoolExecutor(max_workers=get("ai_match_workers"))
    set_val("ai_match_workers", 30)  # 运行时动态修改

系统配置 API 修改后，config watcher 调 set_all() 更新内存值，
新创建的线程池立即使用新值。
"""
from __future__ import annotations
import threading

# 所有并发参数的默认值
_defaults = {
    # ── 全局 ──
    "llm_max_concurrency": 50,       # LLM 并发门控上限（DB 可配，池固定 1000 线程）
    "max_concurrent_evals": 3,       # 最大并发评测数
    "eval_pool_max": 10,             # 评测线程池上界

    # ── PARSING 阶段 ──
    "parse_workers": 4,              # Trace 解析并行（非 LLM）

    # ── INGESTING 阶段 ──
    "source_fill_workers": 8,        # [已废弃] source 补提取走 LLM 共享池
    "ac_fetch_workers": 4,           # 告警中心数据获取并行（非 LLM）

    # ── AI_MATCHING 阶段 ──
    "resolver_workers": 50,          # 单 trace 内 resolver 并行（非 LLM）
    "ai_match_workers": 20,          # [已废弃] AI matcher 走 LLM 共享池
    "ac_llm_workers": 8,             # [已废弃] AC→finding LLM 识别走 LLM 共享池

    # ── FPR 阶段 ──
    "fpr_cond_workers": 2,           # FPR 编排并行（非 LLM）
    "fpr_baseline_workers": 20,      # [已废弃] FPR 基线匹配走 LLM 共享池
    "fpr_baseline_batch": 10,        # [已废弃] FPR batch 走 LLM 共享池

    # ── REPORTING 阶段 ──
    "kg_analysis_workers": 4,        # [已废弃] KG 分析走 LLM 共享池

    # ── 统计 ──
    "bootstrap_workers": 4,          # bootstrap 统计并行（非 LLM）
}

_config = dict(_defaults)
_lock = threading.Lock()

# 参数范围限制
_RANGES = {
    "llm_max_concurrency": (1, 1000),
    "max_concurrent_evals": (1, 10),
    "eval_pool_max": (1, 50),
    "parse_workers": (1, 50),
    "source_fill_workers": (1, 1000),
    "ac_fetch_workers": (1, 50),
    "resolver_workers": (1, 1000),
    "ai_match_workers": (1, 1000),
    "ac_llm_workers": (1, 1000),
    "fpr_cond_workers": (1, 10),
    "fpr_baseline_workers": (1, 1000),
    "fpr_baseline_batch": (1, 1000),
    "kg_analysis_workers": (1, 1000),
    "bootstrap_workers": (1, 20),
}


def get(key: str) -> int:
    """获取某个并发参数的当前值。"""
    with _lock:
        return _config.get(key, _defaults.get(key, 50))


def set_val(key: str, value: int):
    """设置某个并发参数（带范围限制）。"""
    lo, hi = _RANGES.get(key, (1, 200))
    v = max(lo, min(value, hi))
    with _lock:
        _config[key] = v


def get_all() -> dict:
    """获取所有并发参数的当前值（副本）。"""
    with _lock:
        return dict(_config)


def set_all(**kwargs):
    """批量设置并发参数（仅更新已存在的 key）。"""
    with _lock:
        for k, v in kwargs.items():
            if k in _config:
                lo, hi = _RANGES.get(k, (1, 200))
                _config[k] = max(lo, min(v, hi))


def get_keys() -> set:
    """返回所有可配置参数名的集合。"""
    return set(_defaults)
