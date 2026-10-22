"""FindingExtractor 策略接口。

各 agent 平台提取 finding 的方式不同（Turing/Argo 从 events 或
session_graph 提取，WebVulnVerify/CVulnVerify 从验证工具调用提取）。
为支撑后续新增 agent（只加一个实现类，不改匹配主逻辑），
定义统一接口 + 工厂按 agent_type 路由。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict

from ...core.data_pack import DataPack


class FindingExtractor(ABC):
    """从指定 agent 的 DataPack 中提取 finding，填入共享索引。

    索引结构: title/description -> [(session_id, desc_key, agent_type)]
    （与 case_session_matcher._build_finding_index 一致）
    """

    #: 该 extractor 负责的 agent_type
    agent_type: str = ""

    def __init__(self) -> None:
        self._index: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

    @abstractmethod
    def extract(self, packs: list[DataPack], turing_finding_sids: set[str] = None):
        """把 packs 中属于本 agent 的 finding 提取进 self._index。

        Args:
            packs: DataPack 列表（mining 或 verify，视 agent 角色而定）
            turing_finding_sids: Turing 内部含 finding 的 session_id 集合
                （仅 Turing extractor 使用，其他忽略）
        """

    def index(self) -> dict[str, list[tuple[str, str, str]]]:
        """返回提取完成的索引（dict 化，供匹配器合并）。"""
        return dict(self._index)


# ── 工厂：agent_type → extractor 实例 ──
_REGISTRY: dict[str, type[FindingExtractor]] = {}


def register(agent_type: str):
    """类装饰器：注册 agent_type → extractor 类。"""
    def _wrap(cls):
        cls.agent_type = agent_type
        _REGISTRY[agent_type] = cls
        return cls
    return _wrap


def get_finding_extractor(agent_type: str) -> FindingExtractor | None:
    """按 agent_type 返回 extractor 实例，未注册返回 None。"""
    cls = _REGISTRY.get(agent_type)
    return cls() if cls else None


def all_agent_types() -> list[str]:
    """已注册的 agent_type 列表。"""
    return list(_REGISTRY.keys())
