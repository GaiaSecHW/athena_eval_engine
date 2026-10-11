"""v2 Resolvers — 从 RawEvent 提取 Facts。

4 个独立 Resolver，各自消费标准化 RawEvent + TaskRun，不依赖平台特定逻辑。
"""
from .outcome import OutcomeResolver
from .knowledge import KnowledgeResolver
from .tool_action import ToolActionResolver
from .resource import ResourceResolver

__all__ = [
    "OutcomeResolver",
    "KnowledgeResolver",
    "ToolActionResolver",
    "ResourceResolver",
]
