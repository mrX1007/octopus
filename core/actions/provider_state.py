"""Provider state and node classification definitions."""

from __future__ import annotations

from enum import Enum


class ExecutionNodeKind(str, Enum):
    LEAF = "leaf"
    COMPOSITE_ROUTER = "composite_router"


__all__ = [
    "ExecutionNodeKind",
]
