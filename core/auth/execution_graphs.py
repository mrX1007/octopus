"""Execution graph tracking hierarchy and lineage."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionGraphGrant:
    graph_id: str
    root_execution_id: str
    parent_execution_id: str | None = None
    depth: int = 0


class ExecutionGraphRegistry:
    def __init__(self) -> None:
        self._grants: dict[str, ExecutionGraphGrant] = {}

    def register(self, grant: ExecutionGraphGrant) -> None:
        self._grants[grant.graph_id] = grant

    def get(self, graph_id: str) -> ExecutionGraphGrant | None:
        return self._grants.get(graph_id)


__all__ = [
    "ExecutionGraphGrant",
    "ExecutionGraphRegistry",
]
