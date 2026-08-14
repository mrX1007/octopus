"""PR-5 Module: Managed resource models, kinds, staging requests, and lifecycles (§8.3)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class ManagedResourceKind(str, Enum):
    SESSION = "session"
    ROUTE = "route"
    C2_CHANNEL = "c2_channel"
    PROXY = "proxy"
    TUNNEL = "tunnel"
    FILE_HANDLE = "file_handle"


@dataclass(frozen=True)
class ManagedResourceStageRequestV2:
    resource_id: str
    resource_kind: ManagedResourceKind
    descriptor: dict[str, Any]
    retained: bool = True


@dataclass(frozen=True)
class ManagedResourceHandleV2:
    resource_id: str
    resource_kind: ManagedResourceKind
    resource_ref: str
    is_active: bool = True


class ManagedResourceManagerV2:
    """In-memory manager of managed resources during execution."""

    def __init__(self) -> None:
        self._resources: dict[str, ManagedResourceHandleV2] = {}

    def register(self, stage_req: ManagedResourceStageRequestV2) -> ManagedResourceHandleV2:
        handle = ManagedResourceHandleV2(
            resource_id=stage_req.resource_id,
            resource_kind=stage_req.resource_kind,
            resource_ref=f"resource:{stage_req.resource_kind.value}:{stage_req.resource_id}",
            is_active=True,
        )
        self._resources[handle.resource_ref] = handle
        return handle

    def get(self, resource_ref: str) -> Optional[ManagedResourceHandleV2]:
        return self._resources.get(resource_ref)


__all__ = [
    "ManagedResourceHandleV2",
    "ManagedResourceKind",
    "ManagedResourceManagerV2",
    "ManagedResourceStageRequestV2",
]
