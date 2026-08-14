"""Closed provider-owned operation catalog for V2 remote execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class RemoteExecService(str, Enum):
    SMB = "smb"
    WINRM = "winrm"
    DCOM = "dcom"


class RemoteExecOperationId(str, Enum):
    IDENTITY = "operation://identity"
    HOST_INVENTORY = "operation://host-inventory"
    NETWORK_INVENTORY = "operation://network-inventory"
    SERVICE_INVENTORY = "operation://service-inventory"


@dataclass(frozen=True)
class RemoteExecOperationDescriptor:
    operation_id: RemoteExecOperationId
    output_schema_id: str


_REMOTE_EXEC_OPERATIONS: Mapping[RemoteExecOperationId, RemoteExecOperationDescriptor] = MappingProxyType(
    {
        operation_id: RemoteExecOperationDescriptor(
            operation_id=operation_id,
            output_schema_id=f"octopus:remote-operation-output:{operation_id.name.lower()}:1.0",
        )
        for operation_id in RemoteExecOperationId
    }
)


class RemoteExecOperationCatalog:
    """Resolve only reviewed operation IDs; never compile caller commands."""

    def require(self, operation_id: RemoteExecOperationId) -> RemoteExecOperationDescriptor:
        if type(operation_id) is not RemoteExecOperationId:
            raise ValueError("operation_id must be a RemoteExecOperationId")
        return _REMOTE_EXEC_OPERATIONS[operation_id]

    def entries(self) -> tuple[RemoteExecOperationDescriptor, ...]:
        return tuple(_REMOTE_EXEC_OPERATIONS.values())


__all__ = [
    "RemoteExecOperationCatalog",
    "RemoteExecOperationDescriptor",
    "RemoteExecOperationId",
    "RemoteExecService",
]
