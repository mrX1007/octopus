"""Closed control-plane task operation catalog.

These DTOs describe bounded inventory requests.  They are deliberately
separate from the V12 agent-wire envelopes introduced by the protocol layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Union

from typing_extensions import TypeAlias, assert_never


class C2TaskOperationId(str, Enum):
    IDENTITY = "c2-operation://identity"
    HOST_INVENTORY = "c2-operation://host-inventory"
    NETWORK_INVENTORY = "c2-operation://network-inventory"
    SERVICE_INVENTORY = "c2-operation://service-inventory"


@dataclass(frozen=True)
class IdentityTaskPayload:
    payload_kind: Literal["identity"] = field(default="identity", init=False)
    schema_version: Literal["c2-control-payload/identity/1"] = field(
        default="c2-control-payload/identity/1",
        init=False,
    )


@dataclass(frozen=True)
class HostInventoryTaskPayload:
    include_processes: bool
    include_services: bool
    max_items: int
    payload_kind: Literal["host_inventory"] = field(default="host_inventory", init=False)
    schema_version: Literal["c2-control-payload/host-inventory/1"] = field(
        default="c2-control-payload/host-inventory/1",
        init=False,
    )

    def __post_init__(self) -> None:
        if isinstance(self.max_items, bool) or not 1 <= self.max_items <= 1024:
            raise ValueError("max_items must be an integer in 1..1024")


@dataclass(frozen=True)
class NetworkInventoryTaskPayload:
    include_routes: bool
    include_connections: bool
    max_items: int
    payload_kind: Literal["network_inventory"] = field(default="network_inventory", init=False)
    schema_version: Literal["c2-control-payload/network-inventory/1"] = field(
        default="c2-control-payload/network-inventory/1",
        init=False,
    )

    def __post_init__(self) -> None:
        if isinstance(self.max_items, bool) or not 1 <= self.max_items <= 1024:
            raise ValueError("max_items must be an integer in 1..1024")


@dataclass(frozen=True)
class ServiceInventoryTaskPayload:
    service_names: tuple[str, ...]
    include_status: bool
    payload_kind: Literal["service_inventory"] = field(default="service_inventory", init=False)
    schema_version: Literal["c2-control-payload/service-inventory/1"] = field(
        default="c2-control-payload/service-inventory/1",
        init=False,
    )

    def __post_init__(self) -> None:
        normalized = tuple(name.strip() for name in self.service_names)
        if not 1 <= len(normalized) <= 128:
            raise ValueError("service_names must contain 1..128 entries")
        if any(not name or any(ord(character) < 32 for character in name) for name in normalized):
            raise ValueError("service_names contain an invalid name")
        if len({name.casefold() for name in normalized}) != len(normalized):
            raise ValueError("service_names must be unique")
        object.__setattr__(self, "service_names", normalized)


C2TaskPayload: TypeAlias = Union[
    IdentityTaskPayload,
    HostInventoryTaskPayload,
    NetworkInventoryTaskPayload,
    ServiceInventoryTaskPayload,
]


_PAYLOAD_TYPES: dict[C2TaskOperationId, type[C2TaskPayload]] = {
    C2TaskOperationId.IDENTITY: IdentityTaskPayload,
    C2TaskOperationId.HOST_INVENTORY: HostInventoryTaskPayload,
    C2TaskOperationId.NETWORK_INVENTORY: NetworkInventoryTaskPayload,
    C2TaskOperationId.SERVICE_INVENTORY: ServiceInventoryTaskPayload,
}


class TaskOperationCatalog:
    """Immutable operation-to-control-payload binding."""

    def require_payload_type(self, operation_id: C2TaskOperationId) -> type[C2TaskPayload]:
        if type(operation_id) is not C2TaskOperationId:
            raise ValueError(f"unsupported C2 task operation: {operation_id!r}")
        try:
            return _PAYLOAD_TYPES[operation_id]
        except KeyError as exc:  # defensive for forged enum-like objects
            raise ValueError(f"unsupported C2 task operation: {operation_id!r}") from exc

    def validate(self, operation_id: C2TaskOperationId, payload: object) -> None:
        expected = self.require_payload_type(operation_id)
        if type(payload) is not expected:
            raise ValueError(
                f"payload variant mismatch for {operation_id.value}: expected {expected.__name__}"
            )


def operation_for_payload(payload: C2TaskPayload) -> C2TaskOperationId:
    """Exhaustive control-payload-to-operation projection."""

    if isinstance(payload, IdentityTaskPayload):
        if type(payload) is not IdentityTaskPayload:
            raise TypeError("task payload must be an exact closed variant")
        return C2TaskOperationId.IDENTITY
    if isinstance(payload, HostInventoryTaskPayload):
        if type(payload) is not HostInventoryTaskPayload:
            raise TypeError("task payload must be an exact closed variant")
        return C2TaskOperationId.HOST_INVENTORY
    if isinstance(payload, NetworkInventoryTaskPayload):
        if type(payload) is not NetworkInventoryTaskPayload:
            raise TypeError("task payload must be an exact closed variant")
        return C2TaskOperationId.NETWORK_INVENTORY
    if isinstance(payload, ServiceInventoryTaskPayload):
        if type(payload) is not ServiceInventoryTaskPayload:
            raise TypeError("task payload must be an exact closed variant")
        return C2TaskOperationId.SERVICE_INVENTORY
    assert_never(payload)


__all__ = [
    "C2TaskOperationId",
    "C2TaskPayload",
    "HostInventoryTaskPayload",
    "IdentityTaskPayload",
    "NetworkInventoryTaskPayload",
    "ServiceInventoryTaskPayload",
    "TaskOperationCatalog",
    "operation_for_payload",
]
