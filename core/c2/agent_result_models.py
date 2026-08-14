"""Canonical closed result-side DTOs for the V12 agent wire."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Literal, Union

from typing_extensions import TypeAlias

from core.actions.target_scope import NetworkProtocol
from core.c2.agent_task_models import AgentTaskErrorCode, AgentTaskStatus
from core.c2.agent_task_protocol import C2_TASK_SCHEMA_V12, AgentResultSchemaIdV12
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId


def _require_text(value: object, field_name: str, *, allow_empty: bool = False) -> None:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    if (not allow_empty and not value) or len(value.encode("utf-8")) > 65_536:
        raise ValueError(f"{field_name} is empty or exceeds the V12 string bound")


def _require_exact_tuple(
    value: object,
    expected_type: type,
    field_name: str,
) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{field_name} must be a tuple")
    if any(type(item) is not expected_type for item in value):
        raise TypeError(f"{field_name} contains a non-canonical item")


@dataclass(frozen=True)
class AgentProcessSummaryV12:
    pid: int
    name: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid < 1:
            raise ValueError("pid must be a positive integer")
        _require_text(self.name, "process name")


@dataclass(frozen=True)
class AgentServiceSummaryV12:
    name: str
    status: str

    def __post_init__(self) -> None:
        _require_text(self.name, "service name")
        _require_text(self.status, "service status")


@dataclass(frozen=True)
class AgentInterfaceSummaryV12:
    name: str
    addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.name, "interface name")
        if type(self.addresses) is not tuple:
            raise TypeError("addresses must be a tuple")
        for address in self.addresses:
            _require_text(address, "interface address")


@dataclass(frozen=True)
class AgentRouteSummaryV12:
    destination: str
    gateway: str | None
    interface: str

    def __post_init__(self) -> None:
        _require_text(self.destination, "route destination")
        if self.gateway is not None:
            _require_text(self.gateway, "route gateway")
        _require_text(self.interface, "route interface")


@dataclass(frozen=True)
class AgentConnectionSummaryV12:
    protocol: NetworkProtocol
    local_endpoint: str
    remote_endpoint: str | None
    state: str

    def __post_init__(self) -> None:
        if type(self.protocol) is not NetworkProtocol:
            raise TypeError("connection protocol must be NetworkProtocol")
        _require_text(self.local_endpoint, "local_endpoint")
        if self.remote_endpoint is not None:
            _require_text(self.remote_endpoint, "remote_endpoint")
        _require_text(self.state, "connection state")


@dataclass(frozen=True)
class AgentIdentityTaskOutputV12:
    schema_version: Literal["c2-agent-result/identity/1"] = field(
        default="c2-agent-result/identity/1",
        init=False,
    )
    output_kind: Literal["identity"] = field(default="identity", init=False)
    hostname: str
    os: C2TargetOS
    arch: C2TargetArch
    user: str
    process_id: int

    def __post_init__(self) -> None:
        _require_text(self.hostname, "hostname")
        if type(self.os) is not C2TargetOS:
            raise TypeError("os must be C2TargetOS")
        if type(self.arch) is not C2TargetArch:
            raise TypeError("arch must be C2TargetArch")
        _require_text(self.user, "user")
        if type(self.process_id) is not int or self.process_id < 1:
            raise ValueError("process_id must be a positive integer")


@dataclass(frozen=True)
class AgentHostInventoryTaskOutputV12:
    schema_version: Literal["c2-agent-result/host-inventory/1"] = field(
        default="c2-agent-result/host-inventory/1",
        init=False,
    )
    output_kind: Literal["host_inventory"] = field(default="host_inventory", init=False)
    processes: tuple[AgentProcessSummaryV12, ...]
    services: tuple[AgentServiceSummaryV12, ...]
    truncated: bool

    def __post_init__(self) -> None:
        _require_exact_tuple(self.processes, AgentProcessSummaryV12, "processes")
        _require_exact_tuple(self.services, AgentServiceSummaryV12, "services")
        if type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean")


@dataclass(frozen=True)
class AgentNetworkInventoryTaskOutputV12:
    schema_version: Literal["c2-agent-result/network-inventory/1"] = field(
        default="c2-agent-result/network-inventory/1",
        init=False,
    )
    output_kind: Literal["network_inventory"] = field(default="network_inventory", init=False)
    interfaces: tuple[AgentInterfaceSummaryV12, ...]
    routes: tuple[AgentRouteSummaryV12, ...]
    connections: tuple[AgentConnectionSummaryV12, ...]
    truncated: bool

    def __post_init__(self) -> None:
        _require_exact_tuple(self.interfaces, AgentInterfaceSummaryV12, "interfaces")
        _require_exact_tuple(self.routes, AgentRouteSummaryV12, "routes")
        _require_exact_tuple(self.connections, AgentConnectionSummaryV12, "connections")
        if type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean")


@dataclass(frozen=True)
class AgentServiceInventoryTaskOutputV12:
    schema_version: Literal["c2-agent-result/service-inventory/1"] = field(
        default="c2-agent-result/service-inventory/1",
        init=False,
    )
    output_kind: Literal["service_inventory"] = field(default="service_inventory", init=False)
    services: tuple[AgentServiceSummaryV12, ...]
    truncated: bool

    def __post_init__(self) -> None:
        _require_exact_tuple(self.services, AgentServiceSummaryV12, "services")
        if type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean")


AgentTaskOutput: TypeAlias = Union[
    AgentIdentityTaskOutputV12,
    AgentHostInventoryTaskOutputV12,
    AgentNetworkInventoryTaskOutputV12,
    AgentServiceInventoryTaskOutputV12,
]


@dataclass(frozen=True)
class AgentTaskResultV12:
    schema_version: Literal["12.0"]
    result_schema_version: AgentResultSchemaIdV12
    result_id: str
    task_id: str
    operation_id: C2TaskOperationId
    status: AgentTaskStatus
    output: AgentTaskOutput | None
    error_code: AgentTaskErrorCode | None
    completed_at: float

    def __post_init__(self) -> None:
        if self.schema_version != C2_TASK_SCHEMA_V12:
            raise ValueError("V12 task result requires schema_version='12.0'")
        if type(self.result_schema_version) is not AgentResultSchemaIdV12:
            raise TypeError("result_schema_version must be AgentResultSchemaIdV12")
        _require_text(self.result_id, "result_id")
        _require_text(self.task_id, "task_id")
        if type(self.operation_id) is not C2TaskOperationId:
            raise TypeError("operation_id must be C2TaskOperationId")
        if type(self.status) is not AgentTaskStatus:
            raise TypeError("status must be AgentTaskStatus")
        if self.output is not None and type(self.output) not in (
            AgentIdentityTaskOutputV12,
            AgentHostInventoryTaskOutputV12,
            AgentNetworkInventoryTaskOutputV12,
            AgentServiceInventoryTaskOutputV12,
        ):
            raise TypeError("output must be a closed AgentTaskOutput variant")
        if self.error_code is not None and type(self.error_code) is not AgentTaskErrorCode:
            raise TypeError("error_code must be AgentTaskErrorCode or None")
        if type(self.completed_at) not in (int, float) or not math.isfinite(float(self.completed_at)):
            raise ValueError("completed_at must be finite")

        if self.output is not None and self.output.schema_version != self.result_schema_version.value:
            raise ValueError("output schema does not match result_schema_version")
        if self.status is AgentTaskStatus.SUCCEEDED:
            if self.output is None or self.error_code is not None:
                raise ValueError("SUCCEEDED requires output and error_code=None")
        elif self.status is AgentTaskStatus.PARTIAL:
            if self.output is None:
                raise ValueError("PARTIAL requires output")
        elif self.error_code is None:
            raise ValueError("non-success result status requires error_code")


__all__ = [
    "AgentConnectionSummaryV12",
    "AgentHostInventoryTaskOutputV12",
    "AgentIdentityTaskOutputV12",
    "AgentInterfaceSummaryV12",
    "AgentNetworkInventoryTaskOutputV12",
    "AgentProcessSummaryV12",
    "AgentRouteSummaryV12",
    "AgentServiceInventoryTaskOutputV12",
    "AgentServiceSummaryV12",
    "AgentTaskOutput",
    "AgentTaskResultV12",
]
