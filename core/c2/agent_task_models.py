"""Canonical closed task-side DTOs for the V12 agent wire."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Union

from typing_extensions import TypeAlias

from core.c2.agent_task_protocol import (
    C2_TASK_SCHEMA_V12,
    AgentPayloadSchemaIdV12,
    AgentResultSchemaIdV12,
)
from core.c2.task_catalog import C2TaskOperationId


def _require_bounded_text(value: object, field_name: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    if (not allow_empty and not value) or len(value.encode("utf-8")) > 65_536:
        raise ValueError(f"{field_name} is empty or exceeds the V12 string bound")
    return value


def _require_positive_int(value: object, field_name: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        suffix = f"..{maximum}" if maximum is not None else " or greater"
        raise ValueError(f"{field_name} must be an integer in 1{suffix}")
    return value


class AgentTaskStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    INVALID_PAYLOAD = "invalid_payload"


class AgentTaskErrorCode(str, Enum):
    INVALID_PAYLOAD = "invalid_payload"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT = "output_limit"
    EXECUTION_FAILED = "execution_failed"


@dataclass(frozen=True)
class AgentIdentityTaskPayloadV12:
    payload_kind: Literal["identity"] = field(default="identity", init=False)
    schema_version: Literal["c2-agent-payload/identity/1"] = field(
        default="c2-agent-payload/identity/1",
        init=False,
    )


@dataclass(frozen=True)
class AgentHostInventoryTaskPayloadV12:
    include_processes: bool
    include_services: bool
    max_items: int
    payload_kind: Literal["host_inventory"] = field(default="host_inventory", init=False)
    schema_version: Literal["c2-agent-payload/host-inventory/1"] = field(
        default="c2-agent-payload/host-inventory/1",
        init=False,
    )

    def __post_init__(self) -> None:
        if type(self.include_processes) is not bool or type(self.include_services) is not bool:
            raise TypeError("host inventory flags must be booleans")
        _require_positive_int(self.max_items, "max_items", maximum=1_024)


@dataclass(frozen=True)
class AgentNetworkInventoryTaskPayloadV12:
    include_routes: bool
    include_connections: bool
    max_items: int
    payload_kind: Literal["network_inventory"] = field(
        default="network_inventory",
        init=False,
    )
    schema_version: Literal["c2-agent-payload/network-inventory/1"] = field(
        default="c2-agent-payload/network-inventory/1",
        init=False,
    )

    def __post_init__(self) -> None:
        if type(self.include_routes) is not bool or type(self.include_connections) is not bool:
            raise TypeError("network inventory flags must be booleans")
        _require_positive_int(self.max_items, "max_items", maximum=1_024)


@dataclass(frozen=True)
class AgentServiceInventoryTaskPayloadV12:
    service_names: tuple[str, ...]
    include_status: bool
    payload_kind: Literal["service_inventory"] = field(
        default="service_inventory",
        init=False,
    )
    schema_version: Literal["c2-agent-payload/service-inventory/1"] = field(
        default="c2-agent-payload/service-inventory/1",
        init=False,
    )

    def __post_init__(self) -> None:
        if type(self.service_names) is not tuple or not 1 <= len(self.service_names) <= 1_024:
            raise ValueError("service_names must be a tuple with 1..1024 entries")
        if type(self.include_status) is not bool:
            raise TypeError("include_status must be a boolean")
        for name in self.service_names:
            _require_bounded_text(name, "service name")
        if len(set(self.service_names)) != len(self.service_names):
            raise ValueError("service_names must not contain duplicates")


AgentTaskPayloadV12: TypeAlias = Union[
    AgentIdentityTaskPayloadV12,
    AgentHostInventoryTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
]


@dataclass(frozen=True)
class AgentTaskEnvelopeV12:
    schema_version: Literal["12.0"]
    task_id: str
    operation_id: C2TaskOperationId
    payload_schema_version: AgentPayloadSchemaIdV12
    result_schema_version: AgentResultSchemaIdV12
    expected_agent_capabilities_revision: int
    expected_agent_capabilities_digest: str
    expected_agent_artifact_binding_digest: str
    payload: AgentTaskPayloadV12
    issued_at: float
    expires_at: float
    delivery_attempt: int

    def __post_init__(self) -> None:
        if self.schema_version != C2_TASK_SCHEMA_V12:
            raise ValueError("V12 task envelope requires schema_version='12.0'")
        _require_bounded_text(self.task_id, "task_id")
        if type(self.operation_id) is not C2TaskOperationId:
            raise TypeError("operation_id must be C2TaskOperationId")
        if type(self.payload_schema_version) is not AgentPayloadSchemaIdV12:
            raise TypeError("payload_schema_version must be AgentPayloadSchemaIdV12")
        if type(self.result_schema_version) is not AgentResultSchemaIdV12:
            raise TypeError("result_schema_version must be AgentResultSchemaIdV12")
        _require_positive_int(
            self.expected_agent_capabilities_revision,
            "expected_agent_capabilities_revision",
        )
        _require_bounded_text(
            self.expected_agent_capabilities_digest,
            "expected_agent_capabilities_digest",
        )
        _require_bounded_text(
            self.expected_agent_artifact_binding_digest,
            "expected_agent_artifact_binding_digest",
        )
        if type(self.payload) not in (
            AgentIdentityTaskPayloadV12,
            AgentHostInventoryTaskPayloadV12,
            AgentNetworkInventoryTaskPayloadV12,
            AgentServiceInventoryTaskPayloadV12,
        ):
            raise TypeError("payload must be a closed AgentTaskPayloadV12 variant")
        if (
            type(self.issued_at) not in (int, float)
            or type(self.expires_at) not in (int, float)
            or not math.isfinite(float(self.issued_at))
            or not math.isfinite(float(self.expires_at))
            or float(self.expires_at) <= float(self.issued_at)
        ):
            raise ValueError("issued_at and expires_at must be finite and ordered")
        _require_positive_int(self.delivery_attempt, "delivery_attempt")


@dataclass(frozen=True)
class AgentTaskDeliveryAckV12:
    schema_version: Literal["12.0"]
    task_id: str
    delivery_attempt: int
    received_at: float

    def __post_init__(self) -> None:
        if self.schema_version != C2_TASK_SCHEMA_V12:
            raise ValueError("V12 delivery acknowledgement requires schema_version='12.0'")
        _require_bounded_text(self.task_id, "task_id")
        _require_positive_int(self.delivery_attempt, "delivery_attempt")
        if type(self.received_at) not in (int, float) or not math.isfinite(float(self.received_at)):
            raise ValueError("received_at must be finite")


__all__ = [
    "AgentHostInventoryTaskPayloadV12",
    "AgentIdentityTaskPayloadV12",
    "AgentNetworkInventoryTaskPayloadV12",
    "AgentServiceInventoryTaskPayloadV12",
    "AgentTaskDeliveryAckV12",
    "AgentTaskEnvelopeV12",
    "AgentTaskErrorCode",
    "AgentTaskPayloadV12",
    "AgentTaskStatus",
]
