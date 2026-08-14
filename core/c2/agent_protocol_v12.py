"""V12 agent registration and protocol negotiation models.

Wire framing is intentionally not implemented here. ``AgentTaskCodecV12`` is
the sole V12 wire codec and imports these host-side registration DTOs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal, TypeVar

from core.c2.agent_task_protocol import (
    C2_AGENT_PROTOCOL_V11,
    C2_AGENT_PROTOCOL_V12,
    AgentPayloadSchemaIdV12,
    AgentResultSchemaIdV12,
)
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId
from core.secrets import SecretValue

_EnumT = TypeVar(
    "_EnumT",
    C2TaskOperationId,
    AgentPayloadSchemaIdV12,
    AgentResultSchemaIdV12,
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def compute_capabilities_digest(
    *,
    supported_operation_ids: Iterable[C2TaskOperationId],
    supported_payload_schema_versions: Iterable[AgentPayloadSchemaIdV12],
    supported_result_schema_versions: Iterable[AgentResultSchemaIdV12],
) -> str:
    """Return the canonical SHA-256 capability-set digest."""

    canonical = {
        "supported_operation_ids": sorted(item.value for item in supported_operation_ids),
        "supported_payload_schema_versions": sorted(item.value for item in supported_payload_schema_versions),
        "supported_result_schema_versions": sorted(item.value for item in supported_result_schema_versions),
    }
    return hashlib.sha256(_canonical_json(canonical)).hexdigest()


@dataclass(frozen=True)
class AgentCapabilitySetV12:
    supported_operation_ids: tuple[C2TaskOperationId, ...]
    supported_payload_schema_versions: tuple[AgentPayloadSchemaIdV12, ...]
    supported_result_schema_versions: tuple[AgentResultSchemaIdV12, ...]
    capabilities_digest: str

    def __post_init__(self) -> None:
        operation_ids = _canonical_enum_tuple(
            self.supported_operation_ids,
            C2TaskOperationId,
            "supported_operation_ids",
        )
        payload_ids = _canonical_enum_tuple(
            self.supported_payload_schema_versions,
            AgentPayloadSchemaIdV12,
            "supported_payload_schema_versions",
        )
        result_ids = _canonical_enum_tuple(
            self.supported_result_schema_versions,
            AgentResultSchemaIdV12,
            "supported_result_schema_versions",
        )
        expected = compute_capabilities_digest(
            supported_operation_ids=operation_ids,
            supported_payload_schema_versions=payload_ids,
            supported_result_schema_versions=result_ids,
        )
        if type(self.capabilities_digest) is not str or not hmac.compare_digest(
            self.capabilities_digest,
            expected,
        ):
            raise ValueError("capabilities_digest does not match the canonical capability set")
        object.__setattr__(self, "supported_operation_ids", operation_ids)
        object.__setattr__(self, "supported_payload_schema_versions", payload_ids)
        object.__setattr__(self, "supported_result_schema_versions", result_ids)

    @classmethod
    def create(
        cls,
        *,
        supported_operation_ids: Iterable[C2TaskOperationId],
        supported_payload_schema_versions: Iterable[AgentPayloadSchemaIdV12],
        supported_result_schema_versions: Iterable[AgentResultSchemaIdV12],
    ) -> AgentCapabilitySetV12:
        operations = tuple(supported_operation_ids)
        payloads = tuple(supported_payload_schema_versions)
        results = tuple(supported_result_schema_versions)
        return cls(
            supported_operation_ids=operations,
            supported_payload_schema_versions=payloads,
            supported_result_schema_versions=results,
            capabilities_digest=compute_capabilities_digest(
                supported_operation_ids=operations,
                supported_payload_schema_versions=payloads,
                supported_result_schema_versions=results,
            ),
        )


def _canonical_enum_tuple(
    values: tuple[_EnumT, ...],
    enum_type: type[_EnumT],
    field_name: str,
) -> tuple[_EnumT, ...]:
    if type(values) is not tuple or not values:
        raise ValueError(f"{field_name} must be a non-empty tuple")
    if any(type(item) is not enum_type for item in values):
        raise TypeError(f"{field_name} contains a non-canonical enum value")
    if len(set(values)) != len(values):
        raise ValueError(f"{field_name} contains duplicates")
    return tuple(sorted(values, key=lambda item: item.value))


@dataclass(frozen=True, repr=False)
class AgentRegistrationV12:
    protocol_version: Literal["12.0"]
    capabilities: AgentCapabilitySetV12
    deployment_ref: str
    artifact_binding_digest: str
    enrollment_token: SecretValue = field(repr=False, compare=False)
    hostname: str
    os: C2TargetOS
    arch: C2TargetArch
    user: str

    def __post_init__(self) -> None:
        if self.protocol_version != C2_AGENT_PROTOCOL_V12:
            raise ValueError("V12 registration requires protocol_version='12.0'")
        if type(self.capabilities) is not AgentCapabilitySetV12:
            raise TypeError("capabilities must be AgentCapabilitySetV12")
        for field_name in (
            "deployment_ref",
            "artifact_binding_digest",
            "hostname",
            "user",
        ):
            value = getattr(self, field_name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        if not isinstance(self.enrollment_token, SecretValue):
            raise TypeError("enrollment_token must implement SecretValue")
        if type(self.os) is not C2TargetOS:
            raise TypeError("os must be C2TargetOS")
        if type(self.arch) is not C2TargetArch:
            raise TypeError("arch must be C2TargetArch")


class AgentProtocolNegotiatorV12:
    """Select only one of the two explicitly supported transition protocols."""

    @staticmethod
    def negotiate_protocol(advertised_versions: Iterable[str]) -> str:
        versions = tuple(advertised_versions)
        if any(type(item) is not str for item in versions):
            raise TypeError("advertised protocol versions must be strings")
        if C2_AGENT_PROTOCOL_V12 in versions:
            return C2_AGENT_PROTOCOL_V12
        if C2_AGENT_PROTOCOL_V11 in versions:
            return C2_AGENT_PROTOCOL_V11
        raise ValueError("no compatible agent protocol version")


__all__ = [
    "AgentCapabilitySetV12",
    "AgentProtocolNegotiatorV12",
    "AgentRegistrationV12",
    "compute_capabilities_digest",
]
