"""Typed input contracts for canonical action adapters.

Every adapter declares its ``input_type`` pointing to one of these
contracts (or ``None`` for tools that accept no structured input).
The ``MissionPlanCompiler`` validates that the required fields can be
resolved before creating a runnable task.  Missing data yields
``blocked_by_input`` instead of a malformed provider call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional, Union

from typing_extensions import TypeAlias

from core.actions.operation_catalog import RemoteExecOperationId, RemoteExecService
from core.c2.build_models import C2DeploymentSource
from core.c2.deployment_profiles import C2DeploymentMethod, C2DeploymentProfileId
from core.c2.resource_types import C2CleanupReason
from core.c2.task_catalog import C2TaskOperationId, C2TaskPayload, TaskOperationCatalog
from core.c2.transport_catalog import C2Transport, C2TransportConfig, DNSChannelConfig


@dataclass(frozen=True)
class ScanTarget:
    """Network scan target specification."""

    host: str
    ports: str | None = None
    protocol: str | None = None


@dataclass(frozen=True)
class CredentialInput:
    """Credential-bearing action input.

    ``credential_ref`` is an opaque identity from ``CredentialStore``.
    The actual secret is revealed only inside the provider boundary
    after the last policy gate.
    """

    credential_ref: str
    target: str
    service: str | None = None


@dataclass(frozen=True)
class SessionInput:
    """Reference to a confirmed remote session."""

    session_ref: str
    target: str


@dataclass(frozen=True)
class TicketInput:
    """Reference to a Kerberos ticket or similar artifact in SecretStore."""

    ticket_ref: str
    target: str | None = None


@dataclass(frozen=True)
class ArtifactInput:
    """Generic artifact reference."""

    artifact_ref: str
    artifact_type: str


@dataclass(frozen=True)
class PivotRouteInput:
    """Pivot-scoped scan input.

    ``pivot_route_ref`` must reference a confirmed, evaluated pivot/proxy
    fact.  The planner hides this action until such a fact exists.
    """

    pivot_route_ref: str
    scan_target: ScanTarget


@dataclass(frozen=True)
class C2ChannelInput:
    """C2 channel creation parameters."""

    target: str
    transport_type: str
    callback_endpoint: str | None = None


@dataclass(frozen=True)
class C2EnrollmentInput:
    """Opaque enrollment record owned by the separate C2 daemon."""

    enrollment_ref: str
    target: str | None = None


@dataclass(frozen=True)
class C2AgentInput:
    """Reference-only request for a daemon-owned agent/task."""

    agent_ref: str
    task_ref: str
    target: str | None = None


@dataclass(frozen=True)
class C2CleanupInput:
    """Reference to a daemon-owned channel/session cleanup scope."""

    channel_ref: str
    target: str | None = None


@dataclass(frozen=True)
class RemoteExecInput:
    """Remote command execution input."""

    credential_ref: str
    target: str
    command: str
    service: str | None = None


@dataclass(frozen=True)
class PayloadKeyingInput:
    """Payload keying parameters."""

    payload_ref: str
    keying_parameters: dict[str, Any] = field(default_factory=dict)


# Canonical V2 contracts.  The legacy classes above remain the V1 compatibility
# surface; no V2 decoder constructs them.


class PayloadKeyingProfileId(str, Enum):
    HOSTNAME = "keying://hostname"
    USER = "keying://user"
    MAC = "keying://mac"
    MACHINE_ID = "keying://machine-id"
    MULTI = "keying://multi"


class KerberosHashMode(str, Enum):
    KERBEROAST = "kerberoast"
    ASREP = "asrep"


@dataclass(frozen=True)
class PayloadKeyingInputV2:
    payload_ref: str
    profile_id: PayloadKeyingProfileId
    target_metadata_ref: Optional[str]  # noqa: UP045 -- local cp39 decoder compatibility


@dataclass(frozen=True)
class KerberosExtractInputV2:
    credential_ref: str
    target: str


@dataclass(frozen=True)
class KerberosCrackInputV2:
    ticket_ref: str
    mode: KerberosHashMode
    wordlist_ref: str


@dataclass(frozen=True)
class PassTheTicketInputV2:
    ticket_ref: str
    target: str
    operation_id: RemoteExecOperationId


@dataclass(frozen=True)
class PassTheHashInputV2:
    credential_ref: str
    target: str
    operation_id: RemoteExecOperationId


@dataclass(frozen=True)
class CredentialDumpInputV2:
    credential_ref: str
    target: str


@dataclass(frozen=True)
class RemoteExecInputV2:
    credential_ref: str
    target: str
    operation_id: RemoteExecOperationId
    service: Optional[RemoteExecService] = None  # noqa: UP045 -- local cp39 decoder compatibility


@dataclass(frozen=True)
class RemoteForwardInputV2:
    session_ref: str
    target: str
    remote_port: int
    destination_host: str
    destination_port: int

    def __post_init__(self) -> None:
        for field_name in ("remote_port", "destination_port"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not 1 <= value <= 65535:
                raise ValueError(f"{field_name} must be an integer in 1..65535")


@dataclass(frozen=True)
class SSHChainHopInputV2:
    target: str
    credential_ref: str
    port: int = 22

    def __post_init__(self) -> None:
        if isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("port must be an integer in 1..65535")


@dataclass(frozen=True)
class SSHChainInputV2:
    hops: tuple[SSHChainHopInputV2, ...]

    def __post_init__(self) -> None:
        if not self.hops:
            raise ValueError("hops must not be empty")
        if any(type(hop) is not SSHChainHopInputV2 for hop in self.hops):
            raise ValueError("hops contains an invalid variant")


@dataclass(frozen=True)
class PivotProxyScanInputV2:
    route_ref: str
    target: str
    ports: tuple[int, ...]
    timeout_seconds: int

    def __post_init__(self) -> None:
        if not self.ports or len(self.ports) > 65535:
            raise ValueError("ports must not be empty")
        if any(isinstance(port, bool) or not 1 <= port <= 65535 for port in self.ports):
            raise ValueError("ports must contain only integers in 1..65535")
        if len(set(self.ports)) != len(self.ports):
            raise ValueError("ports must be unique")
        if isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be an integer in 1..3600")


@dataclass(frozen=True)
class C2EnrollmentIssueInput:
    channel_ref: str
    target: str
    profile_id: C2DeploymentProfileId
    agent_protocol_version: Literal["12.0"]
    ttl_seconds: int
    max_uses: Literal[1] = 1

    def __post_init__(self) -> None:
        if self.agent_protocol_version != "12.0":
            raise ValueError("agent_protocol_version must be 12.0")
        if isinstance(self.ttl_seconds, bool) or not 1 <= self.ttl_seconds <= 86_400:
            raise ValueError("ttl_seconds is outside the absolute decoder bound")
        if self.max_uses != 1 or isinstance(self.max_uses, bool):
            raise ValueError("max_uses must be exactly 1")


@dataclass(frozen=True)
class C2TaskInputV2:
    agent_ref: str
    target: Optional[str]  # noqa: UP045 -- local cp39 decoder compatibility
    operation_id: C2TaskOperationId
    payload: C2TaskPayload

    def __post_init__(self) -> None:
        TaskOperationCatalog().validate(self.operation_id, self.payload)


@dataclass(frozen=True)
class C2DeployInputV3:
    target: str
    source: C2DeploymentSource
    channel_ref: str
    enrollment_ref: str
    access_session_ref: str
    profile_id: C2DeploymentProfileId
    method: C2DeploymentMethod


@dataclass(frozen=True)
class DNSC2ChannelInputV2:
    target: str
    config: DNSChannelConfig


@dataclass(frozen=True)
class C2ChannelCreateInputV2:
    target: str
    transport: C2Transport
    config: C2TransportConfig

    def __post_init__(self) -> None:
        if self.transport is not C2Transport.DNS or type(self.config) is not DNSChannelConfig:
            raise ValueError("transport/config variant mismatch")


@dataclass(frozen=True)
class C2CleanupInputV2:
    resource_ref: str
    reason: C2CleanupReason


V2InputUnion: TypeAlias = Union[
    PayloadKeyingInputV2,
    KerberosExtractInputV2,
    KerberosCrackInputV2,
    PassTheTicketInputV2,
    PassTheHashInputV2,
    CredentialDumpInputV2,
    RemoteExecInputV2,
    RemoteForwardInputV2,
    SSHChainInputV2,
    PivotProxyScanInputV2,
    C2EnrollmentIssueInput,
    C2TaskInputV2,
    C2DeployInputV3,
    DNSC2ChannelInputV2,
    C2ChannelCreateInputV2,
    C2CleanupInputV2,
]


_REFERENCE_PREFIXES: dict[str, tuple[str, ...]] = {
    "credential_ref": ("credential://",),
    "session_ref": ("session://",),
    "ticket_ref": ("ticket://", "artifact://", "secret://"),
    "artifact_ref": ("artifact://",),
    "pivot_route_ref": ("fact://",),
    "payload_ref": ("artifact://",),
    "enrollment_ref": ("c2-enrollment://",),
    "agent_ref": ("c2-agent://",),
    "task_ref": ("c2-task://",),
    "channel_ref": ("c2-channel://",),
}


def _reference_is_valid(value: object, prefixes: tuple[str, ...]) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    return bool(
        text
        and not any(character.isspace() or ord(character) < 32 for character in text)
        and any(text.startswith(prefix) and len(text) > len(prefix) for prefix in prefixes)
    )


_CANONICAL_FACT_REF = re.compile(r"fact://[1-9][0-9]*\Z")


def validate_typed_input(
    value: object,
    expected_type: type,
    *,
    request_target: str,
) -> tuple[str, ...]:
    """Validate a reference-only input without resolving secret material."""

    if not isinstance(value, expected_type):
        return (f"blocked_by_input:typed_input:{expected_type.__name__}",)

    failures: list[str] = []
    for field_name, prefixes in _REFERENCE_PREFIXES.items():
        if hasattr(value, field_name) and not _reference_is_valid(getattr(value, field_name), prefixes):
            failures.append(f"blocked_by_input:{field_name}")
    if hasattr(value, "pivot_route_ref") and not _CANONICAL_FACT_REF.fullmatch(
        str(getattr(value, "pivot_route_ref", "") or "").strip()
    ):
        failures.append("blocked_by_input:pivot_route_ref")

    raw_typed_target = getattr(value, "target", "")
    if raw_typed_target is not None and not isinstance(raw_typed_target, str):
        failures.append("blocked_by_input:typed_input_target")
    typed_target = raw_typed_target.strip() if isinstance(raw_typed_target, str) else ""
    if isinstance(value, PivotRouteInput):
        if not isinstance(value.scan_target, ScanTarget):
            typed_target = ""
            failures.append("blocked_by_input:scan_target")
        else:
            if not isinstance(value.scan_target.host, str):
                failures.append("blocked_by_input:scan_target.host")
            typed_target = value.scan_target.host.strip() if isinstance(value.scan_target.host, str) else ""
            if value.scan_target.ports is not None and not isinstance(value.scan_target.ports, str):
                failures.append("blocked_by_input:scan_target.ports")
            if value.scan_target.protocol is not None and not isinstance(value.scan_target.protocol, str):
                failures.append("blocked_by_input:scan_target.protocol")
        if isinstance(value.scan_target, ScanTarget) and not typed_target:
            failures.append("blocked_by_input:scan_target.host")
    request_target = str(request_target or "").strip()
    if request_target and hasattr(value, "target") and not typed_target:
        failures.append("blocked_by_input:typed_input_target")
    if typed_target and not request_target:
        failures.append("blocked_by_input:request_target_required")
    if typed_target and request_target and typed_target.casefold() != request_target.casefold():
        failures.append("blocked_by_input:typed_input_target_mismatch")

    if isinstance(value, ScanTarget):
        if not isinstance(value.host, str) or not value.host.strip():
            failures.append("blocked_by_input:host")
        if value.ports is not None and not isinstance(value.ports, str):
            failures.append("blocked_by_input:ports")
        if value.protocol is not None and not isinstance(value.protocol, str):
            failures.append("blocked_by_input:protocol")
    if isinstance(value, C2ChannelInput):
        if not isinstance(value.transport_type, str) or not value.transport_type.strip():
            failures.append("blocked_by_input:transport_type")
        if value.callback_endpoint is not None and not isinstance(value.callback_endpoint, str):
            failures.append("blocked_by_input:callback_endpoint")
    if isinstance(value, RemoteExecInput) and (not isinstance(value.command, str) or not value.command.strip()):
        failures.append("blocked_by_input:command")
    if (
        isinstance(value, (CredentialInput, RemoteExecInput))
        and value.service is not None
        and not isinstance(value.service, str)
    ):
        failures.append("blocked_by_input:service")
    if isinstance(value, ArtifactInput) and (
        not isinstance(value.artifact_type, str) or not value.artifact_type.strip()
    ):
        failures.append("blocked_by_input:artifact_type")
    if isinstance(value, PayloadKeyingInput) and not isinstance(value.keying_parameters, dict):
        failures.append("blocked_by_input:keying_parameters")

    return tuple(dict.fromkeys(failures))


CredentialDumpInput = CredentialInput
LateralAuthInput = CredentialInput
PivotProxyScanInput = PivotRouteInput
PivotRemoteForwardInput = PivotRouteInput
PivotSSHChainInput = PivotRouteInput


__all__ = [
    "ArtifactInput",
    "C2AgentInput",
    "C2ChannelCreateInputV2",
    "C2ChannelInput",
    "C2CleanupInput",
    "C2CleanupInputV2",
    "C2DeployInputV3",
    "C2EnrollmentInput",
    "C2EnrollmentIssueInput",
    "C2TaskInputV2",
    "CredentialDumpInput",
    "CredentialDumpInputV2",
    "CredentialInput",
    "DNSC2ChannelInputV2",
    "KerberosCrackInputV2",
    "KerberosExtractInputV2",
    "KerberosHashMode",
    "LateralAuthInput",
    "PassTheHashInputV2",
    "PassTheTicketInputV2",
    "PayloadKeyingInput",
    "PayloadKeyingInputV2",
    "PayloadKeyingProfileId",
    "PivotProxyScanInput",
    "PivotProxyScanInputV2",
    "PivotRemoteForwardInput",
    "PivotRouteInput",
    "PivotSSHChainInput",
    "RemoteExecInput",
    "RemoteExecInputV2",
    "RemoteForwardInputV2",
    "SSHChainHopInputV2",
    "SSHChainInputV2",
    "ScanTarget",
    "SessionInput",
    "TicketInput",
    "V2InputUnion",
    "validate_typed_input",
]
