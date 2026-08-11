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
from typing import Any


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


__all__ = [
    "ArtifactInput",
    "C2AgentInput",
    "C2ChannelInput",
    "C2CleanupInput",
    "C2EnrollmentInput",
    "CredentialInput",
    "PayloadKeyingInput",
    "PivotRouteInput",
    "RemoteExecInput",
    "ScanTarget",
    "SessionInput",
    "TicketInput",
    "validate_typed_input",
]
