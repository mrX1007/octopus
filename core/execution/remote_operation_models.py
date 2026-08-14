from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Union

from typing_extensions import TypeAlias


class RemoteOperationServiceV1(str, Enum):
    SMBEXEC = "smbexec"
    WINRM = "winrm"
    DCOM = "dcom"


class RemoteOperationAttemptStateV1(str, Enum):
    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    CONFIRMED = "confirmed"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"
    RECONCILING = "reconciling"


RemoteExecOperationId: TypeAlias = str
ParticipantPayloadDraftRefV2: TypeAlias = Any


@dataclass(frozen=True)
class RemoteOperationOutputReservationRefV1:
    reference: str
    transaction_id: str
    operation_id: RemoteExecOperationId
    output_schema_id: str
    reservation_revision: int
    reservation_digest: str


@dataclass(frozen=True)
class RemoteOperationPlanV1:
    transaction_id: str
    action_id: str
    target: str
    service: RemoteOperationServiceV1
    operation_id: str
    operation_payload_schema_id: str
    operation_payload_ref: ParticipantPayloadDraftRefV2
    output_reservation_ref: RemoteOperationOutputReservationRefV1
    credential_ref: str
    credential_revision: int
    attempt_id: str
    idempotency_key: str
    plan_digest: str


@dataclass(frozen=True)
class IdentityRemoteOperationOutputV1:
    principal_name: str
    domain_name: str | None
    machine_name: str


@dataclass(frozen=True)
class HostRemoteOperationOutputV1:
    hostname: str
    os_name: str
    os_version: str
    architecture: str


@dataclass(frozen=True)
class NetworkInterfaceOutputV1:
    name: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class NetworkRemoteOperationOutputV1:
    interfaces: tuple[NetworkInterfaceOutputV1, ...]
    routes: tuple[str, ...]
    connections: tuple[str, ...]


@dataclass(frozen=True)
class ServiceStatusOutputV1:
    service_name: str
    state: str
    start_mode: str | None


@dataclass(frozen=True)
class ServiceRemoteOperationOutputV1:
    services: tuple[ServiceStatusOutputV1, ...]


RemoteOperationOutputV1: TypeAlias = Union[
    IdentityRemoteOperationOutputV1,
    HostRemoteOperationOutputV1,
    NetworkRemoteOperationOutputV1,
    ServiceRemoteOperationOutputV1,
]


@dataclass(frozen=True)
class RemoteOperationBackendRequestV1:
    attempt_id: str
    idempotency_key: str
    plan_ref: ParticipantPayloadDraftRefV2
    plan_digest: str
    absolute_deadline_monotonic: float


class RemoteOperationEffectDispositionV1(str, Enum):
    CONFIRMED = "confirmed"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RemoteOperationEffectReceiptV1:
    transaction_id: str
    participant_id: str
    attempt_id: str
    plan_digest: str
    disposition: RemoteOperationEffectDispositionV1
    backend_receipt_ref: str | None
    output: RemoteOperationOutputV1 | None
    output_digest: str | None
    probe_token: str
    attempt_revision: int
    receipt_digest: str


@dataclass(frozen=True)
class RemoteOperationEffectProbeV1:
    transaction_id: str
    participant_id: str
    attempt_id: str
    disposition: RemoteOperationEffectDispositionV1
    backend_receipt_ref: str | None
    output: RemoteOperationOutputV1 | None
    output_digest: str | None
    attempt_revision: int
    probe_digest: str
