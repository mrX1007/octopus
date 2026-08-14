"""Control commands."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Protocol, Union, runtime_checkable

_NONCE_RE = re.compile(r"^[0-9a-zA-Z_\-]+$")
_HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _require_bounded_str(value: object, name: str, min_len: int = 1, max_len: int = 256) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a str")
    if not (min_len <= len(value) <= max_len):
        raise ValueError(f"{name} length must be between {min_len} and {max_len}")
    return value


def _require_positive_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an int")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _require_finite_number(value: object, name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite number")
    val = float(value)
    if not math.isfinite(val) or val <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return val


def _require_hex_64_or_empty(value: object, name: str, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a str")
    if allow_empty and not value:
        return value
    if not _HEX_64_RE.match(value):
        raise ValueError(f"{name} must be a 64-character hex string")
    return value


class C2ControlActionV1(str, Enum):
    PING = "ping"
    VERSION = "version"
    READINESS = "readiness"
    LIST_AGENTS = "list_agents"
    LIST_RESULTS = "list_results"
    ACK_RESULTS = "ack_results"
    PURGE_RESULTS = "purge_results"
    MANAGE_OPERATORS_LIST = "manage_operators_list"
    MANAGE_OPERATORS_CREATE = "manage_operators_create"
    MANAGE_OPERATORS_DEACTIVATE = "manage_operators_deactivate"
    MANAGE_OPERATORS_ROTATE = "manage_operators_rotate"
    SYNC_OPERATOR_PEER_BINDINGS = "sync_operator_peer_bindings"
    REVOKE_OPERATOR_PEER_BINDING = "revoke_operator_peer_binding"
    SYNC_OPERATOR_MISSION_GRANTS = "sync_operator_mission_grants"
    REVOKE_OPERATOR_MISSION_GRANT = "revoke_operator_mission_grant"
    RESERVE_ENROLLMENT_FOR_BUILD = "reserve_enrollment_for_build"
    CHECKOUT_ENROLLMENT_BUILD_MATERIAL = "checkout_enrollment_build_material"
    RELEASE_ENROLLMENT_BUILD_RESERVATION = "release_enrollment_build_reservation"
    QUERY_ENROLLMENT_BUILD_RESERVATION = "query_enrollment_build_reservation"
    PREPARE_ENROLLMENT_DEPLOYMENT = "prepare_enrollment_deployment"
    COMMIT_ENROLLMENT_DEPLOYMENT = "commit_enrollment_deployment"
    FINALIZE_ENROLLMENT_DEPLOYMENT = "finalize_enrollment_deployment"
    ABORT_ENROLLMENT_DEPLOYMENT = "abort_enrollment_deployment"
    QUERY_ENROLLMENT_DEPLOYMENT = "query_enrollment_deployment"
    REVOKE_ENROLLMENT = "revoke_enrollment"
    PREPARE_C2_RESOURCE = "prepare_c2_resource"
    COMMIT_C2_RESOURCE = "commit_c2_resource"
    FINALIZE_C2_RESOURCE_VISIBILITY = "finalize_c2_resource_visibility"
    ABORT_C2_RESOURCE = "abort_c2_resource"
    QUERY_C2_RESOURCE = "query_c2_resource"
    CANCEL_TASK = "cancel_task"
    CLEANUP_DAEMON_RESOURCE = "cleanup_daemon_resource"
    REGISTER_DEPLOYMENT_MIRROR = "register_deployment_mirror"


@dataclass(frozen=True)
class ParticipantControlAuthorizationV1:
    key_id: str
    transaction_id: str
    participant_id: str
    mission_id: str
    subject_id: str
    action_id: str
    coordinator_revision: int
    request_digest: str
    expires_at: float
    nonce: str
    signature: str

    def __post_init__(self) -> None:
        _require_bounded_str(self.key_id, "key_id", 1, 256)
        _require_bounded_str(self.transaction_id, "transaction_id", 1, 256)
        _require_bounded_str(self.participant_id, "participant_id", 1, 256)
        _require_bounded_str(self.mission_id, "mission_id", 1, 256)
        _require_bounded_str(self.subject_id, "subject_id", 1, 256)
        _require_bounded_str(self.action_id, "action_id", 1, 256)
        _require_positive_int(self.coordinator_revision, "coordinator_revision")
        if not isinstance(self.request_digest, str) or not self.request_digest:
            raise ValueError("request_digest must be a non-empty string")
        _require_finite_number(self.expires_at, "expires_at")
        _require_bounded_str(self.nonce, "nonce", 1, 256)
        if type(self.signature) is not str:
            raise ValueError("signature must be a str")


@dataclass(frozen=True)
class ExecutionControlAuthorizationV1:
    """Pre-participant executor authority for enrollment build checkout only."""

    key_id: str
    transaction_id: str
    request_id: str
    mission_id: str
    subject_id: str
    action_id: Literal["c2:c2_deploy"]
    coordinator_revision: int
    request_digest: str
    expires_at: float
    nonce: str
    signature: str

    def __post_init__(self) -> None:
        _require_bounded_str(self.key_id, "key_id", 1, 256)
        _require_bounded_str(self.transaction_id, "transaction_id", 1, 256)
        _require_bounded_str(self.request_id, "request_id", 1, 256)
        _require_bounded_str(self.mission_id, "mission_id", 1, 256)
        _require_bounded_str(self.subject_id, "subject_id", 1, 256)
        _require_positive_int(self.coordinator_revision, "coordinator_revision")
        _require_finite_number(self.expires_at, "expires_at")
        _require_bounded_str(self.nonce, "nonce", 1, 256)
        if type(self.signature) is not str:
            raise ValueError("signature must be a str")



@dataclass(frozen=True)
class ParticipantControlRequestV1:
    action: C2ControlActionV1
    authorization: ParticipantControlAuthorizationV1
    payload_schema_id: str
    payload_digest: str
    canonical_payload_b64u: str = field(repr=False, compare=False)
    prior_receipt_ref: str | None = None
    prior_receipt_digest: str | None = None
    expected_resource_revision: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, C2ControlActionV1):
            if isinstance(self.action, str):
                try:
                    object.__setattr__(self, "action", C2ControlActionV1(self.action))
                except ValueError as exc:
                    raise ValueError(f"invalid action: {self.action}") from exc
            else:
                raise ValueError(f"action must be C2ControlActionV1, got {type(self.action)}")
        if not isinstance(self.authorization, ParticipantControlAuthorizationV1):
            raise ValueError("authorization must be ParticipantControlAuthorizationV1")
        _require_bounded_str(self.payload_schema_id, "payload_schema_id", 1, 256)
        if not isinstance(self.payload_digest, str) or not self.payload_digest:
            raise ValueError("payload_digest must be a non-empty string")
        if type(self.canonical_payload_b64u) is not str:
            raise ValueError("canonical_payload_b64u must be a str")
        if self.expected_resource_revision is not None:
            if type(self.expected_resource_revision) is not int or self.expected_resource_revision < 0:
                raise ValueError("expected_resource_revision must be a non-negative int")


@dataclass(frozen=True)
class ParticipantControlReceiptV1:
    transaction_id: str
    participant_id: str
    action: C2ControlActionV1
    resource_ref: str | None
    resource_revision: int | None
    receipt_ref: str
    receipt_digest: str
    daemon_instance_id: str
    result_payload_schema_id: str | None
    result_payload_digest: str | None
    result_payload_b64u: str | None = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        _require_bounded_str(self.transaction_id, "transaction_id", 1, 256)
        _require_bounded_str(self.participant_id, "participant_id", 1, 256)
        _require_bounded_str(self.receipt_ref, "receipt_ref", 1, 256)
        _require_bounded_str(self.daemon_instance_id, "daemon_instance_id", 1, 256)
        if not isinstance(self.receipt_digest, str) or not self.receipt_digest:
            raise ValueError("receipt_digest must be a non-empty string")
        if self.resource_revision is not None:
            if type(self.resource_revision) is not int or self.resource_revision < 0:
                raise ValueError("resource_revision must be a non-negative int")


class ParticipantControlPhaseV1(str, Enum):
    PENDING = "pending"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED_VISIBLE = "finalized_visible"
    ABORTED = "aborted"
    FAILED = "failed"


@dataclass(frozen=True)
class ParticipantControlQuerySnapshotV1:
    transaction_id: str
    participant_id: str
    resource_ref: str | None
    resource_revision: int | None
    phase: ParticipantControlPhaseV1
    receipt_ref: str | None
    receipt_digest: str | None
    snapshot_digest: str
    result_payload_schema_id: str | None
    result_payload_digest: str | None
    result_payload_b64u: str | None = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        _require_bounded_str(self.transaction_id, "transaction_id", 1, 256)
        _require_bounded_str(self.participant_id, "participant_id", 1, 256)
        if not isinstance(self.phase, ParticipantControlPhaseV1):
            if isinstance(self.phase, str):
                object.__setattr__(self, "phase", ParticipantControlPhaseV1(self.phase))
            else:
                raise ValueError("phase must be ParticipantControlPhaseV1")
        if not isinstance(self.snapshot_digest, str) or not self.snapshot_digest:
            raise ValueError("snapshot_digest must be a non-empty string")
        if self.resource_revision is not None:
            if type(self.resource_revision) is not int or self.resource_revision < 0:
                raise ValueError("resource_revision must be a non-negative int")


class C2ControlErrorCodeV1(str, Enum):
    MALFORMED = "malformed"
    NOT_AUTHORIZED = "not_authorized"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    WRONG_PHASE = "wrong_phase"
    REPLAY = "replay"
    UNAVAILABLE = "unavailable"
    INTERNAL_FAILURE = "internal_failure"


@dataclass(frozen=True)
class BoundedControlErrorV1:
    reason_code: C2ControlErrorCodeV1
    retryable: bool
    detail_ref: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.reason_code, C2ControlErrorCodeV1):
            if isinstance(self.reason_code, str):
                object.__setattr__(self, "reason_code", C2ControlErrorCodeV1(self.reason_code))
            else:
                raise ValueError("reason_code must be C2ControlErrorCodeV1")
        if type(self.retryable) is not bool:
            raise ValueError("retryable must be a bool")


@dataclass(frozen=True)
class SignedControlResponseV1:
    protocol_version: str
    daemon_instance_id: str
    daemon_generation: str
    request_digest: str
    request_nonce: str
    response_type: str  # "receipt", "snapshot", "error"
    response_payload_b64u: str
    response_digest: str
    issued_at_ms: int
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        _require_bounded_str(self.protocol_version, "protocol_version", 1, 32)
        _require_bounded_str(self.daemon_instance_id, "daemon_instance_id", 1, 256)
        _require_bounded_str(self.daemon_generation, "daemon_generation", 1, 256)
        _require_bounded_str(self.request_digest, "request_digest", 1, 256)
        _require_bounded_str(self.request_nonce, "request_nonce", 8, 128)
        _require_bounded_str(self.response_type, "response_type", 1, 64)
        if type(self.response_payload_b64u) is not str:
            raise ValueError("response_payload_b64u must be a str")
        if not isinstance(self.response_digest, str) or not self.response_digest:
            raise ValueError("response_digest must be a non-empty string")
        _require_positive_int(self.issued_at_ms, "issued_at_ms")
        _require_bounded_str(self.key_id, "key_id", 1, 256)
        if type(self.signature) is not str:
            raise ValueError("signature must be a str")


ParticipantControlResponseV1 = Union[
    ParticipantControlReceiptV1,
    ParticipantControlQuerySnapshotV1,
    BoundedControlErrorV1,
    SignedControlResponseV1,
]


@runtime_checkable
class ParticipantControlSignerV1(Protocol):
    def sign_participant_request(
        self, unsigned_request: ParticipantControlRequestV1
    ) -> ParticipantControlRequestV1: ...
    def sign_execution_request(
        self,
        *,
        action: C2ControlActionV1,
        authorization: ExecutionControlAuthorizationV1,
        payload_schema_id: str,
        payload_digest: str,
    ) -> ExecutionControlAuthorizationV1: ...


@runtime_checkable
class ParticipantControlVerifierV1(Protocol):
    def verify_participant_request(self, request: ParticipantControlRequestV1) -> None: ...
    def verify_execution_request(
        self,
        *,
        action: C2ControlActionV1,
        authorization: ExecutionControlAuthorizationV1,
        payload_schema_id: str,
        payload_digest: str,
    ) -> None: ...

