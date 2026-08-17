"""Control commands and wire protocol models for C2 Control Plane (§14.2-§14.6)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Protocol, Union, runtime_checkable

_NONCE_RE = re.compile(r"^[0-9a-zA-Z_\-]{16,128}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_128_RE = re.compile(r"^[0-9a-f]{128}$")
_B64URL_RE = re.compile(r"^[0-9a-zA-Z_\-]+$")
_B64URL_86_RE = re.compile(r"^[0-9a-zA-Z_\-]{86}$")


def _require_bounded_str(value: object, name: str, min_len: int = 1, max_len: int = 256) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a str")
    if not (min_len <= len(value) <= max_len):
        raise ValueError(f"{name} length must be between {min_len} and {max_len}")
    return value


def _require_positive_int(value: object, name: str) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _require_non_negative_int(value: object, name: str) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _require_finite_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    val = float(value)
    if not math.isfinite(val) or val <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return val


def _require_hex_64(value: object, name: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a str")
    if not _HEX_64_RE.match(value):
        raise ValueError(f"{name} must be a 64-character lowercase hex string")
    return value


def _require_nonce(value: object, name: str = "nonce") -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a str")
    if not _NONCE_RE.match(value):
        raise ValueError(f"{name} must be 16-128 URL-safe characters")
    return value


def _require_ed25519_b64u_sig(value: object, name: str = "signature") -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a str")
    if not value:
        return value
    if not _B64URL_86_RE.match(value):
        raise ValueError(f"{name} must be 86 URL-safe characters (unpadded base64url Ed25519 signature)")
    return value


def _require_signature_format(value: object, name: str = "signature") -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a str")
    if not value:
        return value
    if _B64URL_86_RE.match(value):
        return value
    if len(value) in (64, 128) and _B64URL_RE.match(value):
        return value
    raise ValueError(f"{name} must be valid unpadded base64url Ed25519 signature")


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


C2ControlActionV2 = C2ControlActionV1
C2ControlAction = C2ControlActionV1


class ParticipantControlPhaseV2(str, Enum):
    PREPARED = "prepared"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED_VISIBLE = "finalized_visible"
    ABORTED = "aborted"
    RECOVERY_REQUIRED = "recovery_required"


class ParticipantControlPhaseV1(str, Enum):
    PENDING = "pending"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED_VISIBLE = "finalized_visible"
    ABORTED = "aborted"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"


@dataclass(frozen=True)
class ParticipantControlAuthorizationV2:
    protocol_version: Literal["2.0"]
    key_id: str
    transaction_id: str
    participant_id: str
    mission_id: str
    subject_id: str
    action_id: str
    coordinator_revision: int
    issued_at_ms: int
    expires_at_ms: int
    nonce: str
    request_digest: str
    signature: str

    def __post_init__(self) -> None:
        if self.protocol_version != "2.0":
            raise ValueError(f"protocol_version must be '2.0', got {self.protocol_version!r}")
        _require_bounded_str(self.key_id, "key_id", 1, 256)
        _require_bounded_str(self.transaction_id, "transaction_id", 1, 256)
        _require_bounded_str(self.participant_id, "participant_id", 1, 256)
        _require_bounded_str(self.mission_id, "mission_id", 1, 256)
        _require_bounded_str(self.subject_id, "subject_id", 1, 256)
        _require_bounded_str(self.action_id, "action_id", 1, 256)
        _require_positive_int(self.coordinator_revision, "coordinator_revision")
        _require_positive_int(self.issued_at_ms, "issued_at_ms")
        _require_positive_int(self.expires_at_ms, "expires_at_ms")
        if self.expires_at_ms <= self.issued_at_ms:
            raise ValueError("expires_at_ms must be greater than issued_at_ms")
        if (self.expires_at_ms - self.issued_at_ms) > 300000:
            raise ValueError("TTL cannot exceed 300,000 ms (5 minutes)")
        _require_nonce(self.nonce, "nonce")
        if self.request_digest:
            _require_hex_64(self.request_digest, "request_digest")
        _require_ed25519_b64u_sig(self.signature, "signature")


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
        _require_bounded_str(self.request_digest, "request_digest", 1, 256)
        _require_finite_number(self.expires_at, "expires_at")
        _require_nonce(self.nonce, "nonce")
        _require_signature_format(self.signature, "signature")


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
        _require_nonce(self.nonce, "nonce")
        _require_signature_format(self.signature, "signature")


@dataclass(frozen=True)
class ParticipantControlRequestV2:
    action: C2ControlActionV1
    authorization: ParticipantControlAuthorizationV2
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
        if not isinstance(self.authorization, ParticipantControlAuthorizationV2):
            raise ValueError("authorization must be ParticipantControlAuthorizationV2")
        _require_bounded_str(self.payload_schema_id, "payload_schema_id", 1, 256)
        _require_hex_64(self.payload_digest, "payload_digest")
        if type(self.canonical_payload_b64u) is not str:
            raise ValueError("canonical_payload_b64u must be a str")
        if self.expected_resource_revision is not None:
            _require_non_negative_int(self.expected_resource_revision, "expected_resource_revision")
        if (self.prior_receipt_ref is None) != (self.prior_receipt_digest is None):
            raise ValueError("prior_receipt_ref and prior_receipt_digest must both be present or both None")
        if self.prior_receipt_digest is not None:
            _require_hex_64(self.prior_receipt_digest, "prior_receipt_digest")


@dataclass(frozen=True)
class ParticipantControlRequestV1:
    action: C2ControlActionV1
    authorization: ParticipantControlAuthorizationV1 | ParticipantControlAuthorizationV2
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
        if not isinstance(self.authorization, (ParticipantControlAuthorizationV1, ParticipantControlAuthorizationV2)):
            raise ValueError("authorization must be ParticipantControlAuthorizationV1 or V2")
        _require_bounded_str(self.payload_schema_id, "payload_schema_id", 1, 256)
        _require_hex_64(self.payload_digest, "payload_digest")
        if type(self.canonical_payload_b64u) is not str:
            raise ValueError("canonical_payload_b64u must be a str")
        if self.expected_resource_revision is not None:
            _require_non_negative_int(self.expected_resource_revision, "expected_resource_revision")
        if (self.prior_receipt_ref is None) != (self.prior_receipt_digest is None):
            raise ValueError("prior_receipt_ref and prior_receipt_digest must both be present or both None")
        if self.prior_receipt_digest is not None:
            _require_hex_64(self.prior_receipt_digest, "prior_receipt_digest")


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
        _require_hex_64(self.receipt_digest, "receipt_digest")
        if self.resource_revision is not None:
            _require_non_negative_int(self.resource_revision, "resource_revision")
        if self.result_payload_digest is not None:
            _require_hex_64(self.result_payload_digest, "result_payload_digest")


ParticipantControlReceiptV2 = ParticipantControlReceiptV1


@dataclass(frozen=True)
class ParticipantControlQuerySnapshotV1:
    transaction_id: str
    participant_id: str
    resource_ref: str | None
    resource_revision: int | None
    phase: ParticipantControlPhaseV1 | ParticipantControlPhaseV2
    receipt_ref: str | None
    receipt_digest: str | None
    snapshot_digest: str
    result_payload_schema_id: str | None
    result_payload_digest: str | None
    result_payload_b64u: str | None = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        _require_bounded_str(self.transaction_id, "transaction_id", 1, 256)
        _require_bounded_str(self.participant_id, "participant_id", 1, 256)
        if not isinstance(self.phase, (ParticipantControlPhaseV1, ParticipantControlPhaseV2)):
            if isinstance(self.phase, str):
                object.__setattr__(self, "phase", ParticipantControlPhaseV1(self.phase))
            else:
                raise ValueError("phase must be ParticipantControlPhaseV1 or V2")
        _require_hex_64(self.snapshot_digest, "snapshot_digest")
        if self.resource_revision is not None:
            _require_non_negative_int(self.resource_revision, "resource_revision")
        if self.receipt_digest is not None:
            _require_hex_64(self.receipt_digest, "receipt_digest")
        if self.result_payload_digest is not None:
            _require_hex_64(self.result_payload_digest, "result_payload_digest")


ParticipantControlQuerySnapshotV2 = ParticipantControlQuerySnapshotV1


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


BoundedControlErrorV2 = BoundedControlErrorV1


@dataclass(frozen=True)
class SignedControlResponseV2:
    protocol_version: Literal["2.0"]
    service_id: str
    boot_instance_id: str
    daemon_generation: str
    request_digest: str
    request_nonce: str
    response_type: Literal["receipt", "snapshot", "error"]
    response_payload_b64u: str
    response_digest: str
    issued_at_ms: int
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if self.protocol_version not in ("2.0", "1.0"):
            raise ValueError(f"invalid protocol_version: {self.protocol_version!r}")
        _require_bounded_str(self.service_id, "service_id", 0, 256)
        _require_bounded_str(self.boot_instance_id, "boot_instance_id", 0, 256)
        _require_bounded_str(self.daemon_generation, "daemon_generation", 1, 256)
        _require_hex_64(self.request_digest, "request_digest")
        _require_nonce(self.request_nonce, "request_nonce")
        if self.response_type not in ("receipt", "snapshot", "error"):
            raise ValueError(f"invalid response_type: {self.response_type}")
        if type(self.response_payload_b64u) is not str:
            raise ValueError("response_payload_b64u must be a str")
        _require_hex_64(self.response_digest, "response_digest")
        _require_positive_int(self.issued_at_ms, "issued_at_ms")
        _require_bounded_str(self.key_id, "key_id", 1, 256)


@dataclass(frozen=True)
class SignedControlResponseV1:
    protocol_version: str
    daemon_instance_id: str
    daemon_generation: str
    request_digest: str
    request_nonce: str
    response_type: Literal["receipt", "snapshot", "error"] | str
    response_payload_b64u: str
    response_digest: str
    issued_at_ms: int
    key_id: str
    signature: str
    service_id: str = ""
    boot_instance_id: str = ""

    def __post_init__(self) -> None:
        _require_bounded_str(self.protocol_version, "protocol_version", 1, 32)
        _require_bounded_str(self.daemon_instance_id, "daemon_instance_id", 1, 256)
        _require_bounded_str(self.daemon_generation, "daemon_generation", 1, 256)
        _require_hex_64(self.request_digest, "request_digest")
        _require_nonce(self.request_nonce, "request_nonce")
        if self.response_type not in ("receipt", "snapshot", "error"):
            raise ValueError(f"invalid response_type: {self.response_type}")
        if type(self.response_payload_b64u) is not str:
            raise ValueError("response_payload_b64u must be a str")
        _require_hex_64(self.response_digest, "response_digest")
        _require_positive_int(self.issued_at_ms, "issued_at_ms")
        _require_bounded_str(self.key_id, "key_id", 1, 256)
        _require_signature_format(self.signature, "signature")


ParticipantControlResponseV1 = Union[
    ParticipantControlReceiptV1,
    ParticipantControlQuerySnapshotV1,
    BoundedControlErrorV1,
    SignedControlResponseV1,
    SignedControlResponseV2,
]

ParticipantControlResponseV2 = Union[
    ParticipantControlReceiptV2,
    ParticipantControlQuerySnapshotV2,
    BoundedControlErrorV2,
    SignedControlResponseV2,
]


@runtime_checkable
class ParticipantControlSignerV1(Protocol):
    def sign_participant_request(
        self, unsigned_request: ParticipantControlRequestV1 | ParticipantControlRequestV2
    ) -> ParticipantControlRequestV1 | ParticipantControlRequestV2: ...
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
    def verify_participant_request(
        self, request: ParticipantControlRequestV1 | ParticipantControlRequestV2
    ) -> None: ...
    def verify_execution_request(
        self,
        *,
        action: C2ControlActionV1,
        authorization: ExecutionControlAuthorizationV1,
        payload_schema_id: str,
        payload_digest: str,
    ) -> None: ...


__all__ = [
    "BoundedControlErrorV1",
    "BoundedControlErrorV2",
    "C2ControlAction",
    "C2ControlActionV1",
    "C2ControlActionV2",
    "C2ControlErrorCodeV1",
    "ExecutionControlAuthorizationV1",
    "ParticipantControlAuthorizationV1",
    "ParticipantControlAuthorizationV2",
    "ParticipantControlPhaseV1",
    "ParticipantControlPhaseV2",
    "ParticipantControlQuerySnapshotV1",
    "ParticipantControlQuerySnapshotV2",
    "ParticipantControlReceiptV1",
    "ParticipantControlReceiptV2",
    "ParticipantControlRequestV1",
    "ParticipantControlRequestV2",
    "ParticipantControlResponseV1",
    "ParticipantControlResponseV2",
    "ParticipantControlSignerV1",
    "ParticipantControlVerifierV1",
    "SignedControlResponseV1",
    "SignedControlResponseV2",
]
