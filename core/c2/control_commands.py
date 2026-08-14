"""Control commands."""
from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field
from typing import Literal, Union, Protocol, runtime_checkable

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
    result_payload_b64u: str | None = field(repr=False, compare=False)

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
    result_payload_b64u: str | None = field(repr=False, compare=False)

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

ParticipantControlResponseV1 = Union[ParticipantControlReceiptV1, ParticipantControlQuerySnapshotV1, BoundedControlErrorV1]

@runtime_checkable
class ParticipantControlSignerV1(Protocol):
    def sign_participant_request(self, unsigned_request: ParticipantControlRequestV1) -> ParticipantControlRequestV1: ...
    def sign_execution_request(self, *, action: C2ControlActionV1, authorization: ExecutionControlAuthorizationV1, payload_schema_id: str, payload_digest: str) -> ExecutionControlAuthorizationV1: ...

@runtime_checkable
class ParticipantControlVerifierV1(Protocol):
    def verify_participant_request(self, request: ParticipantControlRequestV1) -> None: ...
    def verify_execution_request(self, *, action: C2ControlActionV1, authorization: ExecutionControlAuthorizationV1, payload_schema_id: str, payload_digest: str) -> None: ...
