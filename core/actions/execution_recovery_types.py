"""PR-5 Module: Execution recovery reference and state models (§8.1, §8.4)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Literal

from core.actions.checkout_models import CheckoutRecoveryRefV2
from core.actions.execution_commit_types import ExecutionCommitStateV2


class InvocationFinalizationIntentPhaseV2(str, Enum):
    CREATED = "created"
    OWNERS_FENCED = "owners_fenced"
    EFFECT_FENCED = "effect_fenced"
    RESULT_COMMITTED = "result_committed"
    CLEANUP_COMPLETE = "cleanup_complete"


class ExecutionFenceOperationV2(str, Enum):
    COMMIT = "commit"
    ROLLBACK = "rollback"
    RECONCILE = "reconcile"


@dataclass(frozen=True)
class InvocationFinalizationIntentRefV2:
    reference: str
    revision: int
    execution_id: str
    transaction_id: str
    phase: InvocationFinalizationIntentPhaseV2
    intent_digest: str


@dataclass(frozen=True)
class ExecutionCommitRecoveryRefV2:
    reference: str
    revision: int
    transaction_id: str
    coordinator_state: str
    recovery_digest: str


@dataclass(frozen=True)
class CancellationRecoveryRefV2:
    reference: str
    revision: int
    root_execution_id: str
    execution_graph_id: str
    token_id: str
    state: Literal["active", "cancel_requested", "cancelled", "completed"]
    cancellation_digest: str


@dataclass(frozen=True)
class CancellationRecoveryRecordV2:
    cancellation_ref: CancellationRecoveryRefV2
    requested_reason_code: str | None
    requested_at_utc: float | None


@dataclass(frozen=True)
class CancellationControllerBindingV2:
    reference: str
    cancellation_revision: int
    token_id: str
    controller_binding_id: str
    binding_digest: str


@dataclass(frozen=True)
class CancellationCompletionReceiptV2:
    cancellation_ref: CancellationRecoveryRefV2
    cleared_controller_binding_ids: tuple[str, ...]
    completion_digest: str


@dataclass(frozen=True)
class ExecutionNoReturnAdmissionBodyV2:
    root_execution_id: str
    execution_graph_id: str
    transaction_id: str
    cancellation_revision: int
    decision_identity_digest: str
    external_effect_participant_id: str | None
    external_effect_registration_digest: str | None

    def __post_init__(self) -> None:
        if (self.external_effect_participant_id is None) != (self.external_effect_registration_digest is None):
            raise ValueError("external_effect_admission_fields_all_or_none")


def canonical_execution_no_return_admission_digest(
    body: ExecutionNoReturnAdmissionBodyV2,
) -> str:
    payload = {
        "cancellation_revision": body.cancellation_revision,
        "decision_identity_digest": body.decision_identity_digest,
        "execution_graph_id": body.execution_graph_id,
        "external_effect_participant_id": body.external_effect_participant_id,
        "external_effect_registration_digest": body.external_effect_registration_digest,
        "root_execution_id": body.root_execution_id,
        "transaction_id": body.transaction_id,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@dataclass(frozen=True)
class ExecutionNoReturnAdmissionRefV2:
    reference: str
    revision: int
    transaction_id: str
    admission_digest: str


@dataclass(frozen=True)
class ExecutionNoReturnAdmissionReceiptV2:
    admission_ref: ExecutionNoReturnAdmissionRefV2
    body: ExecutionNoReturnAdmissionBodyV2

    def __post_init__(self) -> None:
        if self.admission_ref.transaction_id != self.body.transaction_id:
            raise ValueError("admission_transaction_mismatch")
        if self.admission_ref.admission_digest != (canonical_execution_no_return_admission_digest(self.body)):
            raise ValueError("admission_digest_mismatch")


@dataclass(frozen=True)
class ExecutionContinuationRecoveryRefV2:
    reference: str
    revision: int
    parent_execution_id: str
    continuation_kind: Literal["composite_child"]
    handoff_state: Literal["reserved", "custody_transferred", "completed"]
    record_digest: str


@dataclass(frozen=True)
class ExecutionContinuationPendingBindingV2:
    kind: Literal["composite_child"]
    reference: str
    revision: int
    parent_execution_id: str
    binding_digest: str


@dataclass(frozen=True)
class InvocationScopeRecoveryRefV2:
    scope_id: str
    revision: int
    journal_ref: str
    journal_digest: str


@dataclass(frozen=True)
class ApprovalGraphRecoveryRefV2:
    graph_id: str
    graph_revision: int
    owner: bool
    graph_digest: str


@dataclass(frozen=True)
class ExecutionContinuationRecoveryRecordV2:
    continuation_ref: ExecutionContinuationRecoveryRefV2
    pending: ExecutionContinuationPendingBindingV2
    intent_ref: InvocationFinalizationIntentRefV2
    checkout_ref: CheckoutRecoveryRefV2 | None
    scope_ref: InvocationScopeRecoveryRefV2 | None
    coordinator_ref: ExecutionCommitRecoveryRefV2 | None
    graph_ref: ApprovalGraphRecoveryRefV2 | None
    final_report_ref: str | None
    final_report_digest: str | None


@dataclass(frozen=True)
class ExecutionContinuationCompletionReceiptV2:
    continuation_ref: ExecutionContinuationRecoveryRefV2
    final_report_ref: str
    final_report_digest: str
    intent_ref: InvocationFinalizationIntentRefV2
    completion_digest: str


@dataclass(frozen=True)
class ExternalEffectRegistrationIdentityV2:
    transaction_id: str
    participant_id: str
    registration_digest: str


@dataclass(frozen=True)
class ParticipantExecutionAuthorityBindingV2:
    execution_id: str
    action_id: str
    transaction_id: str
    mission_id: str
    subject_id: str
    checkout_recovery_ref: CheckoutRecoveryRefV2
    intent_reference: str
    issued_intent_revision: int
    issued_intent_digest: str
    coordinator_transaction_id: str
    coordinator_record_ref: str
    issued_coordinator_revision: int
    issued_coordinator_digest: str
    binding_digest: str


@dataclass(frozen=True)
class ExecutionFinalizationFenceV2:
    intent_ref: InvocationFinalizationIntentRefV2
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2
    operation: ExecutionFenceOperationV2
    fence_digest: str


@dataclass(frozen=True)
class FenceValidationReceiptV2:
    intent_ref: InvocationFinalizationIntentRefV2
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2
    transaction_id: str
    operation: ExecutionFenceOperationV2
    coordinator_state: ExecutionCommitStateV2
    evidence_set_digest: str
    validation_digest: str


__all__ = [
    "ApprovalGraphRecoveryRefV2",
    "CancellationCompletionReceiptV2",
    "CancellationControllerBindingV2",
    "CancellationRecoveryRecordV2",
    "CancellationRecoveryRefV2",
    "CheckoutRecoveryRefV2",
    "ExecutionCommitRecoveryRefV2",
    "ExecutionContinuationCompletionReceiptV2",
    "ExecutionContinuationPendingBindingV2",
    "ExecutionContinuationRecoveryRecordV2",
    "ExecutionContinuationRecoveryRefV2",
    "ExecutionFenceOperationV2",
    "ExecutionFinalizationFenceV2",
    "ExecutionNoReturnAdmissionBodyV2",
    "ExecutionNoReturnAdmissionReceiptV2",
    "ExecutionNoReturnAdmissionRefV2",
    "ExternalEffectRegistrationIdentityV2",
    "FenceValidationReceiptV2",
    "InvocationFinalizationIntentPhaseV2",
    "InvocationFinalizationIntentRefV2",
    "InvocationScopeRecoveryRefV2",
    "ParticipantExecutionAuthorityBindingV2",
    "canonical_execution_no_return_admission_digest",
]
