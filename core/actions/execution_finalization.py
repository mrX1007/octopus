"""PR-5 Module: Invocation finalization intent store and types."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from core.actions.checkout_models import CheckoutRecoveryRefV2
from core.actions.execution_recovery_types import (
    ApprovalGraphRecoveryRefV2,
    CancellationRecoveryRefV2,
    ExecutionContinuationRecoveryRefV2,
    InvocationScopeRecoveryRefV2,
)
from core.actions.execution_results_v2 import (
    ActionExecutionReportEnvelopeV2,
    FinalizationPersistedV2,
    FinalizationPersistenceOutcomeV2,
    FinalizationRetryEnqueuedV2,
    canonical_finalization_persistence_outcome_digest,
)
from core.actions.finalization_retry import (
    FinalizationRetryClaimRecordV2,
    FinalizationRetryCompletionReceiptV2,
    FinalizationRetryReconcilerV2,
    FinalizationRetryRecordV2,
    FinalizationRetryStateV2,
    FinalizationRetryStoreV2,
)


class InvocationLeaseRecoveryRefV2:
    pass


class AttemptLeaseRecoveryRefV2:
    pass


class ExecutionCommitRecoveryRefV2:
    pass


class ProviderCallRecoveryRefV2:
    pass


class EffectDispatchAuthorizationV2:
    pass


class PrimaryExecutionOutcomeSnapshotV2:
    pass


class PreparedFinalizationSnapshotV2:
    pass


class ReportPublicationCheckpointV2:
    pass


class InvocationFinalizationIntentPhaseV2(str, Enum):
    CREATED = "created"
    OWNERS_FENCED = "owners_fenced"
    EFFECT_FENCED = "effect_fenced"
    RESULT_COMMITTED = "result_committed"
    CLEANUP_COMPLETE = "cleanup_complete"


@dataclass(frozen=True)
class InvocationFinalizationIntentRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    transaction_id: str
    intent_digest: str


@dataclass(frozen=True)
class InvocationFinalizationIntentBodyV2:
    execution_id: str
    action_id: str
    transaction_id: str
    phase: InvocationFinalizationIntentPhaseV2
    ingress_recovery_ref: InvocationLeaseRecoveryRefV2 | Any = None
    cancellation_recovery_ref: CancellationRecoveryRefV2 | Any = None
    continuation_recovery_ref: ExecutionContinuationRecoveryRefV2 | None = None
    approval_graph_recovery_ref: ApprovalGraphRecoveryRefV2 | None = None
    attempt_recovery_ref: AttemptLeaseRecoveryRefV2 | None = None
    checkout_recovery_ref: CheckoutRecoveryRefV2 | None = None
    scope_recovery_ref: InvocationScopeRecoveryRefV2 | None = None
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2 | None = None
    provider_call_recovery_ref: ProviderCallRecoveryRefV2 | None = None
    effect_dispatch_authorization: EffectDispatchAuthorizationV2 | None = None
    primary_outcome: PrimaryExecutionOutcomeSnapshotV2 | None = None
    prepared_finalization: PreparedFinalizationSnapshotV2 | None = None
    report_publication: ReportPublicationCheckpointV2 | None = None


@dataclass(frozen=True)
class InvocationFinalizationIntentRecordV2:
    intent_ref: InvocationFinalizationIntentRefV2
    body: InvocationFinalizationIntentBodyV2


@dataclass(frozen=True)
class InvocationFinalizationIntentCheckpointV2:
    expected_revision: int
    phase: InvocationFinalizationIntentPhaseV2
    ingress_recovery_ref: InvocationLeaseRecoveryRefV2 | Any = None
    cancellation_recovery_ref: CancellationRecoveryRefV2 | Any = None
    continuation_recovery_ref: ExecutionContinuationRecoveryRefV2 | None = None
    approval_graph_recovery_ref: ApprovalGraphRecoveryRefV2 | None = None
    attempt_recovery_ref: AttemptLeaseRecoveryRefV2 | None = None
    checkout_recovery_ref: CheckoutRecoveryRefV2 | None = None
    scope_recovery_ref: InvocationScopeRecoveryRefV2 | None = None
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2 | None = None
    provider_call_recovery_ref: ProviderCallRecoveryRefV2 | None = None
    effect_dispatch_authorization: EffectDispatchAuthorizationV2 | None = None
    primary_outcome: PrimaryExecutionOutcomeSnapshotV2 | None = None
    prepared_finalization: PreparedFinalizationSnapshotV2 | None = None
    report_publication: ReportPublicationCheckpointV2 | None = None


def canonical_finalization_intent_digest(
    record: InvocationFinalizationIntentRecordV2,
) -> str:
    phase_val = record.body.phase.value if hasattr(record.body.phase, "value") else str(record.body.phase)
    payload = {
        "reference": record.intent_ref.reference,
        "revision": record.intent_ref.revision,
        "execution_id": record.intent_ref.execution_id,
        "action_id": record.intent_ref.action_id,
        "transaction_id": record.intent_ref.transaction_id,
        "phase": phase_val,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@dataclass(frozen=True)
class InvocationFinalizationIntentCompletionReceiptV2:
    intent_ref: InvocationFinalizationIntentRefV2
    persistence_outcome_digest: str
    report_ref: str
    report_revision: int
    report_digest: str
    completion_digest: str


def canonical_finalization_intent_completion_digest(
    receipt: InvocationFinalizationIntentCompletionReceiptV2,
) -> str:
    payload = {
        "reference": receipt.intent_ref.reference,
        "revision": receipt.intent_ref.revision,
        "persistence_outcome_digest": receipt.persistence_outcome_digest,
        "report_ref": receipt.report_ref,
        "report_revision": receipt.report_revision,
        "report_digest": receipt.report_digest,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@runtime_checkable
class InvocationFinalizationIntentStoreV2(Protocol):
    def checkpoint(
        self,
        intent: InvocationFinalizationIntentRecordV2,
        update: InvocationFinalizationIntentCheckpointV2,
    ) -> InvocationFinalizationIntentRecordV2: ...
    def require(
        self,
        reference: InvocationFinalizationIntentRefV2,
    ) -> InvocationFinalizationIntentRecordV2: ...
    def require_current(
        self,
        stable_reference: str,
    ) -> InvocationFinalizationIntentRecordV2: ...
    def complete(
        self,
        intent_ref: InvocationFinalizationIntentRefV2,
        outcome: FinalizationPersistenceOutcomeV2,
        report: ActionExecutionReportEnvelopeV2,
    ) -> InvocationFinalizationIntentCompletionReceiptV2: ...
    def require_completion(
        self,
        intent_ref: InvocationFinalizationIntentRefV2,
    ) -> InvocationFinalizationIntentCompletionReceiptV2: ...
    def list_pending(self) -> tuple[InvocationFinalizationIntentRecordV2, ...]: ...


class DefaultInvocationFinalizationIntentStoreV2:
    """Production in-memory implementation of InvocationFinalizationIntentStoreV2."""

    def __init__(self) -> None:
        self._records: dict[str, InvocationFinalizationIntentRecordV2] = {}
        self._completions: dict[str, InvocationFinalizationIntentCompletionReceiptV2] = {}

    def checkpoint(
        self,
        intent: InvocationFinalizationIntentRecordV2,
        update: InvocationFinalizationIntentCheckpointV2,
    ) -> InvocationFinalizationIntentRecordV2:
        ref_key = intent.intent_ref.reference
        if ref_key in self._records:
            existing = self._records[ref_key]
            if existing.intent_ref.revision != update.expected_revision:
                raise ValueError(
                    f"Revision mismatch: expected {update.expected_revision}, got {existing.intent_ref.revision}"
                )
        else:
            self._records[ref_key] = intent

        new_revision = update.expected_revision + 1
        new_body = InvocationFinalizationIntentBodyV2(
            execution_id=intent.body.execution_id,
            action_id=intent.body.action_id,
            transaction_id=intent.body.transaction_id,
            phase=update.phase,
            ingress_recovery_ref=update.ingress_recovery_ref,
            cancellation_recovery_ref=update.cancellation_recovery_ref,
            continuation_recovery_ref=update.continuation_recovery_ref,
            approval_graph_recovery_ref=update.approval_graph_recovery_ref,
            attempt_recovery_ref=update.attempt_recovery_ref,
            checkout_recovery_ref=update.checkout_recovery_ref,
            scope_recovery_ref=update.scope_recovery_ref,
            coordinator_recovery_ref=update.coordinator_recovery_ref,
            provider_call_recovery_ref=update.provider_call_recovery_ref,
            effect_dispatch_authorization=update.effect_dispatch_authorization,
            primary_outcome=update.primary_outcome,
            prepared_finalization=update.prepared_finalization,
            report_publication=update.report_publication,
        )
        dummy_ref = InvocationFinalizationIntentRefV2(
            reference=ref_key,
            revision=new_revision,
            execution_id=intent.intent_ref.execution_id,
            action_id=intent.intent_ref.action_id,
            transaction_id=intent.intent_ref.transaction_id,
            intent_digest="",
        )
        temp_record = InvocationFinalizationIntentRecordV2(intent_ref=dummy_ref, body=new_body)
        digest = canonical_finalization_intent_digest(temp_record)
        final_ref = InvocationFinalizationIntentRefV2(
            reference=ref_key,
            revision=new_revision,
            execution_id=intent.intent_ref.execution_id,
            action_id=intent.intent_ref.action_id,
            transaction_id=intent.intent_ref.transaction_id,
            intent_digest=digest,
        )
        final_record = InvocationFinalizationIntentRecordV2(intent_ref=final_ref, body=new_body)
        self._records[ref_key] = final_record
        return final_record

    def require(
        self,
        reference: InvocationFinalizationIntentRefV2,
    ) -> InvocationFinalizationIntentRecordV2:
        record = self._records.get(reference.reference)
        if record is None:
            raise KeyError(f"No finalization intent record found for {reference.reference}")
        if record.intent_ref != reference:
            raise ValueError(f"Intent ref mismatch: stored {record.intent_ref} != requested {reference}")
        return record

    def require_current(
        self,
        stable_reference: str,
    ) -> InvocationFinalizationIntentRecordV2:
        record = self._records.get(stable_reference)
        if record is None:
            raise KeyError(f"No finalization intent record found for {stable_reference}")
        return record

    def complete(
        self,
        intent_ref: InvocationFinalizationIntentRefV2,
        outcome: FinalizationPersistenceOutcomeV2,
        report: ActionExecutionReportEnvelopeV2,
    ) -> InvocationFinalizationIntentCompletionReceiptV2:
        ref_key = intent_ref.reference
        current = self._records.get(ref_key)
        if current is None:
            raise KeyError(f"No finalization intent record found for {ref_key}")
        if current.intent_ref != intent_ref:
            raise ValueError("finalization intent revision mismatch")
        if type(report) is not ActionExecutionReportEnvelopeV2:
            raise TypeError("completion requires an exact report envelope")
        terminal = report.report
        if (
            terminal.execution_id != intent_ref.execution_id
            or terminal.action_id != intent_ref.action_id
            or terminal.transaction_id != intent_ref.transaction_id
        ):
            raise ValueError("finalization report identity mismatch")
        if type(outcome) is FinalizationPersistedV2:
            if terminal.finalization_ref != outcome.finalization_ref:
                raise ValueError("persisted finalization outcome/report mismatch")
        elif type(outcome) is FinalizationRetryEnqueuedV2:
            if terminal.finalization_retry_ref != outcome.retry_ref:
                raise ValueError("retry finalization outcome/report mismatch")
        else:
            raise TypeError("unknown finalization persistence outcome")

        persistence_digest = canonical_finalization_persistence_outcome_digest(outcome)
        receipt = InvocationFinalizationIntentCompletionReceiptV2(
            intent_ref=intent_ref,
            persistence_outcome_digest=persistence_digest,
            report_ref=report.report_ref,
            report_revision=report.report_revision,
            report_digest=report.report_digest,
            completion_digest="",
        )
        digest = canonical_finalization_intent_completion_digest(receipt)
        final_receipt = InvocationFinalizationIntentCompletionReceiptV2(
            intent_ref=intent_ref,
            persistence_outcome_digest=persistence_digest,
            report_ref=report.report_ref,
            report_revision=report.report_revision,
            report_digest=report.report_digest,
            completion_digest=digest,
        )
        existing = self._completions.get(ref_key)
        if existing is not None:
            if existing != final_receipt:
                raise ValueError("conflicting finalization intent completion")
            return existing
        self._completions[ref_key] = final_receipt
        return final_receipt

    def require_completion(
        self,
        intent_ref: InvocationFinalizationIntentRefV2,
    ) -> InvocationFinalizationIntentCompletionReceiptV2:
        receipt = self._completions.get(intent_ref.reference)
        if receipt is None:
            raise KeyError(f"No completion receipt found for {intent_ref.reference}")
        return receipt

    def list_pending(self) -> tuple[InvocationFinalizationIntentRecordV2, ...]:
        pending = [rec for ref, rec in self._records.items() if ref not in self._completions]
        return tuple(pending)


class ExecutionFinalizationFenceAuthorityV2:
    """Authority managing finalization fences across executors."""

    def __init__(self) -> None:
        self._fences: dict[str, Any] = {}

    def fence(self, tx_id: str) -> bool:
        self._fences[tx_id] = True
        return True


__all__ = [
    "DefaultInvocationFinalizationIntentStoreV2",
    "ExecutionFinalizationFenceAuthorityV2",
    "FinalizationRetryClaimRecordV2",
    "FinalizationRetryCompletionReceiptV2",
    "FinalizationRetryReconcilerV2",
    "FinalizationRetryRecordV2",
    "FinalizationRetryStateV2",
    "FinalizationRetryStoreV2",
    "InvocationFinalizationIntentBodyV2",
    "InvocationFinalizationIntentCheckpointV2",
    "InvocationFinalizationIntentCompletionReceiptV2",
    "InvocationFinalizationIntentPhaseV2",
    "InvocationFinalizationIntentRecordV2",
    "InvocationFinalizationIntentRefV2",
    "InvocationFinalizationIntentStoreV2",
    "canonical_finalization_intent_completion_digest",
    "canonical_finalization_intent_digest",
]
