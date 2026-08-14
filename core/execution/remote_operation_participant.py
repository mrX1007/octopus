from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol, runtime_checkable

from core.actions.checkout_models import CheckoutRecoveryRefV2
from core.actions.execution_recovery_types import ExecutionFinalizationFenceV2
from core.execution.remote_operation_models import (
    RemoteOperationBackendRequestV1,
    RemoteOperationEffectDispositionV1,
    RemoteOperationEffectProbeV1,
    RemoteOperationEffectReceiptV1,
    RemoteOperationPlanV1,
)


@dataclass(frozen=True)
class ParticipantRetryPolicyV2:
    max_attempts: int = 3
    initial_backoff_ms: int = 100
    max_backoff_ms: int = 1000


@dataclass(frozen=True)
class ParticipantOperationContextV2:
    operation_attempt_id: str = ""
    absolute_deadline_monotonic: float = 0.0
    retry_policy: ParticipantRetryPolicyV2 | None = None


@dataclass
class ParticipantPrepareRequestV2:
    transaction_id: str
    participant_id: str
    operation: ParticipantOperationContextV2


@dataclass
class ParticipantPrepareOutcomeV2:
    participant_id: str
    is_ready: bool
    prepare_receipt: ParticipantPrepareReceiptV2 | None = None
    error: str | None = None


@dataclass
class ParticipantCommitRequestV2:
    transaction_id: str
    participant_id: str
    prepare_receipt: ParticipantPrepareReceiptV2
    operation: ParticipantOperationContextV2


@dataclass
class ParticipantCommitReceiptV2:
    participant_id: str
    success: bool
    effect_receipt: RemoteOperationEffectReceiptV1 | None = None
    error: str | None = None


@dataclass
class ParticipantPrepareReceiptV2:
    participant_id: str
    plan_digest: str


@dataclass
class ParticipantFinalizeReceiptV2:
    participant_id: str
    finalized: bool


@dataclass
class ParticipantRollbackReceiptV2:
    participant_id: str
    rolled_back: bool


@dataclass
class ParticipantReconcileResultV2:
    participant_id: str
    reconciled: bool


@runtime_checkable
class ExecutionCommitParticipant(Protocol):
    participant_id: str
    transaction_id: str


class ParticipantKindV2(str, Enum):
    EXTERNAL_EFFECT = "external_effect"


class ExternalEffectKindV2(str, Enum):
    REMOTE_OPERATION = "remote_operation"


@runtime_checkable
class RemoteOperationBackendV1(Protocol):
    def dispatch(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectReceiptV1: ...

    def probe(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectProbeV1: ...


@runtime_checkable
class RemoteOperationCredentialLeaseV1(Protocol):
    @property
    def lease_id(self) -> str: ...

    def transfer_to_protected_worker_channel(
        self,
        *,
        backend_request_digest: str,
    ) -> str: ...

    def close_and_zeroize(self) -> None: ...


@dataclass
class DefaultRemoteOperationCredentialLeaseV1:
    _lease_id: str
    _is_closed: bool = False

    @property
    def lease_id(self) -> str:
        return self._lease_id

    @property
    def is_closed(self) -> bool:
        return self._is_closed

    def transfer_to_protected_worker_channel(
        self,
        *,
        backend_request_digest: str,
    ) -> str:
        if self._is_closed:
            raise RuntimeError("Lease is closed")
        return f"protected-channel-{self._lease_id}-{backend_request_digest}"

    def close_and_zeroize(self) -> None:
        self._is_closed = True


@runtime_checkable
class RemoteOperationCredentialResolverV1(Protocol):
    def acquire(
        self,
        *,
        plan: RemoteOperationPlanV1,
        checkout_recovery_ref: CheckoutRecoveryRefV2,
        mission_id: str,
        subject_id: str,
        target: str,
        operation: ParticipantOperationContextV2,
        fence: ExecutionFinalizationFenceV2,
    ) -> RemoteOperationCredentialLeaseV1: ...


class DefaultRemoteOperationCredentialResolverV1:
    def acquire(
        self,
        *,
        plan: RemoteOperationPlanV1,
        checkout_recovery_ref: CheckoutRecoveryRefV2,
        mission_id: str,
        subject_id: str,
        target: str,
        operation: ParticipantOperationContextV2,
        fence: ExecutionFinalizationFenceV2,
    ) -> RemoteOperationCredentialLeaseV1:
        if not plan.credential_ref:
            raise ValueError("Plan credential reference cannot be empty")
        if target and plan.target and target != plan.target:
            raise ValueError(f"Target mismatch: requested '{target}', plan target is '{plan.target}'")
        lease_id = f"lease-{plan.credential_ref}-{plan.credential_revision}-{mission_id or 'default'}-{subject_id or 'default'}"
        return DefaultRemoteOperationCredentialLeaseV1(_lease_id=lease_id)


class RemoteOperationExternalEffectParticipant(ExecutionCommitParticipant):
    participant_id: str
    transaction_id: str
    participant_kind: Literal[ParticipantKindV2.EXTERNAL_EFFECT]
    effect_kind: Literal[ExternalEffectKindV2.REMOTE_OPERATION]

    def __init__(
        self,
        participant_id: str,
        transaction_id: str,
        backend: RemoteOperationBackendV1,
        plan: RemoteOperationPlanV1,
        credential_resolver: RemoteOperationCredentialResolverV1 | None = None,
    ):
        self.participant_id = participant_id
        self.transaction_id = transaction_id
        self.participant_kind = ParticipantKindV2.EXTERNAL_EFFECT
        self.effect_kind = ExternalEffectKindV2.REMOTE_OPERATION
        self.backend = backend
        self.plan = plan
        self.credential_resolver = credential_resolver or DefaultRemoteOperationCredentialResolverV1()

    def prepare(self, request: ParticipantPrepareRequestV2) -> ParticipantPrepareOutcomeV2:
        if request.transaction_id != self.transaction_id:
            return ParticipantPrepareOutcomeV2(
                participant_id=self.participant_id,
                is_ready=False,
                error=f"Transaction ID mismatch: expected {self.transaction_id}, got {request.transaction_id}",
            )
        if request.participant_id != self.participant_id:
            return ParticipantPrepareOutcomeV2(
                participant_id=self.participant_id,
                is_ready=False,
                error=f"Participant ID mismatch: expected {self.participant_id}, got {request.participant_id}",
            )

        receipt = ParticipantPrepareReceiptV2(participant_id=self.participant_id, plan_digest=self.plan.plan_digest)
        return ParticipantPrepareOutcomeV2(participant_id=self.participant_id, is_ready=True, prepare_receipt=receipt)

    def commit(self, request: ParticipantCommitRequestV2) -> ParticipantCommitReceiptV2:
        if request.transaction_id != self.transaction_id:
            return ParticipantCommitReceiptV2(
                participant_id=self.participant_id,
                success=False,
                error=f"Transaction ID mismatch: expected {self.transaction_id}, got {request.transaction_id}",
            )
        if request.participant_id != self.participant_id:
            return ParticipantCommitReceiptV2(
                participant_id=self.participant_id,
                success=False,
                error=f"Participant ID mismatch: expected {self.participant_id}, got {request.participant_id}",
            )
        if request.prepare_receipt.plan_digest != self.plan.plan_digest:
            return ParticipantCommitReceiptV2(
                participant_id=self.participant_id, success=False, error="Plan digest mismatch"
            )

        import time

        backend_request = RemoteOperationBackendRequestV1(
            attempt_id=self.plan.attempt_id,
            idempotency_key=self.plan.idempotency_key,
            plan_ref=self.plan.operation_payload_ref,
            plan_digest=self.plan.plan_digest,
            absolute_deadline_monotonic=time.monotonic() + 30.0,
        )

        try:
            effect_receipt = self.backend.dispatch(backend_request)
            return ParticipantCommitReceiptV2(
                participant_id=self.participant_id, success=True, effect_receipt=effect_receipt
            )
        except Exception as e:
            return ParticipantCommitReceiptV2(participant_id=self.participant_id, success=False, error=str(e))

    def finalize_visibility(
        self,
        prepare_receipt: ParticipantPrepareReceiptV2,
        commit_receipt: ParticipantCommitReceiptV2,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantFinalizeReceiptV2:
        if prepare_receipt.participant_id != self.participant_id:
            return ParticipantFinalizeReceiptV2(participant_id=self.participant_id, finalized=False)
        return ParticipantFinalizeReceiptV2(participant_id=self.participant_id, finalized=True)

    def rollback(
        self,
        receipt: ParticipantPrepareReceiptV2 | None,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantRollbackReceiptV2:
        return ParticipantRollbackReceiptV2(participant_id=self.participant_id, rolled_back=True)

    def reconcile(
        self,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantReconcileResultV2:
        backend_request = RemoteOperationBackendRequestV1(
            attempt_id=self.plan.attempt_id,
            idempotency_key=self.plan.idempotency_key,
            plan_ref=self.plan.operation_payload_ref,
            plan_digest=self.plan.plan_digest,
            absolute_deadline_monotonic=0.0,
        )
        try:
            probe = self.backend.probe(backend_request)
            reconciled = probe.disposition != RemoteOperationEffectDispositionV1.UNKNOWN
            return ParticipantReconcileResultV2(participant_id=self.participant_id, reconciled=reconciled)
        except Exception:
            return ParticipantReconcileResultV2(participant_id=self.participant_id, reconciled=False)
