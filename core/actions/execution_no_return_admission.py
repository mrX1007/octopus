"""Execution no-return admission store protocol and default implementation."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol, runtime_checkable

from core.actions.execution_recovery_types import (
    CancellationRecoveryRecordV2,
    ExecutionNoReturnAdmissionBodyV2,
    ExecutionNoReturnAdmissionReceiptV2,
    ExecutionNoReturnAdmissionRefV2,
    canonical_execution_no_return_admission_digest,
)

def canonical_digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(str(obj)).encode()).hexdigest()

@runtime_checkable
class ExecutionNoReturnAdmissionStoreV2(Protocol):
    def admit(
        self,
        *,
        cancellation: CancellationRecoveryRecordV2,
        transaction_id: str,
        decision_identity_digest: str,
        external_effect_participant_id: str | None,
        external_effect_registration_digest: str | None,
    ) -> ExecutionNoReturnAdmissionReceiptV2: ...

    def require(
        self,
        reference: ExecutionNoReturnAdmissionRefV2,
    ) -> ExecutionNoReturnAdmissionReceiptV2: ...

    def require_for_transaction(
        self,
        transaction_id: str,
    ) -> ExecutionNoReturnAdmissionReceiptV2 | None: ...


class DefaultExecutionNoReturnAdmissionStoreV2:
    """Production in-memory implementation of ExecutionNoReturnAdmissionStoreV2."""

    def __init__(self) -> None:
        self._store: dict[str, ExecutionNoReturnAdmissionReceiptV2] = {}

    def admit(
        self,
        *,
        cancellation: CancellationRecoveryRecordV2,
        transaction_id: str,
        decision_identity_digest: str,
        external_effect_participant_id: str | None = None,
        external_effect_registration_digest: str | None = None,
    ) -> ExecutionNoReturnAdmissionReceiptV2:
        if transaction_id in self._store:
            return self._store[transaction_id]

        body = ExecutionNoReturnAdmissionBodyV2(
            root_execution_id=cancellation.cancellation_ref.root_execution_id,
            execution_graph_id=cancellation.cancellation_ref.execution_graph_id,
            transaction_id=transaction_id,
            cancellation_revision=cancellation.cancellation_ref.revision,
            decision_identity_digest=decision_identity_digest,
            external_effect_participant_id=external_effect_participant_id,
            external_effect_registration_digest=external_effect_registration_digest,
        )
        admission_digest = canonical_execution_no_return_admission_digest(body)
        admission_ref = ExecutionNoReturnAdmissionRefV2(
            reference=f"adm:{transaction_id}",
            revision=1,
            transaction_id=transaction_id,
            admission_digest=admission_digest,
        )
        receipt = ExecutionNoReturnAdmissionReceiptV2(
            admission_ref=admission_ref,
            body=body,
        )
        self._store[transaction_id] = receipt
        return receipt

    def require(
        self,
        reference: ExecutionNoReturnAdmissionRefV2,
    ) -> ExecutionNoReturnAdmissionReceiptV2:
        receipt = self._store.get(reference.transaction_id)
        if receipt is None:
            raise KeyError(f"No admission receipt found for transaction {reference.transaction_id}")
        if receipt.admission_ref != reference:
            raise ValueError(f"Admission ref mismatch: stored {receipt.admission_ref} != requested {reference}")
        return receipt

    def require_for_transaction(
        self,
        transaction_id: str,
    ) -> ExecutionNoReturnAdmissionReceiptV2 | None:
        return self._store.get(transaction_id)
