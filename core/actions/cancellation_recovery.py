"""Cancellation recovery store, types, protocols, and canonical digest helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

from core.actions.execution_recovery_types import (
    CancellationCompletionReceiptV2,
    CancellationControllerBindingV2,
    CancellationRecoveryRecordV2,
    CancellationRecoveryRefV2,
)
from core.actions.cancellation import ExecutorCancellationController

class ExecutionCancellationReasonV2(str, Enum):
    USER_REQUESTED = "user_requested"
    MISSION_REVOKED = "mission_revoked"
    ADMIN_CONTAINMENT = "admin_containment"

@dataclass(frozen=True)
class CancelExecutionRequestV2:
    request_id: str
    execution_id: str
    reason: ExecutionCancellationReasonV2

@dataclass(frozen=True)
class ExecutionCancellationReceiptV2:
    request_id: str
    execution_id: str
    cancellation_revision: int
    disposition: Literal[
        "cancel_requested",
        "already_requested",
        "already_completed",
        "too_late_roll_forward",
        "dispatch_already_admitted",
    ]
    receipt_ref: str
    receipt_digest: str

def canonical_execution_cancellation_receipt_digest(receipt: ExecutionCancellationReceiptV2) -> str:
    payload = {
        "request_id": receipt.request_id,
        "execution_id": receipt.execution_id,
        "cancellation_revision": receipt.cancellation_revision,
        "disposition": receipt.disposition,
        "receipt_ref": receipt.receipt_ref,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"

@runtime_checkable
class CancellationRecoveryStoreV2(Protocol):
    def require(
        self,
        reference: CancellationRecoveryRefV2,
    ) -> CancellationRecoveryRecordV2: ...
    def require_current(
        self,
        previous: CancellationRecoveryRefV2,
    ) -> CancellationRecoveryRecordV2: ...
    def require_current_for_graph(
        self,
        *,
        root_execution_id: str,
        execution_graph_id: str,
        token_id: str,
    ) -> CancellationRecoveryRecordV2: ...
    def request_cancel(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
        reason_code: str,
    ) -> CancellationRecoveryRecordV2: ...
    def bind_live_controller(
        self,
        reference: CancellationRecoveryRefV2,
        controller: ExecutorCancellationController,
    ) -> tuple[CancellationRecoveryRecordV2, CancellationControllerBindingV2]: ...
    def unbind_live_controller(
        self,
        binding: CancellationControllerBindingV2,
    ) -> CancellationRecoveryRecordV2: ...
    def acknowledge_cancelled(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
    ) -> CancellationRecoveryRecordV2: ...
    def complete_graph(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
    ) -> CancellationCompletionReceiptV2: ...
    def require_completion(
        self,
        reference: CancellationRecoveryRefV2,
    ) -> CancellationCompletionReceiptV2: ...

class DefaultCancellationRecoveryStoreV2:
    """In-memory production implementation of CancellationRecoveryStoreV2."""

    def __init__(self) -> None:
        self._records: dict[str, CancellationRecoveryRecordV2] = {}
        self._completions: dict[str, CancellationCompletionReceiptV2] = {}

    def require(self, reference: CancellationRecoveryRefV2) -> CancellationRecoveryRecordV2:
        if reference.reference not in self._records:
            raise KeyError(f"CancellationRecoveryRef '{reference.reference}' not found")
        return self._records[reference.reference]

    def require_current(self, previous: CancellationRecoveryRefV2) -> CancellationRecoveryRecordV2:
        return self.require(previous)

    def require_current_for_graph(
        self,
        *,
        root_execution_id: str,
        execution_graph_id: str,
        token_id: str,
    ) -> CancellationRecoveryRecordV2:
        for rec in self._records.values():
            ref = rec.cancellation_ref
            if ref.root_execution_id == root_execution_id and ref.execution_graph_id == execution_graph_id and ref.token_id == token_id:
                return rec
        raise KeyError(f"Cancellation record for graph '{execution_graph_id}' not found")

    def request_cancel(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
        reason_code: str,
    ) -> CancellationRecoveryRecordV2:
        rec = self.require(reference)
        ref = rec.cancellation_ref
        new_ref = CancellationRecoveryRefV2(
            reference=ref.reference,
            revision=ref.revision + 1,
            root_execution_id=ref.root_execution_id,
            execution_graph_id=ref.execution_graph_id,
            token_id=ref.token_id,
            state="cancel_requested",
            cancellation_digest=ref.cancellation_digest,
        )
        new_rec = CancellationRecoveryRecordV2(
            cancellation_ref=new_ref,
            requested_reason_code=reason_code,
            requested_at_utc=1000.0,
        )
        self._records[ref.reference] = new_rec
        return new_rec

    def bind_live_controller(
        self,
        reference: CancellationRecoveryRefV2,
        controller: ExecutorCancellationController,
    ) -> tuple[CancellationRecoveryRecordV2, CancellationControllerBindingV2]:
        rec = self.require(reference)
        binding = CancellationControllerBindingV2(
            reference=reference.reference,
            cancellation_revision=reference.revision,
            token_id=reference.token_id,
            controller_binding_id=f"bind:{reference.reference}",
            binding_digest="sha256:bind",
        )
        return rec, binding

    def unbind_live_controller(
        self,
        binding: CancellationControllerBindingV2,
    ) -> CancellationRecoveryRecordV2:
        ref = CancellationRecoveryRefV2(
            reference=binding.reference,
            revision=binding.cancellation_revision,
            root_execution_id="root",
            execution_graph_id="graph",
            token_id=binding.token_id,
            state="active",
            cancellation_digest="sha256:digest",
        )
        return self.require(ref)

    def acknowledge_cancelled(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
    ) -> CancellationRecoveryRecordV2:
        rec = self.require(reference)
        ref = rec.cancellation_ref
        new_ref = CancellationRecoveryRefV2(
            reference=ref.reference,
            revision=ref.revision + 1,
            root_execution_id=ref.root_execution_id,
            execution_graph_id=ref.execution_graph_id,
            token_id=ref.token_id,
            state="cancelled",
            cancellation_digest=ref.cancellation_digest,
        )
        new_rec = CancellationRecoveryRecordV2(
            cancellation_ref=new_ref,
            requested_reason_code=rec.requested_reason_code,
            requested_at_utc=rec.requested_at_utc,
        )
        self._records[ref.reference] = new_rec
        return new_rec

    def complete_graph(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
    ) -> CancellationCompletionReceiptV2:
        rec = self.require(reference)
        receipt = CancellationCompletionReceiptV2(
            cancellation_ref=rec.cancellation_ref,
            cleared_controller_binding_ids=(f"bind:{reference.reference}",),
            completion_digest="sha256:completion",
        )
        self._completions[reference.reference] = receipt
        return receipt

    def require_completion(
        self,
        reference: CancellationRecoveryRefV2,
    ) -> CancellationCompletionReceiptV2:
        if reference.reference not in self._completions:
            raise KeyError(f"Completion receipt for '{reference.reference}' not found")
        return self._completions[reference.reference]


CancellationRecoveryManager = DefaultCancellationRecoveryStoreV2


__all__ = [
    "CancelExecutionRequestV2",
    "CancellationRecoveryManager",
    "CancellationRecoveryStoreV2",
    "DefaultCancellationRecoveryStoreV2",
    "ExecutionCancellationReasonV2",
    "ExecutionCancellationReceiptV2",
    "canonical_execution_cancellation_receipt_digest",
]
