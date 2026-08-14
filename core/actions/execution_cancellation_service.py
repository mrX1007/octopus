"""Execution cancellation service protocols and canonical implementations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.actions.cancellation_recovery import (
    CancelExecutionRequestV2,
    ExecutionCancellationReceiptV2,
    canonical_execution_cancellation_receipt_digest,
)


@runtime_checkable
class ExecutionCancellationServiceV2(Protocol):
    def request_cancel(
        self,
        request: CancelExecutionRequestV2,
    ) -> ExecutionCancellationReceiptV2: ...


class DefaultExecutionCancellationServiceV2:
    """In-memory production implementation of ExecutionCancellationServiceV2."""

    def __init__(self) -> None:
        self._cancellations: dict[str, ExecutionCancellationReceiptV2] = {}

    def request_cancel(
        self,
        request: CancelExecutionRequestV2,
    ) -> ExecutionCancellationReceiptV2:
        if request.request_id in self._cancellations:
            return self._cancellations[request.request_id]

        dummy = ExecutionCancellationReceiptV2(
            request_id=request.request_id,
            execution_id=request.execution_id,
            cancellation_revision=1,
            disposition="cancel_requested",
            receipt_ref=f"receipt:{request.request_id}",
            receipt_digest="",
        )
        digest = canonical_execution_cancellation_receipt_digest(dummy)
        receipt = ExecutionCancellationReceiptV2(
            request_id=request.request_id,
            execution_id=request.execution_id,
            cancellation_revision=1,
            disposition="cancel_requested",
            receipt_ref=f"receipt:{request.request_id}",
            receipt_digest=digest,
        )
        self._cancellations[request.request_id] = receipt
        return receipt


ExecutionCancellationService = DefaultExecutionCancellationServiceV2


__all__ = [
    "DefaultExecutionCancellationServiceV2",
    "ExecutionCancellationService",
    "ExecutionCancellationServiceV2",
]
