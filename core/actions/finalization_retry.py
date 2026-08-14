"""PR-5 Module: Finalization retry definitions (§8.7)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FinalizationRetryStateV2(str, Enum):
    ENQUEUED = "enqueued"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class FinalizationRetryRecordV2:
    retry_id: str
    execution_id: str
    action_id: str
    transaction_id: str
    state: FinalizationRetryStateV2 = FinalizationRetryStateV2.ENQUEUED
    attempt_count: int = 0


@dataclass(frozen=True)
class FinalizationRetryClaimRecordV2:
    claim_id: str
    retry_id: str
    claimant_id: str
    leased_until: float


@dataclass(frozen=True)
class FinalizationRetryCompletionReceiptV2:
    retry_id: str
    receipt_digest: str


class FinalizationRetryStoreV2:
    def __init__(self) -> None:
        self._records: dict[str, FinalizationRetryRecordV2] = {}

    def enqueue(self, record: FinalizationRetryRecordV2) -> None:
        self._records[record.retry_id] = record

    def get(self, retry_id: str) -> FinalizationRetryRecordV2 | None:
        return self._records.get(retry_id)


class FinalizationRetryReconcilerV2:
    def reconcile(self, store: FinalizationRetryStoreV2) -> int:
        return 0


__all__ = [
    "FinalizationRetryClaimRecordV2",
    "FinalizationRetryCompletionReceiptV2",
    "FinalizationRetryReconcilerV2",
    "FinalizationRetryRecordV2",
    "FinalizationRetryStateV2",
    "FinalizationRetryStoreV2",
]
