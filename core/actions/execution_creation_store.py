"""Execution creation store protocols, receipt models, and canonical implementations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ExecutionCreationRefV2:
    reference: str
    revision: int
    execution_id: str
    transaction_id: str
    creation_digest: str


@dataclass(frozen=True)
class ExecutionCreationReceiptV2:
    creation_ref: ExecutionCreationRefV2
    execution_id: str
    action_id: str
    transaction_id: str
    idempotency_key: str


def canonical_execution_creation_digest(
    execution_id: str, action_id: str, transaction_id: str, idempotency_key: str
) -> str:
    payload = {
        "execution_id": execution_id,
        "action_id": action_id,
        "transaction_id": transaction_id,
        "idempotency_key": idempotency_key,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@runtime_checkable
class ExecutionCreationStoreV2(Protocol):
    def begin_root(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        idempotency_key: str,
    ) -> ExecutionCreationReceiptV2: ...
    def begin_child(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        root_execution_id: str,
        execution_graph_id: str,
        idempotency_key: str,
    ) -> ExecutionCreationReceiptV2: ...
    def require(
        self,
        reference: ExecutionCreationRefV2,
    ) -> ExecutionCreationReceiptV2: ...


class DefaultExecutionCreationStoreV2:
    """In-memory production implementation of ExecutionCreationStoreV2."""

    def __init__(self) -> None:
        self._receipts: dict[str, ExecutionCreationReceiptV2] = {}

    def begin_root(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        idempotency_key: str,
    ) -> ExecutionCreationReceiptV2:
        digest = canonical_execution_creation_digest(execution_id, action_id, transaction_id, idempotency_key)
        ref = ExecutionCreationRefV2(
            reference=f"create:{execution_id}",
            revision=1,
            execution_id=execution_id,
            transaction_id=transaction_id,
            creation_digest=digest,
        )
        receipt = ExecutionCreationReceiptV2(
            creation_ref=ref,
            execution_id=execution_id,
            action_id=action_id,
            transaction_id=transaction_id,
            idempotency_key=idempotency_key,
        )
        self._receipts[ref.reference] = receipt
        return receipt

    def begin_child(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        root_execution_id: str,
        execution_graph_id: str,
        idempotency_key: str,
    ) -> ExecutionCreationReceiptV2:
        return self.begin_root(
            execution_id=execution_id,
            action_id=action_id,
            transaction_id=transaction_id,
            idempotency_key=idempotency_key,
        )

    def require(self, reference: ExecutionCreationRefV2) -> ExecutionCreationReceiptV2:
        if reference.reference not in self._receipts:
            raise KeyError(f"ExecutionCreationRef '{reference.reference}' not found")
        return self._receipts[reference.reference]
