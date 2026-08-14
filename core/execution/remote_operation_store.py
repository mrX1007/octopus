from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol, runtime_checkable

from core.execution.remote_operation_models import RemoteOperationOutputReservationRefV1


@runtime_checkable
class RemoteOperationStoreV1(Protocol):
    def reserve_output_schema(
        self, transaction_id: str, operation_id: str, schema_id: str
    ) -> RemoteOperationOutputReservationRefV1: ...


class DefaultRemoteOperationStoreV1:
    def __init__(self) -> None:
        self._reservations: dict[str, RemoteOperationOutputReservationRefV1] = {}
        self._outputs: dict[str, dict[str, Any]] = {}
        self._state_cas: dict[str, str] = {}

    def _compute_digest(self, data: dict) -> str:
        s = json.dumps(data, sort_keys=True)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def reserve_output_schema(
        self, transaction_id: str, operation_id: str, schema_id: str
    ) -> RemoteOperationOutputReservationRefV1:
        if not transaction_id or not operation_id or not schema_id:
            raise ValueError("transaction_id, operation_id, and schema_id must non-empty strings")

        key = f"{transaction_id}:{operation_id}"

        reservation_revision = 1
        if key in self._reservations:
            reservation_revision = self._reservations[key].reservation_revision + 1

        data = {
            "transaction_id": transaction_id,
            "operation_id": operation_id,
            "output_schema_id": schema_id,
            "revision": reservation_revision,
        }
        digest = self._compute_digest(data)

        ref = RemoteOperationOutputReservationRefV1(
            reference=f"res-{digest[:8]}",
            transaction_id=transaction_id,
            operation_id=operation_id,
            output_schema_id=schema_id,
            reservation_revision=reservation_revision,
            reservation_digest=digest,
        )
        self._reservations[key] = ref
        return ref

    def get_reservation(self, transaction_id: str, operation_id: str) -> RemoteOperationOutputReservationRefV1 | None:
        key = f"{transaction_id}:{operation_id}"
        return self._reservations.get(key)

    def validate_reservation(self, ref: RemoteOperationOutputReservationRefV1) -> bool:
        if not ref:
            return False
        key = f"{ref.transaction_id}:{ref.operation_id}"
        stored = self._reservations.get(key)
        if stored is None:
            return False
        return (
            stored.reservation_revision == ref.reservation_revision
            and stored.reservation_digest == ref.reservation_digest
            and stored.output_schema_id == ref.output_schema_id
        )

    def record_output(
        self,
        reservation_ref: RemoteOperationOutputReservationRefV1,
        output: Any,
        output_digest: str,
    ) -> bool:
        if not self.validate_reservation(reservation_ref):
            return False
        key = f"{reservation_ref.transaction_id}:{reservation_ref.operation_id}"
        self._outputs[key] = {"output": output, "output_digest": output_digest, "reservation_ref": reservation_ref}
        return True

    def get_output(self, transaction_id: str, operation_id: str) -> dict[str, Any] | None:
        key = f"{transaction_id}:{operation_id}"
        return self._outputs.get(key)

    def clear(self) -> None:
        self._reservations.clear()
        self._outputs.clear()
        self._state_cas.clear()
