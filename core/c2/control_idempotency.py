"""Mission and subject-bound idempotency for control plane operations (§14.6)."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Any, Dict, Optional, Tuple


class IdempotencyStateV1(str, Enum):
    PENDING = "pending"
    COMMITTED = "committed"
    FAILED = "failed"


@dataclass(frozen=True)
class IdempotencyRecordV1:
    operator_id: str
    subject_id: str
    mission_id: str
    action: str
    idempotency_key: str
    request_id: str
    payload_schema_id: str
    payload_digest: str
    state: IdempotencyStateV1
    created_at: float
    response_json: Optional[str] = None


class IdempotencyConflictError(ValueError):
    """Raised when an idempotency key is reused with a different binding or payload."""


def compute_idempotency_fingerprint(
    operator_id: str,
    subject_id: str,
    mission_id: str,
    action: str,
    payload_schema_id: str,
    payload_digest: str,
) -> str:
    """Compute domain-separated canonical digest of idempotency binding."""
    raw = (
        f"OCTOPUS-IDEMPOTENCY-V1:{operator_id}:{subject_id}:{mission_id}:"
        f"{action}:{payload_schema_id}:{payload_digest}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class IdempotencyStoreV1:
    """Thread-safe in-memory/durable idempotency store with strict binding enforcement."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._by_key: Dict[Tuple[str, str, str, str, str], IdempotencyRecordV1] = {}
        self._by_request_id: Dict[Tuple[str, str], IdempotencyRecordV1] = {}

    def reserve(
        self,
        *,
        operator_id: str,
        subject_id: str,
        mission_id: str,
        action: str,
        idempotency_key: str,
        request_id: str,
        payload_schema_id: str,
        payload_digest: str,
        now: Optional[float] = None,
    ) -> IdempotencyRecordV1:
        ts = time.time() if now is None else now
        key_tuple = (operator_id, subject_id, mission_id, action, idempotency_key)
        req_tuple = (operator_id, request_id)

        with self._lock:
            # Check existing idempotency key
            if key_tuple in self._by_key:
                existing = self._by_key[key_tuple]
                if (
                    existing.subject_id != subject_id
                    or existing.mission_id != mission_id
                    or existing.action != action
                    or existing.payload_schema_id != payload_schema_id
                    or existing.payload_digest != payload_digest
                ):
                    raise IdempotencyConflictError(
                        f"Idempotency key {idempotency_key} already used with different payload or binding"
                    )
                return existing

            # Check existing request_id
            if req_tuple in self._by_request_id:
                existing_req = self._by_request_id[req_tuple]
                if (
                    existing_req.subject_id != subject_id
                    or existing_req.mission_id != mission_id
                    or existing_req.action != action
                    or existing_req.payload_digest != payload_digest
                ):
                    raise IdempotencyConflictError(
                        f"Request ID {request_id} already used with different parameters"
                    )
                return existing_req

            rec = IdempotencyRecordV1(
                operator_id=operator_id,
                subject_id=subject_id,
                mission_id=mission_id,
                action=action,
                idempotency_key=idempotency_key,
                request_id=request_id,
                payload_schema_id=payload_schema_id,
                payload_digest=payload_digest,
                state=IdempotencyStateV1.PENDING,
                created_at=ts,
            )
            self._by_key[key_tuple] = rec
            self._by_request_id[req_tuple] = rec
            return rec

    def commit(
        self,
        *,
        operator_id: str,
        subject_id: str,
        mission_id: str,
        action: str,
        idempotency_key: str,
        response_data: Any,
    ) -> IdempotencyRecordV1:
        key_tuple = (operator_id, subject_id, mission_id, action, idempotency_key)
        with self._lock:
            existing = self._by_key.get(key_tuple)
            if existing is None:
                raise KeyError(f"No pending reservation for {idempotency_key}")
            resp_str = json.dumps(response_data, sort_keys=True) if response_data is not None else None
            updated = IdempotencyRecordV1(
                operator_id=existing.operator_id,
                subject_id=existing.subject_id,
                mission_id=existing.mission_id,
                action=existing.action,
                idempotency_key=existing.idempotency_key,
                request_id=existing.request_id,
                payload_schema_id=existing.payload_schema_id,
                payload_digest=existing.payload_digest,
                state=IdempotencyStateV1.COMMITTED,
                created_at=existing.created_at,
                response_json=resp_str,
            )
            self._by_key[key_tuple] = updated
            self._by_request_id[(existing.operator_id, existing.request_id)] = updated
            return updated
