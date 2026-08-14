"""Control models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum


class ParticipantControlPhaseV1(str, Enum):
    PENDING = "pending"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED_VISIBLE = "finalized_visible"
    ABORTED = "aborted"
    FAILED = "failed"


@dataclass(frozen=True)
class ControlRequestDigest:
    request_digest: str
    payload_digest: str

    def __post_init__(self) -> None:
        if not self.request_digest:
            raise ValueError("request_digest must not be empty")
        if not self.payload_digest:
            raise ValueError("payload_digest must not be empty")


@dataclass(frozen=True)
class ControlPayloadDigest:
    schema_id: str
    digest: str
    canonical_b64u: str

    def __post_init__(self) -> None:
        if not self.schema_id:
            raise ValueError("schema_id must not be empty")
        if not self.digest:
            raise ValueError("digest must not be empty")


def calculate_payload_digest(payload: bytes | str | dict) -> str:
    """Calculate SHA-256 hex digest of payload data."""
    if isinstance(payload, dict):
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = payload
    return hashlib.sha256(raw).hexdigest()


def calculate_request_digest(
    action: str,
    payload_digest: str,
    mission_id: str,
    subject_id: str,
    nonce: str,
) -> str:
    """Calculate SHA-256 hex digest of control request fields."""
    components = f"{action}:{payload_digest}:{mission_id}:{subject_id}:{nonce}"
    return hashlib.sha256(components.encode("utf-8")).hexdigest()


def calculate_receipt_digest(
    transaction_id: str,
    participant_id: str,
    receipt_ref: str,
    result_payload_digest: str | None = None,
) -> str:
    """Calculate SHA-256 hex digest of participant control receipt."""
    res_dig = result_payload_digest or ""
    components = f"{transaction_id}:{participant_id}:{receipt_ref}:{res_dig}"
    return hashlib.sha256(components.encode("utf-8")).hexdigest()


def calculate_snapshot_digest(
    transaction_id: str,
    participant_id: str,
    phase: str,
    receipt_digest: str | None = None,
) -> str:
    """Calculate SHA-256 hex digest of participant query snapshot."""
    rec_dig = receipt_digest or ""
    components = f"{transaction_id}:{participant_id}:{phase}:{rec_dig}"
    return hashlib.sha256(components.encode("utf-8")).hexdigest()
