"""Control plane enrollment request and receipt DTOs (§15.7)."""

from __future__ import annotations

from dataclasses import dataclass

ENROLLMENT_PAYLOAD_SCHEMA_V1 = "c2:enrollment:control-payload:1.0"


@dataclass(frozen=True)
class EnrollmentControlPayloadV1:
    profile_id: str
    channel_ref: str
    target_id: str
    max_uses: int = 1
    expires_in_seconds: float = 3600.0
    operator_id: str | None = None
    subject_id: str | None = None
    mission_id: str | None = None


@dataclass(frozen=True)
class EnrollmentControlReceiptV1:
    enrollment_ref: str
    token_preview: str
    expires_at: float
    max_uses: int
    revision: int = 1
