"""C2 Enrollment service managing enrollment state machine transitions (§15.7, §16.2)."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from threading import RLock
from typing import Dict, List, Optional


class EnrollmentStateV1:
    ISSUED = "issued"
    RESERVED_FOR_BUILD = "reserved_for_build"
    EMBEDDED_IN_ARTIFACT = "embedded_in_artifact"
    RESERVED_FOR_DEPLOYMENT = "reserved_for_deployment"
    CONSUMED_BY_AGENT = "consumed_by_agent"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class EnrollmentRecordV1:
    enrollment_ref: str
    token: str
    token_hash: str
    profile_id: str
    channel_ref: str
    target_id: str
    state: str
    max_uses: int
    used_count: int
    created_at: float
    expires_at: float
    revision: int = 1


class EnrollmentService:
    """Thread-safe enrollment lifecycle manager."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: Dict[str, EnrollmentRecordV1] = {}

    def issue(
        self,
        *,
        profile_id: str,
        channel_ref: str,
        target_id: str,
        max_uses: int = 1,
        expires_in_seconds: float = 3600.0,
        now: Optional[float] = None,
    ) -> EnrollmentRecordV1:
        ts = time.time() if now is None else now
        tok = secrets.token_urlsafe(32)
        tok_hash = hashlib.sha256(tok.encode("utf-8")).hexdigest()
        ref = f"enr_{secrets.token_hex(6)}"

        rec = EnrollmentRecordV1(
            enrollment_ref=ref,
            token=tok,
            token_hash=tok_hash,
            profile_id=profile_id,
            channel_ref=channel_ref,
            target_id=target_id,
            state=EnrollmentStateV1.ISSUED,
            max_uses=max_uses,
            used_count=0,
            created_at=ts,
            expires_at=ts + expires_in_seconds,
            revision=1,
        )
        with self._lock:
            self._records[ref] = rec
        return rec

    def get(self, enrollment_ref: str) -> Optional[EnrollmentRecordV1]:
        with self._lock:
            return self._records.get(enrollment_ref)

    def reserve_for_build(self, enrollment_ref: str, expected_revision: int) -> EnrollmentRecordV1:
        with self._lock:
            existing = self._records.get(enrollment_ref)
            if existing is None:
                raise KeyError(f"Enrollment {enrollment_ref} not found")
            if existing.revision != expected_revision:
                raise ValueError(f"Revision mismatch: expected {expected_revision}, got {existing.revision}")
            if existing.state != EnrollmentStateV1.ISSUED:
                raise ValueError(f"Cannot reserve enrollment in state {existing.state}")

            updated = EnrollmentRecordV1(
                enrollment_ref=existing.enrollment_ref,
                token=existing.token,
                token_hash=existing.token_hash,
                profile_id=existing.profile_id,
                channel_ref=existing.channel_ref,
                target_id=existing.target_id,
                state=EnrollmentStateV1.RESERVED_FOR_BUILD,
                max_uses=existing.max_uses,
                used_count=existing.used_count,
                created_at=existing.created_at,
                expires_at=existing.expires_at,
                revision=existing.revision + 1,
            )
            self._records[enrollment_ref] = updated
            return updated

    def mark_embedded(self, enrollment_ref: str, expected_revision: int) -> EnrollmentRecordV1:
        with self._lock:
            existing = self._records.get(enrollment_ref)
            if existing is None:
                raise KeyError(f"Enrollment {enrollment_ref} not found")
            if existing.revision != expected_revision:
                raise ValueError(f"Revision mismatch: expected {expected_revision}, got {existing.revision}")
            if existing.state != EnrollmentStateV1.RESERVED_FOR_BUILD:
                raise ValueError(f"Cannot mark embedded from state {existing.state}")

            updated = EnrollmentRecordV1(
                enrollment_ref=existing.enrollment_ref,
                token=existing.token,
                token_hash=existing.token_hash,
                profile_id=existing.profile_id,
                channel_ref=existing.channel_ref,
                target_id=existing.target_id,
                state=EnrollmentStateV1.EMBEDDED_IN_ARTIFACT,
                max_uses=existing.max_uses,
                used_count=existing.used_count,
                created_at=existing.created_at,
                expires_at=existing.expires_at,
                revision=existing.revision + 1,
            )
            self._records[enrollment_ref] = updated
            return updated

    def consume(self, enrollment_ref: str, token: str) -> EnrollmentRecordV1:
        with self._lock:
            existing = self._records.get(enrollment_ref)
            if existing is None:
                raise KeyError(f"Enrollment {enrollment_ref} not found")
            tok_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if existing.token_hash != tok_hash:
                raise ValueError("Invalid enrollment token")
            if existing.used_count >= existing.max_uses:
                raise ValueError("Enrollment maximum uses exceeded")

            new_count = existing.used_count + 1
            new_state = (
                EnrollmentStateV1.CONSUMED_BY_AGENT
                if new_count >= existing.max_uses
                else existing.state
            )
            updated = EnrollmentRecordV1(
                enrollment_ref=existing.enrollment_ref,
                token=existing.token,
                token_hash=existing.token_hash,
                profile_id=existing.profile_id,
                channel_ref=existing.channel_ref,
                target_id=existing.target_id,
                state=new_state,
                max_uses=existing.max_uses,
                used_count=new_count,
                created_at=existing.created_at,
                expires_at=existing.expires_at,
                revision=existing.revision + 1,
            )
            self._records[enrollment_ref] = updated
            return updated
