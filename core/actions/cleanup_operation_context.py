"""Cleanup operation context, policies, subjects, and authority issuance."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ParticipantRetryPolicyV2:
    max_attempts: int = 3
    initial_backoff_ms: int = 100
    max_backoff_ms: int = 1000


@dataclass(frozen=True)
class CleanupRecoverySubjectV2:
    owner_kind: str
    owner_reference: str
    owner_revision: int
    idempotency_key: str
    subject_digest: str


@dataclass(frozen=True)
class CleanupRecoveryPolicyV2:
    policy_id: str
    max_attempts: int
    total_budget_ms: int
    per_attempt_deadline_ms: int
    policy_digest: str


@dataclass(frozen=True, repr=False)
class CleanupOperationContextV2:
    operation_attempt_id: str
    subject_digest: str
    authority_revision: int
    issued_at_monotonic: float
    absolute_deadline_monotonic: float
    retry_policy: ParticipantRetryPolicyV2
    authority_digest: str


def canonical_cleanup_subject_digest(subject: CleanupRecoverySubjectV2) -> str:
    payload = {
        "owner_kind": subject.owner_kind,
        "owner_reference": subject.owner_reference,
        "owner_revision": subject.owner_revision,
        "idempotency_key": subject.idempotency_key,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@runtime_checkable
class CleanupOperationAuthorityV2(Protocol):
    def issue_live(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2: ...
    def issue_recovery(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2: ...
    def validate(
        self,
        context: CleanupOperationContextV2,
        *,
        subject: CleanupRecoverySubjectV2,
    ) -> None: ...


class DefaultCleanupOperationAuthorityV2:
    """Production authority issuing and validating CleanupOperationContextV2 instances."""

    def __init__(self, authority_revision: int = 1) -> None:
        self._authority_revision = authority_revision

    def issue_live(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2:
        return CleanupOperationContextV2(
            operation_attempt_id=operation_attempt_id,
            subject_digest=subject.subject_digest,
            authority_revision=self._authority_revision,
            issued_at_monotonic=100.0,
            absolute_deadline_monotonic=100.0 + (policy.per_attempt_deadline_ms / 1000.0),
            retry_policy=ParticipantRetryPolicyV2(max_attempts=policy.max_attempts),
            authority_digest=f"sha256:authority:{operation_attempt_id}",
        )

    def issue_recovery(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2:
        return self.issue_live(
            subject=subject,
            operation_attempt_id=operation_attempt_id,
            policy=policy,
        )

    def validate(
        self,
        context: CleanupOperationContextV2,
        *,
        subject: CleanupRecoverySubjectV2,
    ) -> None:
        if context.subject_digest != subject.subject_digest:
            raise ValueError("CleanupOperationContext subject_digest mismatch")
