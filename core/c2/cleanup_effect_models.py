"""C2 cleanup effect models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


class C2CleanupEffectOutcomeV1(str, Enum):
    CLEANED = "cleaned"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"


class C2CleanupAttemptStateV1(str, Enum):
    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    CLEANED = "cleaned"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"
    RECONCILING = "reconciling"


C2CleanupResourceKindV1 = Literal["c2_channel", "c2_enrollment", "c2_task", "deployment"]


@dataclass(frozen=True)
class C2CleanupPlanV1:
    schema_version: Literal["1.0"]
    transaction_id: str
    participant_id: str
    resource_ref: str
    expected_revision: int
    resource_kind: C2CleanupResourceKindV1
    lifecycle_owner: str
    reason: str
    mission_id: str
    subject_id: str
    cleanup_attempt_id: str
    cleanup_recipe_ref: str | None
    request_digest: str
    idempotency_digest: str


@dataclass(frozen=True)
class C2CleanupAttemptRecordV1:
    transaction_id: str
    participant_id: str
    cleanup_attempt_id: str
    resource_ref: str
    plan_digest: str
    state: C2CleanupAttemptStateV1
    backend_probe_token: str | None
    revision: int


@dataclass(frozen=True)
class C2CleanupEffectReceiptV1:
    transaction_id: str
    participant_id: str
    cleanup_attempt_id: str
    resource_ref: str
    request_digest: str
    outcome: C2CleanupEffectOutcomeV1
    participant_revision: int
    backend_probe_token: str | None
    remote_effect_ref: str | None
    receipt_digest: str


@dataclass(frozen=True)
class C2CleanupEffectProbeV1:
    transaction_id: str
    participant_id: str
    cleanup_attempt_id: str
    resource_ref: str
    request_digest: str
    outcome: C2CleanupEffectOutcomeV1
    observed_revision: int | None
    backend_probe_token: str | None
    probe_digest: str


@dataclass(frozen=True)
class C2CleanupBackendRequestV1:
    plan: C2CleanupPlanV1
    expected_attempt_revision: int
    backend_probe_token: str | None
