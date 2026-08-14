"""Main-process DeploymentStore — single canonical owner of deployments (§16.4)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import RLock

from core.c2.deployment_attempts import DeploymentAttemptRecord


@dataclass(frozen=True)
class DeploymentRecordV1:
    deployment_ref: str
    mission_id: str
    subject_id: str
    channel_ref: str
    enrollment_ref: str
    target_id: str
    profile_id: str
    method: str
    status: str
    created_at: float
    revision: int = 1


class DeploymentStore:
    """Canonical thread-safe deployment store in main process."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._deployments: dict[str, DeploymentRecordV1] = {}
        self._attempts: dict[str, DeploymentAttemptRecord] = {}

    def allocate_deployment(
        self,
        *,
        deployment_ref: str,
        mission_id: str,
        subject_id: str,
        channel_ref: str,
        enrollment_ref: str,
        target_id: str,
        profile_id: str,
        method: str,
        now: float | None = None,
    ) -> DeploymentRecordV1:
        ts = time.time() if now is None else now
        with self._lock:
            if deployment_ref in self._deployments:
                return self._deployments[deployment_ref]
            rec = DeploymentRecordV1(
                deployment_ref=deployment_ref,
                mission_id=mission_id,
                subject_id=subject_id,
                channel_ref=channel_ref,
                enrollment_ref=enrollment_ref,
                target_id=target_id,
                profile_id=profile_id,
                method=method,
                status="allocated",
                created_at=ts,
                revision=1,
            )
            self._deployments[deployment_ref] = rec
            return rec

    def get_deployment(self, deployment_ref: str) -> DeploymentRecordV1 | None:
        with self._lock:
            return self._deployments.get(deployment_ref)

    def list_deployments(self, mission_id: str | None = None) -> list[DeploymentRecordV1]:
        with self._lock:
            items = list(self._deployments.values())
            if mission_id is not None:
                items = [d for d in items if d.mission_id == mission_id]
            return items

    def update_status(
        self,
        deployment_ref: str,
        new_status: str,
        expected_revision: int | None = None,
    ) -> DeploymentRecordV1:
        with self._lock:
            existing = self._deployments.get(deployment_ref)
            if existing is None:
                raise KeyError(f"Deployment {deployment_ref} not found")
            if expected_revision is not None and existing.revision != expected_revision:
                raise ValueError(f"Deployment revision mismatch: expected {expected_revision}, got {existing.revision}")
            updated = DeploymentRecordV1(
                deployment_ref=existing.deployment_ref,
                mission_id=existing.mission_id,
                subject_id=existing.subject_id,
                channel_ref=existing.channel_ref,
                enrollment_ref=existing.enrollment_ref,
                target_id=existing.target_id,
                profile_id=existing.profile_id,
                method=existing.method,
                status=new_status,
                created_at=existing.created_at,
                revision=existing.revision + 1,
            )
            self._deployments[deployment_ref] = updated
            return updated

    def record_attempt(self, attempt: DeploymentAttemptRecord) -> None:
        with self._lock:
            self._attempts[attempt.deployment_attempt_id] = attempt

    def get_attempt(self, attempt_id: str) -> DeploymentAttemptRecord | None:
        with self._lock:
            return self._attempts.get(attempt_id)
