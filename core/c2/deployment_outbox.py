"""Deployment outbox messaging for daemon mirror updates (§16.4)."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True)
class DeploymentOutboxMessage:
    message_id: str
    deployment_ref: str
    action: str
    payload_digest: str
    status: str
    created_at: float


class DeploymentOutboxStore:
    """Thread-safe outbox queue for deployment mirror synchronization."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._messages: dict[str, DeploymentOutboxMessage] = {}

    def enqueue(
        self,
        deployment_ref: str,
        action: str,
        payload_digest: str,
        now: float | None = None,
    ) -> DeploymentOutboxMessage:
        ts = time.time() if now is None else now
        msg = DeploymentOutboxMessage(
            message_id=f"outbox-{uuid.uuid4().hex[:10]}",
            deployment_ref=deployment_ref,
            action=action,
            payload_digest=payload_digest,
            status="pending",
            created_at=ts,
        )
        with self._lock:
            self._messages[msg.message_id] = msg
        return msg

    def list_pending(self) -> list[DeploymentOutboxMessage]:
        with self._lock:
            return [m for m in self._messages.values() if m.status == "pending"]

    def mark_delivered(self, message_id: str) -> None:
        with self._lock:
            m = self._messages.get(message_id)
            if m is not None:
                self._messages[message_id] = DeploymentOutboxMessage(
                    message_id=m.message_id,
                    deployment_ref=m.deployment_ref,
                    action=m.action,
                    payload_digest=m.payload_digest,
                    status="delivered",
                    created_at=m.created_at,
                )
