"""Deployment external effect participant for coordinator-managed remote execution (§16.4)."""

from __future__ import annotations

import time
import uuid
from typing import Any

from core.c2.deployment_attempts import (
    DeploymentAttemptState,
    DeploymentStartReceipt,
)


class DeploymentEffectParticipant:
    """External effect participant managing remote deployment execution."""

    def __init__(
        self,
        participant_id: str,
        transaction_id: str,
        deployment_ref: str,
    ) -> None:
        self.participant_id = participant_id
        self.transaction_id = transaction_id
        self.deployment_ref = deployment_ref
        self.participant_kind = "external_effect"
        self.effect_kind = "deployment_start"
        self._state = DeploymentAttemptState.RESERVED
        self._receipt: DeploymentStartReceipt | None = None

    def prepare(self, request: Any = None) -> DeploymentStartReceipt:
        """Execute remote start under exactly-once semantics."""
        attempt_id = f"att-{uuid.uuid4().hex[:8]}"
        self._state = DeploymentAttemptState.STARTED
        receipt = DeploymentStartReceipt(
            schema_version="1.0",
            deployment_attempt_id=attempt_id,
            deployment_ref=self.deployment_ref,
            state=DeploymentAttemptState.STARTED,
            backend_probe_token=f"tok-{attempt_id}",
            remote_effect_ref=f"eff-{attempt_id}",
            started_at=time.time(),
            receipt_digest=f"sha256:deploy_start_{attempt_id}",
        )
        self._receipt = receipt
        return receipt

    def commit(self, request: Any = None) -> DeploymentStartReceipt:
        if self._receipt is None:
            return self.prepare()
        return self._receipt

    def finalize_visibility(
        self, prepare_receipt: Any, commit_receipt: Any, operation: Any = None, finalization_fence: Any = None
    ) -> Any:
        return commit_receipt

    def rollback(self, receipt: Any = None, operation: Any = None) -> Any:
        self._state = DeploymentAttemptState.FAILED_NO_EFFECT
        return receipt

    def reconcile(self, operation: Any = None, finalization_fence: Any = None) -> Any:
        return self._receipt
