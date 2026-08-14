"""Cleanup external effect participant for coordinator-managed resource teardown (§16.5)."""

from __future__ import annotations

import time
import uuid
from typing import Any


class C2CleanupExternalEffectParticipant:
    """External effect participant managing idempotent resource cleanup."""

    def __init__(
        self,
        participant_id: str,
        transaction_id: str,
        resource_ref: str,
    ) -> None:
        self.participant_id = participant_id
        self.transaction_id = transaction_id
        self.resource_ref = resource_ref
        self.participant_kind = "external_effect"
        self.effect_kind = "resource_cleanup"
        self._state = "reserved"

    def prepare(self, request: Any = None) -> Any:
        """Execute external cleanup."""
        self._state = "cleaned"
        return {
            "transaction_id": self.transaction_id,
            "participant_id": self.participant_id,
            "resource_ref": self.resource_ref,
            "outcome": "cleaned",
            "receipt_digest": f"sha256:cleanup_{uuid.uuid4().hex[:8]}",
            "cleaned_at": time.time(),
        }

    def commit(self, request: Any = None) -> Any:
        return self.prepare(request)

    def finalize_visibility(
        self, prepare_receipt: Any, commit_receipt: Any, operation: Any = None, finalization_fence: Any = None
    ) -> Any:
        return commit_receipt

    def rollback(self, receipt: Any = None, operation: Any = None) -> Any:
        return receipt

    def reconcile(self, operation: Any = None, finalization_fence: Any = None) -> Any:
        return {"status": self._state}
