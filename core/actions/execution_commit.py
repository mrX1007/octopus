"""PR-5 Module: Execution commit coordinator, 2PC participant execution, and visibility finalization (§8.2, §8.4)."""

from __future__ import annotations

import time
import uuid
from typing import List, Optional

from core.actions.execution_commit_participants import (
    ExecutionCommitParticipant,
    ParticipantCommitReceiptV2,
    ParticipantFinalizeReceiptV2,
    ParticipantKindV2,
    ParticipantPrepareResultV2,
    ParticipantRollbackReceiptV2,
    ParticipantStateV2,
    ParticipantVisibilityModeV2,
)
from core.actions.execution_commit_types import (
    ExecutionCommitDecisionBindingV2,
    ExecutionCommitRecordV2,
    ExecutionCommitStateV2,
)

CommitStateV2 = ExecutionCommitStateV2


class CommitPreparationFailedError(RuntimeError):
    """Raised when one or more participants fail the prepare phase."""


class CommitFinalizationFailedError(RuntimeError):
    """Raised when one or more participants fail the visibility finalization phase."""


class ExecutionCommitCoordinator:
    """Production 2PC coordinator managing transactional staging, hidden commit, and visibility finalization."""

    def __init__(self, transaction_id: str | None = None) -> None:
        self.transaction_id = transaction_id or f"tx-{uuid.uuid4().hex[:12]}"
        self.revision = 1
        self.state = ExecutionCommitStateV2.OPEN
        self._participants: List[ExecutionCommitParticipant] = []
        self._prepare_receipts: dict[str, ParticipantPrepareResultV2] = {}
        self._commit_receipts: dict[str, ParticipantCommitReceiptV2] = {}
        self._finalize_receipts: dict[str, ParticipantFinalizeReceiptV2] = {}

    def register_participant(self, participant: ExecutionCommitParticipant) -> None:
        if self.state != ExecutionCommitStateV2.OPEN:
            raise RuntimeError(f"Cannot register participant in state {self.state}")
        self._participants.append(participant)

    def prepare_all(self) -> bool:
        self.state = ExecutionCommitStateV2.PREPARING
        for p in self._participants:
            try:
                res = p.prepare(self.transaction_id)
                self._prepare_receipts[p.participant_id] = res
                if not res.can_commit or res.state != ParticipantStateV2.PREPARED:
                    self.rollback_all()
                    return False
            except Exception as exc:
                self.rollback_all()
                raise CommitPreparationFailedError(f"Participant '{p.participant_id}' failed prepare: {exc}") from exc

        self.state = ExecutionCommitStateV2.PREPARED
        return True

    def commit_all_hidden(self) -> bool:
        if self.state != ExecutionCommitStateV2.PREPARED:
            raise RuntimeError(f"Cannot commit hidden from state {self.state}")

        self.state = ExecutionCommitStateV2.COMMITTING
        for p in self._participants:
            try:
                receipt = p.commit_hidden(self.transaction_id)
                self._commit_receipts[p.participant_id] = receipt
            except Exception:
                self.state = ExecutionCommitStateV2.IN_DOUBT
                return False

        self.state = ExecutionCommitStateV2.COMMIT_APPLIED
        return True

    def finalize_all_visibility(self) -> bool:
        if self.state != ExecutionCommitStateV2.COMMIT_APPLIED:
            raise RuntimeError(f"Cannot finalize visibility from state {self.state}")

        self.state = ExecutionCommitStateV2.FINALIZING_VISIBILITY
        for p in self._participants:
            try:
                receipt = p.finalize_visibility(self.transaction_id)
                self._finalize_receipts[p.participant_id] = receipt
            except Exception as exc:
                self.state = ExecutionCommitStateV2.FAILED_RECONCILIATION
                raise CommitFinalizationFailedError(f"Participant '{p.participant_id}' failed visibility finalization: {exc}") from exc

        self.state = ExecutionCommitStateV2.COMMITTED
        return True

    def execute_commit_protocol(self) -> bool:
        """Helper to run the full two-phase commit protocol with visibility finalization."""
        if not self.prepare_all():
            return False
        if not self.commit_all_hidden():
            return False
        return self.finalize_all_visibility()

    def rollback_all(self) -> None:
        self.state = ExecutionCommitStateV2.ROLLING_BACK
        for p in self._participants:
            try:
                p.rollback(self.transaction_id)
            except Exception:
                pass
        self.state = ExecutionCommitStateV2.ROLLED_BACK


__all__ = [
    "CommitFinalizationFailedError",
    "CommitPreparationFailedError",
    "ExecutionCommitCoordinator",
]
