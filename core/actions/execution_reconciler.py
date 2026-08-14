"""PR-5 Module: Execution reconciler and recovery evaluation (§8.4)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from core.actions.execution_commit_types import ExecutionCommitStateV2


class ReconciliationDispositionV2(str, Enum):
    ROLL_FORWARD = "roll_forward"
    ROLL_BACK = "roll_back"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


@dataclass(frozen=True)
class ReconciliationDecisionV2:
    transaction_id: str
    target_state: ExecutionCommitStateV2
    disposition: ReconciliationDispositionV2
    reason_code: str


class ExecutionReconcilerV2:
    """Reconciler that resolves in-doubt execution states during recovery."""

    def evaluate_in_doubt(
        self,
        transaction_id: str,
        current_state: ExecutionCommitStateV2,
        has_committed_marker: bool,
    ) -> ReconciliationDecisionV2:
        if has_committed_marker:
            return ReconciliationDecisionV2(
                transaction_id=transaction_id,
                target_state=ExecutionCommitStateV2.COMMITTED,
                disposition=ReconciliationDispositionV2.ROLL_FORWARD,
                reason_code="committed_marker_present",
            )
        return ReconciliationDecisionV2(
            transaction_id=transaction_id,
            target_state=ExecutionCommitStateV2.ROLLED_BACK,
            disposition=ReconciliationDispositionV2.ROLL_BACK,
            reason_code="no_committed_marker_abort_cleanly",
        )


__all__ = [
    "ExecutionReconcilerV2",
    "ReconciliationDecisionV2",
    "ReconciliationDispositionV2",
]
