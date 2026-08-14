from __future__ import annotations

from typing import Any


from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlErrorCodeV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
)


class ControlTransactionCoordinator:
    """Coordinator for two-phase commit (2PC) transactions across resource participants."""

    def __init__(self) -> None:
        self._participants: dict[str, Any] = {}

    def register_participant(self, participant_id: str, participant: Any) -> None:
        """Register a resource participant."""
        self._participants[participant_id] = participant

    def execute_transaction(
        self, request: ParticipantControlRequestV1
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Execute a 2PC transaction across registered participants."""
        p_id = request.authorization.participant_id
        participant = self._participants.get(p_id)
        if participant is None:
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1.UNAVAILABLE,
                retryable=False,
                detail_ref=f"unregistered_participant:{p_id}",
            )

        # Phase 1: Prepare
        prep_res = participant.prepare(request)
        if isinstance(prep_res, BoundedControlErrorV1):
            return prep_res

        # Phase 2: Commit
        commit_res = participant.commit(request)
        if isinstance(commit_res, BoundedControlErrorV1):
            participant.rollback(prep_res)
            return commit_res

        # Phase 3: Finalize Visibility
        final_res = participant.finalize_visibility(prep_res, commit_res)
        return final_res

