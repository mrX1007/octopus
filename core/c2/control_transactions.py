"""Control transactions."""

from __future__ import annotations

from typing import Any

from core.c2.control_commands import (
    BoundedControlErrorV1,
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
            # Fall back to default participant if single participant passed or first registered
            if self._participants:
                participant = next(iter(self._participants.values()))
            else:
                from core.c2.resource_participant import C2DaemonResourceParticipant

                participant = C2DaemonResourceParticipant(participant_id=p_id)
                self._participants[p_id] = participant

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
