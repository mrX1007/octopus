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
        """Execute a 2PC transaction across registered participants with chained receipts."""
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

        # Phase 2: Commit (chained to prepare receipt)
        commit_req = ParticipantControlRequestV1(
            action=request.action,
            authorization=request.authorization,
            payload_schema_id=request.payload_schema_id,
            payload_digest=request.payload_digest,
            canonical_payload_b64u=request.canonical_payload_b64u,
            prior_receipt_ref=prep_res.receipt_ref,
            prior_receipt_digest=prep_res.receipt_digest,
            expected_resource_revision=request.expected_resource_revision,
        )
        commit_res = participant.commit(commit_req)
        if isinstance(commit_res, BoundedControlErrorV1):
            participant.rollback(prep_res)
            return commit_res

        # Phase 3: Finalize Visibility (chained to commit receipt)
        finalize_req = ParticipantControlRequestV1(
            action=request.action,
            authorization=request.authorization,
            payload_schema_id=request.payload_schema_id,
            payload_digest=request.payload_digest,
            canonical_payload_b64u=request.canonical_payload_b64u,
            prior_receipt_ref=commit_res.receipt_ref,
            prior_receipt_digest=commit_res.receipt_digest,
            expected_resource_revision=request.expected_resource_revision,
        )
        final_res = participant.finalize_visibility(finalize_req)
        return final_res


__all__ = [
    "ControlTransactionCoordinator",
]
