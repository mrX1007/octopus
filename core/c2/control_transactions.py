"""Coordinator for two-phase commit (2PC) transactions across resource participants (§14.4)."""

from __future__ import annotations

import dataclasses
from typing import Any

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    BoundedControlErrorV1,
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV1,
    C2ControlErrorCodeV2,
    ParticipantControlReceiptV1,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV1,
    ParticipantControlRequestV2,
)


class ControlTransactionCoordinator:
    """Coordinator for two-phase commit (2PC) transactions across resource participants."""

    def __init__(self) -> None:
        self._participants: dict[str, Any] = {}

    def register_participant(self, participant_id: str, participant: Any) -> None:
        """Register a resource participant."""
        self._participants[participant_id] = participant

    def execute_v2_transaction(
        self,
        request: ParticipantControlRequestV2,
        *,
        authority: VerifiedMutationAuthority,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Execute a canonical V2 2PC transaction across registered participants with strict authority."""
        if type(authority) is not VerifiedMutationAuthority:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="mandatory_verified_mutation_authority_required",
            )
        if not isinstance(request, ParticipantControlRequestV2):
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
                retryable=False,
                detail_ref="invalid_v2_request_instance",
            )

        p_id = request.authorization.participant_id
        participant = self._participants.get(p_id)
        if participant is None:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
                retryable=False,
                detail_ref=f"unregistered_participant:{p_id}",
            )

        if request.action == C2ControlAction.PREPARE_ENROLLMENT_DEPLOYMENT:
            commit_action = C2ControlAction.COMMIT_ENROLLMENT_DEPLOYMENT
            finalize_action = C2ControlAction.FINALIZE_ENROLLMENT_DEPLOYMENT
            abort_action = C2ControlAction.ABORT_ENROLLMENT_DEPLOYMENT
        else:
            commit_action = C2ControlAction.COMMIT_C2_RESOURCE
            finalize_action = C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY
            abort_action = C2ControlAction.ABORT_C2_RESOURCE

        # Phase 1: Prepare
        prep_res = participant.prepare(request, authority=authority)
        if isinstance(prep_res, (BoundedControlErrorV1, BoundedControlErrorV2)):
            return prep_res

        # Phase 2: Commit (chained to prepare receipt)
        commit_auth_obj = dataclasses.replace(
            request.authorization,
            action_id=commit_action.value,
            nonce=f"{request.authorization.nonce}_commit",
        )
        commit_authority_obj = dataclasses.replace(
            authority,
            action_id=commit_action.value,
        )
        commit_req = ParticipantControlRequestV2(
            action=commit_action,
            authorization=commit_auth_obj,
            payload_schema_id=request.payload_schema_id,
            payload_digest=request.payload_digest,
            canonical_payload_b64u=request.canonical_payload_b64u,
            prior_receipt_ref=prep_res.receipt_ref,
            prior_receipt_digest=prep_res.receipt_digest,
            expected_resource_revision=request.expected_resource_revision,
        )
        commit_res = participant.commit(commit_req, authority=commit_authority_obj)
        if isinstance(commit_res, (BoundedControlErrorV1, BoundedControlErrorV2)):
            abort_authority_obj = dataclasses.replace(
                authority,
                action_id=abort_action.value,
            )
            participant.rollback(prep_res, authority=abort_authority_obj)
            return commit_res

        # Phase 3: Finalize Visibility (chained to commit receipt)
        finalize_auth_obj = dataclasses.replace(
            request.authorization,
            action_id=finalize_action.value,
            nonce=f"{request.authorization.nonce}_finalize",
        )
        finalize_authority_obj = dataclasses.replace(
            authority,
            action_id=finalize_action.value,
        )
        finalize_req = ParticipantControlRequestV2(
            action=finalize_action,
            authorization=finalize_auth_obj,
            payload_schema_id=request.payload_schema_id,
            payload_digest=request.payload_digest,
            canonical_payload_b64u=request.canonical_payload_b64u,
            prior_receipt_ref=commit_res.receipt_ref,
            prior_receipt_digest=commit_res.receipt_digest,
            expected_resource_revision=request.expected_resource_revision,
        )
        final_res = participant.finalize_visibility(finalize_req, authority=finalize_authority_obj)
        return final_res

    def execute_transaction(
        self,
        request: ParticipantControlRequestV1 | ParticipantControlRequestV2,
        authority: Any = None,
    ) -> ParticipantControlReceiptV1 | ParticipantControlReceiptV2 | BoundedControlErrorV1 | BoundedControlErrorV2:
        """Execute a 2PC transaction across registered participants with chained receipts."""
        if isinstance(request, ParticipantControlRequestV2):
            if authority is None or type(authority) is not VerifiedMutationAuthority:
                return BoundedControlErrorV2(
                    reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                    retryable=False,
                    detail_ref="mandatory_verified_mutation_authority_required",
                )
            return self.execute_v2_transaction(request, authority=authority)

        # Legacy V1 path only
        p_id = request.authorization.participant_id
        participant = self._participants.get(p_id)
        if participant is None:
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1.UNAVAILABLE,
                retryable=False,
                detail_ref=f"unregistered_participant:{p_id}",
            )

        prep_res = participant.prepare(request)
        if isinstance(prep_res, BoundedControlErrorV1):
            return prep_res

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
        return participant.finalize_visibility(finalize_req)


__all__ = [
    "ControlTransactionCoordinator",
]
