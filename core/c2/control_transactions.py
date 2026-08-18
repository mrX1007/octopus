"""Coordinator for two-phase commit (2PC) transactions across resource participants (§14.4)."""

from __future__ import annotations

from typing import Any

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    BoundedControlErrorV1,
    BoundedControlErrorV2,
    C2ControlErrorCodeV1,
    C2ControlErrorCodeV2,
    ParticipantControlReceiptV1,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV1,
    ParticipantControlRequestV2,
)


def _validate_transaction_intent_invariants(
    *requests_and_authorities: tuple[ParticipantControlRequestV2, VerifiedMutationAuthority],
) -> BoundedControlErrorV2 | None:
    """Validate that all phase requests and verified authorities share the exact same transaction intent."""
    if not requests_and_authorities:
        return None
    base_req, base_auth = requests_and_authorities[0]
    for req, auth in requests_and_authorities:
        if type(auth) is not VerifiedMutationAuthority:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="mandatory_verified_mutation_authority_required",
            )
        if not isinstance(req, ParticipantControlRequestV2):
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
                retryable=False,
                detail_ref="invalid_v2_request_instance",
            )
        # Verify request matches its own authority
        if req.authorization.transaction_id != auth.transaction_id:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_transaction_mismatch",
            )
        if req.authorization.participant_id != auth.participant_id:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_participant_mismatch",
            )
        req_act = req.action.value if hasattr(req.action, "value") else str(req.action)
        if req_act != auth.action_id or req.authorization.action_id != auth.action_id:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_action_mismatch",
            )
        if req.authorization.mission_id != auth.mission_id or req.authorization.subject_id != auth.subject_id:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_scope_mismatch",
            )
        if req.authorization.request_digest != auth.request_digest:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_request_digest_mismatch",
            )

        # Cross-phase Intent Invariants:
        # Same transaction_id, participant_id, operator_id, subject_id, mission_id,
        # payload_schema_id, payload_digest, and compatible expected_resource_revision
        if auth.transaction_id != base_auth.transaction_id:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="transaction_intent_mismatch:transaction_id",
            )
        if auth.participant_id != base_auth.participant_id:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="transaction_intent_mismatch:participant_id",
            )
        if (
            auth.operator_id != base_auth.operator_id
            or auth.subject_id != base_auth.subject_id
            or auth.mission_id != base_auth.mission_id
        ):
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="transaction_intent_mismatch:scope",
            )
        if req.payload_schema_id != base_req.payload_schema_id or req.payload_digest != base_req.payload_digest:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="transaction_intent_mismatch:payload",
            )
        if req.expected_resource_revision != base_req.expected_resource_revision:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="transaction_intent_mismatch:expected_revision",
            )
    return None


class ControlTransactionCoordinator:
    """Coordinator for two-phase commit (2PC) transactions across resource participants."""

    def __init__(self) -> None:
        self._participants: dict[str, Any] = {}

    def register_participant(self, participant_id: str, participant: Any) -> None:
        """Register a resource participant."""
        self._participants[participant_id] = participant

    def prepare(
        self,
        request: ParticipantControlRequestV2,
        *,
        authority: VerifiedMutationAuthority,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Execute the prepare phase on the registered participant."""
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
        return participant.prepare(request, authority=authority)

    def commit(
        self,
        request: ParticipantControlRequestV2,
        *,
        authority: VerifiedMutationAuthority,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Execute the commit phase on the registered participant."""
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
        return participant.commit(request, authority=authority)

    def finalize_visibility(
        self,
        request: ParticipantControlRequestV2,
        *,
        authority: VerifiedMutationAuthority,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Execute the finalize visibility phase on the registered participant."""
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
        return participant.finalize_visibility(request, authority=authority)

    def rollback(
        self,
        request_or_receipt: ParticipantControlRequestV2 | ParticipantControlReceiptV2,
        *,
        authority: VerifiedMutationAuthority,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Execute rollback/abort on the registered participant."""
        if type(authority) is not VerifiedMutationAuthority:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="mandatory_verified_mutation_authority_required",
            )
        p_id = authority.participant_id
        participant = self._participants.get(p_id)
        if participant is None:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
                retryable=False,
                detail_ref=f"unregistered_participant:{p_id}",
            )
        return participant.rollback(request_or_receipt, authority=authority)

    def execute_v2_transaction(
        self,
        prepare_request: ParticipantControlRequestV2,
        commit_request: ParticipantControlRequestV2,
        finalize_request: ParticipantControlRequestV2,
        *,
        prepare_authority: VerifiedMutationAuthority,
        commit_authority: VerifiedMutationAuthority,
        finalize_authority: VerifiedMutationAuthority,
        abort_request: ParticipantControlRequestV2 | None = None,
        abort_authority: VerifiedMutationAuthority | None = None,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Execute a canonical V2 2PC transaction across registered participants with strict independent authority."""
        intent_err = _validate_transaction_intent_invariants(
            (prepare_request, prepare_authority),
            (commit_request, commit_authority),
            (finalize_request, finalize_authority),
        )
        if intent_err is not None:
            return intent_err

        if abort_request is not None and abort_authority is not None:
            abort_intent_err = _validate_transaction_intent_invariants(
                (prepare_request, prepare_authority),
                (abort_request, abort_authority),
            )
            if abort_intent_err is not None:
                return abort_intent_err

        # Phase 1: Prepare
        prep_res = self.prepare(prepare_request, authority=prepare_authority)
        if isinstance(prep_res, (BoundedControlErrorV1, BoundedControlErrorV2)):
            return prep_res

        # Phase 2: Commit (chained to prepare receipt)
        if (
            commit_request.prior_receipt_ref != prep_res.receipt_ref
            or commit_request.prior_receipt_digest != prep_res.receipt_digest
        ):
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                retryable=False,
                detail_ref="commit_prior_receipt_mismatch",
            )

        commit_res = self.commit(commit_request, authority=commit_authority)
        if isinstance(commit_res, (BoundedControlErrorV1, BoundedControlErrorV2)):
            if abort_authority is not None:
                self.rollback(abort_request or prep_res, authority=abort_authority)
            return commit_res

        # Phase 3: Finalize Visibility (chained to commit receipt)
        if (
            finalize_request.prior_receipt_ref != commit_res.receipt_ref
            or finalize_request.prior_receipt_digest != commit_res.receipt_digest
        ):
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                retryable=False,
                detail_ref="finalize_prior_receipt_mismatch",
            )

        return self.finalize_visibility(finalize_request, authority=finalize_authority)

    def execute_v1_transaction(
        self,
        request: ParticipantControlRequestV1,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Execute legacy V1 2PC transaction across registered participants with chained receipts."""
        if not isinstance(request, ParticipantControlRequestV1):
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1.UNAVAILABLE,
                retryable=False,
                detail_ref="invalid_v1_request_instance",
            )

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

    def execute_transaction(
        self,
        request: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Route to V1 or V2 transaction execution with strict type isolation."""
        if isinstance(request, ParticipantControlRequestV1):
            return self.execute_v1_transaction(request)
        if isinstance(request, ParticipantControlRequestV2):
            return self.execute_v2_transaction(request, *args, **kwargs)
        return BoundedControlErrorV2(
            reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
            retryable=False,
            detail_ref="unsupported_transaction_request_type",
        )


__all__ = [
    "ControlTransactionCoordinator",
]
