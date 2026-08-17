"""Tests for C2 resource visibility fence and hidden commit state (§14.6A)."""

from __future__ import annotations

import time

import pytest

from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlAuthorizationV2,
    ParticipantControlPhaseV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.resource_participant import C2DaemonResourceParticipant

pytestmark = pytest.mark.unit


def _make_req(
    action: C2ControlAction,
    tx_id: str,
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
) -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="key-1",
        transaction_id=tx_id,
        participant_id="part-vis-1",
        mission_id="m-vis",
        subject_id="sub-vis",
        action_id=action.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_vis_12345678",
        signature="0" * 86,
    )
    return ParticipantControlRequestV2(
        action=action,
        authorization=auth,
        payload_schema_id="schema:dns_channel",
        payload_digest="0" * 64,
        canonical_payload_b64u="ey...",
        prior_receipt_ref=prior_receipt_ref,
        prior_receipt_digest=prior_receipt_digest,
    )


def test_resource_hidden_until_finalization():
    part = C2DaemonResourceParticipant(participant_id="part-vis-1")
    prep = part.prepare(_make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-vis-1"))
    assert isinstance(prep, ParticipantControlReceiptV2)

    # Commit keeps resource COMMITTED_HIDDEN
    commit = part.commit(
        _make_req(
            C2ControlAction.COMMIT_C2_RESOURCE,
            "tx-vis-1",
            prior_receipt_ref=prep.receipt_ref,
            prior_receipt_digest=prep.receipt_digest,
        )
    )
    assert isinstance(commit, ParticipantControlReceiptV2)
    assert part._committed_resources["tx-vis-1"]["phase"] == ParticipantControlPhaseV2.COMMITTED_HIDDEN

    # Finalize visibility transitions to FINALIZED_VISIBLE
    part.finalize_visibility(prep, commit)
    assert part._committed_resources["tx-vis-1"]["phase"] == ParticipantControlPhaseV2.FINALIZED_VISIBLE


def test_aborted_resource_never_becomes_visible():
    part = C2DaemonResourceParticipant(participant_id="part-vis-2")
    prep = part.prepare(_make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-vis-2"))
    assert isinstance(prep, ParticipantControlReceiptV2)

    part.rollback(prep)
    # Check that transaction is removed from pending
    assert "tx-vis-2" not in part._pending_transactions
