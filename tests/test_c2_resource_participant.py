"""Tests for C2 daemon resource participant."""

from __future__ import annotations

import time

import pytest

from core.c2.control_commands import (
    BoundedControlErrorV2,
    C2ControlAction,
    ParticipantControlAuthorizationV2,
    ParticipantControlPhaseV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.resource_participant import C2DaemonResourceParticipant

pytestmark = pytest.mark.unit


def _make_request(
    tx_id: str = "tx1",
    action: C2ControlAction = C2ControlAction.PREPARE_C2_RESOURCE,
    rev: int | None = None,
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
) -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id=tx_id,
        participant_id="part1",
        mission_id="m1",
        subject_id="s1",
        action_id=action.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_part1_12345678",
        signature="0" * 86,
    )
    return ParticipantControlRequestV2(
        action=action,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
        expected_resource_revision=rev,
        prior_receipt_ref=prior_receipt_ref,
        prior_receipt_digest=prior_receipt_digest,
    )


def test_resource_participant_2pc_lifecycle():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    req = _make_request("tx_2pc_1")

    # 1. Prepare
    prep_receipt = participant.prepare(req)
    assert isinstance(prep_receipt, ParticipantControlReceiptV2)
    assert prep_receipt.transaction_id == "tx_2pc_1"
    assert prep_receipt.resource_revision == 0

    # 2. Commit
    commit_req = _make_request(
        "tx_2pc_1",
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        prior_receipt_ref=prep_receipt.receipt_ref,
        prior_receipt_digest=prep_receipt.receipt_digest,
    )
    commit_receipt = participant.commit(commit_req)
    assert isinstance(commit_receipt, ParticipantControlReceiptV2)
    assert commit_receipt.resource_revision == 1

    # 3. Finalize
    final_receipt = participant.finalize_visibility(prep_receipt, commit_receipt)
    assert final_receipt.resource_revision == 1


def test_resource_participant_revision_mismatch_error():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    # Expected revision 5, but current is 0
    req = _make_request("tx_mismatch", rev=5)

    res = participant.prepare(req)
    assert isinstance(res, BoundedControlErrorV2)
    assert res.retryable is True


def test_resource_participant_rollback():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    req = _make_request("tx_rollback_1")

    prep_rcpt = participant.prepare(req)
    assert isinstance(prep_rcpt, ParticipantControlReceiptV2)

    rollback_rcpt = participant.rollback(prep_rcpt)
    assert isinstance(rollback_rcpt, ParticipantControlReceiptV2)
    assert rollback_rcpt.transaction_id == "tx_rollback_1"


def test_resource_participant_reconcile():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    snap = participant.reconcile()
    assert snap.participant_id == "part1"
    assert snap.phase == ParticipantControlPhaseV2.FINALIZED_VISIBLE
