"""Tests for C2 daemon resource participant."""
from __future__ import annotations

import time
import pytest
from core.c2.resource_participant import C2DaemonResourceParticipant
from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
    ParticipantControlReceiptV1,
    ParticipantControlPhaseV1,
    BoundedControlErrorV1,
)

pytestmark = pytest.mark.unit


def _make_request(tx_id: str = "tx1", rev: int | None = None) -> ParticipantControlRequestV1:
    auth = ParticipantControlAuthorizationV1(
        key_id="k1",
        transaction_id=tx_id,
        participant_id="part1",
        mission_id="m1",
        subject_id="s1",
        action_id="prepare_c2_resource",
        coordinator_revision=1,
        request_digest="reqdig",
        expires_at=time.time() + 300,
        nonce="n1",
        signature="sig1",
    )
    return ParticipantControlRequestV1(
        action=C2ControlActionV1.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="pdig",
        canonical_payload_b64u="e30",
        expected_resource_revision=rev,
    )


def test_resource_participant_2pc_lifecycle():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    req = _make_request("tx_2pc_1")

    # 1. Prepare
    prep_receipt = participant.prepare(req)
    assert isinstance(prep_receipt, ParticipantControlReceiptV1)
    assert prep_receipt.transaction_id == "tx_2pc_1"
    assert prep_receipt.resource_revision == 0

    # 2. Commit
    commit_receipt = participant.commit(req)
    assert isinstance(commit_receipt, ParticipantControlReceiptV1)
    assert commit_receipt.resource_revision == 1

    # 3. Finalize
    final_receipt = participant.finalize_visibility(prep_receipt, commit_receipt)
    assert final_receipt.resource_revision == 1


def test_resource_participant_revision_mismatch_error():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    # Expected revision 5, but current is 0
    req = _make_request("tx_mismatch", rev=5)

    res = participant.prepare(req)
    assert isinstance(res, BoundedControlErrorV1)
    assert res.retryable is True


def test_resource_participant_rollback():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    req = _make_request("tx_rollback_1")

    prep_rcpt = participant.prepare(req)
    assert isinstance(prep_rcpt, ParticipantControlReceiptV1)

    rollback_rcpt = participant.rollback(prep_rcpt)
    assert isinstance(rollback_rcpt, ParticipantControlReceiptV1)
    assert rollback_rcpt.transaction_id == "tx_rollback_1"


def test_resource_participant_reconcile():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    snap = participant.reconcile()
    assert snap.participant_id == "part1"
    assert snap.phase == ParticipantControlPhaseV1.FINALIZED_VISIBLE
