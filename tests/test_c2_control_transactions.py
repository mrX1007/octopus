"""Tests for C2 control transaction coordinator."""

from __future__ import annotations

import time

import pytest

from core.c2.control_commands import (
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.control_transactions import ControlTransactionCoordinator
from core.c2.resource_participant import C2DaemonResourceParticipant

pytestmark = pytest.mark.unit


def _make_req(tx_id: str = "tx_1") -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id=tx_id,
        participant_id="part_test",
        mission_id="m1",
        subject_id="s1",
        action_id="prepare_c2_resource",
        coordinator_revision=1,
        request_digest="a" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_12345678901234",
        signature="c" * 86,
    )
    return ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="d" * 64,
        canonical_payload_b64u="e30",
    )


def test_coordinator_execute_transaction_success():
    coord = ControlTransactionCoordinator()
    participant = C2DaemonResourceParticipant(participant_id="part_test")
    coord.register_participant("part_test", participant)

    req = _make_req("tx_coord_1")
    receipt = coord.execute_transaction(req)
    assert isinstance(receipt, ParticipantControlReceiptV2)
    assert receipt.transaction_id == "tx_coord_1"
    assert receipt.resource_revision == 1


def test_coordinator_rejects_unregistered_participant():
    coord = ControlTransactionCoordinator()
    req = _make_req("tx_unregistered_1")
    res = coord.execute_transaction(req)
    assert not isinstance(res, ParticipantControlReceiptV2)
    assert res.reason_code == C2ControlErrorCodeV2.UNAVAILABLE
    assert "unregistered_participant" in res.detail_ref


def test_coordinator_multiple_transactions():
    coord = ControlTransactionCoordinator()
    participant = C2DaemonResourceParticipant(participant_id="part_test")
    coord.register_participant("part_test", participant)

    req1 = _make_req("tx_multi_1")
    req2 = _make_req("tx_multi_2")

    r1 = coord.execute_transaction(req1)
    r2 = coord.execute_transaction(req2)

    assert isinstance(r1, ParticipantControlReceiptV2)
    assert isinstance(r2, ParticipantControlReceiptV2)
    assert r1.resource_revision == 1
    assert r2.resource_revision == 2
