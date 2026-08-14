"""Tests for C2 control transaction coordinator."""
from __future__ import annotations

import time
import pytest
from core.c2.control_transactions import ControlTransactionCoordinator
from core.c2.resource_participant import C2DaemonResourceParticipant
from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
    ParticipantControlReceiptV1,
)

pytestmark = pytest.mark.unit


def _make_req(tx_id: str = "tx_1") -> ParticipantControlRequestV1:
    auth = ParticipantControlAuthorizationV1(
        key_id="k1",
        transaction_id=tx_id,
        participant_id="part_test",
        mission_id="m1",
        subject_id="s1",
        action_id="prepare_c2_resource",
        coordinator_revision=1,
        request_digest="reqdig",
        expires_at=time.time() + 300,
        nonce="n1",
        signature="sig",
    )
    return ParticipantControlRequestV1(
        action=C2ControlActionV1.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="pdig",
        canonical_payload_b64u="e30",
    )


def test_coordinator_execute_transaction_success():
    coord = ControlTransactionCoordinator()
    participant = C2DaemonResourceParticipant(participant_id="part_test")
    coord.register_participant("part_test", participant)

    req = _make_req("tx_coord_1")
    receipt = coord.execute_transaction(req)
    assert isinstance(receipt, ParticipantControlReceiptV1)
    assert receipt.transaction_id == "tx_coord_1"
    assert receipt.resource_revision == 1


def test_coordinator_auto_creates_participant():
    coord = ControlTransactionCoordinator()
    req = _make_req("tx_auto_1")
    receipt = coord.execute_transaction(req)
    assert isinstance(receipt, ParticipantControlReceiptV1)
    assert receipt.transaction_id == "tx_auto_1"


def test_coordinator_multiple_transactions():
    coord = ControlTransactionCoordinator()
    req1 = _make_req("tx_multi_1")
    req2 = _make_req("tx_multi_2")

    r1 = coord.execute_transaction(req1)
    r2 = coord.execute_transaction(req2)

    assert isinstance(r1, ParticipantControlReceiptV1)
    assert isinstance(r2, ParticipantControlReceiptV1)
    assert r1.resource_revision == 1
    assert r2.resource_revision == 2
