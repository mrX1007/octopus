"""Tests for C2 control transaction coordinator."""

from __future__ import annotations

import os
import sqlite3
import time

import pytest

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.control_transactions import ControlTransactionCoordinator
from core.c2.resource_participant import C2DaemonResourceParticipant
from tests.helpers.c2_authority import provision_test_authority

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"P" * 32


def _setup_participant_and_auth(
    part_id: str = "part_test",
) -> tuple[C2DaemonResourceParticipant, VerifiedMutationAuthority]:
    participant = C2DaemonResourceParticipant(participant_id=part_id)
    with sqlite3.connect(participant._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_coord",
            subject_id="s1",
            key_id="k1",
            public_key=TEST_ED_PUB,
            mission_id="m1",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )
    now_ms = int(time.time() * 1000)
    auth = VerifiedMutationAuthority(
        operator_id="op_coord",
        subject_id="s1",
        mission_id="m1",
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id="k1",
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest="a" * 64,
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="",
        participant_id=part_id,
        action_id="",
    )
    return participant, auth


def _make_req(tx_id: str = "tx_1", part_id: str = "part_test") -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id=tx_id,
        participant_id=part_id,
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
    participant, auth = _setup_participant_and_auth("part_test")
    coord.register_participant("part_test", participant)

    req = _make_req("tx_coord_1", "part_test")
    mut_auth = VerifiedMutationAuthority(
        operator_id=auth.operator_id,
        subject_id=auth.subject_id,
        mission_id=auth.mission_id,
        peer_pid=auth.peer_pid,
        peer_uid=auth.peer_uid,
        peer_gid=auth.peer_gid,
        key_id=auth.key_id,
        key_revision=auth.key_revision,
        operator_revision=auth.operator_revision,
        peer_binding_revision=auth.peer_binding_revision,
        mission_grant_revision=auth.mission_grant_revision,
        request_digest=req.authorization.request_digest,
        authorization_issued_at_ms=req.authorization.issued_at_ms,
        authorization_expires_at_ms=req.authorization.expires_at_ms,
        transaction_id="tx_coord_1",
        participant_id="part_test",
        action_id="",
    )
    receipt = coord.execute_transaction(req, authority=mut_auth)
    assert isinstance(receipt, ParticipantControlReceiptV2)
    assert receipt.transaction_id == "tx_coord_1"
    assert receipt.resource_revision == 1


def test_coordinator_rejects_unregistered_participant():
    coord = ControlTransactionCoordinator()
    req = _make_req("tx_unregistered_1", "part_unregistered")
    res = coord.execute_transaction(req)
    assert not isinstance(res, ParticipantControlReceiptV2)
    assert res.reason_code == C2ControlErrorCodeV2.UNAVAILABLE
    assert "unregistered_participant" in res.detail_ref


def test_coordinator_multiple_transactions():
    coord = ControlTransactionCoordinator()
    participant, auth = _setup_participant_and_auth("part_test")
    coord.register_participant("part_test", participant)

    req1 = _make_req("tx_multi_1", "part_test")
    mut_auth1 = VerifiedMutationAuthority(
        operator_id=auth.operator_id,
        subject_id=auth.subject_id,
        mission_id=auth.mission_id,
        peer_pid=auth.peer_pid,
        peer_uid=auth.peer_uid,
        peer_gid=auth.peer_gid,
        key_id=auth.key_id,
        key_revision=auth.key_revision,
        operator_revision=auth.operator_revision,
        peer_binding_revision=auth.peer_binding_revision,
        mission_grant_revision=auth.mission_grant_revision,
        request_digest=req1.authorization.request_digest,
        authorization_issued_at_ms=req1.authorization.issued_at_ms,
        authorization_expires_at_ms=req1.authorization.expires_at_ms,
        transaction_id="tx_multi_1",
        participant_id="part_test",
        action_id="",
    )
    req2 = _make_req("tx_multi_2", "part_test")
    mut_auth2 = VerifiedMutationAuthority(
        operator_id=auth.operator_id,
        subject_id=auth.subject_id,
        mission_id=auth.mission_id,
        peer_pid=auth.peer_pid,
        peer_uid=auth.peer_uid,
        peer_gid=auth.peer_gid,
        key_id=auth.key_id,
        key_revision=auth.key_revision,
        operator_revision=auth.operator_revision,
        peer_binding_revision=auth.peer_binding_revision,
        mission_grant_revision=auth.mission_grant_revision,
        request_digest=req2.authorization.request_digest,
        authorization_issued_at_ms=req2.authorization.issued_at_ms,
        authorization_expires_at_ms=req2.authorization.expires_at_ms,
        transaction_id="tx_multi_2",
        participant_id="part_test",
        action_id="",
    )

    r1 = coord.execute_transaction(req1, authority=mut_auth1)
    r2 = coord.execute_transaction(req2, authority=mut_auth2)

    assert isinstance(r1, ParticipantControlReceiptV2)
    assert isinstance(r2, ParticipantControlReceiptV2)
    assert r1.resource_revision == 1
    assert r2.resource_revision == 2
