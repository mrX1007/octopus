"""Tests for C2 control transaction coordinator."""

from __future__ import annotations

import os
import sqlite3
import time
import uuid

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
        transaction_id="tx_default",
        participant_id=part_id,
        action_id="prepare_c2_resource",
    )
    return participant, auth


def _make_req(tx_id: str = "tx_1", part_id: str = "part_test", nonce: str | None = None) -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    req_nonce = nonce or f"nonce_{uuid.uuid4().hex[:14]}"
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
        nonce=req_nonce,
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
        action_id="prepare_c2_resource",
    )
    receipt = coord.execute_transaction(req, authority=mut_auth)
    assert isinstance(receipt, ParticipantControlReceiptV2)
    assert receipt.transaction_id == "tx_coord_1"
    assert receipt.resource_revision == 1


def test_coordinator_rejects_unregistered_participant():
    coord = ControlTransactionCoordinator()
    participant, auth = _setup_participant_and_auth("part_test")
    req = _make_req("tx_unregistered_1", "part_unregistered")
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
        transaction_id="tx_unregistered_1",
        participant_id="part_unregistered",
        action_id="prepare_c2_resource",
    )
    # 1. Unregistered participant with authority returns UNAVAILABLE
    res = coord.execute_transaction(req, authority=mut_auth)
    assert not isinstance(res, ParticipantControlReceiptV2)
    assert res.reason_code == C2ControlErrorCodeV2.UNAVAILABLE
    assert "unregistered_participant" in res.detail_ref

    # 2. V2 request without authority returns NOT_AUTHORIZED
    res_no_auth = coord.execute_transaction(req)
    assert res_no_auth.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED


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
        action_id="prepare_c2_resource",
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
        action_id="prepare_c2_resource",
    )

    r1 = coord.execute_transaction(req1, authority=mut_auth1)
    r2 = coord.execute_transaction(req2, authority=mut_auth2)

    assert isinstance(r1, ParticipantControlReceiptV2)
    assert isinstance(r2, ParticipantControlReceiptV2)
    assert r1.resource_revision == 1
    assert r2.resource_revision == 2


def test_coordinator_v1_unregistered_and_failure_rollbacks():
    """Verify coordinator handling for V1 unregistered participant and commit rollback propagation."""
    from unittest.mock import MagicMock

    from core.c2.control_commands import (
        BoundedControlErrorV1,
        BoundedControlErrorV2,
        C2ControlErrorCodeV1,
        C2ControlErrorCodeV2,
        ParticipantControlAuthorizationV1,
        ParticipantControlRequestV1,
    )

    coord = ControlTransactionCoordinator()

    # 1. V1 request to unregistered participant returns BoundedControlErrorV1
    auth_v1 = ParticipantControlAuthorizationV1(
        key_id="k1",
        transaction_id="tx_v1_1",
        participant_id="part_unreg_v1",
        mission_id="m1",
        subject_id="s1",
        action_id=C2ControlAction.PREPARE_C2_RESOURCE.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        expires_at=time.time() + 100,
        nonce="nonce123456789012",
        signature="0" * 86,
    )
    req_v1 = ParticipantControlRequestV1(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth_v1,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    res_v1 = coord.execute_transaction(req_v1)
    assert isinstance(res_v1, BoundedControlErrorV1)
    assert res_v1.reason_code == C2ControlErrorCodeV1.UNAVAILABLE

    # 2. Mock participant where prepare fails with BoundedControlErrorV2
    mock_part = MagicMock()
    mock_part.prepare.return_value = BoundedControlErrorV2(
        reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
        retryable=False,
        detail_ref="prep_failed",
    )
    coord.register_participant("part_mock", mock_part)

    now_ms = int(time.time() * 1000)
    real_auth = VerifiedMutationAuthority(
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
        transaction_id="tx_fail_prep",
        participant_id="part_mock",
        action_id="prepare_c2_resource",
    )
    req_v2 = _make_req("tx_fail_prep", "part_mock")
    res_prep_fail = coord.execute_transaction(req_v2, authority=real_auth)
    assert isinstance(res_prep_fail, BoundedControlErrorV2)
    assert res_prep_fail.detail_ref == "prep_failed"

    # 3. Mock participant where commit fails with BoundedControlErrorV2 (with authority)
    prep_receipt = ParticipantControlReceiptV2(
        transaction_id="tx_fail_commit",
        participant_id="part_mock",
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        resource_ref="c2:res:1",
        resource_revision=1,
        receipt_ref="rcpt:prep",
        receipt_digest="0" * 64,
        daemon_instance_id="inst1",
        result_payload_schema_id=None,
        result_payload_digest=None,
    )
    mock_part.prepare.return_value = prep_receipt
    mock_part.commit.return_value = BoundedControlErrorV2(
        reason_code=C2ControlErrorCodeV2.INTERNAL_FAILURE,
        retryable=False,
        detail_ref="commit_failed",
    )

    real_commit_auth = VerifiedMutationAuthority(
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
        transaction_id="tx_fail_commit",
        participant_id="part_mock",
        action_id="prepare_c2_resource",
    )
    req_commit_fail = _make_req("tx_fail_commit", "part_mock")
    res_commit_fail = coord.execute_transaction(req_commit_fail, authority=real_commit_auth)
    assert isinstance(res_commit_fail, BoundedControlErrorV2)
    assert res_commit_fail.detail_ref == "commit_failed"
    import dataclasses

    expected_abort_auth = dataclasses.replace(real_commit_auth, action_id="abort_c2_resource")
    mock_part.rollback.assert_called_with(prep_receipt, authority=expected_abort_auth)

    # 4. Commit fails without authority
    res_commit_fail_no_auth = coord.execute_transaction(req_commit_fail, authority=None)
    assert isinstance(res_commit_fail_no_auth, BoundedControlErrorV2)
    assert res_commit_fail_no_auth.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED
