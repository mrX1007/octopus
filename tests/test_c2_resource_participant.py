"""Tests for C2 daemon resource participant."""

from __future__ import annotations

import os
import sqlite3
import time
import uuid

import pytest

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV2,
    ParticipantControlPhaseV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.resource_participant import C2DaemonResourceParticipant
from tests.helpers.c2_authority import provision_test_authority

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"P" * 32


def _setup_participant_with_auth(
    participant_id: str = "part1",
) -> tuple[C2DaemonResourceParticipant, VerifiedMutationAuthority]:
    participant = C2DaemonResourceParticipant(participant_id=participant_id)
    with sqlite3.connect(participant._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_admin",
            subject_id="s1",
            key_id="k1",
            public_key=TEST_ED_PUB,
            mission_id="m1",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )

    now_ms = int(time.time() * 1000)
    auth = VerifiedMutationAuthority(
        operator_id="op_admin",
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
        request_digest="0" * 64,
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="tx_default",
        participant_id=participant_id,
        action_id="prepare_c2_resource",
    )
    return participant, auth


def _make_request(
    tx_id: str = "tx1",
    action: C2ControlAction = C2ControlAction.PREPARE_C2_RESOURCE,
    rev: int | None = None,
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
    participant_id: str = "part1",
    nonce: str | None = None,
) -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    req_nonce = nonce or f"nonce_{action.value}_{uuid.uuid4().hex[:12]}"
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id=tx_id,
        participant_id=participant_id,
        mission_id="m1",
        subject_id="s1",
        action_id=action.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce=req_nonce,
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
    participant, auth = _setup_participant_with_auth("part1")
    req = _make_request("tx_2pc_1", participant_id="part1")
    prep_auth = VerifiedMutationAuthority(
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
        transaction_id="tx_2pc_1",
        participant_id="part1",
        action_id=req.action.value,
    )

    # 1. Prepare
    prep_receipt = participant.prepare(req, authority=prep_auth)
    assert isinstance(prep_receipt, ParticipantControlReceiptV2)
    assert prep_receipt.transaction_id == "tx_2pc_1"
    assert prep_receipt.resource_revision == 0

    # 2. Commit
    commit_req = _make_request(
        "tx_2pc_1",
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        prior_receipt_ref=prep_receipt.receipt_ref,
        prior_receipt_digest=prep_receipt.receipt_digest,
        participant_id="part1",
    )
    commit_auth = VerifiedMutationAuthority(
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
        request_digest=commit_req.authorization.request_digest,
        authorization_issued_at_ms=commit_req.authorization.issued_at_ms,
        authorization_expires_at_ms=commit_req.authorization.expires_at_ms,
        transaction_id="tx_2pc_1",
        participant_id="part1",
        action_id=commit_req.action.value,
    )
    commit_receipt = participant.commit(commit_req, authority=commit_auth)
    assert isinstance(commit_receipt, ParticipantControlReceiptV2)
    assert commit_receipt.resource_revision == 1

    # 3. Finalize
    finalize_req = _make_request(
        "tx_2pc_1",
        action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        prior_receipt_ref=commit_receipt.receipt_ref,
        prior_receipt_digest=commit_receipt.receipt_digest,
        participant_id="part1",
    )
    finalize_auth = VerifiedMutationAuthority(
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
        request_digest=finalize_req.authorization.request_digest,
        authorization_issued_at_ms=finalize_req.authorization.issued_at_ms,
        authorization_expires_at_ms=finalize_req.authorization.expires_at_ms,
        transaction_id="tx_2pc_1",
        participant_id="part1",
        action_id=finalize_req.action.value,
    )
    final_receipt = participant.finalize_visibility(finalize_req, authority=finalize_auth)
    assert isinstance(final_receipt, ParticipantControlReceiptV2)
    assert final_receipt.resource_revision == 1


def test_resource_participant_revision_mismatch_error():
    participant, auth = _setup_participant_with_auth("part1")
    # Expected revision 5, but current is 0
    req = _make_request("tx_mismatch", rev=5, participant_id="part1")
    prep_auth = VerifiedMutationAuthority(
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
        transaction_id="tx_mismatch",
        participant_id="part1",
        action_id=req.action.value,
    )

    res = participant.prepare(req, authority=prep_auth)
    assert isinstance(res, BoundedControlErrorV2)
    assert res.retryable is True


def test_resource_participant_rollback():
    participant, auth = _setup_participant_with_auth("part1")
    req = _make_request("tx_rollback_1", participant_id="part1")
    prep_auth = VerifiedMutationAuthority(
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
        transaction_id="tx_rollback_1",
        participant_id="part1",
        action_id=req.action.value,
    )

    prep_rcpt = participant.prepare(req, authority=prep_auth)
    assert isinstance(prep_rcpt, ParticipantControlReceiptV2)

    abort_req = _make_request(
        "tx_rollback_1",
        action=C2ControlAction.ABORT_C2_RESOURCE,
        prior_receipt_ref=prep_rcpt.receipt_ref,
        prior_receipt_digest=prep_rcpt.receipt_digest,
        participant_id="part1",
    )
    abort_auth = VerifiedMutationAuthority(
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
        request_digest=abort_req.authorization.request_digest,
        authorization_issued_at_ms=abort_req.authorization.issued_at_ms,
        authorization_expires_at_ms=abort_req.authorization.expires_at_ms,
        transaction_id="tx_rollback_1",
        participant_id="part1",
        action_id=abort_req.action.value,
    )
    rollback_rcpt = participant.rollback(abort_req, authority=abort_auth)
    assert isinstance(rollback_rcpt, ParticipantControlReceiptV2)
    assert rollback_rcpt.transaction_id == "tx_rollback_1"


def test_resource_participant_reconcile():
    participant = C2DaemonResourceParticipant(participant_id="part1")
    snap = participant.reconcile()
    assert snap.participant_id == "part1"
    assert snap.phase == ParticipantControlPhaseV2.FINALIZED_VISIBLE


def test_resource_participant_error_and_fence_paths():
    """Verify fence errors and mismatch handling across commit, finalize_visibility, and rollback."""
    participant, auth = _setup_participant_with_auth("part1")
    req = _make_request("tx_err_1", participant_id="part1")
    now_ms = int(time.time() * 1000)

    # 1. Prepare with DB fence failure (e.g. invalid key revision)
    bad_fence_auth = VerifiedMutationAuthority(
        operator_id=auth.operator_id,
        subject_id=auth.subject_id,
        mission_id=auth.mission_id,
        peer_pid=auth.peer_pid,
        peer_uid=auth.peer_uid,
        peer_gid=auth.peer_gid,
        key_id=auth.key_id,
        key_revision=999,  # Bad key revision
        operator_revision=auth.operator_revision,
        peer_binding_revision=auth.peer_binding_revision,
        mission_grant_revision=auth.mission_grant_revision,
        request_digest=req.authorization.request_digest,
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="tx_err_1",
        participant_id="part1",
        action_id=req.action.value,
    )
    res_prep_fence = participant.prepare(req, authority=bad_fence_auth)
    assert isinstance(res_prep_fence, BoundedControlErrorV2)

    # 2. Commit with DB fence failure
    commit_req = _make_request("tx_err_1", action=C2ControlAction.COMMIT_C2_RESOURCE, participant_id="part1")
    res_commit_fence = participant.commit(commit_req, authority=bad_fence_auth)
    assert isinstance(res_commit_fence, BoundedControlErrorV2)

    # 3. Finalize visibility with DB fence failure
    finalize_req = _make_request(
        "tx_err_1", action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY, participant_id="part1"
    )
    res_final_fence = participant.finalize_visibility(finalize_req, authority=bad_fence_auth)
    assert isinstance(res_final_fence, BoundedControlErrorV2)

    # 4. Rollback with DB fence failure
    res_roll_fence = participant.rollback(req, authority=bad_fence_auth)
    assert isinstance(res_roll_fence, BoundedControlErrorV2)

    # 5. Rollback with valid authority for unknown transaction returns clean receipt
    valid_auth = VerifiedMutationAuthority(
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
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="tx_unknown",
        participant_id="part1",
        action_id=C2ControlAction.ABORT_C2_RESOURCE.value,
    )
    unknown_req = _make_request("tx_unknown", action=C2ControlAction.ABORT_C2_RESOURCE, participant_id="part1")
    roll_unk = participant.rollback(unknown_req, authority=valid_auth)
    assert isinstance(roll_unk, BoundedControlErrorV2)
    assert roll_unk.reason_code == C2ControlErrorCodeV2.WRONG_PHASE
    assert "transaction_not_found" in roll_unk.detail_ref
