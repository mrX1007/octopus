"""Tests for C2 resource visibility fence and hidden commit state (§14.6A)."""

from __future__ import annotations

import os
import sqlite3
import time

import pytest

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    C2ControlAction,
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
    participant_id: str = "part-vis-1",
) -> tuple[C2DaemonResourceParticipant, VerifiedMutationAuthority]:
    part = C2DaemonResourceParticipant(participant_id=participant_id)
    with sqlite3.connect(part._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op-vis",
            subject_id="sub-vis",
            key_id="key-1",
            public_key=TEST_ED_PUB,
            mission_id="m-vis",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )
    now_ms = int(time.time() * 1000)
    auth = VerifiedMutationAuthority(
        operator_id="op-vis",
        subject_id="sub-vis",
        mission_id="m-vis",
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id="key-1",
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest="0" * 64,
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="",
        participant_id=participant_id,
        action_id="",
    )
    return part, auth


def _make_req(
    action: C2ControlAction,
    tx_id: str,
    participant_id: str = "part-vis-1",
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
) -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="key-1",
        transaction_id=tx_id,
        participant_id=participant_id,
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
    part, auth = _setup_participant_with_auth(participant_id="part-vis-1")
    prep_req = _make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-vis-1", participant_id="part-vis-1")
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
        request_digest=prep_req.authorization.request_digest,
        authorization_issued_at_ms=prep_req.authorization.issued_at_ms,
        authorization_expires_at_ms=prep_req.authorization.expires_at_ms,
        transaction_id="tx-vis-1",
        participant_id="part-vis-1",
        action_id=prep_req.action.value,
    )
    prep = part.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep, ParticipantControlReceiptV2)

    # Commit keeps resource COMMITTED_HIDDEN
    commit_req = _make_req(
        C2ControlAction.COMMIT_C2_RESOURCE,
        "tx-vis-1",
        participant_id="part-vis-1",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
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
        transaction_id="tx-vis-1",
        participant_id="part-vis-1",
        action_id=commit_req.action.value,
    )
    commit = part.commit(commit_req, authority=commit_auth)
    assert isinstance(commit, ParticipantControlReceiptV2)
    assert part._committed_resources["tx-vis-1"]["phase"] == ParticipantControlPhaseV2.COMMITTED_HIDDEN

    # Finalize visibility transitions to FINALIZED_VISIBLE
    fin_req = _make_req(
        C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        "tx-vis-1",
        participant_id="part-vis-1",
        prior_receipt_ref=commit.receipt_ref,
        prior_receipt_digest=commit.receipt_digest,
    )
    fin_auth = VerifiedMutationAuthority(
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
        request_digest=fin_req.authorization.request_digest,
        authorization_issued_at_ms=fin_req.authorization.issued_at_ms,
        authorization_expires_at_ms=fin_req.authorization.expires_at_ms,
        transaction_id="tx-vis-1",
        participant_id="part-vis-1",
        action_id=fin_req.action.value,
    )
    part.finalize_visibility(fin_req, authority=fin_auth)
    assert part._committed_resources["tx-vis-1"]["phase"] == ParticipantControlPhaseV2.FINALIZED_VISIBLE


def test_aborted_resource_never_becomes_visible():
    part, auth = _setup_participant_with_auth(participant_id="part-vis-2")
    prep_req = _make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-vis-2", participant_id="part-vis-2")
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
        request_digest=prep_req.authorization.request_digest,
        authorization_issued_at_ms=prep_req.authorization.issued_at_ms,
        authorization_expires_at_ms=prep_req.authorization.expires_at_ms,
        transaction_id="tx-vis-2",
        participant_id="part-vis-2",
        action_id=prep_req.action.value,
    )
    prep = part.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep, ParticipantControlReceiptV2)

    abort_req = _make_req(
        C2ControlAction.ABORT_C2_RESOURCE,
        "tx-vis-2",
        participant_id="part-vis-2",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
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
        transaction_id="tx-vis-2",
        participant_id="part-vis-2",
        action_id=abort_req.action.value,
    )
    part.rollback(abort_req, authority=abort_auth)
    # Check that transaction is removed from pending
    assert "tx-vis-2" not in part._pending_transactions
