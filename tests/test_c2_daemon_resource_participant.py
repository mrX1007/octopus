"""Tests for C2 daemon resource participant 2PC transaction contracts (§14.6A)."""

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
    participant_id: str = "part-1", daemon_instance_id: str = "inst-1"
) -> tuple[C2DaemonResourceParticipant, VerifiedMutationAuthority]:
    part = C2DaemonResourceParticipant(participant_id=participant_id, daemon_instance_id=daemon_instance_id)
    with sqlite3.connect(part._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op-1",
            subject_id="sub-1",
            key_id="key-1",
            public_key=TEST_ED_PUB,
            mission_id="m-1",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )
    now_ms = int(time.time() * 1000)
    auth = VerifiedMutationAuthority(
        operator_id="op-1",
        subject_id="sub-1",
        mission_id="m-1",
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
    part_id: str = "part-1",
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
) -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="key-1",
        transaction_id=tx_id,
        participant_id=part_id,
        mission_id="m-1",
        subject_id="sub-1",
        action_id=action.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce-1-1234567890",
        signature="0" * 86,
    )
    return ParticipantControlRequestV2(
        action=action,
        authorization=auth,
        payload_schema_id="schema:enrollment",
        payload_digest="0" * 64,
        canonical_payload_b64u="ey...",
        prior_receipt_ref=prior_receipt_ref,
        prior_receipt_digest=prior_receipt_digest,
    )


def test_daemon_resource_participant_2pc_lifecycle():
    part, auth = _setup_participant_with_auth(participant_id="part-1", daemon_instance_id="inst-1")

    # 1. Prepare
    prep_req = _make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-100")
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
        transaction_id="tx-100",
        participant_id="part-1",
        action_id=prep_req.action.value,
    )
    prep_res = part.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep_res, ParticipantControlReceiptV2)
    assert prep_res.transaction_id == "tx-100"
    assert prep_res.resource_ref is not None

    # 2. Commit
    commit_req = _make_req(
        C2ControlAction.COMMIT_C2_RESOURCE,
        "tx-100",
        prior_receipt_ref=prep_res.receipt_ref,
        prior_receipt_digest=prep_res.receipt_digest,
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
        transaction_id="tx-100",
        participant_id="part-1",
        action_id=commit_req.action.value,
    )
    commit_res = part.commit(commit_req, authority=commit_auth)
    assert isinstance(commit_res, ParticipantControlReceiptV2)
    assert commit_res.resource_revision == 1

    # 3. Finalize visibility
    fin_req = _make_req(
        C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        "tx-100",
        prior_receipt_ref=commit_res.receipt_ref,
        prior_receipt_digest=commit_res.receipt_digest,
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
        transaction_id="tx-100",
        participant_id="part-1",
        action_id=fin_req.action.value,
    )
    fin_res = part.finalize_visibility(fin_req, authority=fin_auth)
    assert fin_res.transaction_id == "tx-100"
    assert part._committed_resources["tx-100"]["phase"] == ParticipantControlPhaseV2.FINALIZED_VISIBLE


def test_daemon_resource_participant_rollback():
    part, auth = _setup_participant_with_auth(participant_id="part-1", daemon_instance_id="inst-1")
    prep_req = _make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-200")
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
        transaction_id="tx-200",
        participant_id="part-1",
        action_id=prep_req.action.value,
    )
    prep_res = part.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep_res, ParticipantControlReceiptV2)

    abort_req = _make_req(
        C2ControlAction.ABORT_C2_RESOURCE,
        "tx-200",
        prior_receipt_ref=prep_res.receipt_ref,
        prior_receipt_digest=prep_res.receipt_digest,
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
        transaction_id="tx-200",
        participant_id="part-1",
        action_id=abort_req.action.value,
    )
    rollback_res = part.rollback(abort_req, authority=abort_auth)
    assert rollback_res.transaction_id == "tx-200"
    assert "tx-200" not in part._pending_transactions
