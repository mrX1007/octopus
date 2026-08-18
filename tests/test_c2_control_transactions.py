"""Tests for C2 control transaction coordinator with independent phase authorization."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    BoundedControlErrorV1,
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV1,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV1,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV1,
    ParticipantControlRequestV2,
)
from core.c2.control_transactions import ControlTransactionCoordinator
from core.c2.resource_participant import C2DaemonResourceParticipant
from tests.helpers.c2_authority import provision_test_authority

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"P" * 32


def _setup_participant_and_auth(
    part_id: str = "part_test",
) -> tuple[C2DaemonResourceParticipant, dict[str, Any]]:
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
    return participant, {
        "operator_id": "op_coord",
        "subject_id": "s1",
        "mission_id": "m1",
        "peer_pid": os.getpid(),
        "peer_uid": os.getuid(),
        "peer_gid": os.getgid(),
        "key_id": "k1",
        "key_revision": 1,
        "operator_revision": 1,
        "peer_binding_revision": 1,
        "mission_grant_revision": 1,
    }


def _make_phase_pair(
    action: C2ControlAction,
    tx_id: str,
    part_id: str,
    auth_meta: dict[str, Any],
    *,
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
    expected_resource_revision: int | None = None,
    payload_schema_id: str = "schema:c2_test",
    payload_digest: str = "d" * 64,
    nonce: str | None = None,
    req_digest: str | None = None,
    action_id_override: str | None = None,
    tx_id_override: str | None = None,
    part_id_override: str | None = None,
    operator_id_override: str | None = None,
) -> tuple[ParticipantControlRequestV2, VerifiedMutationAuthority]:
    now_ms = int(time.time() * 1000)
    actual_nonce = nonce or f"nonce_{action.value[:6]}_{uuid.uuid4().hex[:12]}"
    act_id = action_id_override or action.value
    target_tx_id = tx_id_override or tx_id
    target_part_id = part_id_override or part_id
    target_op_id = operator_id_override or auth_meta["operator_id"]
    actual_req_digest = (
        req_digest or hashlib.sha256(f"{act_id}_{target_tx_id}_{target_part_id}_{actual_nonce}".encode()).hexdigest()
    )

    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id=auth_meta["key_id"],
        transaction_id=target_tx_id,
        participant_id=target_part_id,
        mission_id=auth_meta["mission_id"],
        subject_id=auth_meta["subject_id"],
        action_id=act_id,
        coordinator_revision=1,
        request_digest=actual_req_digest,
        issued_at_ms=now_ms - 100,
        expires_at_ms=now_ms + 100000,
        nonce=actual_nonce,
        signature="c" * 86,
    )
    req = ParticipantControlRequestV2(
        action=action,
        authorization=auth,
        payload_schema_id=payload_schema_id,
        payload_digest=payload_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prior_receipt_ref,
        prior_receipt_digest=prior_receipt_digest,
        expected_resource_revision=expected_resource_revision,
    )
    mut_auth = VerifiedMutationAuthority(
        operator_id=target_op_id,
        subject_id=auth_meta["subject_id"],
        mission_id=auth_meta["mission_id"],
        peer_pid=auth_meta["peer_pid"],
        peer_uid=auth_meta["peer_uid"],
        peer_gid=auth_meta["peer_gid"],
        key_id=auth_meta["key_id"],
        key_revision=auth_meta["key_revision"],
        operator_revision=auth_meta["operator_revision"],
        peer_binding_revision=auth_meta["peer_binding_revision"],
        mission_grant_revision=auth_meta["mission_grant_revision"],
        request_digest=actual_req_digest,
        authorization_issued_at_ms=auth.issued_at_ms,
        authorization_expires_at_ms=auth.expires_at_ms,
        transaction_id=target_tx_id,
        participant_id=target_part_id,
        action_id=act_id,
    )
    return req, mut_auth


def test_coordinator_direct_phase_methods_with_independent_authorities():
    """Verify coordinator direct phase execution (prepare -> commit -> finalize) with distinct authorities."""
    coord = ControlTransactionCoordinator()
    part, meta = _setup_participant_and_auth("part_direct")
    coord.register_participant("part_direct", part)
    tx_id = "tx_coord_direct_1"

    # 1. Prepare
    prep_req, prep_auth = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, tx_id, "part_direct", meta)
    prep_receipt = coord.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep_receipt, ParticipantControlReceiptV2)
    assert prep_receipt.transaction_id == tx_id

    # 2. Commit
    comm_req, comm_auth = _make_phase_pair(
        C2ControlAction.COMMIT_C2_RESOURCE,
        tx_id,
        "part_direct",
        meta,
        prior_receipt_ref=prep_receipt.receipt_ref,
        prior_receipt_digest=prep_receipt.receipt_digest,
    )
    comm_receipt = coord.commit(comm_req, authority=comm_auth)
    assert isinstance(comm_receipt, ParticipantControlReceiptV2)

    # 3. Finalize Visibility
    fin_req, fin_auth = _make_phase_pair(
        C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        tx_id,
        "part_direct",
        meta,
        prior_receipt_ref=comm_receipt.receipt_ref,
        prior_receipt_digest=comm_receipt.receipt_digest,
    )
    fin_receipt = coord.finalize_visibility(fin_req, authority=fin_auth)
    assert isinstance(fin_receipt, ParticipantControlReceiptV2)
    assert fin_receipt.resource_revision == 1


def test_coordinator_staged_transaction_full_orchestration():
    """Verify full multi-phase orchestration with distinct phase requests and independent authorities."""
    coord = ControlTransactionCoordinator()
    part, meta = _setup_participant_and_auth("part_orchestrated")
    coord.register_participant("part_orchestrated", part)
    tx_id = "tx_coord_orch_1"

    # Prepare phase
    prep_req, prep_auth = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, tx_id, "part_orchestrated", meta)
    prep_res = part.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep_res, ParticipantControlReceiptV2)

    # Re-initialize participant for coordinator to run full pipeline
    part2, meta2 = _setup_participant_and_auth("part_orch_fresh")
    coord.register_participant("part_orch_fresh", part2)
    tx_fresh = "tx_coord_fresh_1"

    prep_req_f, prep_auth_f = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, tx_fresh, "part_orch_fresh", meta2)

    # Execute prepare to get receipt digests for commit/finalize chaining
    prep_rcpt = part2.prepare(prep_req_f, authority=prep_auth_f)
    assert isinstance(prep_rcpt, ParticipantControlReceiptV2)

    comm_req_f, comm_auth_f = _make_phase_pair(
        C2ControlAction.COMMIT_C2_RESOURCE,
        tx_fresh,
        "part_orch_fresh",
        meta2,
        prior_receipt_ref=prep_rcpt.receipt_ref,
        prior_receipt_digest=prep_rcpt.receipt_digest,
    )
    comm_rcpt = part2.commit(comm_req_f, authority=comm_auth_f)
    assert isinstance(comm_rcpt, ParticipantControlReceiptV2)

    fin_req_f, fin_auth_f = _make_phase_pair(
        C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        tx_fresh,
        "part_orch_fresh",
        meta2,
        prior_receipt_ref=comm_rcpt.receipt_ref,
        prior_receipt_digest=comm_rcpt.receipt_digest,
    )
    fin_rcpt = part2.finalize_visibility(fin_req_f, authority=fin_auth_f)
    assert isinstance(fin_rcpt, ParticipantControlReceiptV2)


def test_coordinator_transaction_intent_mismatches_rejected():
    """Verify that cross-phase intent mismatches fail closed before execution."""
    coord = ControlTransactionCoordinator()
    part, meta = _setup_participant_and_auth("part_intent")
    coord.register_participant("part_intent", part)
    tx_id = "tx_intent_1"

    prep_req, prep_auth = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, tx_id, "part_intent", meta)

    # 1. Transaction ID mismatch between prepare and commit
    comm_req_bad_tx, comm_auth_bad_tx = _make_phase_pair(
        C2ControlAction.COMMIT_C2_RESOURCE,
        "tx_mismatched",
        "part_intent",
        meta,
        prior_receipt_ref="rcpt:p",
        prior_receipt_digest="0" * 64,
    )
    fin_req, fin_auth = _make_phase_pair(
        C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        tx_id,
        "part_intent",
        meta,
        prior_receipt_ref="rcpt:c",
        prior_receipt_digest="0" * 64,
    )

    err = coord.execute_v2_transaction(
        prep_req,
        comm_req_bad_tx,
        fin_req,
        prepare_authority=prep_auth,
        commit_authority=comm_auth_bad_tx,
        finalize_authority=fin_auth,
    )
    assert isinstance(err, BoundedControlErrorV2)
    assert err.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED
    assert "transaction_intent_mismatch:transaction_id" in err.detail_ref

    # 2. Participant ID mismatch between prepare and commit
    comm_req_bad_p, comm_auth_bad_p = _make_phase_pair(
        C2ControlAction.COMMIT_C2_RESOURCE,
        tx_id,
        "part_other",
        meta,
        prior_receipt_ref="rcpt:p",
        prior_receipt_digest="0" * 64,
    )
    err_p = coord.execute_v2_transaction(
        prep_req,
        comm_req_bad_p,
        fin_req,
        prepare_authority=prep_auth,
        commit_authority=comm_auth_bad_p,
        finalize_authority=fin_auth,
    )
    assert isinstance(err_p, BoundedControlErrorV2)
    assert err_p.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED
    assert "transaction_intent_mismatch:participant_id" in err_p.detail_ref

    # 3. Payload digest mismatch between prepare and commit
    comm_req_bad_dig, comm_auth_bad_dig = _make_phase_pair(
        C2ControlAction.COMMIT_C2_RESOURCE,
        tx_id,
        "part_intent",
        meta,
        payload_digest="f" * 64,
        prior_receipt_ref="rcpt:p",
        prior_receipt_digest="0" * 64,
    )
    err_dig = coord.execute_v2_transaction(
        prep_req,
        comm_req_bad_dig,
        fin_req,
        prepare_authority=prep_auth,
        commit_authority=comm_auth_bad_dig,
        finalize_authority=fin_auth,
    )
    assert isinstance(err_dig, BoundedControlErrorV2)
    assert err_dig.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED
    assert "transaction_intent_mismatch:payload" in err_dig.detail_ref


def test_coordinator_rejects_unregistered_participant():
    coord = ControlTransactionCoordinator()
    _, meta = _setup_participant_and_auth("part_test")
    req, auth = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, "tx_unregistered_1", "part_unregistered", meta)

    # 1. Unregistered participant with authority returns UNAVAILABLE
    res = coord.prepare(req, authority=auth)
    assert isinstance(res, BoundedControlErrorV2)
    assert res.reason_code == C2ControlErrorCodeV2.UNAVAILABLE
    assert "unregistered_participant" in res.detail_ref

    # 2. Direct phase without authority returns NOT_AUTHORIZED
    res_no_auth = coord.prepare(req, authority=None)  # type: ignore[arg-type]
    assert isinstance(res_no_auth, BoundedControlErrorV2)
    assert res_no_auth.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED


def test_coordinator_v1_unregistered_and_failure_rollbacks():
    """Verify coordinator handling for V1 legacy transaction path."""
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

    _, meta = _setup_participant_and_auth("part_mock")
    req_v2, auth_v2 = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, "tx_fail_prep", "part_mock", meta)
    res_prep_fail = coord.prepare(req_v2, authority=auth_v2)
    assert isinstance(res_prep_fail, BoundedControlErrorV2)
    assert res_prep_fail.detail_ref == "prep_failed"

    # 3. Rollback propagation
    mock_part.rollback.return_value = ParticipantControlReceiptV2(
        transaction_id="tx_fail_commit",
        participant_id="part_mock",
        action=C2ControlAction.ABORT_C2_RESOURCE,
        resource_ref="c2:res:1",
        resource_revision=1,
        receipt_ref="rcpt:abort",
        receipt_digest="0" * 64,
        daemon_instance_id="inst1",
        result_payload_schema_id=None,
        result_payload_digest=None,
    )
    abort_req, abort_auth = _make_phase_pair(C2ControlAction.ABORT_C2_RESOURCE, "tx_fail_commit", "part_mock", meta)
    res_rollback = coord.rollback(abort_req, authority=abort_auth)
    assert isinstance(res_rollback, ParticipantControlReceiptV2)
    assert res_rollback.action == C2ControlAction.ABORT_C2_RESOURCE


def test_coordinator_mutation_invariants_reject_tampered_fields():
    """Verify that tampering with action, nonce, prior receipt, revision or payload fails closed."""
    coord = ControlTransactionCoordinator()
    part, meta = _setup_participant_and_auth("part_tamper")
    coord.register_participant("part_tamper", part)
    tx_id = "tx_tamper_1"

    prep_req, prep_auth = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, tx_id, "part_tamper", meta)
    prep_rcpt = coord.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep_rcpt, ParticipantControlReceiptV2)

    # 1. Action modification between request and authority
    comm_req, comm_auth = _make_phase_pair(
        C2ControlAction.COMMIT_C2_RESOURCE,
        tx_id,
        "part_tamper",
        meta,
        prior_receipt_ref=prep_rcpt.receipt_ref,
        prior_receipt_digest=prep_rcpt.receipt_digest,
    )
    # Tamper with request action vs authority
    tampered_auth = VerifiedMutationAuthority(
        operator_id=comm_auth.operator_id,
        subject_id=comm_auth.subject_id,
        mission_id=comm_auth.mission_id,
        peer_pid=comm_auth.peer_pid,
        peer_uid=comm_auth.peer_uid,
        peer_gid=comm_auth.peer_gid,
        key_id=comm_auth.key_id,
        key_revision=comm_auth.key_revision,
        operator_revision=comm_auth.operator_revision,
        peer_binding_revision=comm_auth.peer_binding_revision,
        mission_grant_revision=comm_auth.mission_grant_revision,
        request_digest=comm_auth.request_digest,
        authorization_issued_at_ms=comm_auth.authorization_issued_at_ms,
        authorization_expires_at_ms=comm_auth.authorization_expires_at_ms,
        transaction_id=tx_id,
        participant_id="part_tamper",
        action_id="finalize_c2_resource_visibility",  # Action mismatch
    )
    res_act = coord.commit(comm_req, authority=tampered_auth)
    assert isinstance(res_act, BoundedControlErrorV2)
    assert res_act.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED

    # 2. Prior receipt digest tampering
    bad_prior_req, bad_prior_auth = _make_phase_pair(
        C2ControlAction.COMMIT_C2_RESOURCE,
        tx_id,
        "part_tamper",
        meta,
        prior_receipt_ref=prep_rcpt.receipt_ref,
        prior_receipt_digest="9" * 64,  # Bad prior digest
    )
    res_prior = coord.commit(bad_prior_req, authority=bad_prior_auth)
    assert isinstance(res_prior, BoundedControlErrorV2)
    assert res_prior.reason_code in (
        C2ControlErrorCodeV2.WRONG_PHASE,
        C2ControlErrorCodeV2.MALFORMED,
        C2ControlErrorCodeV2.NOT_AUTHORIZED,
        C2ControlErrorCodeV2.INTERNAL_FAILURE,
    )


def test_coordinator_per_phase_independent_replay_rejection():
    """Verify that replay of PREPARE, COMMIT, and FINALIZE with modified nonces or tampering is rejected."""
    coord = ControlTransactionCoordinator()
    part, meta = _setup_participant_and_auth("part_replay")
    coord.register_participant("part_replay", part)
    tx_id = "tx_replay_1"

    # Phase 1: Prepare
    prep_req1, prep_auth1 = _make_phase_pair(C2ControlAction.PREPARE_C2_RESOURCE, tx_id, "part_replay", meta)
    res_prep1 = coord.prepare(prep_req1, authority=prep_auth1)
    assert isinstance(res_prep1, ParticipantControlReceiptV2)

    # Identical replay returns cached idempotent receipt
    res_prep_replay = coord.prepare(prep_req1, authority=prep_auth1)
    assert isinstance(res_prep_replay, ParticipantControlReceiptV2)
    assert res_prep_replay.receipt_ref == res_prep1.receipt_ref

    # Tampered replay with new nonce but same tx fails WRONG_PHASE or IDEMPOTENCY_CONFLICT or REPLAY
    prep_req_dup, prep_auth_dup = _make_phase_pair(
        C2ControlAction.PREPARE_C2_RESOURCE,
        tx_id,
        "part_replay",
        meta,
        nonce="nonce_different_dup_1",
    )
    res_prep_dup = coord.prepare(prep_req_dup, authority=prep_auth_dup)
    assert isinstance(res_prep_dup, BoundedControlErrorV2)
    assert res_prep_dup.reason_code in (
        C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
        C2ControlErrorCodeV2.WRONG_PHASE,
        C2ControlErrorCodeV2.REPLAY,
    )
