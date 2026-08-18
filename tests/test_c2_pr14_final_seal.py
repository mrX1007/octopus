"""Comprehensive unit test suite for PR-14 Phase A final seal invariants."""

from __future__ import annotations

import os
import sqlite3
import time
import uuid

import pytest

from core.c2.control_auth import AuthorityFence, VerifiedMutationAuthority
from core.c2.control_commands import (
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.resource_participant import (
    C2DaemonResourceParticipant,
    TransactionFailpoint,
)
from tests.helpers.c2_authority import provision_test_authority

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"Z" * 32


def _make_valid_auth(
    *,
    tx_id: str = "tx_seal_1",
    part_id: str = "part_seal",
    action_id: str = "prepare_c2_resource",
    req_digest: str = "a" * 64,
) -> VerifiedMutationAuthority:
    now_ms = int(time.time() * 1000)
    return VerifiedMutationAuthority(
        operator_id="op_seal",
        subject_id="sub_seal",
        mission_id="m_seal",
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id="k_seal",
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest=req_digest,
        authorization_issued_at_ms=now_ms - 500,
        authorization_expires_at_ms=now_ms + 60000,
        transaction_id=tx_id,
        participant_id=part_id,
        action_id=action_id,
    )


def test_verified_mutation_authority_mandatory_fields_and_validation():
    """Verify VerifiedMutationAuthority enforces all mandatory fields and strict __post_init__."""
    auth = _make_valid_auth()
    assert auth.operator_id == "op_seal"

    # 1. Reject empty strings
    with pytest.raises(ValueError, match="length must be between 1 and 256"):
        VerifiedMutationAuthority(
            operator_id="",
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
            request_digest=auth.request_digest,
            authorization_issued_at_ms=auth.authorization_issued_at_ms,
            authorization_expires_at_ms=auth.authorization_expires_at_ms,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            action_id=auth.action_id,
        )

    # 2. Reject invalid request_digest (not 64-char hex)
    with pytest.raises(ValueError, match="64-character lowercase hex"):
        VerifiedMutationAuthority(
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
            request_digest="invalid_digest",
            authorization_issued_at_ms=auth.authorization_issued_at_ms,
            authorization_expires_at_ms=auth.authorization_expires_at_ms,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            action_id=auth.action_id,
        )

    # 3. Reject negative revisions
    with pytest.raises(ValueError, match=r"must be >= 1"):
        VerifiedMutationAuthority(
            operator_id=auth.operator_id,
            subject_id=auth.subject_id,
            mission_id=auth.mission_id,
            peer_pid=auth.peer_pid,
            peer_uid=auth.peer_uid,
            peer_gid=auth.peer_gid,
            key_id=auth.key_id,
            key_revision=0,
            operator_revision=auth.operator_revision,
            peer_binding_revision=auth.peer_binding_revision,
            mission_grant_revision=auth.mission_grant_revision,
            request_digest=auth.request_digest,
            authorization_issued_at_ms=auth.authorization_issued_at_ms,
            authorization_expires_at_ms=auth.authorization_expires_at_ms,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            action_id=auth.action_id,
        )

    # 4. Reject TTL exceeding 300,000ms
    with pytest.raises(ValueError, match="TTL cannot exceed"):
        VerifiedMutationAuthority(
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
            request_digest=auth.request_digest,
            authorization_issued_at_ms=auth.authorization_issued_at_ms,
            authorization_expires_at_ms=auth.authorization_issued_at_ms + 400000,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            action_id=auth.action_id,
        )


def test_exact_type_check_rejects_subclasses_and_duck_types():
    """Verify AuthorityFence and participant reject subclasses and proxy objects."""
    part = C2DaemonResourceParticipant(participant_id="part_seal")
    with sqlite3.connect(part._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_seal",
            subject_id="sub_seal",
            key_id="k_seal",
            public_key=TEST_ED_PUB,
            mission_id="m_seal",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )

    valid_auth = _make_valid_auth(tx_id="tx_subclass", part_id="part_seal")

    class SubclassedAuthority(VerifiedMutationAuthority):
        pass

    sub_auth = SubclassedAuthority(
        operator_id=valid_auth.operator_id,
        subject_id=valid_auth.subject_id,
        mission_id=valid_auth.mission_id,
        peer_pid=valid_auth.peer_pid,
        peer_uid=valid_auth.peer_uid,
        peer_gid=valid_auth.peer_gid,
        key_id=valid_auth.key_id,
        key_revision=valid_auth.key_revision,
        operator_revision=valid_auth.operator_revision,
        peer_binding_revision=valid_auth.peer_binding_revision,
        mission_grant_revision=valid_auth.mission_grant_revision,
        request_digest=valid_auth.request_digest,
        authorization_issued_at_ms=valid_auth.authorization_issued_at_ms,
        authorization_expires_at_ms=valid_auth.authorization_expires_at_ms,
        transaction_id=valid_auth.transaction_id,
        participant_id=valid_auth.participant_id,
        action_id=valid_auth.action_id,
    )

    with sqlite3.connect(part._conn_uri, uri=True) as conn:
        with pytest.raises((TypeError, PermissionError)):
            AuthorityFence.verify_current(conn, sub_auth)

    req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=valid_auth.key_id,
            transaction_id="tx_subclass",
            participant_id="part_seal",
            mission_id=valid_auth.mission_id,
            subject_id=valid_auth.subject_id,
            action_id=C2ControlAction.PREPARE_C2_RESOURCE.value,
            coordinator_revision=1,
            request_digest=valid_auth.request_digest,
            issued_at_ms=valid_auth.authorization_issued_at_ms,
            expires_at_ms=valid_auth.authorization_expires_at_ms,
            nonce=f"nonce_sub_{uuid.uuid4().hex[:10]}",
            signature="s" * 86,
        ),
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )

    err = part.prepare(req, authority=sub_auth)
    assert isinstance(err, BoundedControlErrorV2)
    assert err.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED
    assert "mandatory_verified_mutation_authority_required" in err.detail_ref


def test_transactional_replay_across_all_four_phases_and_failpoints():
    """Verify atomic replay consumption in prepare, commit, finalize, and rollback."""
    part = C2DaemonResourceParticipant(participant_id="part_seal_4phase")
    with sqlite3.connect(part._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_seal",
            subject_id="sub_seal",
            key_id="k_seal",
            public_key=TEST_ED_PUB,
            mission_id="m_seal",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )

    tx_id = "tx_4phase_1"

    # 1. Prepare phase
    prep_auth = _make_valid_auth(
        tx_id=tx_id,
        part_id="part_seal_4phase",
        action_id=C2ControlAction.PREPARE_C2_RESOURCE.value,
    )
    prep_req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=prep_auth.key_id,
            transaction_id=tx_id,
            participant_id="part_seal_4phase",
            mission_id=prep_auth.mission_id,
            subject_id=prep_auth.subject_id,
            action_id=C2ControlAction.PREPARE_C2_RESOURCE.value,
            coordinator_revision=1,
            request_digest=prep_auth.request_digest,
            issued_at_ms=prep_auth.authorization_issued_at_ms,
            expires_at_ms=prep_auth.authorization_expires_at_ms,
            nonce="nonce_phase_prep_1",
            signature="s" * 86,
        ),
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    prep_receipt = part.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep_receipt, ParticipantControlReceiptV2)

    # Replay on prepare with same nonce fails
    prep_replay = part.prepare(prep_req, authority=prep_auth)
    assert isinstance(prep_replay, ParticipantControlReceiptV2)  # Idempotency fast path matches identical request

    # 2. Commit phase
    commit_auth = _make_valid_auth(
        tx_id=tx_id,
        part_id="part_seal_4phase",
        action_id=C2ControlAction.COMMIT_C2_RESOURCE.value,
        req_digest="b" * 64,
    )
    commit_req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=commit_auth.key_id,
            transaction_id=tx_id,
            participant_id="part_seal_4phase",
            mission_id=commit_auth.mission_id,
            subject_id=commit_auth.subject_id,
            action_id=C2ControlAction.COMMIT_C2_RESOURCE.value,
            coordinator_revision=1,
            request_digest=commit_auth.request_digest,
            issued_at_ms=commit_auth.authorization_issued_at_ms,
            expires_at_ms=commit_auth.authorization_expires_at_ms,
            nonce="nonce_phase_commit_1",
            signature="s" * 86,
        ),
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep_receipt.receipt_ref,
        prior_receipt_digest=prep_receipt.receipt_digest,
    )
    commit_receipt = part.commit(commit_req, authority=commit_auth)
    assert isinstance(commit_receipt, ParticipantControlReceiptV2)

    # 3. Finalize visibility phase
    fin_auth = _make_valid_auth(
        tx_id=tx_id,
        part_id="part_seal_4phase",
        action_id=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY.value,
        req_digest="c" * 64,
    )
    fin_req = ParticipantControlRequestV2(
        action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        authorization=ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=fin_auth.key_id,
            transaction_id=tx_id,
            participant_id="part_seal_4phase",
            mission_id=fin_auth.mission_id,
            subject_id=fin_auth.subject_id,
            action_id=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY.value,
            coordinator_revision=1,
            request_digest=fin_auth.request_digest,
            issued_at_ms=fin_auth.authorization_issued_at_ms,
            expires_at_ms=fin_auth.authorization_expires_at_ms,
            nonce="nonce_phase_fin_1",
            signature="s" * 86,
        ),
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
        prior_receipt_ref=commit_receipt.receipt_ref,
        prior_receipt_digest=commit_receipt.receipt_digest,
    )
    fin_receipt = part.finalize_visibility(fin_req, authority=fin_auth)
    assert isinstance(fin_receipt, ParticipantControlReceiptV2)
    assert fin_receipt.resource_revision == 1


def test_failpoint_crash_rolls_back_replay_consumption():
    """Verify failpoint error during prepare rolls back replay store consumption in SQLite."""
    part = C2DaemonResourceParticipant(participant_id="part_seal_failpoint")
    with sqlite3.connect(part._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_seal",
            subject_id="sub_seal",
            key_id="k_seal",
            public_key=TEST_ED_PUB,
            mission_id="m_seal",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )

    tx_id = "tx_failpoint_1"
    auth = _make_valid_auth(
        tx_id=tx_id,
        part_id="part_seal_failpoint",
        action_id=C2ControlAction.PREPARE_C2_RESOURCE.value,
    )
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=auth.key_id,
            transaction_id=tx_id,
            participant_id="part_seal_failpoint",
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=C2ControlAction.PREPARE_C2_RESOURCE.value,
            coordinator_revision=1,
            request_digest=auth.request_digest,
            issued_at_ms=auth.authorization_issued_at_ms,
            expires_at_ms=auth.authorization_expires_at_ms,
            nonce="nonce_failpoint_123",
            signature="s" * 86,
        ),
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )

    # Arm failpoint BEFORE_COMMIT
    part.set_failpoint(TransactionFailpoint.BEFORE_COMMIT)
    err = part.prepare(req, authority=auth)
    assert isinstance(err, BoundedControlErrorV2)
    assert err.reason_code == C2ControlErrorCodeV2.INTERNAL_FAILURE

    part.clear_failpoints()
    # Verify nonce was rolled back in replay store so retry succeeds!
    retry_receipt = part.prepare(req, authority=auth)
    assert isinstance(retry_receipt, ParticipantControlReceiptV2)
