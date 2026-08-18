"""Tests for enrollment transaction participant and token authority."""

from __future__ import annotations

import os
import sqlite3
import time

import pytest

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.enrollment import EnrollmentAuthority
from core.c2.resource_participant import C2DaemonResourceParticipant
from tests.helpers.c2_authority import provision_test_authority

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"P" * 32


class MockDatabase:
    def __init__(self):
        self.used_tokens = set()

    def consume_enrollment_token(self, fingerprint: str, expires_at: int, current: int) -> bool:
        if fingerprint in self.used_tokens:
            return False
        self.used_tokens.add(fingerprint)
        return True


def test_enrollment_authority_issue_and_consume(tmp_path):
    key_file = tmp_path / "enrollment.key"
    authority = EnrollmentAuthority(key_file)
    db = MockDatabase()

    token = authority.issue(ttl_seconds=300)
    assert "." in token

    # First consume succeeds
    assert authority.consume(token, db) is True
    # Replay/second consume fails
    assert authority.consume(token, db) is False


def test_enrollment_authority_invalid_signature(tmp_path):
    key_file = tmp_path / "enrollment.key"
    authority = EnrollmentAuthority(key_file)
    db = MockDatabase()

    token = authority.issue(ttl_seconds=300)
    parts = token.split(".")
    tampered_token = parts[0] + ".invalid_sig"

    assert authority.consume(tampered_token, db) is False


def test_enrollment_transaction_participant_2pc():
    participant = C2DaemonResourceParticipant("enrollment_participant")
    with sqlite3.connect(participant._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_enr",
            subject_id="s1",
            key_id="k1",
            public_key=TEST_ED_PUB,
            mission_id="m1",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )

    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id="tx_enr_1",
        participant_id="enrollment_participant",
        mission_id="m1",
        subject_id="s1",
        action_id=C2ControlAction.PREPARE_ENROLLMENT_DEPLOYMENT.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_enr_12345678",
        signature="0" * 86,
    )
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_ENROLLMENT_DEPLOYMENT,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    prep_auth = VerifiedMutationAuthority(
        operator_id="op_enr",
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
        transaction_id="tx_enr_1",
        participant_id="enrollment_participant",
        action_id=C2ControlAction.PREPARE_ENROLLMENT_DEPLOYMENT.value,
    )

    prep = participant.prepare(req, authority=prep_auth)
    assert isinstance(prep, ParticipantControlReceiptV2)

    commit_auth_obj = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id="tx_enr_1",
        participant_id="enrollment_participant",
        mission_id="m1",
        subject_id="s1",
        action_id=C2ControlAction.COMMIT_ENROLLMENT_DEPLOYMENT.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_enr_commit_123",
        signature="0" * 86,
    )
    commit_req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_ENROLLMENT_DEPLOYMENT,
        authorization=commit_auth_obj,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    commit_auth = VerifiedMutationAuthority(
        operator_id="op_enr",
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
        transaction_id="tx_enr_1",
        participant_id="enrollment_participant",
        action_id=C2ControlAction.COMMIT_ENROLLMENT_DEPLOYMENT.value,
    )
    commit = participant.commit(commit_req, authority=commit_auth)
    assert isinstance(commit, ParticipantControlReceiptV2)
