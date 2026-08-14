"""Tests for enrollment transaction participant and token authority."""

from __future__ import annotations

import time

import pytest

from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
)
from core.c2.enrollment import EnrollmentAuthority
from core.c2.resource_participant import C2DaemonResourceParticipant

pytestmark = pytest.mark.unit


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
    auth = ParticipantControlAuthorizationV1(
        key_id="k1",
        transaction_id="tx_enr_1",
        participant_id="enrollment_participant",
        mission_id="m1",
        subject_id="s1",
        action_id="prepare_enrollment_deployment",
        coordinator_revision=1,
        request_digest="rdig",
        expires_at=time.time() + 300,
        nonce="n1",
        signature="sig",
    )
    req = ParticipantControlRequestV1(
        action=C2ControlActionV1.PREPARE_ENROLLMENT_DEPLOYMENT,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="pdig",
        canonical_payload_b64u="e30",
    )

    prep = participant.prepare(req)
    assert isinstance(prep, ParticipantControlReceiptV1)
    commit = participant.commit(req)
    assert isinstance(commit, ParticipantControlReceiptV1)
