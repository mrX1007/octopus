"""Tests for C2 control signing and verifier."""

from __future__ import annotations

import hashlib
import time

import pytest

from core.c2.control_commands import (
    C2ControlActionV1,
    ExecutionControlAuthorizationV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
)
from core.c2.control_models import strict_b64url_decode
from core.c2.control_signing import ControlSignerV1, ControlVerifierV1

pytestmark = pytest.mark.unit


def _valid_test_payload() -> tuple[str, str]:
    b64u = "e30"  # b"{}"
    payload_bytes = strict_b64url_decode(b64u)
    pdig = hashlib.sha256(payload_bytes).hexdigest()
    return b64u, pdig


def test_signer_verifier_participant_request():
    secret = b"supersecretkey123456789012345678"
    signer = ControlSignerV1(key_id="k_test", secret_key=secret)
    verifier = ControlVerifierV1()
    verifier.register_key("k_test", secret)

    b64u, pdig = _valid_test_payload()
    unsigned_auth = ParticipantControlAuthorizationV1(
        key_id="k_test",
        transaction_id="tx_100",
        participant_id="part_1",
        mission_id="mission_1",
        subject_id="subj_1",
        action_id="ping",
        coordinator_revision=1,
        request_digest="dig_req_1",
        expires_at=time.time() + 300,
        nonce="nonce_abc",
        signature="",
    )
    unsigned_req = ParticipantControlRequestV1(
        action=C2ControlActionV1.PING,
        authorization=unsigned_auth,
        payload_schema_id="s1",
        payload_digest=pdig,
        canonical_payload_b64u=b64u,
    )

    signed_req = signer.sign_participant_request(unsigned_req)
    assert signed_req.authorization.signature != ""

    # Verify signature passes
    payload_bytes = verifier.verify_participant_request(signed_req)
    assert payload_bytes == b"{}"


def test_verifier_invalid_signature_raises():
    secret = b"supersecretkey123456789012345678"
    signer = ControlSignerV1(key_id="k_test", secret_key=secret)
    verifier = ControlVerifierV1()
    verifier.register_key("k_test", b"wrongsecretkey123456789012345678")

    b64u, pdig = _valid_test_payload()
    unsigned_auth = ParticipantControlAuthorizationV1(
        key_id="k_test",
        transaction_id="tx_100",
        participant_id="part_1",
        mission_id="mission_1",
        subject_id="subj_1",
        action_id="ping",
        coordinator_revision=1,
        request_digest="dig_req_1",
        expires_at=time.time() + 300,
        nonce="nonce_abc",
        signature="",
    )
    unsigned_req = ParticipantControlRequestV1(
        action=C2ControlActionV1.PING,
        authorization=unsigned_auth,
        payload_schema_id="s1",
        payload_digest=pdig,
        canonical_payload_b64u=b64u,
    )
    signed_req = signer.sign_participant_request(unsigned_req)

    with pytest.raises(ValueError, match="Invalid participant request signature"):
        verifier.verify_participant_request(signed_req)


def test_verifier_expired_request_raises():
    secret = b"supersecretkey123456789012345678"
    signer = ControlSignerV1(key_id="k_test", secret_key=secret)
    verifier = ControlVerifierV1()
    verifier.register_key("k_test", secret)

    b64u, pdig = _valid_test_payload()
    expired_auth = ParticipantControlAuthorizationV1(
        key_id="k_test",
        transaction_id="tx_100",
        participant_id="part_1",
        mission_id="mission_1",
        subject_id="subj_1",
        action_id="ping",
        coordinator_revision=1,
        request_digest="dig_req_1",
        expires_at=time.time() - 100,  # Expired
        nonce="nonce_abc",
        signature="",
    )
    unsigned_req = ParticipantControlRequestV1(
        action=C2ControlActionV1.PING,
        authorization=expired_auth,
        payload_schema_id="s1",
        payload_digest=pdig,
        canonical_payload_b64u=b64u,
    )
    signed_req = signer.sign_participant_request(unsigned_req)

    with pytest.raises(ValueError, match="expired"):
        verifier.verify_participant_request(signed_req)


def test_execution_request_signing_and_verification():
    secret = b"execsecretkey123456789012345678"
    signer = ControlSignerV1(key_id="k_exec", secret_key=secret)
    verifier = ControlVerifierV1({"k_exec": secret})

    exec_auth = ExecutionControlAuthorizationV1(
        key_id="k_exec",
        transaction_id="tx_exec_1",
        request_id="req_exec_1",
        mission_id="m1",
        subject_id="sub1",
        action_id="c2:c2_deploy",
        coordinator_revision=1,
        request_digest="reqdig",
        expires_at=time.time() + 300,
        nonce="nonce_x_1234",
        signature="",
    )

    signed_exec = signer.sign_execution_request(
        action="c2:c2_deploy",
        authorization=exec_auth,
        payload_schema_id="schema_exec",
        payload_digest="pdig_exec",
    )
    assert signed_exec.signature != ""

    verifier.verify_execution_request(
        action="c2:c2_deploy",
        authorization=signed_exec,
        payload_schema_id="schema_exec",
        payload_digest="pdig_exec",
    )

