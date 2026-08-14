"""Tests for C2 control signing rotation (§14.5)."""

from __future__ import annotations

import pytest

from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
)
from core.c2.control_signing import ControlSignerV1, ControlVerifierV1
from core.c2.control_signing_keyring import ControlSigningKeyring

pytestmark = pytest.mark.unit


def test_keyring_registration_and_active_key():
    keyring = ControlSigningKeyring()
    keyring.register_key("key-1", b"secret-123456789012345678901234567890", valid_from=100.0, valid_until=200.0)
    assert keyring.get_key("key-1", now=150.0) == b"secret-123456789012345678901234567890"
    assert keyring.get_key("key-1", now=250.0) is None
    k_id, sec = keyring.get_active_key(now=150.0)
    assert k_id == "key-1"
    assert sec == b"secret-123456789012345678901234567890"


def test_keyring_rotation_maintains_transition_window():
    keyring = ControlSigningKeyring()
    keyring.register_key("key-1", b"secret-1" * 4, valid_from=0.0, valid_until=1000.0)

    # Rotate at t=500 with 100s transition
    keyring.rotate_key("key-2", b"secret-2" * 4, now=500.0, transition_seconds=100.0)

    # At t=550, both keys valid
    assert keyring.get_key("key-1", now=550.0) == b"secret-1" * 4
    assert keyring.get_key("key-2", now=550.0) == b"secret-2" * 4

    # New active is key-2
    assert keyring.get_active_key(now=550.0) == ("key-2", b"secret-2" * 4)

    # At t=650, old key-1 expired, key-2 still valid
    assert keyring.get_key("key-1", now=650.0) is None
    assert keyring.get_key("key-2", now=650.0) == b"secret-2" * 4


def test_verifier_with_rotated_keys():
    keyring = ControlSigningKeyring()
    keyring.register_key("key-old", b"old-secret" * 4, valid_from=0.0, valid_until=1000.0)

    signer_old = ControlSignerV1("key-old", b"old-secret" * 4)

    auth = ParticipantControlAuthorizationV1(
        key_id="key-old",
        transaction_id="tx-1",
        participant_id="part-1",
        mission_id="m-1",
        subject_id="sub-1",
        action_id="c2:c2_task",
        coordinator_revision=1,
        request_digest="sha256:req",
        expires_at=550.0,
        nonce="nonce-1",
        signature="",
    )
    req = ParticipantControlRequestV1(
        action=C2ControlActionV1.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema:task",
        payload_digest="sha256:payload",
        canonical_payload_b64u="ey...",
    )
    signed_req = signer_old.sign_participant_request(req)

    # Keyring rotation
    keyring.rotate_key("key-new", b"new-secret" * 4, now=500.0, transition_seconds=100.0)

    verifier = ControlVerifierV1(
        key_store={k.key_id: k.secret_key for k in keyring.list_keys() if k.is_valid(now=520.0)}
    )

    # Verification succeeds during transition window
    verifier.verify_participant_request(signed_req, now=520.0)

    # Verification fails after old key expiry
    verifier_after = ControlVerifierV1(
        key_store={k.key_id: k.secret_key for k in keyring.list_keys() if k.is_valid(now=650.0)}
    )
    with pytest.raises(ValueError, match="Unknown key_id"):
        verifier_after.verify_participant_request(signed_req, now=520.0)
