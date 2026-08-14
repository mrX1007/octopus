"""Tests for control server identity and signed challenge verification (§14.2, §14.3)."""

from __future__ import annotations

import pytest
from core.c2.control_server_identity import (
    generate_server_identity_keypair,
    sign_server_challenge,
    verify_server_challenge,
)

pytestmark = pytest.mark.unit


def test_server_identity_keypair_generation_and_challenge_verification():
    priv, pub = generate_server_identity_keypair()
    assert len(priv) == 32
    assert len(pub) == 32

    sig = sign_server_challenge(
        private_key_bytes=priv,
        daemon_instance_id="inst-1",
        server_nonce="nonce-abc",
        listener_st_dev=12345,
        listener_st_ino=67890,
        boot_id="boot-uuid-1",
    )
    assert isinstance(sig, str)
    assert len(sig) > 0

    # Successful verification
    ok = verify_server_challenge(
        public_key_bytes=pub,
        signature_b64u=sig,
        daemon_instance_id="inst-1",
        server_nonce="nonce-abc",
        listener_st_dev=12345,
        listener_st_ino=67890,
        boot_id="boot-uuid-1",
    )
    assert ok is True


def test_server_challenge_rejects_tampered_metadata():
    priv, pub = generate_server_identity_keypair()
    sig = sign_server_challenge(
        private_key_bytes=priv,
        daemon_instance_id="inst-1",
        server_nonce="nonce-abc",
        listener_st_dev=12345,
        listener_st_ino=67890,
        boot_id="boot-uuid-1",
    )

    # Inode mismatch
    assert verify_server_challenge(
        public_key_bytes=pub,
        signature_b64u=sig,
        daemon_instance_id="inst-1",
        server_nonce="nonce-abc",
        listener_st_dev=12345,
        listener_st_ino=99999,  # Mismatched inode
        boot_id="boot-uuid-1",
    ) is False

    # Wrong public key
    _, other_pub = generate_server_identity_keypair()
    assert verify_server_challenge(
        public_key_bytes=other_pub,
        signature_b64u=sig,
        daemon_instance_id="inst-1",
        server_nonce="nonce-abc",
        listener_st_dev=12345,
        listener_st_ino=67890,
        boot_id="boot-uuid-1",
    ) is False
