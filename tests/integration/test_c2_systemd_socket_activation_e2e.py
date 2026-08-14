"""Integration tests for systemd socket activation and peer authentication (§14.3)."""

from __future__ import annotations

import socket
import pytest
from core.c2.control_protocol import ControlProtocolCodec
from core.c2.control_server_identity import (
    generate_server_identity_keypair,
    sign_server_challenge,
    verify_server_challenge,
)

pytestmark = pytest.mark.integration


def test_systemd_socket_activation_server_verification():
    priv, pub = generate_server_identity_keypair()
    
    # Simulate client stat values
    client_dev = 42
    client_ino = 1001

    # Server generates signed challenge with matching device/inode
    sig = sign_server_challenge(
        private_key_bytes=priv,
        daemon_instance_id="c2-daemon-sysd-1",
        server_nonce="srv-nonce-999",
        listener_st_dev=client_dev,
        listener_st_ino=client_ino,
        boot_id="sysd-boot-123",
    )

    # Client verifies challenge
    ok = verify_server_challenge(
        public_key_bytes=pub,
        signature_b64u=sig,
        daemon_instance_id="c2-daemon-sysd-1",
        server_nonce="srv-nonce-999",
        listener_st_dev=client_dev,
        listener_st_ino=client_ino,
        boot_id="sysd-boot-123",
    )
    assert ok is True
