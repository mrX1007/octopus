"""Integration tests for C2 socket activation identity and permissions contract (§14.2)."""

from __future__ import annotations

from pathlib import Path
import pytest
from core.c2.control_server_identity import (
    generate_server_identity_keypair,
    sign_server_challenge,
    verify_server_challenge,
)

pytestmark = pytest.mark.integration


def test_socket_unit_and_permission_contracts():
    socket_path = Path("data/octopus-c2.socket")
    sysusers_path = Path("data/octopus-c2.sysusers")
    tmpfiles_path = Path("data/octopus-c2.tmpfiles")

    assert socket_path.exists(), "octopus-c2.socket unit must exist"
    assert sysusers_path.exists(), "octopus-c2.sysusers must exist"
    assert tmpfiles_path.exists(), "octopus-c2.tmpfiles must exist"

    socket_text = socket_path.read_text(encoding="utf-8")
    assert "SocketUser=octopus-c2" in socket_text
    assert "SocketGroup=octopus-c2-clients" in socket_text
    assert "SocketMode=0660" in socket_text

    sysusers_text = sysusers_path.read_text(encoding="utf-8")
    assert "octopus-c2" in sysusers_text
    assert "octopus-c2-clients" in sysusers_text


def test_signed_identity_handshake_simulation():
    priv, pub = generate_server_identity_keypair()
    sig = sign_server_challenge(
        private_key_bytes=priv,
        daemon_instance_id="inst-e2e-1",
        server_nonce="nonce-e2e-1",
        listener_st_dev=100,
        listener_st_ino=200,
        boot_id="boot-e2e",
    )

    verified = verify_server_challenge(
        public_key_bytes=pub,
        signature_b64u=sig,
        daemon_instance_id="inst-e2e-1",
        server_nonce="nonce-e2e-1",
        listener_st_dev=100,
        listener_st_ino=200,
        boot_id="boot-e2e",
    )
    assert verified is True
