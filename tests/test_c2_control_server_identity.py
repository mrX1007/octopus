"""Unit tests for core/c2/control_server_identity.py."""

from __future__ import annotations

import os
import stat
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_server_identity import (
    load_or_persist_daemon_response_key,
    load_or_persist_service_id,
    parse_env_daemon_key,
    validate_trusted_parent_directory,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]


def test_validate_trusted_parent_directory(tmp_path):
    safe_dir = tmp_path / "safe"
    safe_dir.mkdir(mode=0o700)
    validate_trusted_parent_directory(str(safe_dir))

    # Symlink forbidden
    link_dir = tmp_path / "link_dir"
    os.symlink(safe_dir, link_dir)
    with pytest.raises(RuntimeError, match="symlink parent directory forbidden"):
        validate_trusted_parent_directory(str(link_dir))


def test_parse_env_daemon_key():
    # 64-hex valid key
    hex_key = "a" * 64
    parsed = parse_env_daemon_key(hex_key)
    assert len(parsed) == 32
    assert parsed == bytes.fromhex(hex_key)

    # Invalid length
    with pytest.raises(ValueError, match="OCTOPUS_C2_DAEMON_SECRET must decode to exactly 32 bytes"):
        parse_env_daemon_key("abc")

    # Non-base64/non-hex
    with pytest.raises(ValueError, match="invalid_configured_daemon_key_encoding"):
        parse_env_daemon_key("!" * 64)


def test_load_or_persist_service_id(tmp_path):
    srv_file = tmp_path / "service_id"
    # First creation
    srv_id1 = load_or_persist_service_id(str(srv_file))
    assert srv_id1.startswith("srv_")
    assert os.path.exists(srv_file)

    # Permission check
    st = os.stat(srv_file)
    assert st.st_mode & 0o077 == 0

    # Second read
    srv_id2 = load_or_persist_service_id(str(srv_file))
    assert srv_id1 == srv_id2


def test_load_or_persist_daemon_response_key_file(tmp_path):
    key_file = tmp_path / "daemon.key"

    # First generation
    key_id, priv1, pub1 = load_or_persist_daemon_response_key(str(key_file))
    assert key_id == "daemon_resp_key_1"
    assert len(pub1) == 32
    assert os.path.exists(key_file)

    # Second read
    key_id2, priv2, pub2 = load_or_persist_daemon_response_key(str(key_file))
    assert key_id2 == "daemon_resp_key_1"
    assert pub1 == pub2


def test_load_or_persist_daemon_response_key_env():
    hex_key = "4" * 64
    key_id, priv, pub = load_or_persist_daemon_response_key("/tmp/unused", env_secret=hex_key)
    assert key_id == "daemon_resp_key_1"
    assert len(pub) == 32
