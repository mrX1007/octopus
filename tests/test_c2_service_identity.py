"""Tests for C2 service identity."""
from __future__ import annotations

import pytest
from core.c2.service_identity import (
    C2ServiceIdentity,
    create_service_identity,
    verify_service_identity,
)

pytestmark = pytest.mark.unit


def test_create_service_identity():
    identity = create_service_identity(domain="c2.test", socket_path="/tmp/c2.sock")
    assert identity.service_id.startswith("srv_")
    assert identity.domain == "c2.test"
    assert identity.socket_path == "/tmp/c2.sock"
    assert len(identity.fingerprint) == 64


def test_verify_service_identity_valid():
    identity = create_service_identity()
    assert verify_service_identity(identity) is True


def test_verify_service_identity_invalid():
    invalid_ident = C2ServiceIdentity(
        service_id="srv_1",
        domain="domain.com",
        socket_path="/sock",
        fingerprint="short_fp",
        created_at=100.0,
    )
    assert verify_service_identity(invalid_ident) is False


def test_service_identity_post_init_validation():
    with pytest.raises(ValueError, match="service_id must not be empty"):
        C2ServiceIdentity(
            service_id="",
            domain="domain.com",
            socket_path="/sock",
            fingerprint="0" * 64,
            created_at=100.0,
        )
