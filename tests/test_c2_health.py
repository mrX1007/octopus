"""Tests for C2 Control Plane dedicated health and readiness protocol."""

from __future__ import annotations

import json
import os
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_health import (
    HealthRequestV2,
    HealthTrustDescriptor,
    SignedHealthResponseV2,
    VerifiedHealthStatusV2,
    load_health_trust_descriptor,
    query_health_status,
)
from core.c2.control_models import (
    calculate_health_signature_digest,
    canonical_json_bytes,
)
from core.c2.control_protocol import strict_json_loads

pytestmark = [pytest.mark.unit, pytest.mark.contract]

TEST_ED_PRIV = ed25519.Ed25519PrivateKey.generate()
TEST_ED_PUB = TEST_ED_PRIV.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)


def test_health_request_v2_defaults():
    req = HealthRequestV2()
    assert req.protocol_version == "2.0"
    assert req.probe_id == "health_probe"
    assert len(req.nonce) >= 16
    assert req.timestamp_ms > 0


def test_health_trust_descriptor_validation():
    # Valid descriptor
    desc = HealthTrustDescriptor(
        version="2.0",
        service_id="srv_test_1",
        key_id="k_health_1",
        public_key=TEST_ED_PUB,
        valid_from_ms=1000,
        valid_until_ms=2000,
        revoked=False,
    )
    assert desc.version == "2.0"
    assert desc.service_id == "srv_test_1"

    # Invalid version
    with pytest.raises(ValueError, match="version must be '2.0'"):
        HealthTrustDescriptor(
            version="1.0",
            service_id="srv_test_1",
            key_id="k_health_1",
            public_key=TEST_ED_PUB,
            valid_from_ms=1000,
            valid_until_ms=2000,
        )

    # Invalid key length
    with pytest.raises(ValueError, match="public_key must be exactly 32 bytes"):
        HealthTrustDescriptor(
            version="2.0",
            service_id="srv_test_1",
            key_id="k_health_1",
            public_key=b"too_short",
            valid_from_ms=1000,
            valid_until_ms=2000,
        )

    # Invalid timestamps
    with pytest.raises(ValueError, match="valid_until_ms must be greater than valid_from_ms"):
        HealthTrustDescriptor(
            version="2.0",
            service_id="srv_test_1",
            key_id="k_health_1",
            public_key=TEST_ED_PUB,
            valid_from_ms=2000,
            valid_until_ms=1000,
        )


def test_load_health_trust_descriptor_from_file(tmp_path):
    trust_file = tmp_path / "health_trust.json"
    doc = {
        "version": "2.0",
        "service_id": "srv_file_test",
        "key_id": "k_health_file",
        "public_key_hex": TEST_ED_PUB.hex(),
        "valid_from_ms": 1000,
        "valid_until_ms": 2000000000000,
        "revoked": False,
    }
    with open(trust_file, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    os.chmod(trust_file, 0o600)

    desc = load_health_trust_descriptor(str(trust_file))
    assert desc.service_id == "srv_file_test"
    assert desc.public_key == TEST_ED_PUB


def test_query_health_status_missing_trust():
    status = query_health_status("/tmp/nonexistent.sock")
    assert status.reachable is False
    assert "missing_trust_configuration" in status.reason_code


def test_query_health_status_socket_not_found():
    desc = HealthTrustDescriptor(
        version="2.0",
        service_id="srv_test",
        key_id="k1",
        public_key=TEST_ED_PUB,
        valid_from_ms=0,
        valid_until_ms=2000000000000,
    )
    status = query_health_status("/tmp/nonexistent_socket_test_123.sock", trust_descriptor=desc)
    assert status.reachable is False
    assert status.reason_code == "socket_not_found"


def test_query_health_status_revoked_trust():
    desc = HealthTrustDescriptor(
        version="2.0",
        service_id="srv_test",
        key_id="k1",
        public_key=TEST_ED_PUB,
        valid_from_ms=0,
        valid_until_ms=2000000000000,
        revoked=True,
    )
    status = query_health_status("/tmp/any.sock", trust_descriptor=desc)
    assert status.reachable is False
    assert status.reason_code == "trust_descriptor_revoked"
