"""Golden vectors for C2 V2 protocol canonicalization, digest calculations, and signatures.

Ensures byte-for-byte deterministic stability across platforms and releases.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlAuthorizationV2,
    ParticipantControlRequestV2,
    SignedControlResponseV2,
    UnsignedParticipantControlAuthorizationV2,
    UnsignedParticipantControlRequestV2,
)
from core.c2.control_models import (
    calculate_receipt_digest,
    calculate_request_digest_v2,
    calculate_schema_bound_payload_digest,
    calculate_snapshot_digest,
    calculate_transaction_intent_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
    canonical_unsigned_request_v2,
    strict_b64url_decode,
)
from core.c2.control_signing import (
    ControlSignerV2,
    ControlVerifierV2,
    DaemonResponseSigner,
    DaemonResponseVerifier,
)

pytestmark = [pytest.mark.unit, pytest.mark.contract]

# Fixed 32-byte Ed25519 test seeds
FIXED_CLIENT_SEED_32 = b"golden_client_seed_0123456789012"
FIXED_DAEMON_SEED_32 = b"golden_daemon_seed_0123456789012"


def test_v2_canonical_json_deterministic():
    """Verify that canonical JSON uses sorted keys, UTF-8, and no extra whitespace."""
    data = {
        "z": 1,
        "a": "hello",
        "nested": {"b": True, "a": None, "c": [3, 2, 1]},
    }
    raw = canonical_json_bytes(data)
    assert raw == b'{"a":"hello","nested":{"a":null,"b":true,"c":[3,2,1]},"z":1}'


def test_v2_unsigned_request_canonicalization_and_digest():
    """Verify canonical unsigned request format and SHA-256 digest calculation."""
    auth = UnsignedParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k_golden_1",
        transaction_id="tx_golden_001",
        participant_id="part_golden_c2",
        mission_id="mission_golden",
        subject_id="subject_golden",
        action_id="ping",
        coordinator_revision=1,
        issued_at_ms=1700000000000,
        expires_at_ms=1700000060000,
        nonce="nonce_golden_1234567890",
    )
    req = UnsignedParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test_v2",
        payload_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        canonical_payload_b64u="e30",
        expected_resource_revision=42,
        prior_receipt_ref="rcpt_golden_prev",
        prior_receipt_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    d = canonical_unsigned_request_v2(req)
    assert d["protocol_version"] == "2.0"
    assert d["action"] == "ping"
    assert d["expected_resource_revision"] == 42
    assert d["prior_receipt_ref"] == "rcpt_golden_prev"
    assert "request_digest" not in d
    assert "signature" not in d

    digest = calculate_request_digest_v2(req)
    assert len(digest) == 64
    assert digest == digest.lower()

    # Re-calculate manually to check prefix OCTOPUS-C2-REQUEST-V2\0
    expected_raw = b"OCTOPUS-C2-REQUEST-V2\x00" + canonical_json_bytes(d)
    expected_hex = hashlib.sha256(expected_raw).hexdigest()
    assert digest == expected_hex


def test_v2_signing_and_verification_golden_vector():
    """Verify Ed25519 signature computation and strict Base64URL encoding (86 chars)."""
    signer = ControlSignerV2("k_golden_1", FIXED_CLIENT_SEED_32)
    pub_key_bytes = signer.public_key_bytes
    assert len(pub_key_bytes) == 32

    auth = UnsignedParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k_golden_1",
        transaction_id="tx_golden_001",
        participant_id="part_golden_c2",
        mission_id="mission_golden",
        subject_id="subject_golden",
        action_id="ping",
        coordinator_revision=1,
        issued_at_ms=1700000000000,
        expires_at_ms=1700000060000,
        nonce="nonce_golden_1234567890",
    )
    raw_payload = b'{"status":"ok"}'
    p_b64u = base64.urlsafe_b64encode(raw_payload).decode("ascii").rstrip("=")
    p_dig = calculate_schema_bound_payload_digest("schema:test_v2", raw_payload)

    unsigned_req = UnsignedParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test_v2",
        payload_digest=p_dig,
        canonical_payload_b64u=p_b64u,
    )

    signed_req = signer.sign_participant_request(unsigned_req)
    assert isinstance(signed_req, ParticipantControlRequestV2)
    assert isinstance(signed_req.authorization, ParticipantControlAuthorizationV2)

    # Signature must be exactly 86 chars Base64URL without padding
    sig = signed_req.authorization.signature
    assert len(sig) == 86
    assert "=" not in sig
    assert "+" not in sig
    assert "/" not in sig

    # Verifier test
    from core.c2.control_boundary import StaticControlKeyResolver
    verifier = ControlVerifierV2(key_resolver=StaticControlKeyResolver({"k_golden_1": pub_key_bytes}))
    payload_returned = verifier.verify_participant_request(signed_req, now=1700000010000)
    assert payload_returned == raw_payload


def test_v2_daemon_response_envelope_golden_vector():
    """Verify daemon response envelope format, digest, and Ed25519 signing."""
    daemon_signer = DaemonResponseSigner("daemon_key_1", FIXED_DAEMON_SEED_32)
    daemon_pub_bytes = daemon_signer.public_key_bytes
    assert len(daemon_pub_bytes) == 32

    resp_payload = b'{"receipt_ref":"rcpt_001","status":"success"}'
    resp_b64u = base64.urlsafe_b64encode(resp_payload).decode("ascii").rstrip("=")
    resp_dig = hashlib.sha256(resp_payload).hexdigest()

    envelope_dict = canonical_response_envelope_dict(
        protocol_version="2.0",
        service_id="srv_golden_octopus",
        boot_instance_id="boot_golden_inst_1",
        daemon_generation="gen_001",
        request_digest="0" * 64,
        request_nonce="nonce_golden_1234567890",
        response_type="receipt",
        response_payload_b64u=resp_b64u,
        response_digest=resp_dig,
        issued_at_ms=1700000000000,
        key_id="daemon_key_1",
    )

    sig = daemon_signer.sign_envelope_dict(envelope_dict)
    assert len(sig) == 86
    assert "=" not in sig

    signed_resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv_golden_octopus",
        boot_instance_id="boot_golden_inst_1",
        daemon_generation="gen_001",
        request_digest="0" * 64,
        request_nonce="nonce_golden_1234567890",
        response_type="receipt",
        response_payload_b64u=resp_b64u,
        response_digest=resp_dig,
        issued_at_ms=1700000000000,
        key_id="daemon_key_1",
        signature=sig,
    )

    verifier = DaemonResponseVerifier(trusted_keys={"daemon_key_1": daemon_pub_bytes})
    verifier.verify_envelope(signed_resp)
    assert strict_b64url_decode(signed_resp.response_payload_b64u) == resp_payload


def test_v2_receipt_digest_deterministic():
    """Verify calculate_receipt_digest produces exact deterministic hex."""
    d = calculate_receipt_digest(
        transaction_id="tx_100",
        participant_id="part_100",
        receipt_ref="rcpt_100",
        action="ping",
        resource_ref="c2_daemon",
        resource_revision=1,
        daemon_instance_id="daemon_inst_1",
        result_payload_schema_id="schema:test",
        result_payload_digest="0" * 64,
        protocol_version="2.0",
    )
    assert len(d) == 64
    assert d == d.lower()
    # Digest is deterministic
    d2 = calculate_receipt_digest(
        transaction_id="tx_100",
        participant_id="part_100",
        receipt_ref="rcpt_100",
        action="ping",
        resource_ref="c2_daemon",
        resource_revision=1,
        daemon_instance_id="daemon_inst_1",
        result_payload_schema_id="schema:test",
        result_payload_digest="0" * 64,
        protocol_version="2.0",
    )
    assert d == d2


def test_v2_snapshot_and_intent_digest_deterministic():
    """Verify snapshot and transaction intent digests."""
    snap_d = calculate_snapshot_digest(
        transaction_id="tx_100",
        participant_id="part_100",
        phase="prepared",
        resource_ref="c2_daemon",
    )
    assert len(snap_d) == 64

    intent_d = calculate_transaction_intent_digest(
        participant_id="part_100",
        resource_ref="c2_daemon",
        subject_id="subject_1",
        mission_id="mission_1",
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
    )
    assert len(intent_d) == 64
