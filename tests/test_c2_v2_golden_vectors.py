"""True fixed golden vector regression tests for C2 V2 protocol.

Loads literal reviewed constants from tests/fixtures/c2_v2_golden_vectors.json
and asserts byte-for-byte matching without relying on runtime re-calculation.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlRequestV2,
    SignedControlResponseV2,
    UnsignedParticipantControlAuthorizationV2,
    UnsignedParticipantControlRequestV2,
)
from core.c2.control_models import (
    calculate_health_signature_digest,
    calculate_receipt_digest,
    calculate_request_digest_v2,
    calculate_schema_bound_payload_digest,
    calculate_snapshot_digest,
    calculate_transaction_intent_digest,
    canonical_json_bytes,
    canonical_unsigned_request_v2,
    strict_b64url_decode,
)
from core.c2.control_signing import (
    ControlSignerV2,
    ControlVerifierV2,
    DaemonResponseSigner,
    DaemonResponseVerifier,
)
from tests.helpers.c2_client import make_trusted_daemon_key

pytestmark = [pytest.mark.unit, pytest.mark.contract]

FIXED_CLIENT_SEED_32 = b"golden_client_seed_0123456789012"
FIXED_DAEMON_SEED_32 = b"golden_daemon_seed_0123456789012"

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "c2_v2_golden_vectors.json"


@pytest.fixture(scope="module")
def golden_vectors() -> dict:
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("format_version") == "2.0"

    # Verify checksum
    stored_checksum = data.pop("fixture_checksum_sha256")
    canonical_doc = canonical_json_bytes(data)
    computed_checksum = hashlib.sha256(canonical_doc).hexdigest()
    assert computed_checksum == stored_checksum
    data["fixture_checksum_sha256"] = stored_checksum
    return data


def test_v2_golden_unsigned_request_and_digest(golden_vectors: dict):
    """Verify unsigned request canonicalization and request digest against literal golden constants."""
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

    req = UnsignedParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test_v2",
        payload_digest=p_dig,
        canonical_payload_b64u=p_b64u,
        expected_resource_revision=42,
        prior_receipt_ref="rcpt_golden_prev",
        prior_receipt_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    canonical_dict = canonical_unsigned_request_v2(req)
    canonical_bytes = canonical_json_bytes(canonical_dict)
    assert canonical_bytes.decode("utf-8") == golden_vectors["canonical_unsigned_request_utf8"]

    digest = calculate_request_digest_v2(req)
    assert digest == golden_vectors["request_digest_hex"]
    assert digest == "396f6ecd2541a4be801c52117ec735c6b4c1012c478b8bb6e2c10b012a834e6f"


def test_v2_golden_signing_and_signature(golden_vectors: dict):
    """Verify Ed25519 request signature against literal golden vector constant."""
    signer = ControlSignerV2("k_golden_1", FIXED_CLIENT_SEED_32)
    pub_key_bytes = signer.public_key_bytes
    assert pub_key_bytes.hex() == golden_vectors["client_public_key_hex"]
    assert pub_key_bytes.hex() == "a5412c4f53f3d5ed983a51c3632240ed94410f6a35c7f36156065e7417b38fba"

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
        expected_resource_revision=42,
        prior_receipt_ref="rcpt_golden_prev",
        prior_receipt_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    signed_req = signer.sign_participant_request(unsigned_req)
    assert isinstance(signed_req, ParticipantControlRequestV2)
    assert signed_req.authorization.signature == golden_vectors["request_signature_b64u"]
    assert (
        signed_req.authorization.signature
        == "JlKKGBjFo3iuKQYwJRmWiN4y9My4bEVEEyvliCe8JFYN35Grdl0SOeend8ssvZHR-UGSGRAaSiG6n6aItaA0Bw"
    )

    # Verifier check
    from core.c2.control_boundary import StaticControlKeyResolver

    verifier = ControlVerifierV2(key_resolver=StaticControlKeyResolver({"k_golden_1": pub_key_bytes}))
    payload_returned = verifier.verify_participant_request(signed_req, now=1700000010000)
    assert payload_returned == raw_payload


def test_v2_golden_daemon_response_envelope(golden_vectors: dict):
    """Verify daemon response envelope format and signature against literal golden constants."""
    daemon_signer = DaemonResponseSigner("daemon_key_1", FIXED_DAEMON_SEED_32)
    daemon_pub_bytes = daemon_signer.public_key_bytes
    assert daemon_pub_bytes.hex() == golden_vectors["daemon_public_key_hex"]
    assert daemon_pub_bytes.hex() == "d7d6f500118367251d7f75b3ae05b3b44bfb4cf068c24c6854e4acffa6126c85"

    envelope_dict = golden_vectors["canonical_daemon_response_envelope"]
    sig = daemon_signer.sign_envelope_dict(envelope_dict)
    assert sig == golden_vectors["daemon_response_signature_b64u"]
    assert sig == "k9dee7j0mDheVbuYXHBwNMzA7p1FeS7UrJBrAz8cjgvJouvxwaDRokO_VImdir3C-CPgjdoTV0J9WPi03MY-Cw"

    signed_resp = SignedControlResponseV2(
        protocol_version=envelope_dict["protocol_version"],
        service_id=envelope_dict["service_id"],
        boot_instance_id=envelope_dict["boot_instance_id"],
        daemon_generation=envelope_dict["daemon_generation"],
        request_digest=envelope_dict["request_digest"],
        request_nonce=envelope_dict["request_nonce"],
        response_type=envelope_dict["response_type"],
        response_payload_b64u=envelope_dict["response_payload_b64u"],
        response_digest=envelope_dict["response_digest"],
        issued_at_ms=envelope_dict["issued_at_ms"],
        key_id=envelope_dict["key_id"],
        signature=sig,
    )

    trusted_key = make_trusted_daemon_key(
        service_id=envelope_dict["service_id"],
        key_id="daemon_key_1",
        public_key=daemon_pub_bytes,
        valid_from_ms=0,
        valid_until_ms=2147483647000,
    )
    verifier = DaemonResponseVerifier(trusted_keys={"daemon_key_1": trusted_key})
    verifier.verify_envelope(signed_resp, expected_service_id="srv_golden_octopus")
    assert (
        strict_b64url_decode(signed_resp.response_payload_b64u).decode("utf-8")
        == golden_vectors["daemon_response_payload_utf8"]
    )


def test_v2_golden_health_response_signature(golden_vectors: dict):
    """Verify health response body digest and signature against literal golden constants."""
    daemon_signer = DaemonResponseSigner("daemon_key_1", FIXED_DAEMON_SEED_32)
    health_body = golden_vectors["health_response_body"]
    transcript = calculate_health_signature_digest(health_body)
    sig_raw = daemon_signer._ed25519_key.sign(transcript)
    sig_b64u = base64.urlsafe_b64encode(sig_raw).decode("ascii").rstrip("=")
    assert sig_b64u == golden_vectors["health_response_signature_b64u"]
    assert sig_b64u == "W7yoOJQddBSfNY-190-K-wUBMUocAGP1ASHWPvvQ8IlhkGQN3gNiLxqh9G4vU9q-p2A93A92RMlH9yza-IJpCA"


def test_v2_golden_2pc_digests(golden_vectors: dict):
    """Verify 2PC receipt, snapshot, and transaction intent digests against literal golden constants."""
    rcpt_digest = calculate_receipt_digest(
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
    assert rcpt_digest == golden_vectors["receipt_digest_hex"]
    assert rcpt_digest == "f30fc73828b3ecdc42e4e14426f60685d04bc7ab523d9a9b18359db28fa5d1be"

    snap_digest = calculate_snapshot_digest(
        transaction_id="tx_100",
        participant_id="part_100",
        phase="prepared",
        resource_ref="c2_daemon",
    )
    assert snap_digest == golden_vectors["snapshot_digest_hex"]
    assert snap_digest == "270dea22dbdb840c39a3a1123432c8fc66af0cdd172704f4fabd1e153f283bc3"

    intent_digest = calculate_transaction_intent_digest(
        participant_id="part_100",
        resource_ref="c2_daemon",
        subject_id="subject_1",
        mission_id="mission_1",
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
    )
    assert intent_digest == golden_vectors["transaction_intent_digest_hex"]
    assert intent_digest == "8c0bdc58153bac80f5af9aa5354b58eeb48fc05fbc25712166912f12e7daeea6"
