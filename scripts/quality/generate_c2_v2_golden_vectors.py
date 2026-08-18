#!/usr/bin/env python3
"""Offline generator script for C2 V2 golden vectors fixture.

NOTE: This script is run offline only during vector review/generation and is NEVER
called by automated tests at runtime.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlAuthorizationV2,
    ParticipantControlRequestV2,
    UnsignedParticipantControlAuthorizationV2,
    UnsignedParticipantControlRequestV2,
)
from core.c2.control_models import (
    calculate_auth_transcript_v2,
    calculate_health_signature_digest,
    calculate_receipt_digest,
    calculate_request_digest_v2,
    calculate_schema_bound_payload_digest,
    calculate_snapshot_digest,
    calculate_transaction_intent_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
    canonical_unsigned_request_v2,
)

FIXED_CLIENT_SEED_32 = b"golden_client_seed_0123456789012"
FIXED_DAEMON_SEED_32 = b"golden_daemon_seed_0123456789012"


def generate_vectors() -> dict:
    client_priv = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_CLIENT_SEED_32)
    client_pub = client_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    daemon_priv = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_DAEMON_SEED_32)
    daemon_pub = daemon_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    # 1. Unsigned request
    unsigned_auth = UnsignedParticipantControlAuthorizationV2(
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
        authorization=unsigned_auth,
        payload_schema_id="schema:test_v2",
        payload_digest=p_dig,
        canonical_payload_b64u=p_b64u,
        expected_resource_revision=42,
        prior_receipt_ref="rcpt_golden_prev",
        prior_receipt_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    canonical_unsigned_dict = canonical_unsigned_request_v2(unsigned_req)
    canonical_unsigned_bytes = canonical_json_bytes(canonical_unsigned_dict)
    req_digest = calculate_request_digest_v2(unsigned_req)

    # 2. Request signature
    transcript = calculate_auth_transcript_v2(unsigned_req, req_digest)
    req_sig_raw = client_priv.sign(transcript)
    req_sig_b64u = base64.urlsafe_b64encode(req_sig_raw).decode("ascii").rstrip("=")

    signed_auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id=unsigned_auth.key_id,
        transaction_id=unsigned_auth.transaction_id,
        participant_id=unsigned_auth.participant_id,
        mission_id=unsigned_auth.mission_id,
        subject_id=unsigned_auth.subject_id,
        action_id=unsigned_auth.action_id,
        coordinator_revision=unsigned_auth.coordinator_revision,
        issued_at_ms=unsigned_auth.issued_at_ms,
        expires_at_ms=unsigned_auth.expires_at_ms,
        nonce=unsigned_auth.nonce,
        request_digest=req_digest,
        signature=req_sig_b64u,
    )
    signed_req = ParticipantControlRequestV2(
        action=unsigned_req.action,
        authorization=signed_auth,
        payload_schema_id=unsigned_req.payload_schema_id,
        payload_digest=unsigned_req.payload_digest,
        canonical_payload_b64u=unsigned_req.canonical_payload_b64u,
        prior_receipt_ref=unsigned_req.prior_receipt_ref,
        prior_receipt_digest=unsigned_req.prior_receipt_digest,
        expected_resource_revision=unsigned_req.expected_resource_revision,
    )

    signed_req_dict = {
        "action": signed_req.action.value,
        "authorization": {
            "action_id": signed_req.authorization.action_id,
            "coordinator_revision": signed_req.authorization.coordinator_revision,
            "expires_at_ms": signed_req.authorization.expires_at_ms,
            "issued_at_ms": signed_req.authorization.issued_at_ms,
            "key_id": signed_req.authorization.key_id,
            "mission_id": signed_req.authorization.mission_id,
            "nonce": signed_req.authorization.nonce,
            "participant_id": signed_req.authorization.participant_id,
            "protocol_version": signed_req.authorization.protocol_version,
            "request_digest": signed_req.authorization.request_digest,
            "signature": signed_req.authorization.signature,
            "subject_id": signed_req.authorization.subject_id,
            "transaction_id": signed_req.authorization.transaction_id,
        },
        "canonical_payload_b64u": signed_req.canonical_payload_b64u,
        "expected_resource_revision": signed_req.expected_resource_revision,
        "payload_digest": signed_req.payload_digest,
        "payload_schema_id": signed_req.payload_schema_id,
        "prior_receipt_digest": signed_req.prior_receipt_digest,
        "prior_receipt_ref": signed_req.prior_receipt_ref,
    }
    canonical_signed_bytes = canonical_json_bytes(signed_req_dict)

    # 3. Daemon Response
    resp_payload = b'{"receipt_ref":"rcpt_001","status":"success"}'
    resp_b64u = base64.urlsafe_b64encode(resp_payload).decode("ascii").rstrip("=")
    resp_dig = hashlib.sha256(resp_payload).hexdigest()

    envelope_dict = canonical_response_envelope_dict(
        protocol_version="2.0",
        service_id="srv_golden_octopus",
        boot_instance_id="boot_golden_inst_1",
        daemon_generation="gen_001",
        request_digest=req_digest,
        request_nonce=unsigned_auth.nonce,
        response_type="receipt",
        response_payload_b64u=resp_b64u,
        response_digest=resp_dig,
        issued_at_ms=1700000000000,
        key_id="daemon_key_1",
    )
    from core.c2.control_models import calculate_response_signature_digest

    resp_transcript = calculate_response_signature_digest(envelope_dict)
    resp_sig_raw = daemon_priv.sign(resp_transcript)
    resp_sig_b64u = base64.urlsafe_b64encode(resp_sig_raw).decode("ascii").rstrip("=")

    # 4. Health Response
    health_body_dict = {
        "boot_instance_id": "boot_golden_inst_1",
        "daemon_generation": "gen_001",
        "database_ready": True,
        "issued_at_ms": 1700000000000,
        "key_id": "daemon_key_1",
        "key_store_ready": True,
        "probe_nonce": "nonce_golden_1234567890",
        "protocol_version": "2.0",
        "service_id": "srv_golden_octopus",
    }
    health_transcript = calculate_health_signature_digest(health_body_dict)
    health_sig_raw = daemon_priv.sign(health_transcript)
    health_sig_b64u = base64.urlsafe_b64encode(health_sig_raw).decode("ascii").rstrip("=")

    # 5. 2PC digests
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
    snap_digest = calculate_snapshot_digest(
        transaction_id="tx_100",
        participant_id="part_100",
        phase="prepared",
        resource_ref="c2_daemon",
    )
    intent_digest = calculate_transaction_intent_digest(
        participant_id="part_100",
        resource_ref="c2_daemon",
        subject_id="subject_1",
        mission_id="mission_1",
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
    )

    vector_doc = {
        "format_version": "2.0",
        "client_public_key_hex": client_pub.hex(),
        "daemon_public_key_hex": daemon_pub.hex(),
        "canonical_unsigned_request_utf8": canonical_unsigned_bytes.decode("utf-8"),
        "request_digest_hex": req_digest,
        "request_signature_transcript_hex": transcript.hex(),
        "request_signature_b64u": req_sig_b64u,
        "canonical_signed_request_utf8": canonical_signed_bytes.decode("utf-8"),
        "daemon_response_payload_utf8": resp_payload.decode("utf-8"),
        "canonical_daemon_response_envelope": envelope_dict,
        "daemon_response_signature_b64u": resp_sig_b64u,
        "health_response_body": health_body_dict,
        "health_response_signature_b64u": health_sig_b64u,
        "receipt_digest_hex": rcpt_digest,
        "snapshot_digest_hex": snap_digest,
        "transaction_intent_digest_hex": intent_digest,
    }

    # Compute checksum of document (excluding checksum field)
    doc_canonical = canonical_json_bytes(vector_doc)
    vector_doc["fixture_checksum_sha256"] = hashlib.sha256(doc_canonical).hexdigest()
    return vector_doc


if __name__ == "__main__":
    v = generate_vectors()
    out = Path("tests/fixtures/c2_v2_golden_vectors.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(v, f, indent=2, sort_keys=True)
    print(f"Generated {out} (checksum {v['fixture_checksum_sha256']})")
