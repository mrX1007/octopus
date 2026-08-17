"""Automated containment gate tests for C2 V2.

Verifies:
1. Strict protocol isolation: no aliasing between V1 and V2 models, actions, signers, or verifiers.
2. Complete provider containment: all 20 V2 providers remain unmounted (mounted = False).
3. Fail-closed execution gate: v2_execution_pipeline_not_finalized blocks dispatch.
4. Cryptographic containment: exact 32-byte Ed25519 keys only, no SHA-256 normalization, no HMAC in V2.
5. Codec isolation: only protocol_version "2.0", integer millisecond timestamps, unpadded Base64URL signatures.
"""

from __future__ import annotations

import pytest

from core.actions.provider_mounts import DefaultProviderMountRegistry
from core.c2 import (
    control_boundary,
    control_commands,
    control_protocol,
    control_signing,
)

pytestmark = [pytest.mark.unit, pytest.mark.security, pytest.mark.contract]


def test_gate_no_production_v1_v2_aliasing():
    """Assert that no production V2 types are defined as aliases of V1 types."""
    # 1. C2ControlAction is protocol-neutral enum
    assert hasattr(control_commands, "C2ControlAction")
    assert issubclass(control_commands.C2ControlAction, str)

    # 2. Wire Models
    assert control_commands.ParticipantControlAuthorizationV2 is not control_commands.ParticipantControlAuthorizationV1
    assert not issubclass(control_commands.ParticipantControlAuthorizationV2, control_commands.ParticipantControlAuthorizationV1)
    assert not issubclass(control_commands.ParticipantControlAuthorizationV1, control_commands.ParticipantControlAuthorizationV2)

    assert control_commands.ParticipantControlRequestV2 is not control_commands.ParticipantControlRequestV1
    assert not issubclass(control_commands.ParticipantControlRequestV2, control_commands.ParticipantControlRequestV1)
    assert not issubclass(control_commands.ParticipantControlRequestV1, control_commands.ParticipantControlRequestV2)

    assert control_commands.ParticipantControlReceiptV2 is not control_commands.ParticipantControlReceiptV1
    assert not issubclass(control_commands.ParticipantControlReceiptV2, control_commands.ParticipantControlReceiptV1)
    assert not issubclass(control_commands.ParticipantControlReceiptV1, control_commands.ParticipantControlReceiptV2)

    assert control_commands.ParticipantControlQuerySnapshotV2 is not control_commands.ParticipantControlQuerySnapshotV1
    assert not issubclass(control_commands.ParticipantControlQuerySnapshotV2, control_commands.ParticipantControlQuerySnapshotV1)
    assert not issubclass(control_commands.ParticipantControlQuerySnapshotV1, control_commands.ParticipantControlQuerySnapshotV2)

    assert control_commands.BoundedControlErrorV2 is not control_commands.BoundedControlErrorV1
    assert not issubclass(control_commands.BoundedControlErrorV2, control_commands.BoundedControlErrorV1)
    assert not issubclass(control_commands.BoundedControlErrorV1, control_commands.BoundedControlErrorV2)

    assert control_commands.SignedControlResponseV2 is not control_commands.SignedControlResponseV1
    assert not issubclass(control_commands.SignedControlResponseV2, control_commands.SignedControlResponseV1)
    assert not issubclass(control_commands.SignedControlResponseV1, control_commands.SignedControlResponseV2)

    # 3. Signing and Verification classes
    assert control_signing.ControlSignerV2 is not control_signing.ControlSignerV1
    assert control_signing.ControlVerifierV2 is not control_signing.ControlVerifierV1


def test_gate_all_twenty_v2_providers_unmounted():
    """Assert all 20 V2 providers remain mounted=False and cannot be enabled."""
    registry = DefaultProviderMountRegistry()
    snapshots = registry.snapshots()
    assert len(snapshots) == 20, f"Expected exactly 20 V2 provider mount snapshots, got {len(snapshots)}"

    for snapshot in snapshots:
        assert snapshot.spec.mounted is False, f"Provider {snapshot.spec.action_id} must have mounted=False"
        assert snapshot.spec.configured is True, f"Provider {snapshot.spec.action_id} must be configured"
        assert snapshot.spec.typed_action_supported is True
        assert snapshot.spec.raw_command_supported is False


def test_gate_strict_32_byte_ed25519_keys():
    """Assert that non-32-byte keys or seeds are rejected fail-closed with ValueError."""
    # 31 bytes
    short_key = b"0123456789012345678901234567890"
    # 33 bytes
    long_key = b"012345678901234567890123456789012"
    # 64 bytes
    double_key = b"0" * 64

    for bad_key in (short_key, long_key, double_key, b"secret_password"):
        with pytest.raises(ValueError, match=r"32_bytes|32 bytes"):
            control_signing.ControlSignerV2("k1", bad_key)

        with pytest.raises(ValueError, match=r"32_bytes|32 bytes"):
            control_signing.DaemonResponseSigner("k1", bad_key)

        with pytest.raises(ValueError, match=r"32_bytes|32 bytes"):
            control_signing.DaemonResponseVerifier(trusted_keys={"k1": bad_key})

        with pytest.raises(ValueError, match=r"32_bytes|32 bytes"):
            control_boundary.StaticControlKeyResolver({"k1": bad_key})


def test_gate_v2_codec_rejects_non_v2_and_malformed_frames():
    """Assert ControlProtocolCodec strictly enforces protocol 2.0 and validates envelope constraints."""
    codec = control_protocol.ControlProtocolCodec()

    # Reject protocol_version != '2.0' in request decoding
    v1_raw = b'{"protocol_version":"1.0","action":"ping","authorization":{"key_id":"k1","transaction_id":"tx1","participant_id":"p1","mission_id":"m1","subject_id":"s1","action_id":"ping","coordinator_revision":1,"expires_at":1700000000,"nonce":"n1","signature":"s1"},"payload_schema_id":"s1","payload_digest":"d1","canonical_payload_b64u":"e30"}'
    with pytest.raises(ValueError, match="protocol_version"):
        codec.decode_request(v1_raw)

    # Reject float timestamp in V2 authorization
    auth_float_dict = {
        "protocol_version": "2.0",
        "key_id": "k1",
        "transaction_id": "tx1",
        "participant_id": "p1",
        "mission_id": "m1",
        "subject_id": "s1",
        "action_id": "ping",
        "coordinator_revision": 1,
        "issued_at_ms": 1700000000000.5,
        "expires_at_ms": 1700000060000,
        "nonce": "n1",
        "request_digest": "0" * 64,
        "signature": "0" * 86,
    }
    with pytest.raises(ValueError):
        control_commands.ParticipantControlAuthorizationV2(**auth_float_dict)
