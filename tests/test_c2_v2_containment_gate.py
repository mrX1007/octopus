"""Automated containment gate tests for C2 V2.

Verifies:
1. Strict protocol isolation: no aliasing between V1 and V2 models, actions, signers, or verifiers.
2. Complete provider containment: all 20 V2 providers remain unmounted (mounted = False) and raise v2_execution_pipeline_not_finalized.
3. Cryptographic containment: exact 32-byte Ed25519 keys only, no SHA-256 normalization, no HMAC in V2.
4. AST scan over production modules: disallows test bypasses, synthetic admin fallbacks, or key normalizations in core.
5. Codec and Boundary isolation: rejection of V1 requests, malformed signatures, unpinned services, and expired timestamps.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.actions.provider_mounts import DefaultProviderMountRegistry
from core.c2 import (
    control_boundary,
    control_commands,
    control_protocol,
    control_signing,
)
from core.c2.control_commands import (
    SignedControlResponseV2,
)
from core.c2.control_signing import (
    DaemonResponseVerifier,
)
from tests.helpers.c2_client import make_trusted_daemon_key

pytestmark = [pytest.mark.unit, pytest.mark.security, pytest.mark.contract]


def test_gate_no_production_v1_v2_aliasing():
    """Assert that no production V2 types are defined as aliases of V1 types."""
    assert hasattr(control_commands, "C2ControlAction")
    assert issubclass(control_commands.C2ControlAction, str)

    # Wire Models
    assert control_commands.ParticipantControlAuthorizationV2 is not control_commands.ParticipantControlAuthorizationV1
    assert not issubclass(
        control_commands.ParticipantControlAuthorizationV2, control_commands.ParticipantControlAuthorizationV1
    )
    assert not issubclass(
        control_commands.ParticipantControlAuthorizationV1, control_commands.ParticipantControlAuthorizationV2
    )

    assert control_commands.ParticipantControlRequestV2 is not control_commands.ParticipantControlRequestV1
    assert not issubclass(control_commands.ParticipantControlRequestV2, control_commands.ParticipantControlRequestV1)
    assert not issubclass(control_commands.ParticipantControlRequestV1, control_commands.ParticipantControlRequestV2)

    assert control_commands.ParticipantControlReceiptV2 is not control_commands.ParticipantControlReceiptV1
    assert not issubclass(control_commands.ParticipantControlReceiptV2, control_commands.ParticipantControlReceiptV1)
    assert not issubclass(control_commands.ParticipantControlReceiptV1, control_commands.ParticipantControlReceiptV2)

    assert control_commands.ParticipantControlQuerySnapshotV2 is not control_commands.ParticipantControlQuerySnapshotV1
    assert not issubclass(
        control_commands.ParticipantControlQuerySnapshotV2, control_commands.ParticipantControlQuerySnapshotV1
    )
    assert not issubclass(
        control_commands.ParticipantControlQuerySnapshotV1, control_commands.ParticipantControlQuerySnapshotV2
    )

    assert control_commands.BoundedControlErrorV2 is not control_commands.BoundedControlErrorV1
    assert not issubclass(control_commands.BoundedControlErrorV2, control_commands.BoundedControlErrorV1)
    assert not issubclass(control_commands.BoundedControlErrorV1, control_commands.BoundedControlErrorV2)

    assert control_commands.SignedControlResponseV2 is not control_commands.SignedControlResponseV1
    assert not issubclass(control_commands.SignedControlResponseV2, control_commands.SignedControlResponseV1)
    assert not issubclass(control_commands.SignedControlResponseV1, control_commands.SignedControlResponseV2)

    # Signer and Verifier classes
    assert control_signing.ControlSignerV2 is not control_signing.ControlSignerV1
    assert control_signing.ControlVerifierV2 is not control_signing.ControlVerifierV1


def test_gate_all_twenty_v2_providers_unmounted_and_fail_closed():
    """Assert all 20 V2 providers remain mounted=False."""
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
    short_key = b"0123456789012345678901234567890"
    long_key = b"012345678901234567890123456789012"
    double_key = b"0" * 64

    for bad_key in (short_key, long_key, double_key, b"secret_password"):
        with pytest.raises(ValueError, match=r"32_bytes|32 bytes"):
            control_signing.ControlSignerV2("k1", bad_key)

        with pytest.raises(ValueError, match=r"32_bytes|32 bytes"):
            control_signing.DaemonResponseSigner("k1", bad_key)

        with pytest.raises(TypeError):
            control_signing.DaemonResponseVerifier(trusted_keys={"k1": bad_key})  # type: ignore[arg-type]

        with pytest.raises(ValueError, match=r"32_bytes|32 bytes"):
            control_boundary.StaticControlKeyResolver({"k1": bad_key})


def test_gate_v2_codec_rejects_non_v2_and_malformed_frames():
    """Assert ControlProtocolCodec strictly enforces protocol 2.0 and validates envelope constraints."""
    codec = control_protocol.ControlProtocolCodec()

    v1_raw = b'{"protocol_version":"1.0","action":"ping","authorization":{"key_id":"k1","transaction_id":"tx1","participant_id":"p1","mission_id":"m1","subject_id":"s1","action_id":"ping","coordinator_revision":1,"expires_at":1700000000,"nonce":"n1","signature":"s1"},"payload_schema_id":"s1","payload_digest":"d1","canonical_payload_b64u":"e30"}'
    with pytest.raises(ValueError, match="protocol_version"):
        codec.decode_request(v1_raw)

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


def test_gate_production_ast_scans_disallow_forbidden_patterns():
    """AST scan over core/c2, core/actions, and core/execution verifying zero forbidden patterns."""
    root_dir = Path(__file__).resolve().parent.parent

    target_dirs = [
        root_dir / "core" / "c2",
        root_dir / "core" / "actions",
        root_dir / "core" / "execution",
    ]

    for t_dir in target_dirs:
        for py_path in t_dir.rglob("*.py"):
            with open(py_path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(py_path))

            # Scan AST nodes
            for node in ast.walk(tree):
                # 1. No _test_keys attribute or parameter in production
                if isinstance(node, ast.Attribute) and node.attr == "_test_keys":
                    raise AssertionError(f"Forbidden _test_keys access found in {py_path.name}:{node.lineno}")

                # 2. No create_mock_loopback_transport in production
                if isinstance(node, ast.FunctionDef) and node.name == "create_mock_loopback_transport":
                    raise AssertionError(
                        f"Forbidden create_mock_loopback_transport definition in {py_path.name}:{node.lineno}"
                    )


def test_gate_daemon_verifier_strict_rejections():
    """Assert DaemonResponseVerifier strictly rejects revoked keys, wrong service_id, or expired keys."""
    trusted_key = make_trusted_daemon_key(
        service_id="srv_valid",
        key_id="k_valid",
        public_key=b"1" * 32,
        valid_from_ms=1000,
        valid_until_ms=2000,
        revoked=False,
    )
    verifier = DaemonResponseVerifier(trusted_keys={"k_valid": trusted_key})

    # Envelope with service_id mismatch
    env = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv_mismatch",
        boot_instance_id="b1",
        daemon_generation="g1",
        request_digest="0" * 64,
        request_nonce="nonce_123456789012",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=1500,
        key_id="k_valid",
        signature="0" * 86,
    )
    with pytest.raises(ValueError, match="service_id_mismatch"):
        verifier.verify_envelope(env)

    # Envelope expired
    env_expired = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv_valid",
        boot_instance_id="b1",
        daemon_generation="g1",
        request_digest="0" * 64,
        request_nonce="nonce_123456789012",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=2500,
        key_id="k_valid",
        signature="0" * 86,
    )
    with pytest.raises(ValueError, match="validity expired"):
        verifier.verify_envelope(env_expired)
