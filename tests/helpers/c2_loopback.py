"""Loopback transport helpers for testing C2 control client without sockets."""

from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlReceiptV2,
    SignedControlResponseV2,
)
from core.c2.control_models import (
    calculate_receipt_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
)
from core.c2.control_protocol import (
    ControlProtocolCodec,
)
from core.c2.control_signing import (
    DaemonResponseSigner,
    DaemonResponseVerifier,
    TrustedDaemonResponseKey,
)
from core.c2.protocol import C2_CONTROL_PROTOCOL_VERSION


def create_mock_loopback_transport(
    daemon_signer: DaemonResponseSigner | None = None,
    *,
    daemon_instance_id: str = "daemon_inst_0",
    daemon_generation: str = "gen_0",
    service_id: str = "srv_mock_test_id",
    boot_instance_id: str = "boot_0",
    key_id: str = "mock_daemon_key",
) -> tuple[Callable[[bytes], bytes], DaemonResponseVerifier, str]:
    """Create a loopback transport and corresponding verifier for tests."""
    if daemon_signer is None:
        priv = ed25519.Ed25519PrivateKey.generate()
        signer = DaemonResponseSigner(
            key_id=key_id,
            private_key=priv,
        )
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    else:
        signer = daemon_signer
        priv_key = getattr(daemon_signer, "_ed25519_key", None)
        pub_bytes = (
            priv_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if priv_key
            else b""
        )

    codec = ControlProtocolCodec()

    def _handler(raw_data: bytes) -> bytes:
        req = codec.decode_request(raw_data)
        rcpt_ref = f"rcpt_{req.authorization.transaction_id}"
        receipt = ParticipantControlReceiptV2(
            transaction_id=req.authorization.transaction_id,
            participant_id=req.authorization.participant_id,
            action=req.action,
            resource_ref=f"res_{req.authorization.transaction_id}",
            resource_revision=1,
            receipt_ref=rcpt_ref,
            receipt_digest=calculate_receipt_digest(
                transaction_id=req.authorization.transaction_id,
                participant_id=req.authorization.participant_id,
                receipt_ref=rcpt_ref,
                action=req.action.value if hasattr(req.action, "value") else str(req.action),
                resource_ref=f"res_{req.authorization.transaction_id}",
                resource_revision=1,
                daemon_instance_id=daemon_instance_id,
                protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            ),
            daemon_instance_id=daemon_instance_id,
            result_payload_schema_id=None,
            result_payload_digest=None,
            result_payload_b64u=None,
        )
        res_dict = {
            "action": receipt.action.value if hasattr(receipt.action, "value") else str(receipt.action),
            "daemon_instance_id": receipt.daemon_instance_id,
            "participant_id": receipt.participant_id,
            "receipt_digest": receipt.receipt_digest,
            "receipt_ref": receipt.receipt_ref,
            "resource_ref": receipt.resource_ref,
            "resource_revision": receipt.resource_revision,
            "result_payload_b64u": receipt.result_payload_b64u,
            "result_payload_digest": receipt.result_payload_digest,
            "result_payload_schema_id": receipt.result_payload_schema_id,
            "transaction_id": receipt.transaction_id,
            "type": "receipt",
        }
        payload_bytes = canonical_json_bytes(res_dict)
        payload_b64u = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        payload_digest = hashlib.sha256(payload_bytes).hexdigest()
        issued_at_ms = int(time.time() * 1000)

        envelope_dict = canonical_response_envelope_dict(
            protocol_version="2.0",
            daemon_instance_id=daemon_instance_id,
            daemon_generation=daemon_generation,
            service_id=service_id,
            boot_instance_id=boot_instance_id,
            request_digest=req.authorization.request_digest,
            request_nonce=req.authorization.nonce,
            response_type="receipt",
            response_payload_b64u=payload_b64u,
            response_digest=payload_digest,
            issued_at_ms=issued_at_ms,
            key_id=signer.key_id,
        )
        sig = signer.sign_envelope_dict(envelope_dict)
        signed_env = SignedControlResponseV2(
            protocol_version="2.0",
            service_id=service_id,
            boot_instance_id=boot_instance_id,
            daemon_generation=daemon_generation,
            request_digest=req.authorization.request_digest,
            request_nonce=req.authorization.nonce,
            response_type="receipt",
            response_payload_b64u=payload_b64u,
            response_digest=payload_digest,
            issued_at_ms=issued_at_ms,
            key_id=signer.key_id,
            signature=sig,
        )
        return codec.encode_response(signed_env)

    trusted_key = TrustedDaemonResponseKey(
        service_id=service_id,
        key_id=signer.key_id,
        public_key=pub_bytes,
        valid_from_ms=0,
        valid_until_ms=253402300799000,
    )
    verifier = DaemonResponseVerifier(trusted_keys={signer.key_id: trusted_key})
    return _handler, verifier, service_id
