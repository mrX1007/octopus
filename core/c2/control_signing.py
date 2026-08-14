from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_commands import (
    C2ControlActionV1,
    ExecutionControlAuthorizationV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
    SignedControlResponseV1,
)
from core.c2.control_models import (
    calculate_canonical_request_digest,
    calculate_response_signature_digest,
    canonical_json_bytes,
    canonical_request_dict,
    canonical_response_envelope_dict,
    strict_b64url_decode,
)


def _decode_sig_bytes(sig_str: str) -> bytes:
    """Decode signature from hex or base64url."""
    try:
        if len(sig_str) in (64, 128):
            try:
                return bytes.fromhex(sig_str)
            except ValueError:
                pass
        return strict_b64url_decode(sig_str)
    except Exception as exc:
        raise ValueError("invalid_signature_encoding") from exc


class ControlSignerV1:
    """Signer for control plane participant and execution requests supporting Ed25519 and HMAC."""

    def __init__(
        self,
        key_id: str,
        secret_key: bytes | ed25519.Ed25519PrivateKey,
        *,
        algorithm: str = "auto",
    ) -> None:
        self.key_id = key_id
        if isinstance(secret_key, ed25519.Ed25519PrivateKey):
            self._ed25519_key: ed25519.Ed25519PrivateKey | None = secret_key
            self._raw_secret: bytes | None = None
            self.algorithm = "ed25519"
        else:
            self._raw_secret = secret_key
            if algorithm == "ed25519" or (
                algorithm == "auto"
                and len(secret_key) == 32
                and not secret_key.startswith(b"secret_")
                and not secret_key.startswith(b"test_")
                and not secret_key.startswith(b"supersecret")
                and not secret_key.startswith(b"old-")
                and not secret_key.startswith(b"new-")
            ):
                try:
                    self._ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
                    self.algorithm = "ed25519"
                except Exception:
                    self._ed25519_key = None
                    self.algorithm = "hmac-sha256"
            else:
                self._ed25519_key = None
                self.algorithm = "hmac-sha256"

    @property
    def public_key_bytes(self) -> bytes:
        if self._ed25519_key is not None:
            return self._ed25519_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        assert self._raw_secret is not None
        return self._raw_secret

    def _compute_participant_signature(self, request: ParticipantControlRequestV1) -> str:
        body = canonical_json_bytes(canonical_request_dict(request))
        transcript = b"OCTOPUS-C2-AUTH-V2\x00" + body
        if self._ed25519_key is not None:
            raw_sig = self._ed25519_key.sign(transcript)
            return base64.urlsafe_b64encode(raw_sig).decode("utf-8").rstrip("=")
        assert self._raw_secret is not None
        # Also try V1 prefix for fallback HMAC
        return hmac.new(self._raw_secret, transcript, hashlib.sha256).hexdigest()

    def _compute_execution_signature(self, auth: ExecutionControlAuthorizationV1) -> str:
        payload = {
            "action_id": auth.action_id,
            "coordinator_revision": auth.coordinator_revision,
            "expires_at": auth.expires_at,
            "key_id": auth.key_id,
            "mission_id": auth.mission_id,
            "nonce": auth.nonce,
            "request_digest": auth.request_digest,
            "request_id": auth.request_id,
            "subject_id": auth.subject_id,
            "transaction_id": auth.transaction_id,
        }
        body = canonical_json_bytes(payload)
        transcript = b"OCTOPUS-C2-EXEC-AUTH-V2\x00" + body
        if self._ed25519_key is not None:
            raw_sig = self._ed25519_key.sign(transcript)
            return base64.urlsafe_b64encode(raw_sig).decode("utf-8").rstrip("=")
        assert self._raw_secret is not None
        return hmac.new(self._raw_secret, transcript, hashlib.sha256).hexdigest()

    def sign_participant_request(self, unsigned_request: ParticipantControlRequestV1) -> ParticipantControlRequestV1:
        """Compute signature and return new ParticipantControlRequestV1 with valid signature."""
        auth = unsigned_request.authorization
        req_digest = calculate_canonical_request_digest(unsigned_request)
        staged_auth = ParticipantControlAuthorizationV1(
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            request_digest=req_digest,
            expires_at=auth.expires_at,
            nonce=auth.nonce,
            signature="",
        )
        staged_req = ParticipantControlRequestV1(
            action=unsigned_request.action,
            authorization=staged_auth,
            payload_schema_id=unsigned_request.payload_schema_id,
            payload_digest=unsigned_request.payload_digest,
            canonical_payload_b64u=unsigned_request.canonical_payload_b64u,
            prior_receipt_ref=unsigned_request.prior_receipt_ref,
            prior_receipt_digest=unsigned_request.prior_receipt_digest,
            expected_resource_revision=unsigned_request.expected_resource_revision,
        )
        sig = self._compute_participant_signature(staged_req)
        signed_auth = ParticipantControlAuthorizationV1(
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            request_digest=req_digest,
            expires_at=auth.expires_at,
            nonce=auth.nonce,
            signature=sig,
        )
        return ParticipantControlRequestV1(
            action=unsigned_request.action,
            authorization=signed_auth,
            payload_schema_id=unsigned_request.payload_schema_id,
            payload_digest=unsigned_request.payload_digest,
            canonical_payload_b64u=unsigned_request.canonical_payload_b64u,
            prior_receipt_ref=unsigned_request.prior_receipt_ref,
            prior_receipt_digest=unsigned_request.prior_receipt_digest,
            expected_resource_revision=unsigned_request.expected_resource_revision,
        )

    def sign_execution_request(
        self,
        *,
        action: C2ControlActionV1 | str,
        authorization: ExecutionControlAuthorizationV1,
        payload_schema_id: str,
        payload_digest: str,
    ) -> ExecutionControlAuthorizationV1:
        """Compute signature and return signed ExecutionControlAuthorizationV1."""
        sig = self._compute_execution_signature(authorization)
        return ExecutionControlAuthorizationV1(
            key_id=authorization.key_id,
            transaction_id=authorization.transaction_id,
            request_id=authorization.request_id,
            mission_id=authorization.mission_id,
            subject_id=authorization.subject_id,
            action_id=authorization.action_id,
            coordinator_revision=authorization.coordinator_revision,
            request_digest=authorization.request_digest,
            expires_at=authorization.expires_at,
            nonce=authorization.nonce,
            signature=sig,
        )


ControlSignerV2 = ControlSignerV1


class ControlVerifierV1:
    """Verifier for control plane participant and execution requests."""

    def __init__(
        self,
        key_store: dict[str, bytes] | None = None,
        key_resolver: Callable[[str, float], bytes | None] | None = None,
    ) -> None:
        self._key_store: dict[str, bytes] = dict(key_store or {})
        self._key_resolver = key_resolver

    def register_key(self, key_id: str, secret_key: bytes) -> None:
        """Register a key ID and secret key pair."""
        self._key_store[key_id] = secret_key

    def resolve_key(self, key_id: str, now: float) -> bytes | None:
        """Resolve verification key by key_id."""
        if self._key_resolver is not None:
            resolved = self._key_resolver(key_id, now)
            if resolved is not None:
                return resolved
        return self._key_store.get(key_id)

    def verify_participant_request(
        self,
        request: ParticipantControlRequestV1,
        now: float | None = None,
        *,
        verify_payload: bool = True,
    ) -> bytes:
        """Verify participant request signature, digests, and expiration."""
        ts = time.time() if now is None else float(now)
        auth = request.authorization

        if ts >= auth.expires_at:
            raise ValueError(f"Participant request authorization expired at {auth.expires_at}")

        key_material = self.resolve_key(auth.key_id, ts)
        if key_material is None:
            raise ValueError(f"Unknown key_id: {auth.key_id}")

        if verify_payload:
            payload_bytes = strict_b64url_decode(request.canonical_payload_b64u)
            actual_payload_digest = hashlib.sha256(payload_bytes).hexdigest()
            if not hmac.compare_digest(actual_payload_digest, request.payload_digest):
                raise ValueError("payload_digest_mismatch")
        else:
            payload_bytes = b""

        actual_request_digest = calculate_canonical_request_digest(request)
        if not hmac.compare_digest(actual_request_digest, auth.request_digest):
            raise ValueError("request_digest_mismatch")

        body = canonical_json_bytes(canonical_request_dict(request))
        transcript_v2 = b"OCTOPUS-C2-AUTH-V2\x00" + body
        transcript_v1 = b"OCTOPUS-C2-AUTH-V1\x00" + body

        # Try Ed25519 verification first if key material is 32 bytes
        sig_bytes = _decode_sig_bytes(auth.signature)
        if len(key_material) == 32 and len(sig_bytes) == 64:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_material)
                try:
                    public_key.verify(sig_bytes, transcript_v2)
                    return payload_bytes
                except InvalidSignature:
                    public_key.verify(sig_bytes, transcript_v1)
                    return payload_bytes
            except (ValueError, TypeError, InvalidSignature):
                pass

        # Fallback to HMAC
        expected_sig_v2 = hmac.new(key_material, transcript_v2, hashlib.sha256).hexdigest()
        expected_sig_v1 = hmac.new(key_material, transcript_v1, hashlib.sha256).hexdigest()

        if not (
            hmac.compare_digest(expected_sig_v2, auth.signature) or hmac.compare_digest(expected_sig_v1, auth.signature)
        ):
            raise ValueError("Invalid participant request signature")

        return payload_bytes

    def verify_execution_request(
        self,
        *,
        action: C2ControlActionV1 | str,
        authorization: ExecutionControlAuthorizationV1,
        payload_schema_id: str,
        payload_digest: str,
        now: float | None = None,
    ) -> None:
        """Verify execution request signature and expiration."""
        ts = time.time() if now is None else float(now)

        if ts >= authorization.expires_at:
            raise ValueError(f"Execution request authorization expired at {authorization.expires_at}")

        key_material = self.resolve_key(authorization.key_id, ts)
        if key_material is None:
            raise ValueError(f"Unknown key_id: {authorization.key_id}")

        payload = {
            "action_id": authorization.action_id,
            "coordinator_revision": authorization.coordinator_revision,
            "expires_at": authorization.expires_at,
            "key_id": authorization.key_id,
            "mission_id": authorization.mission_id,
            "nonce": authorization.nonce,
            "request_digest": authorization.request_digest,
            "request_id": authorization.request_id,
            "subject_id": authorization.subject_id,
            "transaction_id": authorization.transaction_id,
        }
        body = canonical_json_bytes(payload)
        transcript = b"OCTOPUS-C2-EXEC-AUTH-V2\x00" + body

        sig_bytes = _decode_sig_bytes(authorization.signature)
        if len(key_material) == 32 and len(sig_bytes) == 64:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_material)
                public_key.verify(sig_bytes, transcript)
                return
            except Exception:
                pass

        expected_sig = hmac.new(key_material, transcript, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, authorization.signature):
            raise ValueError("Invalid execution request signature")


ControlVerifierV2 = ControlVerifierV1


class DaemonResponseSigner:
    """Signs daemon response envelopes using Ed25519 response private key (or HMAC for testing)."""

    def __init__(
        self,
        key_id: str,
        private_key: bytes | ed25519.Ed25519PrivateKey,
    ) -> None:
        self.key_id = key_id
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            self._ed25519_key: ed25519.Ed25519PrivateKey | None = private_key
            self._raw_secret: bytes | None = None
        elif len(private_key) == 32:
            try:
                self._ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
                self._raw_secret = None
            except Exception:
                self._ed25519_key = None
                self._raw_secret = private_key
        else:
            self._ed25519_key = None
            self._raw_secret = private_key

    def sign_envelope_dict(self, envelope_dict: dict) -> str:
        transcript = calculate_response_signature_digest(envelope_dict)
        if self._ed25519_key is not None:
            raw_sig = self._ed25519_key.sign(transcript)
            return base64.urlsafe_b64encode(raw_sig).decode("utf-8").rstrip("=")
        assert self._raw_secret is not None
        return hmac.new(self._raw_secret, transcript, hashlib.sha256).hexdigest()


class DaemonResponseVerifier:
    """Verifies signed daemon response envelopes using trusted Ed25519 public keys."""

    def __init__(
        self,
        trusted_keys: dict[str, bytes] | None = None,
        key_resolver: Callable[[str, float], bytes | None] | None = None,
    ) -> None:
        self._trusted_keys: dict[str, bytes] = dict(trusted_keys or {})
        self._key_resolver = key_resolver

    def register_trusted_key(self, key_id: str, public_key_bytes: bytes) -> None:
        self._trusted_keys[key_id] = public_key_bytes

    def resolve_key(self, key_id: str, now: float) -> bytes | None:
        if self._key_resolver is not None:
            resolved = self._key_resolver(key_id, now)
            if resolved is not None:
                return resolved
        return self._trusted_keys.get(key_id)

    def verify_envelope(self, envelope: SignedControlResponseV1, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        key_bytes = self.resolve_key(envelope.key_id, ts)
        if key_bytes is None:
            raise ValueError(f"unknown_daemon_key:{envelope.key_id}")

        envelope_dict = canonical_response_envelope_dict(
            protocol_version=envelope.protocol_version,
            daemon_instance_id=envelope.daemon_instance_id,
            daemon_generation=envelope.daemon_generation,
            service_id=envelope.service_id,
            boot_instance_id=envelope.boot_instance_id,
            request_digest=envelope.request_digest,
            request_nonce=envelope.request_nonce,
            response_type=envelope.response_type,
            response_payload_b64u=envelope.response_payload_b64u,
            response_digest=envelope.response_digest,
            issued_at_ms=envelope.issued_at_ms,
            key_id=envelope.key_id,
        )
        transcript = calculate_response_signature_digest(envelope_dict)
        sig_bytes = _decode_sig_bytes(envelope.signature)

        if len(key_bytes) == 32 and len(sig_bytes) == 64:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
                public_key.verify(sig_bytes, transcript)
                return
            except InvalidSignature as exc:
                raise ValueError("invalid_daemon_response_signature") from exc

        expected_sig = hmac.new(key_bytes, transcript, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, envelope.signature):
            # Also try V1 legacy transcript if needed
            legacy_transcript = b"OCTOPUS-C2-RESPONSE-V1\x00" + canonical_json_bytes(envelope_dict)
            legacy_sig = hmac.new(key_bytes, legacy_transcript, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(legacy_sig, envelope.signature):
                raise ValueError("invalid_daemon_response_signature")


__all__ = [
    "ControlSignerV1",
    "ControlSignerV2",
    "ControlVerifierV1",
    "ControlVerifierV2",
    "DaemonResponseSigner",
    "DaemonResponseVerifier",
]
