"""Ed25519 cryptographic signing and verification for C2 Control Plane (§14.2-§14.6)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_commands import (
    ExecutionControlAuthorizationV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlAuthorizationV2,
    ParticipantControlRequestV1,
    ParticipantControlRequestV2,
    SignedControlResponseV2,
    UnsignedParticipantControlRequestV2,
)
from core.c2.control_models import (
    calculate_auth_transcript_v2,
    calculate_canonical_auth_transcript,
    calculate_canonical_request_digest,
    calculate_request_digest_v2,
    calculate_response_signature_digest,
    calculate_schema_bound_payload_digest,
    canonical_response_envelope_dict,
    strict_b64url_decode,
    strict_decode_signature_v2,
)


def _decode_sig_bytes_v1(signature_str: str) -> bytes:
    """Legacy helper for decoding base64/base64url signatures."""
    rem = len(signature_str) % 4
    if rem != 0:
        signature_str += "=" * (4 - rem)
    try:
        return base64.urlsafe_b64decode(signature_str.encode("ascii"))
    except Exception:
        return base64.b64decode(signature_str.encode("ascii"))


@dataclass(frozen=True)
class TrustedDaemonResponseKey:
    """Trust anchor descriptor for daemon response verification key."""

    service_id: str
    key_id: str
    public_key: bytes  # exactly 32 bytes
    valid_from_ms: int
    valid_until_ms: int
    revoked: bool = False
    predecessor_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.service_id) is not str or not self.service_id or len(self.service_id) > 256:
            raise ValueError("service_id must be a non-empty str with len <= 256")
        if type(self.key_id) is not str or not self.key_id or len(self.key_id) > 256:
            raise ValueError("key_id must be a non-empty str with len <= 256")
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            raise ValueError(
                f"public_key must be exactly 32 bytes, got {len(self.public_key) if isinstance(self.public_key, bytes) else type(self.public_key)}"
            )
        if type(self.valid_from_ms) is not int or isinstance(self.valid_from_ms, bool):
            raise ValueError("valid_from_ms must be an int")
        if type(self.valid_until_ms) is not int or isinstance(self.valid_until_ms, bool):
            raise ValueError("valid_until_ms must be an int")
        if self.valid_until_ms <= self.valid_from_ms:
            raise ValueError("valid_until_ms must be greater than valid_from_ms")
        if type(self.revoked) is not bool:
            raise ValueError("revoked must be a bool")
        if self.predecessor_id is not None and (type(self.predecessor_id) is not str or len(self.predecessor_id) > 256):
            raise ValueError("predecessor_id must be a str with len <= 256 or None")


class ControlSignerV2:
    """Strict Ed25519 signer for Control Protocol V2 requests (zero normalization, 32-byte seed only)."""

    def __init__(
        self,
        key_id: str,
        secret_key: bytes | ed25519.Ed25519PrivateKey,
        algorithm: str | None = None,
    ) -> None:
        self.key_id = key_id
        if isinstance(secret_key, ed25519.Ed25519PrivateKey):
            self._ed25519_key: ed25519.Ed25519PrivateKey = secret_key
        elif isinstance(secret_key, (bytes, bytearray)):
            if len(secret_key) != 32:
                raise ValueError(f"ed25519_private_seed_must_be_32_bytes: got {len(secret_key)}")
            self._ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(secret_key))
        else:
            raise TypeError("secret_key must be Ed25519PrivateKey or 32-byte seed")
        self.algorithm = "ed25519"

    @property
    def public_key_bytes(self) -> bytes:
        return self._ed25519_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def sign_participant_request(
        self, unsigned_request: ParticipantControlRequestV2 | UnsignedParticipantControlRequestV2
    ) -> ParticipantControlRequestV2:
        """Compute Ed25519 signature and return strict signed ParticipantControlRequestV2."""
        auth = unsigned_request.authorization
        req_digest = calculate_request_digest_v2(unsigned_request)
        transcript = calculate_auth_transcript_v2(unsigned_request, req_digest)

        raw_sig = self._ed25519_key.sign(transcript)
        sig_str = base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")

        signed_auth_v2 = ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            issued_at_ms=auth.issued_at_ms,
            expires_at_ms=auth.expires_at_ms,
            nonce=auth.nonce,
            request_digest=req_digest,
            signature=sig_str,
        )
        return ParticipantControlRequestV2(
            action=unsigned_request.action,
            authorization=signed_auth_v2,
            payload_schema_id=unsigned_request.payload_schema_id,
            payload_digest=unsigned_request.payload_digest,
            canonical_payload_b64u=unsigned_request.canonical_payload_b64u,
            prior_receipt_ref=unsigned_request.prior_receipt_ref,
            prior_receipt_digest=unsigned_request.prior_receipt_digest,
            expected_resource_revision=unsigned_request.expected_resource_revision,
        )

    sign_request = sign_participant_request


class ControlVerifierV2:
    """Strict Ed25519 verifier for Control Protocol V2 requests (zero normalization, 32-byte pubkey only)."""

    def __init__(
        self,
        key_store: dict[str, bytes] | None = None,
        key_resolver: Callable[[str, float], bytes | None] | Any = None,
    ) -> None:
        self._key_store: dict[str, bytes] = {}
        if key_store:
            for k, v in key_store.items():
                self.register_key(k, v)
        self._key_resolver = key_resolver

    def register_key(self, key_id: str, verification_key: bytes) -> None:
        """Register a key ID and Ed25519 public key pair (strictly 32 bytes)."""
        if len(verification_key) != 32:
            raise ValueError(f"verification_key must be exactly 32 bytes, got {len(verification_key)}")
        self._key_store[key_id] = bytes(verification_key)

    def resolve_key(self, key_id: str, now: float) -> bytes | None:
        """Resolve verification key by key_id without normalization."""
        if self._key_resolver is not None:
            if callable(self._key_resolver):
                resolved = self._key_resolver(key_id, now)
            elif hasattr(self._key_resolver, "require_key"):
                try:
                    res_key = self._key_resolver.require_key(key_id, now=now)
                    resolved = res_key.verification_key if hasattr(res_key, "verification_key") else res_key
                except Exception:
                    resolved = None
            elif hasattr(self._key_resolver, "resolve_key"):
                resolved = self._key_resolver.resolve_key(key_id, now)
            else:
                resolved = None
            if resolved is not None:
                if len(resolved) != 32:
                    raise ValueError(f"resolved verification key must be exactly 32 bytes, got {len(resolved)}")
                return bytes(resolved)
        key = self._key_store.get(key_id)
        if key is not None and len(key) != 32:
            raise ValueError(f"stored verification key must be exactly 32 bytes, got {len(key)}")
        return key

    def verify_participant_request(
        self,
        request: ParticipantControlRequestV2,
        now: float | None = None,
        *,
        verify_payload: bool = True,
    ) -> bytes:
        """Verify V2 participant request signature, digests, and expiration strictly via Ed25519."""
        if not isinstance(request, ParticipantControlRequestV2):
            raise TypeError(f"request must be ParticipantControlRequestV2, got {type(request).__name__}")

        auth = request.authorization
        ts_ms = int(time.time() * 1000) if now is None else int(now * 1000 if now < 10000000000 else now)

        if ts_ms >= auth.expires_at_ms:
            raise ValueError(f"Participant request authorization expired at {auth.expires_at_ms}")

        key_material = self.resolve_key(auth.key_id, ts_ms / 1000.0)
        if key_material is None:
            raise ValueError(f"Unknown key_id: {auth.key_id}")
        if len(key_material) != 32:
            raise ValueError(f"verification_key must be exactly 32 bytes, got {len(key_material)}")

        if verify_payload:
            payload_bytes = strict_b64url_decode(request.canonical_payload_b64u)
            actual_payload_digest = calculate_schema_bound_payload_digest(request.payload_schema_id, payload_bytes)
            if not hmac.compare_digest(actual_payload_digest, request.payload_digest):
                raise ValueError("payload_digest_mismatch")
        else:
            payload_bytes = b""

        actual_request_digest = calculate_request_digest_v2(request)
        if not hmac.compare_digest(actual_request_digest, auth.request_digest):
            raise ValueError("request_digest_mismatch")

        transcript = calculate_auth_transcript_v2(request, actual_request_digest)
        sig_bytes = strict_decode_signature_v2(auth.signature)

        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_material)
            public_key.verify(sig_bytes, transcript)
        except Exception as exc:
            raise ValueError("Invalid participant request signature") from exc

        return payload_bytes


class DaemonResponseSigner:
    """Signs daemon response envelopes using Ed25519 response private key (strictly 32 bytes)."""

    def __init__(
        self,
        key_id: str,
        private_key: bytes | ed25519.Ed25519PrivateKey,
    ) -> None:
        self.key_id = key_id
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            self._ed25519_key: ed25519.Ed25519PrivateKey = private_key
        elif isinstance(private_key, (bytes, bytearray)):
            if len(private_key) != 32:
                raise ValueError(f"ed25519_private_seed_must_be_32_bytes: got {len(private_key)}")
            self._ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(private_key))
        else:
            raise TypeError("private_key must be Ed25519PrivateKey or 32-byte bytes")

    @property
    def public_key_bytes(self) -> bytes:
        return self._ed25519_key.public_key().public_bytes_raw()

    def sign_envelope_dict(self, envelope_dict: dict) -> str:
        transcript = calculate_response_signature_digest(envelope_dict)
        raw_sig = self._ed25519_key.sign(transcript)
        return base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")


class DaemonResponseVerifier:
    """Verifies signed daemon responses against trusted Ed25519 public keys with full trust metadata (zero normalization)."""

    def __init__(
        self,
        trusted_keys: dict[str, TrustedDaemonResponseKey] | None = None,
        key_resolver: Callable[[str, int], TrustedDaemonResponseKey | None] | None = None,
    ) -> None:
        self._trusted_keys: dict[str, TrustedDaemonResponseKey] = {}
        if trusted_keys:
            for k, v in trusted_keys.items():
                if not isinstance(v, TrustedDaemonResponseKey):
                    raise TypeError("trusted key must be a TrustedDaemonResponseKey instance")
                if v.key_id != k:
                    raise ValueError(f"trusted key map key '{k}' must match key_id '{v.key_id}'")
                self._trusted_keys[k] = v
        self._key_resolver = key_resolver

    def resolve_key(self, key_id: str, issued_at_ms: int) -> TrustedDaemonResponseKey | None:
        if self._key_resolver is not None:
            resolved = self._key_resolver(key_id, issued_at_ms)
            if resolved is not None:
                if not isinstance(resolved, TrustedDaemonResponseKey):
                    raise TypeError("resolved key must be a TrustedDaemonResponseKey instance")
                return resolved
        return self._trusted_keys.get(key_id)

    def verify_envelope(
        self,
        envelope: SignedControlResponseV2,
        expected_service_id: str | None = None,
    ) -> None:
        key_obj = self.resolve_key(envelope.key_id, envelope.issued_at_ms)
        if key_obj is None:
            raise ValueError(f"Unknown daemon response key_id: {envelope.key_id}")
        if not isinstance(key_obj, TrustedDaemonResponseKey):
            raise TypeError("trusted key must be a TrustedDaemonResponseKey instance")

        if key_obj.key_id != envelope.key_id:
            raise ValueError(f"key_id_mismatch: trusted {key_obj.key_id} != envelope {envelope.key_id}")
        if key_obj.service_id != envelope.service_id:
            raise ValueError(f"service_id_mismatch: trusted {key_obj.service_id} != envelope {envelope.service_id}")
        if expected_service_id is not None and envelope.service_id != expected_service_id:
            raise ValueError(
                f"expected_service_id_mismatch: expected {expected_service_id} != envelope {envelope.service_id}"
            )

        if key_obj.revoked:
            raise ValueError(f"Daemon response key is revoked: {envelope.key_id}")
        if envelope.issued_at_ms < key_obj.valid_from_ms or envelope.issued_at_ms > key_obj.valid_until_ms:
            raise ValueError(f"Daemon response key validity expired for key_id: {envelope.key_id}")

        pub_bytes = key_obj.public_key
        if len(pub_bytes) != 32:
            raise ValueError(f"public_key must be exactly 32 bytes, got {len(pub_bytes)}")

        env_dict = canonical_response_envelope_dict(
            protocol_version=envelope.protocol_version,
            daemon_instance_id=getattr(envelope, "daemon_instance_id", "daemon_inst_0"),
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

        transcript = calculate_response_signature_digest(env_dict)
        sig_bytes = strict_decode_signature_v2(envelope.signature)

        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            public_key.verify(sig_bytes, transcript)
        except Exception as exc:
            raise ValueError(f"daemon_signature_verification_failed: {exc}") from exc


# ─── Legacy V1 Signer & Verifier (Isolated) ────────────────────


class ControlSignerV1:
    """Legacy Control Protocol V1 signer with automatic key normalization (isolated from V2)."""

    def __init__(
        self,
        key_id: str,
        secret_key: bytes | ed25519.Ed25519PrivateKey,
        algorithm: str | None = None,
    ) -> None:
        self.key_id = key_id
        if isinstance(secret_key, ed25519.Ed25519PrivateKey):
            self._ed25519_key: ed25519.Ed25519PrivateKey = secret_key
        elif isinstance(secret_key, (bytes, bytearray)):
            raw_key = bytes(secret_key) if len(secret_key) == 32 else hashlib.sha256(bytes(secret_key)).digest()
            self._ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_key)
        else:
            raise TypeError("secret_key must be Ed25519PrivateKey or bytes")
        self.algorithm = "ed25519"

    @property
    def public_key_bytes(self) -> bytes:
        return self._ed25519_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def sign_participant_request(self, unsigned_request: ParticipantControlRequestV1) -> ParticipantControlRequestV1:
        auth = unsigned_request.authorization
        req_digest = calculate_canonical_request_digest(unsigned_request)

        staged_auth_v1 = ParticipantControlAuthorizationV1(
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            request_digest=req_digest,
            expires_at=getattr(auth, "expires_at", 0.0),
            nonce=auth.nonce,
            signature="",
        )
        staged_req_v1 = ParticipantControlRequestV1(
            action=unsigned_request.action,
            authorization=staged_auth_v1,
            payload_schema_id=unsigned_request.payload_schema_id,
            payload_digest=unsigned_request.payload_digest,
            canonical_payload_b64u=unsigned_request.canonical_payload_b64u,
            prior_receipt_ref=unsigned_request.prior_receipt_ref,
            prior_receipt_digest=unsigned_request.prior_receipt_digest,
            expected_resource_revision=unsigned_request.expected_resource_revision,
        )
        transcript = calculate_canonical_auth_transcript(staged_req_v1, req_digest)
        raw_sig = self._ed25519_key.sign(transcript)
        sig_str = base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")

        signed_auth_v1 = ParticipantControlAuthorizationV1(
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            request_digest=req_digest,
            expires_at=getattr(auth, "expires_at", 0.0),
            nonce=auth.nonce,
            signature=sig_str,
        )
        return ParticipantControlRequestV1(
            action=unsigned_request.action,
            authorization=signed_auth_v1,
            payload_schema_id=unsigned_request.payload_schema_id,
            payload_digest=unsigned_request.payload_digest,
            canonical_payload_b64u=unsigned_request.canonical_payload_b64u,
            prior_receipt_ref=unsigned_request.prior_receipt_ref,
            prior_receipt_digest=unsigned_request.prior_receipt_digest,
            expected_resource_revision=unsigned_request.expected_resource_revision,
        )

    sign_request = sign_participant_request

    def sign_execution_request(
        self,
        action: str,
        authorization: Any,
        payload_schema_id: str,
        payload_digest: str,
        canonical_payload_b64u: str = "",
    ) -> Any:
        req_digest = getattr(authorization, "request_digest", "") or "exec_digest"
        transcript = hashlib.sha256(
            f"{action}:{authorization.transaction_id}:{authorization.nonce}:{req_digest}:{payload_digest}".encode()
        ).digest()
        raw_sig = self._ed25519_key.sign(transcript)
        sig = base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")
        return ExecutionControlAuthorizationV1(
            key_id=authorization.key_id,
            transaction_id=authorization.transaction_id,
            request_id=getattr(authorization, "request_id", ""),
            mission_id=authorization.mission_id,
            subject_id=authorization.subject_id,
            action_id=authorization.action_id,
            coordinator_revision=authorization.coordinator_revision,
            request_digest=req_digest,
            expires_at=getattr(authorization, "expires_at", 0),
            nonce=authorization.nonce,
            signature=sig,
        )


class ControlVerifierV1:
    """Legacy Control Protocol V1 verifier with legacy normalization fallback (isolated from V2)."""

    def __init__(
        self,
        key_store: dict[str, bytes] | None = None,
        key_resolver: Any = None,
    ) -> None:
        self._key_store: dict[str, bytes] = {}
        if key_store is not None:
            for k, v in key_store.items():
                self.register_key(k, v)
        self._key_resolver = key_resolver

    def register_key(self, key_id: str, verification_key: bytes) -> None:
        if len(verification_key) == 32:
            self._key_store[key_id] = verification_key
        else:
            seed = hashlib.sha256(verification_key).digest()
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            self._key_store[key_id] = priv.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )

    def resolve_key(self, key_id: str, now: float) -> bytes | None:
        if self._key_resolver is not None:
            if callable(self._key_resolver):
                resolved = self._key_resolver(key_id, now)
            elif hasattr(self._key_resolver, "require_key"):
                try:
                    res_key = self._key_resolver.require_key(key_id, now=now)
                    resolved = res_key.verification_key if hasattr(res_key, "verification_key") else res_key
                except Exception:
                    resolved = None
            elif hasattr(self._key_resolver, "resolve_key"):
                resolved = self._key_resolver.resolve_key(key_id, now)
            else:
                resolved = None
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
        auth = request.authorization
        ts = time.time() if now is None else (now / 1000.0 if now > 10000000000 else now)
        if ts >= getattr(auth, "expires_at", 0):
            raise ValueError(f"Participant request authorization expired at {getattr(auth, 'expires_at', 0)}")
        key_material = self.resolve_key(auth.key_id, ts)
        if key_material is None:
            raise ValueError(f"Unknown key_id: {auth.key_id}")

        payload_bytes = strict_b64url_decode(request.canonical_payload_b64u) if verify_payload else b""

        actual_request_digest = calculate_canonical_request_digest(request)
        transcript = calculate_canonical_auth_transcript(request, actual_request_digest)
        sig_bytes = _decode_sig_bytes_v1(auth.signature)

        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(key_material)
            pub.verify(sig_bytes, transcript)
            return payload_bytes
        except Exception:
            try:
                seed = key_material if len(key_material) == 32 else hashlib.sha256(key_material).digest()
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                priv.public_key().verify(sig_bytes, transcript)
                return payload_bytes
            except Exception as exc:
                raise ValueError("Invalid participant request signature") from exc

    def verify_execution_request(
        self,
        action: str,
        authorization: Any,
        payload_schema_id: str,
        payload_digest: str,
        canonical_payload_b64u: str = "",
        now: float | None = None,
    ) -> None:
        ts = time.time() if now is None else now
        if ts >= getattr(authorization, "expires_at", 0):
            raise ValueError("execution authorization expired")
        key_material = self.resolve_key(authorization.key_id, ts)
        if key_material is None:
            raise ValueError(f"Unknown key_id: {authorization.key_id}")
        transcript = hashlib.sha256(
            f"{action}:{authorization.transaction_id}:{authorization.nonce}:{authorization.request_digest}:{payload_digest}".encode()
        ).digest()
        sig_bytes = _decode_sig_bytes_v1(authorization.signature)
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(key_material)
            pub.verify(sig_bytes, transcript)
        except Exception:
            try:
                seed = key_material if len(key_material) == 32 else hashlib.sha256(key_material).digest()
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                priv.public_key().verify(sig_bytes, transcript)
            except Exception as exc:
                raise ValueError("Invalid execution request signature") from exc


__all__ = [
    "ControlSignerV1",
    "ControlSignerV2",
    "ControlVerifierV1",
    "ControlVerifierV2",
    "DaemonResponseSigner",
    "DaemonResponseVerifier",
    "TrustedDaemonResponseKey",
]
