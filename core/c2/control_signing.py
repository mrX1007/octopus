from __future__ import annotations

import hashlib
import hmac
import time

from typing import Callable

from core.c2.control_commands import (
    C2ControlActionV1,
    ExecutionControlAuthorizationV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
)
from core.c2.control_models import (
    calculate_canonical_request_digest,
    canonical_json_bytes,
    canonical_request_dict,
    strict_b64url_decode,
)


class ControlSignerV1:
    """Signer for control plane participant and execution requests."""

    def __init__(self, key_id: str, secret_key: bytes) -> None:
        self.key_id = key_id
        self._secret_key = secret_key

    def _compute_participant_signature(self, request: ParticipantControlRequestV1) -> str:
        body = canonical_json_bytes(canonical_request_dict(request))
        return hmac.new(self._secret_key, b"OCTOPUS-C2-AUTH-V1\x00" + body, hashlib.sha256).hexdigest()

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
        return hmac.new(self._secret_key, b"OCTOPUS-C2-EXEC-AUTH-V1\x00" + body, hashlib.sha256).hexdigest()

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
        """Resolve verification secret key by key_id."""
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

        secret_key = self.resolve_key(auth.key_id, ts)
        if secret_key is None:
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
        expected_sig = hmac.new(secret_key, b"OCTOPUS-C2-AUTH-V1\x00" + body, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, auth.signature):
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

        secret_key = self.resolve_key(authorization.key_id, ts)
        if secret_key is None:
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
        expected_sig = hmac.new(secret_key, b"OCTOPUS-C2-EXEC-AUTH-V1\x00" + body, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, authorization.signature):
            raise ValueError("Invalid execution request signature")

