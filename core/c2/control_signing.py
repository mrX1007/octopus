"""Control signing."""

from __future__ import annotations

import hashlib
import hmac
import time

from core.c2.control_commands import (
    C2ControlActionV1,
    ExecutionControlAuthorizationV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
)


class ControlSignerV1:
    """Signer for control plane participant and execution requests."""

    def __init__(self, key_id: str, secret_key: bytes) -> None:
        self.key_id = key_id
        self._secret_key = secret_key

    def _compute_participant_signature(self, auth: ParticipantControlAuthorizationV1) -> str:
        canonical = (
            f"{auth.key_id}:{auth.transaction_id}:{auth.participant_id}:"
            f"{auth.mission_id}:{auth.subject_id}:{auth.action_id}:"
            f"{auth.coordinator_revision}:{auth.request_digest}:"
            f"{auth.expires_at}:{auth.nonce}"
        )
        return hmac.new(self._secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _compute_execution_signature(self, auth: ExecutionControlAuthorizationV1) -> str:
        canonical = (
            f"{auth.key_id}:{auth.transaction_id}:{auth.request_id}:"
            f"{auth.mission_id}:{auth.subject_id}:{auth.action_id}:"
            f"{auth.coordinator_revision}:{auth.request_digest}:"
            f"{auth.expires_at}:{auth.nonce}"
        )
        return hmac.new(self._secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def sign_participant_request(self, unsigned_request: ParticipantControlRequestV1) -> ParticipantControlRequestV1:
        """Compute signature and return new ParticipantControlRequestV1 with valid signature."""
        auth = unsigned_request.authorization
        sig = self._compute_participant_signature(auth)
        signed_auth = ParticipantControlAuthorizationV1(
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            request_digest=auth.request_digest,
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

    def __init__(self, key_store: dict[str, bytes] | None = None) -> None:
        self._key_store: dict[str, bytes] = key_store or {}

    def register_key(self, key_id: str, secret_key: bytes) -> None:
        """Register a key ID and secret key pair."""
        self._key_store[key_id] = secret_key

    def verify_participant_request(self, request: ParticipantControlRequestV1, now: float | None = None) -> None:
        """Verify participant request signature and expiration."""
        if now is None:
            now = time.time()

        auth = request.authorization
        if now >= auth.expires_at:
            raise ValueError(f"Participant request authorization expired at {auth.expires_at}")

        secret_key = self._key_store.get(auth.key_id)
        if secret_key is None:
            raise ValueError(f"Unknown key_id: {auth.key_id}")

        canonical = (
            f"{auth.key_id}:{auth.transaction_id}:{auth.participant_id}:"
            f"{auth.mission_id}:{auth.subject_id}:{auth.action_id}:"
            f"{auth.coordinator_revision}:{auth.request_digest}:"
            f"{auth.expires_at}:{auth.nonce}"
        )
        expected_sig = hmac.new(secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, auth.signature):
            raise ValueError("Invalid participant request signature")

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
        if now is None:
            now = time.time()

        if now >= authorization.expires_at:
            raise ValueError(f"Execution request authorization expired at {authorization.expires_at}")

        secret_key = self._key_store.get(authorization.key_id)
        if secret_key is None:
            raise ValueError(f"Unknown key_id: {authorization.key_id}")

        canonical = (
            f"{authorization.key_id}:{authorization.transaction_id}:{authorization.request_id}:"
            f"{authorization.mission_id}:{authorization.subject_id}:{authorization.action_id}:"
            f"{authorization.coordinator_revision}:{authorization.request_digest}:"
            f"{authorization.expires_at}:{authorization.nonce}"
        )
        expected_sig = hmac.new(secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, authorization.signature):
            raise ValueError("Invalid execution request signature")
