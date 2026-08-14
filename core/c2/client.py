from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import socket
import struct
import time
import uuid
from typing import Any, Callable


from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlPhaseV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
    SignedControlResponseV1,
)
from core.c2.control_models import (
    calculate_canonical_request_digest,
    calculate_payload_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
    strict_b64url_decode,
)
from core.c2.control_protocol import (
    FRAME_MAGIC,
    MAX_FRAME_SIZE,
    ControlProtocolCodec,
    receive_frame,
    strict_json_loads,
)
from core.c2.control_signing import ControlSignerV1, ControlVerifierV1


class C2ControlError(Exception):
    """Base exception for C2 control client errors."""


class C2DaemonUnavailable(C2ControlError):
    """Daemon socket is not reachable or connection was refused."""


class C2ControlTimeout(C2ControlError):
    """Socket communication timed out."""


class C2ProtocolError(C2ControlError):
    """Protocol error, framing violation, or decoding failure."""


class C2ResponseVerificationError(C2ControlError):
    """Response signature or identity verification failed."""


class C2ControlClient:
    """Base interface / abstract class for C2 Control Client."""

    def close(self) -> None:
        pass

    def __enter__(self) -> C2ControlClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class DefaultC2ControlClient(C2ControlClient):
    """Default production implementation of C2ControlClient."""

    def __init__(
        self,
        signer: ControlSignerV1,
        verifier: ControlVerifierV1 | None = None,
        codec: ControlProtocolCodec | None = None,
        transport_handler: Callable[[bytes], bytes] | None = None,
        daemon_secret_key: bytes | None = None,
        socket_path: str | None = None,
    ) -> None:
        self.signer = signer
        self.verifier = verifier
        self.codec = codec or ControlProtocolCodec()
        self.transport_handler = transport_handler
        self.daemon_secret_key = daemon_secret_key
        self.socket_path = socket_path
        self._is_closed = False

    def send_request(
        self, request: ParticipantControlRequestV1
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Send a signed ParticipantControlRequestV1 and decode response."""
        if self._is_closed:
            raise RuntimeError("Client is closed")

        signed_req = self.signer.sign_participant_request(request)
        encoded_frame = self.codec.encode_request(signed_req)

        if self.transport_handler is not None:
            resp_bytes = self.transport_handler(encoded_frame)
        else:
            sock_path = self.socket_path or os.environ.get("OCTOPUS_C2_SOCKET", "/run/octopus/octopus-c2.sock")
            if not os.path.exists(sock_path) and os.environ.get("OCTOPUS_C2_ALLOW_INSECURE_DEV_SOCKET") == "1":
                if os.path.exists("/tmp/octopus.sock"):
                    sock_path = "/tmp/octopus.sock"
            if not os.path.exists(sock_path):
                raise C2DaemonUnavailable(f"C2 daemon socket not found at {sock_path}")
            resp_bytes = self._socket_transport(sock_path, encoded_frame)

        try:
            raw_response = self.codec.decode_response(resp_bytes)
        except Exception as exc:
            raise C2ProtocolError(f"failed to decode daemon control response: {exc}") from exc

        # Handle signed response envelope
        if isinstance(raw_response, SignedControlResponseV1):
            return self._verify_signed_response(raw_response, signed_req)

        # Correlation validation on direct receipt
        if isinstance(raw_response, ParticipantControlReceiptV1):
            if raw_response.transaction_id != signed_req.authorization.transaction_id:
                raise C2ResponseVerificationError("response_transaction_id_mismatch")
            if raw_response.participant_id != signed_req.authorization.participant_id:
                raise C2ResponseVerificationError("response_participant_id_mismatch")
            if raw_response.action != signed_req.action:
                raise C2ResponseVerificationError("response_action_mismatch")

        return raw_response

    def _verify_signed_response(
        self,
        envelope: SignedControlResponseV1,
        request: ParticipantControlRequestV1,
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Verify signed daemon response envelope and decode inner message."""
        req_auth = request.authorization
        if envelope.request_digest != req_auth.request_digest:
            raise C2ResponseVerificationError("response_request_digest_mismatch")
        if envelope.request_nonce != req_auth.nonce:
            raise C2ResponseVerificationError("response_nonce_mismatch")

        # Verify envelope signature if secret key available
        secret_key = self.daemon_secret_key
        if secret_key is None and self.verifier is not None:
            secret_key = self.verifier.resolve_key(envelope.key_id, envelope.issued_at_ms / 1000.0)

        if secret_key is not None:
            envelope_dict = canonical_response_envelope_dict(
                protocol_version=envelope.protocol_version,
                daemon_instance_id=envelope.daemon_instance_id,
                daemon_generation=envelope.daemon_generation,
                request_digest=envelope.request_digest,
                request_nonce=envelope.request_nonce,
                response_type=envelope.response_type,
                response_payload_b64u=envelope.response_payload_b64u,
                response_digest=envelope.response_digest,
                issued_at_ms=envelope.issued_at_ms,
                key_id=envelope.key_id,
            )
            canonical_bytes = b"OCTOPUS-C2-RESPONSE-V1\x00" + canonical_json_bytes(envelope_dict)
            expected_sig = hmac.new(secret_key, canonical_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, envelope.signature):
                raise C2ResponseVerificationError("invalid_daemon_response_signature")

        # Decode inner payload
        payload_bytes = strict_b64url_decode(envelope.response_payload_b64u)
        actual_digest = hashlib.sha256(payload_bytes).hexdigest()
        if not hmac.compare_digest(actual_digest, envelope.response_digest):
            raise C2ResponseVerificationError("response_digest_mismatch")

        inner_data = strict_json_loads(payload_bytes)
        resp_type = inner_data.get("type", envelope.response_type)

        if resp_type == "receipt":
            receipt = ParticipantControlReceiptV1(
                transaction_id=inner_data["transaction_id"],
                participant_id=inner_data["participant_id"],
                action=C2ControlActionV1(inner_data["action"]),
                resource_ref=inner_data.get("resource_ref"),
                resource_revision=inner_data.get("resource_revision"),
                receipt_ref=inner_data["receipt_ref"],
                receipt_digest=inner_data["receipt_digest"],
                daemon_instance_id=inner_data["daemon_instance_id"],
                result_payload_schema_id=inner_data.get("result_payload_schema_id"),
                result_payload_digest=inner_data.get("result_payload_digest"),
                result_payload_b64u=inner_data.get("result_payload_b64u"),
            )
            if receipt.transaction_id != req_auth.transaction_id:
                raise C2ResponseVerificationError("inner_receipt_transaction_id_mismatch")
            return receipt
        elif resp_type == "snapshot":
            return ParticipantControlQuerySnapshotV1(
                transaction_id=inner_data["transaction_id"],
                participant_id=inner_data["participant_id"],
                resource_ref=inner_data.get("resource_ref"),
                resource_revision=inner_data.get("resource_revision"),
                phase=ParticipantControlPhaseV1(inner_data["phase"]),
                receipt_ref=inner_data.get("receipt_ref"),
                receipt_digest=inner_data.get("receipt_digest"),
                snapshot_digest=inner_data["snapshot_digest"],
                result_payload_schema_id=inner_data.get("result_payload_schema_id"),
                result_payload_digest=inner_data.get("result_payload_digest"),
                result_payload_b64u=inner_data.get("result_payload_b64u"),
            )
        elif resp_type == "error":
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1(inner_data["reason_code"]),
                retryable=bool(inner_data["retryable"]),
                detail_ref=inner_data.get("detail_ref"),
            )
        else:
            raise C2ProtocolError(f"unknown_envelope_inner_type:{resp_type}")

    def _socket_transport(self, sock_path: str, data: bytes) -> bytes:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(10.0)
                try:
                    s.connect(sock_path)
                except ConnectionRefusedError as exc:
                    raise C2DaemonUnavailable(f"connection refused at {sock_path}") from exc
                except FileNotFoundError as exc:
                    raise C2DaemonUnavailable(f"socket not found at {sock_path}") from exc
                except OSError as exc:
                    raise C2DaemonUnavailable(f"socket connect error at {sock_path}: {exc}") from exc

                s.sendall(data)
                try:
                    return receive_frame(s, max_size=MAX_FRAME_SIZE)
                except ConnectionResetError as exc:
                    raise C2DaemonUnavailable(f"daemon closed connection: {exc}") from exc
                except ValueError as exc:
                    raise C2ProtocolError(f"frame violation from daemon: {exc}") from exc
        except socket.timeout as exc:
            raise C2ControlTimeout(f"socket operation timed out for {sock_path}") from exc

    def execute_action(
        self,
        action: C2ControlActionV1 | str,
        payload: dict[str, Any] | bytes | str,
        mission_id: str,
        subject_id: str,
        transaction_id: str,
        participant_id: str = "c2_daemon",
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:


        """Construct, sign, and execute a control action request."""
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0 or ttl_seconds > 300.0:
            raise ValueError(f"invalid ttl_seconds: {ttl_seconds}, must be 0 < ttl <= 300")

        act_enum = C2ControlActionV1(action) if isinstance(action, str) else action

        if isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = canonical_json_bytes(payload)

        b64u = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
        payload_digest = hashlib.sha256(payload_bytes).hexdigest()

        nonce = uuid.uuid4().hex
        expires_at = time.time() + ttl_seconds
        unsigned_auth = ParticipantControlAuthorizationV1(
            key_id=self.signer.key_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            mission_id=mission_id,
            subject_id=subject_id,
            action_id=act_enum.value,
            coordinator_revision=1,
            request_digest="init_digest",  # Signer will compute canonical request digest
            expires_at=expires_at,
            nonce=nonce,
            signature="",
        )

        request = ParticipantControlRequestV1(
            action=act_enum,
            authorization=unsigned_auth,
            payload_schema_id="schema:c2_control_v1",
            payload_digest=payload_digest,
            canonical_payload_b64u=b64u,
        )

        return self.send_request(request)

    def ping(
        self,
        mission_id: str = "mission_control",
        subject_id: str = "operator_root",
        transaction_id: str | None = None,
        participant_id: str | None = None,
    ) -> ParticipantControlReceiptV1:
        """Send a lightweight ping request to verify daemon liveness and protocol."""
        tx_id = transaction_id or f"tx_ping_{uuid.uuid4().hex[:8]}"
        part_id = participant_id or "participant_daemon"
        res = self.execute_action(
            action=C2ControlActionV1.PING,
            payload={"ping": True},
            mission_id=mission_id,
            subject_id=subject_id,
            transaction_id=tx_id,
            participant_id=part_id,
        )
        if isinstance(res, ParticipantControlReceiptV1):
            return res
        raise RuntimeError(f"Ping returned unexpected response: {res}")

    def close(self) -> None:
        self._is_closed = True

    @staticmethod
    def create_mock_loopback_transport(codec: ControlProtocolCodec | None = None) -> Callable[[bytes], bytes]:
        """Test helper: create in-memory loopback transport function."""
        resolved_codec = codec or ControlProtocolCodec()

        def _loopback(data: bytes) -> bytes:
            req = resolved_codec.decode_request(data)
            rcpt_dig = hashlib.sha256(f"mock:{req.authorization.transaction_id}".encode("utf-8")).hexdigest()
            receipt = ParticipantControlReceiptV1(
                transaction_id=req.authorization.transaction_id,
                participant_id=req.authorization.participant_id,
                action=req.action,
                resource_ref=f"ref:{req.authorization.participant_id}",
                resource_revision=1,
                receipt_ref=f"rcpt_{uuid.uuid4().hex[:8]}",
                receipt_digest=rcpt_dig,
                daemon_instance_id="daemon_inst_0",
                result_payload_schema_id=req.payload_schema_id,
                result_payload_digest=req.payload_digest,
                result_payload_b64u=req.canonical_payload_b64u,
            )
            return resolved_codec.encode_response(receipt)

        return _loopback


__all__ = [
    "C2ControlClient",
    "C2ControlError",
    "C2ControlTimeout",
    "C2DaemonUnavailable",
    "C2ProtocolError",
    "C2ResponseVerificationError",
    "DefaultC2ControlClient",
]

