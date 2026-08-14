"""C2 control client."""

from __future__ import annotations

import base64
import os
import socket
import struct
import time
import uuid
from typing import Any, Callable

from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
)
from core.c2.control_models import calculate_payload_digest, calculate_request_digest
from core.c2.control_protocol import ControlProtocolCodec
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
    ) -> None:
        self.signer = signer
        self.verifier = verifier
        self.codec = codec or ControlProtocolCodec()
        self.transport_handler = transport_handler
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
            sock_path = os.environ.get("OCTOPUS_C2_SOCKET", "/run/octopus/octopus-c2.sock")
            if not os.path.exists(sock_path) and os.path.exists("/tmp/octopus.sock"):
                sock_path = "/tmp/octopus.sock"
            if not os.path.exists(sock_path):
                raise C2DaemonUnavailable(f"C2 daemon socket not found at {sock_path}")
            resp_bytes = self._socket_transport(sock_path, encoded_frame)

        try:
            response = self.codec.decode_response(resp_bytes)
        except Exception as exc:
            raise C2ProtocolError(f"failed to decode daemon control response: {exc}") from exc

        return response

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
                chunks = []
                while True:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total = b"".join(chunks)
                    if len(total) >= 9 and total.startswith(b"CTRL1"):
                        payload_len = struct.unpack("!I", total[5:9])[0]
                        if len(total) >= 9 + payload_len:
                            return total[: 9 + payload_len]
                if not chunks:
                    raise C2DaemonUnavailable(f"daemon at {sock_path} closed connection without response")
                return b"".join(chunks)
        except socket.timeout as exc:
            raise C2ControlTimeout(f"socket operation timed out for {sock_path}") from exc

    def execute_action(
        self,
        action: C2ControlActionV1 | str,
        payload: dict[str, Any] | bytes | str,
        mission_id: str,
        subject_id: str,
        transaction_id: str,
        participant_id: str,
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Construct, sign, and execute a control action request."""
        act_enum = C2ControlActionV1(action) if isinstance(action, str) else action
        payload_digest = calculate_payload_digest(payload)

        if isinstance(payload, bytes):
            b64u = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
        elif isinstance(payload, str):
            b64u = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8").rstrip("=")
        else:
            import json

            raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            b64u = base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")

        nonce = uuid.uuid4().hex
        req_digest = calculate_request_digest(
            action=act_enum.value,
            payload_digest=payload_digest,
            mission_id=mission_id,
            subject_id=subject_id,
            nonce=nonce,
        )

        expires_at = time.time() + ttl_seconds
        unsigned_auth = ParticipantControlAuthorizationV1(
            key_id=self.signer.key_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            mission_id=mission_id,
            subject_id=subject_id,
            action_id=act_enum.value,
            coordinator_revision=1,
            request_digest=req_digest,
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

    def ping(self, mission_id: str, subject_id: str) -> ParticipantControlReceiptV1:
        """Send a PING control request and return receipt."""
        tx_id = f"tx_ping_{uuid.uuid4().hex[:8]}"
        part_id = "participant_daemon"
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
            receipt = ParticipantControlReceiptV1(
                transaction_id=req.authorization.transaction_id,
                participant_id=req.authorization.participant_id,
                action=req.action,
                resource_ref=f"ref:{req.authorization.participant_id}",
                resource_revision=1,
                receipt_ref=f"rcpt_{uuid.uuid4().hex[:8]}",
                receipt_digest="digest_ok",
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
