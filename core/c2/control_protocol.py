from __future__ import annotations

import json
import socket
import struct
from enum import Enum
from typing import Any, Protocol, runtime_checkable

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
from core.c2.control_models import canonical_json_bytes

FRAME_MAGIC = b"CTRL1"
MAX_FRAME_SIZE = 16_777_216  # 16 MB limit


def require_exact_int(value: object, name: str) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise ValueError(f"{name}_must_be_int")
    return value


def require_exact_str(value: object, name: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{name}_must_be_str")
    return value


def require_exact_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name}_must_be_bool")
    return value


def require_exact_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name}_must_be_number")
    return float(value)


def _raise_invalid_constant(value: str) -> None:
    raise ValueError(f"invalid_json_constant:{value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def strict_json_loads(data: str | bytes) -> Any:
    """Strict JSON parser rejecting NaN, Infinity, -Infinity and duplicate object keys."""
    raw = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    return json.loads(
        raw,
        parse_constant=_raise_invalid_constant,
        object_pairs_hook=_reject_duplicate_keys,
    )


def recv_exact(sock: socket.socket, byte_count: int) -> bytes:
    """Read exactly byte_count bytes from socket without quadratic copying."""
    result = bytearray()
    while len(result) < byte_count:
        chunk = sock.recv(byte_count - len(result))
        if not chunk:
            raise ConnectionResetError(f"truncated_stream: expected {byte_count} bytes, got {len(result)}")
        result.extend(chunk)
    return bytes(result)


def receive_frame(sock: socket.socket, max_size: int = MAX_FRAME_SIZE) -> bytes:
    """Read a complete CTRL1 frame from socket."""
    header = recv_exact(sock, len(FRAME_MAGIC) + 4)
    if header[: len(FRAME_MAGIC)] != FRAME_MAGIC:
        raise ValueError(f"invalid_control_magic: {header[: len(FRAME_MAGIC)]!r}")
    payload_len = struct.unpack("!I", header[len(FRAME_MAGIC) :])[0]
    if payload_len > max_size:
        raise ValueError(f"control_frame_too_large: {payload_len} exceeds {max_size}")
    payload = recv_exact(sock, payload_len)
    return header + payload


@runtime_checkable
class BoundedFrameReaderV1(Protocol):
    @property
    def remaining_bytes(self) -> int: ...
    def read_exact_into(self, destination: bytearray, *, byte_count: int) -> None: ...
    def require_eof(self) -> None: ...


class MemoryFrameReaderV1:
    """In-memory implementation of BoundedFrameReaderV1."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def remaining_bytes(self) -> int:
        return max(0, len(self._data) - self._offset)

    def read_exact_into(self, destination: bytearray, *, byte_count: int) -> None:
        if byte_count > self.remaining_bytes:
            raise ValueError(f"Requested {byte_count} bytes, but only {self.remaining_bytes} remaining")
        chunk = self._data[self._offset : self._offset + byte_count]
        self._offset += byte_count
        destination.extend(chunk)

    def require_eof(self) -> None:
        if self.remaining_bytes > 0:
            raise ValueError(f"Expected EOF, but {self.remaining_bytes} bytes remain")


class ControlProtocolCodec:
    """Codec for serializing/deserializing control messages over wire frames."""

    def encode_request(self, request: ParticipantControlRequestV1) -> bytes:
        """Encode request into framed bytes."""
        auth_dict = {
            "action_id": request.authorization.action_id,
            "coordinator_revision": request.authorization.coordinator_revision,
            "expires_at": request.authorization.expires_at,
            "key_id": request.authorization.key_id,
            "mission_id": request.authorization.mission_id,
            "nonce": request.authorization.nonce,
            "participant_id": request.authorization.participant_id,
            "request_digest": request.authorization.request_digest,
            "signature": request.authorization.signature,
            "subject_id": request.authorization.subject_id,
            "transaction_id": request.authorization.transaction_id,
        }
        req_dict = {
            "action": request.action.value if isinstance(request.action, Enum) else str(request.action),
            "authorization": auth_dict,
            "canonical_payload_b64u": request.canonical_payload_b64u,
            "expected_resource_revision": request.expected_resource_revision,
            "payload_digest": request.payload_digest,
            "payload_schema_id": request.payload_schema_id,
            "prior_receipt_digest": request.prior_receipt_digest,
            "prior_receipt_ref": request.prior_receipt_ref,
        }
        payload_bytes = canonical_json_bytes(req_dict)
        header = FRAME_MAGIC + struct.pack("!I", len(payload_bytes))
        return header + payload_bytes

    def decode_request(self, reader_or_data: BoundedFrameReaderV1 | bytes) -> ParticipantControlRequestV1:
        """Decode request from reader or bytes with strict type checking."""
        reader = (
            MemoryFrameReaderV1(reader_or_data) if isinstance(reader_or_data, (bytes, bytearray)) else reader_or_data
        )

        buf = bytearray()
        reader.read_exact_into(buf, byte_count=len(FRAME_MAGIC) + 4)
        magic = bytes(buf[: len(FRAME_MAGIC)])
        if magic != FRAME_MAGIC:
            raise ValueError(f"Invalid frame magic: {magic!r}")
        payload_len = struct.unpack("!I", buf[len(FRAME_MAGIC) :])[0]
        if payload_len > MAX_FRAME_SIZE:
            raise ValueError(f"Frame size {payload_len} exceeds limit {MAX_FRAME_SIZE}")

        payload_buf = bytearray()
        reader.read_exact_into(payload_buf, byte_count=payload_len)
        reader.require_eof()
        data = strict_json_loads(bytes(payload_buf))

        if not isinstance(data, dict):
            raise ValueError("request payload must be a JSON object")

        auth_data = data.get("authorization")
        if not isinstance(auth_data, dict):
            raise ValueError("missing authorization object in control request")

        exp_rev = data.get("expected_resource_revision")
        if exp_rev is not None:
            require_exact_int(exp_rev, "expected_resource_revision")

        auth = ParticipantControlAuthorizationV1(
            key_id=require_exact_str(auth_data.get("key_id"), "key_id"),
            transaction_id=require_exact_str(auth_data.get("transaction_id"), "transaction_id"),
            participant_id=require_exact_str(auth_data.get("participant_id"), "participant_id"),
            mission_id=require_exact_str(auth_data.get("mission_id"), "mission_id"),
            subject_id=require_exact_str(auth_data.get("subject_id"), "subject_id"),
            action_id=require_exact_str(auth_data.get("action_id"), "action_id"),
            coordinator_revision=require_exact_int(auth_data.get("coordinator_revision"), "coordinator_revision"),
            request_digest=require_exact_str(auth_data.get("request_digest"), "request_digest"),
            expires_at=require_exact_number(auth_data.get("expires_at"), "expires_at"),
            nonce=require_exact_str(auth_data.get("nonce"), "nonce"),
            signature=require_exact_str(auth_data.get("signature"), "signature"),
        )

        return ParticipantControlRequestV1(
            action=C2ControlActionV1(require_exact_str(data.get("action"), "action")),
            authorization=auth,
            payload_schema_id=require_exact_str(data.get("payload_schema_id"), "payload_schema_id"),
            payload_digest=require_exact_str(data.get("payload_digest"), "payload_digest"),
            canonical_payload_b64u=require_exact_str(data.get("canonical_payload_b64u"), "canonical_payload_b64u"),
            prior_receipt_ref=data.get("prior_receipt_ref"),
            prior_receipt_digest=data.get("prior_receipt_digest"),
            expected_resource_revision=exp_rev,
        )

    def encode_response(
        self,
        response: ParticipantControlReceiptV1
        | ParticipantControlQuerySnapshotV1
        | BoundedControlErrorV1
        | SignedControlResponseV1,
    ) -> bytes:
        """Encode response into framed bytes."""
        if isinstance(response, SignedControlResponseV1):
            res_dict = {
                "boot_instance_id": response.boot_instance_id,
                "daemon_generation": response.daemon_generation,
                "daemon_instance_id": response.daemon_instance_id,
                "issued_at_ms": response.issued_at_ms,
                "key_id": response.key_id,
                "protocol_version": response.protocol_version,
                "request_digest": response.request_digest,
                "request_nonce": response.request_nonce,
                "response_digest": response.response_digest,
                "response_payload_b64u": response.response_payload_b64u,
                "response_type": response.response_type,
                "service_id": response.service_id,
                "signature": response.signature,
                "type": "signed_envelope",
            }
        elif isinstance(response, ParticipantControlReceiptV1):
            res_dict = {
                "action": response.action.value if hasattr(response.action, "value") else str(response.action),
                "daemon_instance_id": response.daemon_instance_id,
                "participant_id": response.participant_id,
                "receipt_digest": response.receipt_digest,
                "receipt_ref": response.receipt_ref,
                "resource_ref": response.resource_ref,
                "resource_revision": response.resource_revision,
                "result_payload_b64u": response.result_payload_b64u,
                "result_payload_digest": response.result_payload_digest,
                "result_payload_schema_id": response.result_payload_schema_id,
                "transaction_id": response.transaction_id,
                "type": "receipt",
            }
        elif isinstance(response, ParticipantControlQuerySnapshotV1):
            res_dict = {
                "participant_id": response.participant_id,
                "phase": response.phase.value if hasattr(response.phase, "value") else str(response.phase),
                "receipt_digest": response.receipt_digest,
                "receipt_ref": response.receipt_ref,
                "resource_ref": response.resource_ref,
                "resource_revision": response.resource_revision,
                "result_payload_b64u": response.result_payload_b64u,
                "result_payload_digest": response.result_payload_digest,
                "result_payload_schema_id": response.result_payload_schema_id,
                "snapshot_digest": response.snapshot_digest,
                "transaction_id": response.transaction_id,
                "type": "snapshot",
            }
        elif isinstance(response, BoundedControlErrorV1):
            res_dict = {
                "detail_ref": response.detail_ref,
                "reason_code": response.reason_code.value
                if hasattr(response.reason_code, "value")
                else str(response.reason_code),
                "retryable": response.retryable,
                "type": "error",
            }
        else:
            raise TypeError(f"Unsupported response type: {type(response)}")

        payload_bytes = canonical_json_bytes(res_dict)
        header = FRAME_MAGIC + struct.pack("!I", len(payload_bytes))
        return header + payload_bytes

    def decode_response(
        self, reader_or_data: BoundedFrameReaderV1 | bytes
    ) -> (
        ParticipantControlReceiptV1
        | ParticipantControlQuerySnapshotV1
        | BoundedControlErrorV1
        | SignedControlResponseV1
    ):
        """Decode response from reader or bytes with strict type checking."""
        reader = (
            MemoryFrameReaderV1(reader_or_data) if isinstance(reader_or_data, (bytes, bytearray)) else reader_or_data
        )

        buf = bytearray()
        reader.read_exact_into(buf, byte_count=len(FRAME_MAGIC) + 4)
        magic = bytes(buf[: len(FRAME_MAGIC)])
        if magic != FRAME_MAGIC:
            raise ValueError(f"Invalid frame magic: {magic!r}")
        payload_len = struct.unpack("!I", buf[len(FRAME_MAGIC) :])[0]
        if payload_len > MAX_FRAME_SIZE:
            raise ValueError(f"Frame size {payload_len} exceeds limit {MAX_FRAME_SIZE}")

        payload_buf = bytearray()
        reader.read_exact_into(payload_buf, byte_count=payload_len)
        reader.require_eof()
        data = strict_json_loads(bytes(payload_buf))

        if not isinstance(data, dict):
            raise ValueError("response payload must be a JSON object")

        msg_type = data.get("type")
        if msg_type == "signed_envelope":
            return SignedControlResponseV1(
                protocol_version=require_exact_str(data.get("protocol_version"), "protocol_version"),
                daemon_instance_id=require_exact_str(data.get("daemon_instance_id"), "daemon_instance_id"),
                daemon_generation=require_exact_str(data.get("daemon_generation"), "daemon_generation"),
                service_id=str(data.get("service_id", "")),
                boot_instance_id=str(data.get("boot_instance_id", "")),
                request_digest=require_exact_str(data.get("request_digest"), "request_digest"),
                request_nonce=require_exact_str(data.get("request_nonce"), "request_nonce"),
                response_type=require_exact_str(data.get("response_type"), "response_type"),
                response_payload_b64u=require_exact_str(data.get("response_payload_b64u"), "response_payload_b64u"),
                response_digest=require_exact_str(data.get("response_digest"), "response_digest"),
                issued_at_ms=require_exact_int(data.get("issued_at_ms"), "issued_at_ms"),
                key_id=require_exact_str(data.get("key_id"), "key_id"),
                signature=require_exact_str(data.get("signature"), "signature"),
            )
        elif msg_type == "receipt":
            res_rev = data.get("resource_revision")
            if res_rev is not None:
                require_exact_int(res_rev, "resource_revision")
            return ParticipantControlReceiptV1(
                transaction_id=require_exact_str(data.get("transaction_id"), "transaction_id"),
                participant_id=require_exact_str(data.get("participant_id"), "participant_id"),
                action=C2ControlActionV1(require_exact_str(data.get("action"), "action")),
                resource_ref=data.get("resource_ref"),
                resource_revision=res_rev,
                receipt_ref=require_exact_str(data.get("receipt_ref"), "receipt_ref"),
                receipt_digest=require_exact_str(data.get("receipt_digest"), "receipt_digest"),
                daemon_instance_id=require_exact_str(data.get("daemon_instance_id"), "daemon_instance_id"),
                result_payload_schema_id=data.get("result_payload_schema_id"),
                result_payload_digest=data.get("result_payload_digest"),
                result_payload_b64u=data.get("result_payload_b64u"),
            )
        elif msg_type == "snapshot":
            res_rev = data.get("resource_revision")
            if res_rev is not None:
                require_exact_int(res_rev, "resource_revision")
            return ParticipantControlQuerySnapshotV1(
                transaction_id=require_exact_str(data.get("transaction_id"), "transaction_id"),
                participant_id=require_exact_str(data.get("participant_id"), "participant_id"),
                resource_ref=data.get("resource_ref"),
                resource_revision=res_rev,
                phase=ParticipantControlPhaseV1(require_exact_str(data.get("phase"), "phase")),
                receipt_ref=data.get("receipt_ref"),
                receipt_digest=data.get("receipt_digest"),
                snapshot_digest=require_exact_str(data.get("snapshot_digest"), "snapshot_digest"),
                result_payload_schema_id=data.get("result_payload_schema_id"),
                result_payload_digest=data.get("result_payload_digest"),
                result_payload_b64u=data.get("result_payload_b64u"),
            )
        elif msg_type == "error":
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1(require_exact_str(data.get("reason_code"), "reason_code")),
                retryable=require_exact_bool(data.get("retryable"), "retryable"),
                detail_ref=data.get("detail_ref"),
            )
        else:
            raise ValueError(f"Unknown message type in frame: {msg_type}")


__all__ = [
    "FRAME_MAGIC",
    "MAX_FRAME_SIZE",
    "BoundedFrameReaderV1",
    "ControlProtocolCodec",
    "MemoryFrameReaderV1",
    "receive_frame",
    "recv_exact",
    "require_exact_bool",
    "require_exact_int",
    "require_exact_number",
    "require_exact_str",
    "strict_json_loads",
]
