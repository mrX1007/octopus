"""Control protocol."""
from __future__ import annotations

import json
import struct
from enum import Enum
from typing import Any, Protocol, runtime_checkable
from core.c2.control_commands import (
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
    ParticipantControlReceiptV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlPhaseV1,
    BoundedControlErrorV1,
)

FRAME_MAGIC = b"CTRL1"
MAX_FRAME_SIZE = 16_777_216  # 16 MB limit


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
            raise ValueError(
                f"Requested {byte_count} bytes, but only {self.remaining_bytes} remaining"
            )
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
            "key_id": request.authorization.key_id,
            "transaction_id": request.authorization.transaction_id,
            "participant_id": request.authorization.participant_id,
            "mission_id": request.authorization.mission_id,
            "subject_id": request.authorization.subject_id,
            "action_id": request.authorization.action_id,
            "coordinator_revision": request.authorization.coordinator_revision,
            "request_digest": request.authorization.request_digest,
            "expires_at": request.authorization.expires_at,
            "nonce": request.authorization.nonce,
            "signature": request.authorization.signature,
        }
        req_dict = {
            "action": request.action.value if isinstance(request.action, Enum) else str(request.action),
            "authorization": auth_dict,
            "payload_schema_id": request.payload_schema_id,
            "payload_digest": request.payload_digest,
            "canonical_payload_b64u": request.canonical_payload_b64u,
            "prior_receipt_ref": request.prior_receipt_ref,
            "prior_receipt_digest": request.prior_receipt_digest,
            "expected_resource_revision": request.expected_resource_revision,
        }
        payload_bytes = json.dumps(req_dict).encode("utf-8")
        header = FRAME_MAGIC + struct.pack(">I", len(payload_bytes))
        return header + payload_bytes

    def decode_request(
        self, reader_or_data: BoundedFrameReaderV1 | bytes
    ) -> ParticipantControlRequestV1:
        """Decode request from reader or bytes."""
        if isinstance(reader_or_data, bytes):
            reader = MemoryFrameReaderV1(reader_or_data)
        else:
            reader = reader_or_data

        buf = bytearray()
        reader.read_exact_into(buf, byte_count=len(FRAME_MAGIC) + 4)
        magic = bytes(buf[: len(FRAME_MAGIC)])
        if magic != FRAME_MAGIC:
            raise ValueError(f"Invalid frame magic: {magic!r}")
        payload_len = struct.unpack(">I", buf[len(FRAME_MAGIC) :])[0]
        if payload_len > MAX_FRAME_SIZE:
            raise ValueError(f"Frame size {payload_len} exceeds limit {MAX_FRAME_SIZE}")

        payload_buf = bytearray()
        reader.read_exact_into(payload_buf, byte_count=payload_len)
        data = json.loads(payload_buf.decode("utf-8"))

        auth_data = data["authorization"]
        auth = ParticipantControlAuthorizationV1(
            key_id=auth_data["key_id"],
            transaction_id=auth_data["transaction_id"],
            participant_id=auth_data["participant_id"],
            mission_id=auth_data["mission_id"],
            subject_id=auth_data["subject_id"],
            action_id=auth_data["action_id"],
            coordinator_revision=int(auth_data["coordinator_revision"]),
            request_digest=auth_data["request_digest"],
            expires_at=float(auth_data["expires_at"]),
            nonce=auth_data["nonce"],
            signature=auth_data["signature"],
        )

        return ParticipantControlRequestV1(
            action=C2ControlActionV1(data["action"]),
            authorization=auth,
            payload_schema_id=data["payload_schema_id"],
            payload_digest=data["payload_digest"],
            canonical_payload_b64u=data["canonical_payload_b64u"],
            prior_receipt_ref=data.get("prior_receipt_ref"),
            prior_receipt_digest=data.get("prior_receipt_digest"),
            expected_resource_revision=data.get("expected_resource_revision"),
        )

    def encode_response(
        self,
        response: ParticipantControlReceiptV1
        | ParticipantControlQuerySnapshotV1
        | BoundedControlErrorV1,
    ) -> bytes:
        """Encode response into framed bytes."""
        if isinstance(response, ParticipantControlReceiptV1):
            res_dict = {
                "type": "receipt",
                "transaction_id": response.transaction_id,
                "participant_id": response.participant_id,
                "action": response.action.value if hasattr(response.action, "value") else str(response.action),
                "resource_ref": response.resource_ref,
                "resource_revision": response.resource_revision,
                "receipt_ref": response.receipt_ref,
                "receipt_digest": response.receipt_digest,
                "daemon_instance_id": response.daemon_instance_id,
                "result_payload_schema_id": response.result_payload_schema_id,
                "result_payload_digest": response.result_payload_digest,
                "result_payload_b64u": response.result_payload_b64u,
            }
        elif isinstance(response, ParticipantControlQuerySnapshotV1):
            res_dict = {
                "type": "snapshot",
                "transaction_id": response.transaction_id,
                "participant_id": response.participant_id,
                "resource_ref": response.resource_ref,
                "resource_revision": response.resource_revision,
                "phase": response.phase.value if hasattr(response.phase, "value") else str(response.phase),
                "receipt_ref": response.receipt_ref,
                "receipt_digest": response.receipt_digest,
                "snapshot_digest": response.snapshot_digest,
                "result_payload_schema_id": response.result_payload_schema_id,
                "result_payload_digest": response.result_payload_digest,
                "result_payload_b64u": response.result_payload_b64u,
            }
        elif isinstance(response, BoundedControlErrorV1):
            res_dict = {
                "type": "error",
                "reason_code": response.reason_code.value if hasattr(response.reason_code, "value") else str(response.reason_code),
                "retryable": response.retryable,
                "detail_ref": response.detail_ref,
            }
        else:
            raise TypeError(f"Unsupported response type: {type(response)}")

        payload_bytes = json.dumps(res_dict).encode("utf-8")
        header = FRAME_MAGIC + struct.pack(">I", len(payload_bytes))
        return header + payload_bytes

    def decode_response(
        self, reader_or_data: BoundedFrameReaderV1 | bytes
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Decode response from reader or bytes."""
        if isinstance(reader_or_data, bytes):
            reader = MemoryFrameReaderV1(reader_or_data)
        else:
            reader = reader_or_data

        buf = bytearray()
        reader.read_exact_into(buf, byte_count=len(FRAME_MAGIC) + 4)
        magic = bytes(buf[: len(FRAME_MAGIC)])
        if magic != FRAME_MAGIC:
            raise ValueError(f"Invalid frame magic: {magic!r}")
        payload_len = struct.unpack(">I", buf[len(FRAME_MAGIC) :])[0]
        if payload_len > MAX_FRAME_SIZE:
            raise ValueError(f"Frame size {payload_len} exceeds limit {MAX_FRAME_SIZE}")

        payload_buf = bytearray()
        reader.read_exact_into(payload_buf, byte_count=payload_len)
        data = json.loads(payload_buf.decode("utf-8"))

        msg_type = data.get("type")
        if msg_type == "receipt":
            return ParticipantControlReceiptV1(
                transaction_id=data["transaction_id"],
                participant_id=data["participant_id"],
                action=C2ControlActionV1(data["action"]),
                resource_ref=data.get("resource_ref"),
                resource_revision=data.get("resource_revision"),
                receipt_ref=data["receipt_ref"],
                receipt_digest=data["receipt_digest"],
                daemon_instance_id=data["daemon_instance_id"],
                result_payload_schema_id=data.get("result_payload_schema_id"),
                result_payload_digest=data.get("result_payload_digest"),
                result_payload_b64u=data.get("result_payload_b64u"),
            )
        elif msg_type == "snapshot":
            return ParticipantControlQuerySnapshotV1(
                transaction_id=data["transaction_id"],
                participant_id=data["participant_id"],
                resource_ref=data.get("resource_ref"),
                resource_revision=data.get("resource_revision"),
                phase=ParticipantControlPhaseV1(data["phase"]),
                receipt_ref=data.get("receipt_ref"),
                receipt_digest=data.get("receipt_digest"),
                snapshot_digest=data["snapshot_digest"],
                result_payload_schema_id=data.get("result_payload_schema_id"),
                result_payload_digest=data.get("result_payload_digest"),
                result_payload_b64u=data.get("result_payload_b64u"),
            )
        elif msg_type == "error":
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1(data["reason_code"]),
                retryable=bool(data["retryable"]),
                detail_ref=data.get("detail_ref"),
            )
        else:
            raise ValueError(f"Unknown message type in frame: {msg_type}")

