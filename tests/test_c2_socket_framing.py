"""Tests for stream socket framing, chunking, coalescing, timeout, and authentication in C2 control daemon."""

from __future__ import annotations

import base64
import socket
import struct
import threading
import time
import uuid

import pytest

from core.c2 import daemon
from core.c2.control_commands import (
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlQuerySnapshotV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
    SignedControlResponseV2,
    UnsignedParticipantControlAuthorizationV2,
    UnsignedParticipantControlRequestV2,
)
from core.c2.control_models import (
    calculate_schema_bound_payload_digest,
    strict_b64url_decode,
)
from core.c2.control_protocol import FRAME_MAGIC, ControlProtocolCodec, strict_json_loads
from core.c2.control_signing import ControlSignerV2

pytestmark = pytest.mark.unit

TEST_KEY_SECRET = b"01234567890123456789012345678901"


@pytest.fixture(autouse=True)
def setup_framing_test_key():
    daemon.register_control_key("test_key", TEST_KEY_SECRET)
    yield


def _create_signed_request(
    action: C2ControlAction = C2ControlAction.PING,
    ttl_seconds: float = 60.0,
    action_id: str | None = None,
    nonce: str | None = None,
) -> tuple[ParticipantControlRequestV2, bytes]:
    signer = ControlSignerV2("test_key", TEST_KEY_SECRET)
    codec = ControlProtocolCodec()
    act_id = action_id if action_id is not None else action.value
    n = nonce if nonce is not None else uuid.uuid4().hex
    now_ms = int(time.time() * 1000)
    p_bytes = b"{}"
    p_b64u = base64.urlsafe_b64encode(p_bytes).decode("ascii").rstrip("=")
    p_dig = calculate_schema_bound_payload_digest("schema:test", p_bytes)

    unsigned_auth = UnsignedParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="test_key",
        transaction_id=f"tx_{uuid.uuid4().hex[:8]}",
        participant_id="part_test",
        mission_id="m_test",
        subject_id="s_test",
        action_id=act_id,
        coordinator_revision=1,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + int(ttl_seconds * 1000),
        nonce=n,
    )
    unsigned_req = UnsignedParticipantControlRequestV2(
        action=action,
        authorization=unsigned_auth,
        payload_schema_id="schema:test",
        payload_digest=p_dig,
        canonical_payload_b64u=p_b64u,
    )
    signed = signer.sign_participant_request(unsigned_req)
    encoded = codec.encode_request(signed)
    return signed, encoded


def _recv_frame(sock: socket.socket) -> bytes:
    """Helper to read one complete framed response from stream socket."""
    hdr = bytearray()
    while len(hdr) < 9:
        chunk = sock.recv(9 - len(hdr))
        if not chunk:
            break
        hdr.extend(chunk)
    if len(hdr) < 9:
        raise EOFError(f"incomplete header received: {len(hdr)} bytes")
    if not hdr.startswith(FRAME_MAGIC):
        raise ValueError(f"invalid frame magic: {hdr[:5]}")
    payload_len = struct.unpack("!I", hdr[5:9])[0]
    payload = bytearray()
    while len(payload) < payload_len:
        chunk = sock.recv(min(8192, payload_len - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) < payload_len:
        raise EOFError(f"incomplete payload received: {len(payload)} of {payload_len}")
    return bytes(hdr + payload)


def _unpack_response(
    raw_resp: bytes, codec: ControlProtocolCodec
) -> ParticipantControlReceiptV2 | ParticipantControlQuerySnapshotV2 | BoundedControlErrorV2 | SignedControlResponseV2:
    resp = codec.decode_response(raw_resp)
    if hasattr(resp, "response_payload_b64u") and resp.response_payload_b64u:
        payload_bytes = strict_b64url_decode(resp.response_payload_b64u)
        data = strict_json_loads(payload_bytes)
        msg_type = data.get("type")
        if msg_type == "receipt":
            return ParticipantControlReceiptV2(
                transaction_id=data["transaction_id"],
                participant_id=data["participant_id"],
                action=C2ControlAction(data["action"]),
                resource_ref=data.get("resource_ref"),
                resource_revision=data.get("resource_revision"),
                receipt_ref=data["receipt_ref"],
                receipt_digest=data["receipt_digest"],
                daemon_instance_id=data.get("daemon_instance_id", "inst_0"),
                result_payload_schema_id=data.get("result_payload_schema_id"),
                result_payload_digest=data.get("result_payload_digest"),
                result_payload_b64u=data.get("result_payload_b64u"),
            )
        elif msg_type == "error":
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2(data["reason_code"]),
                retryable=bool(data.get("retryable", False)),
                detail_ref=data.get("detail_ref", ""),
            )

    return resp


def test_socket_framing_fragmented_byte_by_byte():
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(3.0)
    server_sock.settimeout(3.0)
    codec = ControlProtocolCodec()

    handler_thread = threading.Thread(target=daemon.handle_client, args=(server_sock,), daemon=True)
    handler_thread.start()

    try:
        _, encoded = _create_signed_request(action=C2ControlAction.PING)

        # Send byte by byte to simulate extreme network fragmentation
        for i in range(len(encoded)):
            client_sock.sendall(encoded[i : i + 1])
            time.sleep(0.001)

        raw_resp = _recv_frame(client_sock)
        resp = _unpack_response(raw_resp, codec)
        assert isinstance(resp, ParticipantControlReceiptV2)
        assert resp.action == C2ControlAction.PING
        assert resp.daemon_instance_id.startswith("c2-daemon-")
    finally:
        client_sock.close()
        handler_thread.join(timeout=1.0)


def test_socket_framing_coalesced_frames():
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(3.0)
    server_sock.settimeout(3.0)
    codec = ControlProtocolCodec()

    handler_thread = threading.Thread(target=daemon.handle_client, args=(server_sock,), daemon=True)
    handler_thread.start()

    try:
        _, encoded1 = _create_signed_request(action=C2ControlAction.PING)
        _, encoded2 = _create_signed_request(action=C2ControlAction.READINESS)

        # Send two concatenated frames at once
        client_sock.sendall(encoded1 + encoded2)

        raw_resp1 = _recv_frame(client_sock)
        resp1 = _unpack_response(raw_resp1, codec)
        assert isinstance(resp1, ParticipantControlReceiptV2)
        assert resp1.action == C2ControlAction.PING

        raw_resp2 = _recv_frame(client_sock)
        resp2 = _unpack_response(raw_resp2, codec)
        assert isinstance(resp2, ParticipantControlReceiptV2)
        assert resp2.action == C2ControlAction.READINESS
    finally:
        client_sock.close()
        handler_thread.join(timeout=1.0)


def test_socket_framing_oversized_declared_length_rejected():
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(3.0)
    server_sock.settimeout(3.0)

    handler_thread = threading.Thread(target=daemon.handle_client, args=(server_sock,), daemon=True)
    handler_thread.start()

    try:
        # Declare 20 MiB frame (> 1 MiB max)
        header = FRAME_MAGIC + struct.pack("!I", 20 * 1024 * 1024)
        client_sock.sendall(header)

        # Connection should fail closed (EOFError)
        with pytest.raises(EOFError):
            _recv_frame(client_sock)
    finally:
        client_sock.close()
        handler_thread.join(timeout=1.0)


def test_socket_framing_rejects_expired_authorization():
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(3.0)
    server_sock.settimeout(3.0)
    codec = ControlProtocolCodec()

    handler_thread = threading.Thread(target=daemon.handle_client, args=(server_sock,), daemon=True)
    handler_thread.start()

    try:
        signer = ControlSignerV2("test_key", TEST_KEY_SECRET)
        now_ms = int(time.time() * 1000)
        unsigned_auth = UnsignedParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id="test_key",
            transaction_id="tx_exp_socket",
            participant_id="part_test",
            mission_id="m_test",
            subject_id="s_test",
            action_id="ping",
            coordinator_revision=1,
            issued_at_ms=now_ms - 20000,
            expires_at_ms=now_ms - 10000,
            nonce="nonce_expired_socket_1",
        )
        p_bytes = b"{}"
        p_b64u = base64.urlsafe_b64encode(p_bytes).decode("ascii").rstrip("=")
        p_dig = calculate_schema_bound_payload_digest("schema:test", p_bytes)
        unsigned_req = UnsignedParticipantControlRequestV2(
            action=C2ControlAction.PING,
            authorization=unsigned_auth,
            payload_schema_id="schema:test",
            payload_digest=p_dig,
            canonical_payload_b64u=p_b64u,
        )
        signed = signer.sign_participant_request(unsigned_req)
        encoded = codec.encode_request(signed)

        client_sock.sendall(encoded)

        raw_resp = _recv_frame(client_sock)
        resp = _unpack_response(raw_resp, codec)
        assert isinstance(resp, BoundedControlErrorV2)
        assert resp.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED
        assert resp.detail_ref == "authorization_expired"
    finally:
        client_sock.close()
        handler_thread.join(timeout=1.0)


def test_socket_framing_rejects_nonce_replay():
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(3.0)
    server_sock.settimeout(3.0)
    codec = ControlProtocolCodec()

    handler_thread = threading.Thread(target=daemon.handle_client, args=(server_sock,), daemon=True)
    handler_thread.start()

    try:
        fixed_nonce = "fixed_nonce_12345678"
        _, encoded1 = _create_signed_request(action=C2ControlAction.PING, nonce=fixed_nonce)
        _, encoded2 = _create_signed_request(action=C2ControlAction.PING, nonce=fixed_nonce)

        client_sock.sendall(encoded1)
        raw_resp1 = _recv_frame(client_sock)
        resp1 = _unpack_response(raw_resp1, codec)
        assert isinstance(resp1, ParticipantControlReceiptV2)

        # Second request with same nonce must be rejected
        client_sock.sendall(encoded2)
        raw_resp2 = _recv_frame(client_sock)
        resp2 = _unpack_response(raw_resp2, codec)
        assert isinstance(resp2, BoundedControlErrorV2)
        assert resp2.reason_code == C2ControlErrorCodeV2.REPLAY
        assert resp2.detail_ref == "nonce_replayed"
    finally:
        client_sock.close()
        handler_thread.join(timeout=1.0)


def test_socket_framing_rejects_action_mismatch():
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(3.0)
    server_sock.settimeout(3.0)
    codec = ControlProtocolCodec()

    handler_thread = threading.Thread(target=daemon.handle_client, args=(server_sock,), daemon=True)
    handler_thread.start()

    try:
        _, encoded = _create_signed_request(action=C2ControlAction.PING, action_id="c2_action_different")
        client_sock.sendall(encoded)

        raw_resp = _recv_frame(client_sock)
        resp = _unpack_response(raw_resp, codec)
        assert isinstance(resp, BoundedControlErrorV2)
        assert resp.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED
        assert resp.detail_ref == "action_mismatch"
    finally:
        client_sock.close()
        handler_thread.join(timeout=1.0)


def test_socket_framing_rejects_unsupported_action():
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(3.0)
    server_sock.settimeout(3.0)
    codec = ControlProtocolCodec()

    handler_thread = threading.Thread(target=daemon.handle_client, args=(server_sock,), daemon=True)
    handler_thread.start()

    try:
        _, encoded = _create_signed_request(action=C2ControlAction.RESERVE_ENROLLMENT_FOR_BUILD)
        client_sock.sendall(encoded)

        raw_resp = _recv_frame(client_sock)
        resp = _unpack_response(raw_resp, codec)
        assert isinstance(resp, BoundedControlErrorV2)
        assert resp.reason_code == C2ControlErrorCodeV2.UNAVAILABLE
        assert resp.detail_ref == "unsupported_control_action"
    finally:
        client_sock.close()
        handler_thread.join(timeout=1.0)
