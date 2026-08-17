"""Tests for C2 control protocol codec and frame reader."""

from __future__ import annotations

import time

import pytest

from core.c2.control_commands import (
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.control_protocol import (
    FRAME_MAGIC,
    ControlProtocolCodec,
    MemoryFrameReaderV1,
)

pytestmark = pytest.mark.unit


def test_memory_frame_reader_basic():
    data = b"Hello World"
    reader = MemoryFrameReaderV1(data)
    assert reader.remaining_bytes == 11
    buf = bytearray()
    reader.read_exact_into(buf, byte_count=5)
    assert bytes(buf) == b"Hello"
    assert reader.remaining_bytes == 6

    buf2 = bytearray()
    reader.read_exact_into(buf2, byte_count=6)
    assert bytes(buf2) == b" World"
    assert reader.remaining_bytes == 0
    reader.require_eof()


def test_memory_frame_reader_errors():
    reader = MemoryFrameReaderV1(b"123")
    buf = bytearray()
    with pytest.raises(ValueError, match="Requested 5 bytes"):
        reader.read_exact_into(buf, byte_count=5)

    reader2 = MemoryFrameReaderV1(b"123")
    buf2 = bytearray()
    reader2.read_exact_into(buf2, byte_count=2)
    with pytest.raises(ValueError, match="Expected EOF"):
        reader2.require_eof()


def test_control_protocol_encode_decode_request():
    codec = ControlProtocolCodec()
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id="tx1",
        participant_id="p1",
        mission_id="m1",
        subject_id="s1",
        action_id="ping",
        coordinator_revision=1,
        request_digest="a" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_12345678901234",
        signature="c" * 86,
    )
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema1",
        payload_digest="d" * 64,
        canonical_payload_b64u="eyJwaW5nIjp0cnVlfQ",
    )

    encoded = codec.encode_request(req)
    assert encoded.startswith(FRAME_MAGIC)

    decoded = codec.decode_request(encoded)
    assert decoded.action == C2ControlAction.PING
    assert decoded.authorization.key_id == "k1"
    assert decoded.authorization.transaction_id == "tx1"
    assert decoded.payload_digest == "d" * 64


def test_control_protocol_encode_decode_responses():
    codec = ControlProtocolCodec()

    receipt = ParticipantControlReceiptV2(
        transaction_id="tx2",
        participant_id="p2",
        action=C2ControlAction.READINESS,
        resource_ref="res2",
        resource_revision=1,
        receipt_ref="rcpt2",
        receipt_digest="b" * 64,
        daemon_instance_id="d1",
        result_payload_schema_id=None,
        result_payload_digest=None,
        result_payload_b64u=None,
    )
    enc_rcpt = codec.encode_response(receipt)
    dec_rcpt = codec.decode_response(enc_rcpt)
    assert isinstance(dec_rcpt, ParticipantControlReceiptV2)
    assert dec_rcpt.transaction_id == "tx2"
    assert dec_rcpt.action == C2ControlAction.READINESS

    error = BoundedControlErrorV2(
        reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
        retryable=True,
        detail_ref="conflict",
    )
    enc_err = codec.encode_response(error)
    dec_err = codec.decode_response(enc_err)
    assert isinstance(dec_err, BoundedControlErrorV2)
    assert dec_err.reason_code == C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT
    assert dec_err.retryable is True
