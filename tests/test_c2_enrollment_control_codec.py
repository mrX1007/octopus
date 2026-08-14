"""Tests for enrollment control codec and wire serialization (§15.7)."""

from __future__ import annotations

import pytest
from core.c2.enrollment_control_codec import EnrollmentControlCodec
from core.c2.enrollment_control_models import EnrollmentControlPayloadV1

pytestmark = pytest.mark.unit


def test_enrollment_control_codec_roundtrip():
    payload = EnrollmentControlPayloadV1(
        profile_id="prof-1",
        channel_ref="chan-1",
        target_id="tgt-1",
        max_uses=1,
        expires_in_seconds=1800.0,
        operator_id="op-1",
        subject_id="sub-1",
        mission_id="m-1",
    )
    raw_bytes, digest, b64u = EnrollmentControlCodec.encode_payload(payload)
    assert raw_bytes.startswith(b"{")
    assert digest.startswith("sha256:")
    assert len(b64u) > 0

    decoded = EnrollmentControlCodec.decode_payload(raw_bytes)
    assert decoded.profile_id == "prof-1"
    assert decoded.channel_ref == "chan-1"
    assert decoded.target_id == "tgt-1"
    assert decoded.max_uses == 1
    assert decoded.operator_id == "op-1"
