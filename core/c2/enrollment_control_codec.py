"""Codec for enrollment control plane requests and receipts (§15.7)."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from core.c2.enrollment_control_models import (
    ENROLLMENT_PAYLOAD_SCHEMA_V1,
    EnrollmentControlPayloadV1,
    EnrollmentControlReceiptV1,
)


class EnrollmentControlCodec:
    """Codec for serializing/deserializing enrollment control payloads."""

    @staticmethod
    def encode_payload(payload: EnrollmentControlPayloadV1) -> tuple[bytes, str, str]:
        """Return (canonical_bytes, payload_digest, base64url_string)."""
        data = asdict(payload)
        data["_schema"] = ENROLLMENT_PAYLOAD_SCHEMA_V1
        canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = f"sha256:{hashlib.sha256(canonical_json).hexdigest()}"
        b64u = base64.urlsafe_b64encode(canonical_json).decode("ascii").rstrip("=")
        return canonical_json, digest, b64u

    @staticmethod
    def decode_payload(payload_bytes: bytes) -> EnrollmentControlPayloadV1:
        data = json.loads(payload_bytes.decode("utf-8"))
        data.pop("_schema", None)
        return EnrollmentControlPayloadV1(
            profile_id=data["profile_id"],
            channel_ref=data["channel_ref"],
            target_id=data["target_id"],
            max_uses=data.get("max_uses", 1),
            expires_in_seconds=data.get("expires_in_seconds", 3600.0),
            operator_id=data.get("operator_id"),
            subject_id=data.get("subject_id"),
            mission_id=data.get("mission_id"),
        )
