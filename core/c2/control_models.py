from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from core.c2.control_commands import (
    ParticipantControlPhaseV1,
    ParticipantControlPhaseV2,
)
from core.c2.protocol import C2_CONTROL_PROTOCOL_VERSION

if TYPE_CHECKING:
    from core.c2.control_commands import (
        ParticipantControlRequestV1,
        ParticipantControlRequestV2,
    )

MAX_BASE64_PAYLOAD_LENGTH = 16 * 1024 * 1024
MAX_CONTROL_PAYLOAD_BYTES = 256 * 1024  # 256 KiB decoded limit on control payloads
MAX_HEALTH_PAYLOAD_BYTES = 4 * 1024  # 4 KiB limit on health probe payloads

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ControlRequestDigest:
    request_digest: str
    payload_digest: str

    def __post_init__(self) -> None:
        if not self.request_digest:
            raise ValueError("request_digest must not be empty")
        if not self.payload_digest:
            raise ValueError("payload_digest must not be empty")


@dataclass(frozen=True)
class ControlPayloadDigest:
    schema_id: str
    digest: str
    canonical_b64u: str

    def __post_init__(self) -> None:
        if not self.schema_id:
            raise ValueError("schema_id must not be empty")
        if not self.digest:
            raise ValueError("digest must not be empty")


def canonical_json_bytes(value: object) -> bytes:
    """Encode an object into deterministic canonical UTF-8 JSON bytes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def strict_b64url_decode(value: str, max_len: int = MAX_CONTROL_PAYLOAD_BYTES) -> bytes:
    """Strictly decode unpadded or padded base64url string with size and character validation."""
    if not isinstance(value, str):
        raise ValueError("payload_not_string")
    if len(value) > MAX_BASE64_PAYLOAD_LENGTH:
        raise ValueError("encoded_payload_too_large")
    stripped = value.rstrip("=")
    if not _BASE64URL_RE.match(stripped):
        raise ValueError("invalid_base64url_characters")
    padding = "=" * (-len(stripped) % 4)
    try:
        raw = base64.b64decode(stripped + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid_base64url_payload") from exc
    if len(raw) > max_len:
        raise ValueError("decoded_payload_too_large")
    return raw


def calculate_schema_bound_payload_digest(schema_id: str, payload_bytes: bytes) -> str:
    """Calculate SHA-256 hex digest bound to schema identity: SHA-256(schema_id || NUL || payload_bytes)."""
    return hashlib.sha256(schema_id.encode("utf-8") + b"\x00" + payload_bytes).hexdigest()


def calculate_payload_digest(payload: bytes | str | dict, schema_id: str | None = None) -> str:
    """Calculate SHA-256 hex digest of payload data."""
    if isinstance(payload, dict):
        raw = canonical_json_bytes(payload)
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = payload
    if schema_id:
        return calculate_schema_bound_payload_digest(schema_id, raw)
    return hashlib.sha256(raw).hexdigest()


def calculate_transaction_intent_digest(
    *,
    participant_id: str,
    resource_ref: str,
    mission_id: str,
    subject_id: str,
    operation_kind: str = "c2_resource",
    payload_schema_id: str,
    payload_digest: str,
) -> str:
    """Calculate canonical SHA-256 hex digest of transaction intent across 2PC phases."""
    body = canonical_json_bytes(
        {
            "mission_id": mission_id,
            "operation_kind": operation_kind,
            "participant_id": participant_id,
            "payload_digest": payload_digest,
            "payload_schema_id": payload_schema_id,
            "resource_ref": resource_ref,
            "subject_id": subject_id,
        }
    )
    return hashlib.sha256(b"OCTOPUS-C2-INTENT-V2\x00" + body).hexdigest()


def canonical_unsigned_request_dict(
    request: ParticipantControlRequestV1 | ParticipantControlRequestV2,
) -> dict[str, Any]:
    """Extract canonical unsigned authority dictionary from request."""
    auth = request.authorization
    act_val = request.action.value if hasattr(request.action, "value") else str(request.action)
    expires_ms = int(getattr(auth, "expires_at_ms", int(getattr(auth, "expires_at", 0) * 1000)))
    issued_ms = int(getattr(auth, "issued_at_ms", 0))
    return {
        "action": act_val,
        "action_id": auth.action_id,
        "coordinator_revision": int(auth.coordinator_revision),
        "expected_resource_revision": request.expected_resource_revision
        if request.expected_resource_revision is not None
        else -1,
        "expires_at_ms": expires_ms,
        "issued_at_ms": issued_ms,
        "mission_id": auth.mission_id,
        "nonce": auth.nonce,
        "participant_id": auth.participant_id,
        "payload_digest": request.payload_digest,
        "payload_schema_id": request.payload_schema_id,
        "prior_receipt_digest": request.prior_receipt_digest or "",
        "prior_receipt_ref": request.prior_receipt_ref or "",
        "protocol_version": C2_CONTROL_PROTOCOL_VERSION,
        "subject_id": auth.subject_id,
        "transaction_id": auth.transaction_id,
    }


canonical_request_dict = canonical_unsigned_request_dict


def calculate_canonical_request_digest(request: ParticipantControlRequestV1 | ParticipantControlRequestV2) -> str:
    """Compute canonical SHA-256 request digest over unsigned canonical request dict."""
    body = canonical_json_bytes(canonical_unsigned_request_dict(request))
    return hashlib.sha256(b"OCTOPUS-C2-REQUEST-V2\x00" + body).hexdigest()


def canonical_signed_request_dict(
    request: ParticipantControlRequestV1 | ParticipantControlRequestV2,
    request_digest: str | None = None,
) -> dict[str, Any]:
    """Extract canonical signed request dictionary (including request_digest, excluding signature)."""
    d = canonical_unsigned_request_dict(request)
    d["request_digest"] = request_digest or calculate_canonical_request_digest(request)
    return d


def calculate_canonical_auth_transcript(
    request: ParticipantControlRequestV1 | ParticipantControlRequestV2,
    request_digest: str | None = None,
) -> bytes:
    """Compute canonical transcript to sign for a participant control request."""
    signed_dict = canonical_signed_request_dict(request, request_digest)
    return b"OCTOPUS-C2-AUTH-V2\x00" + canonical_json_bytes(signed_dict)


def calculate_request_digest(
    action: str | None = None,
    payload_digest: str | None = None,
    mission_id: str | None = None,
    subject_id: str | None = None,
    nonce: str | None = None,
    *,
    request: ParticipantControlRequestV1 | ParticipantControlRequestV2 | None = None,
    **kwargs: Any,
) -> str:
    """Calculate SHA-256 hex digest of control request."""
    if request is not None:
        return calculate_canonical_request_digest(request)
    if "request" in kwargs:
        return calculate_canonical_request_digest(kwargs["request"])
    if (
        action is not None
        and payload_digest is not None
        and mission_id is not None
        and subject_id is not None
        and nonce is not None
    ):
        canonical_dict = {
            "action": action,
            "action_id": kwargs.get("action_id", action),
            "coordinator_revision": int(kwargs.get("coordinator_revision", 1)),
            "expected_resource_revision": kwargs.get("expected_resource_revision", -1),
            "expires_at_ms": int(kwargs.get("expires_at_ms", 0)),
            "issued_at_ms": int(kwargs.get("issued_at_ms", 0)),
            "mission_id": mission_id,
            "nonce": nonce,
            "participant_id": kwargs.get("participant_id", ""),
            "payload_digest": payload_digest,
            "payload_schema_id": kwargs.get("payload_schema_id", "schema:c2_control_v1"),
            "prior_receipt_digest": kwargs.get("prior_receipt_digest", ""),
            "prior_receipt_ref": kwargs.get("prior_receipt_ref", ""),
            "protocol_version": C2_CONTROL_PROTOCOL_VERSION,
            "subject_id": subject_id,
            "transaction_id": kwargs.get("transaction_id", ""),
        }
        body = canonical_json_bytes(canonical_dict)
        return hashlib.sha256(b"OCTOPUS-C2-REQUEST-V2\x00" + body).hexdigest()
    raise ValueError("insufficient arguments for calculate_request_digest")


def calculate_receipt_digest(
    transaction_id: str,
    participant_id: str,
    receipt_ref: str,
    result_payload_digest: str | None = None,
    *,
    action: str | None = None,
    resource_ref: str | None = None,
    resource_revision: int | None = None,
    daemon_instance_id: str | None = None,
    result_payload_schema_id: str | None = None,
    protocol_version: str = C2_CONTROL_PROTOCOL_VERSION,
) -> str:
    """Calculate SHA-256 hex digest of participant control receipt binding all security fields."""
    payload = {
        "action": action or "",
        "daemon_instance_id": daemon_instance_id or "",
        "participant_id": participant_id,
        "protocol_version": protocol_version,
        "receipt_ref": receipt_ref,
        "resource_ref": resource_ref or "",
        "resource_revision": resource_revision if resource_revision is not None else 0,
        "result_payload_digest": result_payload_digest or "",
        "result_payload_schema_id": result_payload_schema_id or "",
        "transaction_id": transaction_id,
    }
    return hashlib.sha256(b"OCTOPUS-C2-RECEIPT-V2\x00" + canonical_json_bytes(payload)).hexdigest()


def calculate_snapshot_digest(
    transaction_id: str,
    participant_id: str,
    phase: str,
    receipt_digest: str | None = None,
    *,
    resource_ref: str | None = None,
    resource_revision: int | None = None,
    receipt_ref: str | None = None,
    result_payload_schema_id: str | None = None,
    result_payload_digest: str | None = None,
    protocol_version: str = C2_CONTROL_PROTOCOL_VERSION,
) -> str:
    """Calculate SHA-256 hex digest of participant query snapshot binding complete state."""
    payload = {
        "participant_id": participant_id,
        "phase": phase,
        "protocol_version": protocol_version,
        "receipt_digest": receipt_digest or "",
        "receipt_ref": receipt_ref or "",
        "resource_ref": resource_ref or "",
        "resource_revision": resource_revision if resource_revision is not None else 0,
        "result_payload_digest": result_payload_digest or "",
        "result_payload_schema_id": result_payload_schema_id or "",
        "transaction_id": transaction_id,
    }
    return hashlib.sha256(b"OCTOPUS-C2-SNAPSHOT-V2\x00" + canonical_json_bytes(payload)).hexdigest()


def canonical_response_envelope_dict(
    *,
    protocol_version: str = C2_CONTROL_PROTOCOL_VERSION,
    daemon_instance_id: str | None = None,
    daemon_generation: str = "gen_0",
    service_id: str = "",
    boot_instance_id: str = "",
    request_digest: str = "",
    request_nonce: str = "",
    response_type: str = "receipt",
    response_payload_b64u: str = "",
    response_digest: str = "",
    issued_at_ms: int = 0,
    key_id: str = "",
) -> dict[str, Any]:
    """Construct canonical dict for signed control response envelope."""
    d: dict[str, Any] = {
        "boot_instance_id": boot_instance_id,
        "daemon_generation": daemon_generation,
        "issued_at_ms": issued_at_ms,
        "key_id": key_id,
        "protocol_version": protocol_version,
        "request_digest": request_digest,
        "request_nonce": request_nonce,
        "response_digest": response_digest,
        "response_payload_b64u": response_payload_b64u,
        "response_type": response_type,
        "service_id": service_id,
    }
    if daemon_instance_id is not None and protocol_version != "2.0":
        d["daemon_instance_id"] = daemon_instance_id
    return d


def calculate_response_signature_digest(envelope_dict: dict[str, Any]) -> bytes:
    """Return the transcript bytes to sign for a daemon response envelope."""
    return b"OCTOPUS-C2-RESPONSE-V2\x00" + canonical_json_bytes(envelope_dict)


def calculate_health_signature_digest(health_dict: dict[str, Any]) -> bytes:
    """Return the transcript bytes to sign for a health response."""
    return b"OCTOPUS-C2-HEALTH-RESPONSE-V2\x00" + canonical_json_bytes(health_dict)


__all__ = [
    "MAX_BASE64_PAYLOAD_LENGTH",
    "MAX_CONTROL_PAYLOAD_BYTES",
    "MAX_HEALTH_PAYLOAD_BYTES",
    "ControlPayloadDigest",
    "ControlRequestDigest",
    "ParticipantControlPhaseV1",
    "ParticipantControlPhaseV2",
    "calculate_canonical_auth_transcript",
    "calculate_canonical_request_digest",
    "calculate_health_signature_digest",
    "calculate_payload_digest",
    "calculate_receipt_digest",
    "calculate_request_digest",
    "calculate_response_signature_digest",
    "calculate_schema_bound_payload_digest",
    "calculate_snapshot_digest",
    "calculate_transaction_intent_digest",
    "canonical_json_bytes",
    "canonical_request_dict",
    "canonical_response_envelope_dict",
    "canonical_signed_request_dict",
    "canonical_unsigned_request_dict",
    "strict_b64url_decode",
]
