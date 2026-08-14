"""Bounded V2 request envelope decoder (§4.0)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Final, Literal

from core.actions.input_contracts import V2InputUnion

ACTION_REQUEST_V2_ENVELOPE_SCHEMA_VERSION: str = "2.0"
ACTION_REQUEST_V2_SCHEMA_VERSION: Final = "2.0"
ACTION_REQUEST_V2_MAX_ENVELOPE_BYTES: Final = 10 * 1024 * 1024
ACTION_REQUEST_V2_MAX_DEPTH: Final = 16
ACTION_REQUEST_V2_MAX_STRING_BYTES: Final = 65_536
ACTION_REQUEST_V2_MAX_ITEMS: Final = 10_000

_EXACT_TOP_LEVEL_FIELDS: Final = frozenset(
    {
        "schema_version",
        "request_id",
        "mission_ref",
        "approval_ref",
        "precondition_fact_refs",
        "idempotency_key",
        "typed_input",
    }
)

_AUTHORITY_FIELDS: set[str] = {
    "ingress_session_ref",
    "principal_ref",
    "subject_id",
    "role",
    "approved",
    "approval_id",
    "parent_execution_id",
    "execution_graph_id",
    "execution_budget",
}


class ActionRequestV2EnvelopeValidationError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class BoundedTypedInputPayloadV2:
    schema_id: str
    canonical_json: bytes = field(repr=False, compare=False)
    byte_length: int
    sha256_digest: str


@dataclass(frozen=True, repr=False)
class BoundedActionRequestV2Envelope:
    request_id: str
    mission_ref: str
    approval_ref: str | None
    precondition_fact_refs: tuple[str, ...]
    idempotency_key: str | None
    typed_input_payload: BoundedTypedInputPayloadV2
    schema_version: Literal["2.0"] = field(
        default="2.0",
        init=False,
    )


@dataclass(frozen=True)
class ActionRequestV2:
    request_id: str
    action_id: str
    mission_ref: str
    approval_ref: str | None
    precondition_fact_refs: tuple[str, ...]
    idempotency_key: str | None
    typed_input: V2InputUnion
    schema_version: Literal["2.0"] = field(
        default=ACTION_REQUEST_V2_SCHEMA_VERSION,
        init=False,
    )


class ActionRequestV2EnvelopeDecoder:
    @staticmethod
    def decode(raw_bytes: bytes) -> BoundedActionRequestV2Envelope:
        if not isinstance(raw_bytes, bytes):
            raise ActionRequestV2EnvelopeValidationError("Envelope must be serialized bytes")
        if len(raw_bytes) > ACTION_REQUEST_V2_MAX_ENVELOPE_BYTES:
            raise ActionRequestV2EnvelopeValidationError("Envelope exceeds maximum size limit (10MB)")

        try:
            data = json.loads(
                raw_bytes.decode("utf-8"),
                object_pairs_hook=_object_without_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ActionRequestV2EnvelopeValidationError(f"non-finite JSON number: {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ActionRequestV2EnvelopeValidationError(f"Invalid JSON envelope: {exc}") from exc

        if not isinstance(data, dict):
            raise ActionRequestV2EnvelopeValidationError("Envelope top-level must be a JSON object")

        _validate_json_bounds(data)

        unknown_fields = set(data) - _EXACT_TOP_LEVEL_FIELDS
        if unknown_fields:
            authority_fields = sorted(unknown_fields & _AUTHORITY_FIELDS)
            if authority_fields:
                raise ActionRequestV2EnvelopeValidationError(
                    f"Forbidden authority field in ingress request: '{authority_fields[0]}'"
                )
            raise ActionRequestV2EnvelopeValidationError(
                f"Unknown envelope fields: {', '.join(sorted(unknown_fields))}"
            )
        missing_fields = _EXACT_TOP_LEVEL_FIELDS - set(data)
        if missing_fields:
            raise ActionRequestV2EnvelopeValidationError(
                f"Missing envelope fields: {', '.join(sorted(missing_fields))}"
            )

        schema_version = data["schema_version"]
        if schema_version != ACTION_REQUEST_V2_ENVELOPE_SCHEMA_VERSION:
            raise ActionRequestV2EnvelopeValidationError(
                f"Unsupported schema_version: '{schema_version}', expected '2.0'"
            )

        request_id = _required_bounded_string(data["request_id"], field_name="request_id", max_bytes=256)
        mission_ref = _required_bounded_string(data["mission_ref"], field_name="mission_ref", max_bytes=512)

        approval_ref_val = data["approval_ref"]
        approval_ref = (
            _required_bounded_string(approval_ref_val, field_name="approval_ref", max_bytes=512)
            if approval_ref_val is not None
            else None
        )

        precondition_fact_refs_raw = data["precondition_fact_refs"]
        if not isinstance(precondition_fact_refs_raw, list):
            raise ActionRequestV2EnvelopeValidationError("precondition_fact_refs must be a list of strings")
        if len(precondition_fact_refs_raw) > 256:
            raise ActionRequestV2EnvelopeValidationError("precondition_fact_refs exceeds item limit")
        precondition_fact_refs = tuple(
            _required_bounded_string(item, field_name="precondition_fact_refs[]", max_bytes=512)
            for item in precondition_fact_refs_raw
        )
        if len(set(precondition_fact_refs)) != len(precondition_fact_refs):
            raise ActionRequestV2EnvelopeValidationError("precondition_fact_refs contains duplicates")

        idempotency_key_val = data["idempotency_key"]
        idempotency_key = (
            _required_bounded_string(idempotency_key_val, field_name="idempotency_key", max_bytes=512)
            if idempotency_key_val is not None
            else None
        )

        typed_input_data = data["typed_input"]
        if not isinstance(typed_input_data, dict):
            raise ActionRequestV2EnvelopeValidationError("typed_input object is required")

        schema_id = _required_bounded_string(
            typed_input_data.get("schema_id"),
            field_name="typed_input.schema_id",
            max_bytes=512,
        )

        canonical_payload_bytes = json.dumps(
            typed_input_data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        digest = f"sha256:{hashlib.sha256(canonical_payload_bytes).hexdigest()}"

        bounded_payload = BoundedTypedInputPayloadV2(
            schema_id=schema_id,
            canonical_json=canonical_payload_bytes,
            byte_length=len(canonical_payload_bytes),
            sha256_digest=digest,
        )

        return BoundedActionRequestV2Envelope(
            request_id=request_id,
            mission_ref=mission_ref,
            approval_ref=approval_ref,
            precondition_fact_refs=precondition_fact_refs,
            idempotency_key=idempotency_key,
            typed_input_payload=bounded_payload,
        )

    @staticmethod
    def decode_and_validate(raw_bytes: bytes) -> BoundedActionRequestV2Envelope:
        """Compatibility spelling for the single bounded decoder operation."""

        return ActionRequestV2EnvelopeDecoder.decode(raw_bytes)


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ActionRequestV2EnvelopeValidationError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _required_bounded_string(value: object, *, field_name: str, max_bytes: int) -> str:
    if type(value) is not str:
        raise ActionRequestV2EnvelopeValidationError(f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ActionRequestV2EnvelopeValidationError(f"{field_name} is required")
    if len(normalized.encode("utf-8")) > max_bytes:
        raise ActionRequestV2EnvelopeValidationError(f"{field_name} exceeds string limit")
    if any(ord(character) < 32 for character in normalized):
        raise ActionRequestV2EnvelopeValidationError(f"{field_name} contains a control character")
    return normalized


def _validate_json_bounds(value: object, *, depth: int = 0) -> int:
    if depth > ACTION_REQUEST_V2_MAX_DEPTH:
        raise ActionRequestV2EnvelopeValidationError("Envelope exceeds nesting depth limit")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > ACTION_REQUEST_V2_MAX_STRING_BYTES:
            raise ActionRequestV2EnvelopeValidationError("Envelope contains an oversized string")
        return 1
    if isinstance(value, list):
        total = 1
        for item in value:
            total += _validate_json_bounds(item, depth=depth + 1)
            if total > ACTION_REQUEST_V2_MAX_ITEMS:
                raise ActionRequestV2EnvelopeValidationError("Envelope exceeds aggregate item limit")
        return total
    if isinstance(value, dict):
        total = 1
        for key, item in value.items():
            total += _validate_json_bounds(key, depth=depth + 1)
            total += _validate_json_bounds(item, depth=depth + 1)
            if total > ACTION_REQUEST_V2_MAX_ITEMS:
                raise ActionRequestV2EnvelopeValidationError("Envelope exceeds aggregate item limit")
        return total
    return 1


__all__ = [
    "ACTION_REQUEST_V2_ENVELOPE_SCHEMA_VERSION",
    "ACTION_REQUEST_V2_MAX_DEPTH",
    "ACTION_REQUEST_V2_MAX_ENVELOPE_BYTES",
    "ACTION_REQUEST_V2_MAX_ITEMS",
    "ACTION_REQUEST_V2_MAX_STRING_BYTES",
    "ACTION_REQUEST_V2_SCHEMA_VERSION",
    "ActionRequestV2",
    "ActionRequestV2EnvelopeDecoder",
    "ActionRequestV2EnvelopeValidationError",
    "BoundedActionRequestV2Envelope",
    "BoundedTypedInputPayloadV2",
]
