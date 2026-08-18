"""Unit tests for typed_input_decoders.py."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import MagicMock
import pytest

from core.actions.request_v2 import BoundedTypedInputPayloadV2
from core.actions.typed_input_decoders import (
    DuplicateTypedInputDecoder,
    TypedInputDecoderError,
    TypedInputDecoderNotRegistered,
    TypedInputDecoderRegistry,
    _coerce_value,
    _decode_dataclass,
    _decode_json,
)

pytestmark = pytest.mark.unit


def test_decode_json_validations():
    # Not BoundedTypedInputPayloadV2
    with pytest.raises(TypedInputDecoderError, match="decoder accepts only a bounded typed-input payload"):
        _decode_json("not_a_payload")  # type: ignore

    # canonical_json not bytes
    bad_payload = object.__new__(BoundedTypedInputPayloadV2)
    object.__setattr__(bad_payload, "canonical_json", "not_bytes")
    with pytest.raises(TypedInputDecoderError, match="canonical_json must be bytes"):
        _decode_json(bad_payload)

    # byte length mismatch
    bad_payload2 = object.__new__(BoundedTypedInputPayloadV2)
    raw = b'{"schema_id": "test"}'
    object.__setattr__(bad_payload2, "canonical_json", raw)
    object.__setattr__(bad_payload2, "byte_length", 9999)
    with pytest.raises(TypedInputDecoderError, match="typed input byte length mismatch"):
        _decode_json(bad_payload2)

    # digest mismatch
    bad_payload3 = object.__new__(BoundedTypedInputPayloadV2)
    object.__setattr__(bad_payload3, "canonical_json", raw)
    object.__setattr__(bad_payload3, "byte_length", len(raw))
    object.__setattr__(bad_payload3, "sha256_digest", "sha256:WRONG")
    with pytest.raises(TypedInputDecoderError, match="typed input digest mismatch"):
        _decode_json(bad_payload3)

    # schema_id mismatch
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    bad_payload4 = object.__new__(BoundedTypedInputPayloadV2)
    object.__setattr__(bad_payload4, "canonical_json", raw)
    object.__setattr__(bad_payload4, "byte_length", len(raw))
    object.__setattr__(bad_payload4, "sha256_digest", digest)
    object.__setattr__(bad_payload4, "schema_id", "different_schema")
    with pytest.raises(TypedInputDecoderError, match="typed input schema_id mismatch"):
        _decode_json(bad_payload4)


def test_coerce_value_and_registry():
    # Unsupported literal
    from typing import Literal

    with pytest.raises(TypedInputDecoderError, match="unsupported literal value"):
        _coerce_value("bad_val", Literal["expected"], path="field")

    # Tuple not list
    with pytest.raises(TypedInputDecoderError, match="must be a JSON array"):
        _coerce_value("not_a_list", tuple[str, ...], path="field")

    # String with control char
    with pytest.raises(TypedInputDecoderError, match="must be a non-empty bounded string"):
        _coerce_value("hello\x01world", str, path="field")

    # Bool wrong type
    with pytest.raises(TypedInputDecoderError, match="must be a boolean"):
        _coerce_value(123, bool, path="field")

    # Int wrong type
    with pytest.raises(TypedInputDecoderError, match="must be an integer"):
        _coerce_value("123", int, path="field")

    # Unsupported tuple schema (e.g. fixed length tuple)
    with pytest.raises(TypedInputDecoderError, match="unsupported tuple schema"):
        _coerce_value([1, 2], tuple[int, str], path="field")

    # Enum not string and unknown enum
    from enum import Enum

    class DemoEnum(str, Enum):
        A = "a"

    with pytest.raises(TypedInputDecoderError, match="must be a string enum"):
        _coerce_value(123, DemoEnum, path="field")

    with pytest.raises(TypedInputDecoderError, match="unknown enum value"):
        _coerce_value("unknown_val", DemoEnum, path="field")

    # Dataclass not dict
    from dataclasses import dataclass

    @dataclass
    class DemoDC:
        x: int

    with pytest.raises(TypedInputDecoderError, match="must be an object"):
        _coerce_value("not_a_dict", DemoDC, path="field")

    # Unsupported schema type
    with pytest.raises(TypedInputDecoderError, match="uses an unsupported schema type"):
        _coerce_value(1.23, float, path="field")

    # Registry duplicate and not registered
    reg = TypedInputDecoderRegistry(register_defaults=True)
    with pytest.raises(DuplicateTypedInputDecoder, match="duplicate typed input decoder"):
        reg.register_exact("plugin:payload_keying", "octopus:input:payload_keying:2.0", MagicMock())

    with pytest.raises(TypedInputDecoderNotRegistered):
        reg.require_decoder("unknown_action", "unknown_schema")

    # Decode valid payload
    json_bytes = b'{"schema_id": "octopus:input:payload_keying:2.0", "payload_ref": "art://1", "profile_id": "keying://hostname", "target_metadata_ref": null}'
    digest = "sha256:" + hashlib.sha256(json_bytes).hexdigest()
    payload = object.__new__(BoundedTypedInputPayloadV2)
    object.__setattr__(payload, "schema_id", "octopus:input:payload_keying:2.0")
    object.__setattr__(payload, "canonical_json", json_bytes)
    object.__setattr__(payload, "byte_length", len(json_bytes))
    object.__setattr__(payload, "sha256_digest", digest)

    decoded = reg.decode("plugin:payload_keying", payload)
    assert decoded.payload_ref == "art://1"

    # Dataclass with unknown fields
    bad_json_bytes = b'{"schema_id": "octopus:input:payload_keying:2.0", "payload_ref": "art://1", "profile_id": "keying://hostname", "target_metadata_ref": null, "extra_field": 123}'
    bad_digest = "sha256:" + hashlib.sha256(bad_json_bytes).hexdigest()
    bad_payload = object.__new__(BoundedTypedInputPayloadV2)
    object.__setattr__(bad_payload, "schema_id", "octopus:input:payload_keying:2.0")
    object.__setattr__(bad_payload, "canonical_json", bad_json_bytes)
    object.__setattr__(bad_payload, "byte_length", len(bad_json_bytes))
    object.__setattr__(bad_payload, "sha256_digest", bad_digest)

    with pytest.raises(TypedInputDecoderError, match="contains unknown fields"):
        reg.decode("plugin:payload_keying", bad_payload)
