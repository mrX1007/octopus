"""Unit tests for core/actions/typed_input_decoders.py."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Union
from unittest.mock import MagicMock
import pytest

from core.actions.input_contracts import PayloadKeyingInputV2
from core.actions.request_v2 import BoundedTypedInputPayloadV2
from core.actions.typed_input_decoders import (
    DuplicateTypedInputDecoder,
    TypedInputDecoderError,
    TypedInputDecoderNotRegistered,
    TypedInputDecoderRegistry,
    _coerce_value,
    _decode_dataclass,
    _decode_json,
    _object_without_duplicate_keys,
)

pytestmark = pytest.mark.unit


def _make_payload(schema_id: str, data: dict[str, object]) -> BoundedTypedInputPayloadV2:
    full_data = dict(data)
    full_data["schema_id"] = schema_id
    raw = json.dumps(full_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    return BoundedTypedInputPayloadV2(
        schema_id=schema_id,
        canonical_json=raw,
        byte_length=len(raw),
        sha256_digest=digest,
    )


def test_decode_json_errors():
    # Invalid payload type
    with pytest.raises(TypedInputDecoderError, match="decoder accepts only"):
        _decode_json("not a payload")  # type: ignore[arg-type]

    # canonical_json not bytes
    with pytest.raises(TypedInputDecoderError, match="must be bytes"):
        _decode_json(
            BoundedTypedInputPayloadV2(
                schema_id="s1",
                canonical_json="not bytes",  # type: ignore[arg-type]
                byte_length=10,
                sha256_digest="sha256:abc",
            )
        )

    # byte_length mismatch
    with pytest.raises(TypedInputDecoderError, match="byte length mismatch"):
        _decode_json(
            BoundedTypedInputPayloadV2(
                schema_id="s1",
                canonical_json=b'{"schema_id":"s1"}',
                byte_length=999,
                sha256_digest="sha256:abc",
            )
        )

    # digest mismatch
    raw_mismatch = b'{"schema_id":"s1"}'
    with pytest.raises(TypedInputDecoderError, match="digest mismatch"):
        _decode_json(
            BoundedTypedInputPayloadV2(
                schema_id="s1",
                canonical_json=raw_mismatch,
                byte_length=len(raw_mismatch),
                sha256_digest="sha256:wrong",
            )
        )

    # invalid JSON
    raw_invalid = b"{bad_json"
    digest_invalid = f"sha256:{hashlib.sha256(raw_invalid).hexdigest()}"
    with pytest.raises(TypedInputDecoderError, match="not valid UTF-8 JSON"):
        _decode_json(
            BoundedTypedInputPayloadV2(
                schema_id="s1",
                canonical_json=raw_invalid,
                byte_length=len(raw_invalid),
                sha256_digest=digest_invalid,
            )
        )

    # non-object JSON
    raw_array = b'["item"]'
    digest_array = f"sha256:{hashlib.sha256(raw_array).hexdigest()}"
    with pytest.raises(TypedInputDecoderError, match="must be a JSON object"):
        _decode_json(
            BoundedTypedInputPayloadV2(
                schema_id="s1",
                canonical_json=raw_array,
                byte_length=len(raw_array),
                sha256_digest=digest_array,
            )
        )

    # schema_id mismatch
    raw_mismatch = b'{"schema_id":"other_schema"}'
    digest_mismatch = f"sha256:{hashlib.sha256(raw_mismatch).hexdigest()}"
    with pytest.raises(TypedInputDecoderError, match="schema_id mismatch"):
        _decode_json(
            BoundedTypedInputPayloadV2(
                schema_id="s1",
                canonical_json=raw_mismatch,
                byte_length=len(raw_mismatch),
                sha256_digest=digest_mismatch,
            )
        )


def test_object_without_duplicate_keys():
    pairs = [("k1", 1), ("k2", 2)]
    assert _object_without_duplicate_keys(pairs) == {"k1": 1, "k2": 2}

    dup_pairs = [("k1", 1), ("k1", 2)]
    with pytest.raises(TypedInputDecoderError, match="duplicate JSON field"):
        _object_without_duplicate_keys(dup_pairs)


def test_coerce_value():
    # Union
    assert _coerce_value(None, Union[str, None], path="test") is None
    assert _coerce_value("hello", Union[str, int], path="test") == "hello"
    with pytest.raises(TypedInputDecoderError, match="does not match exactly one closed variant"):
        _coerce_value(True, Union[str, int], path="test")

    # Literal
    assert _coerce_value("val1", Literal["val1", "val2"], path="test") == "val1"
    with pytest.raises(TypedInputDecoderError, match="unsupported literal value"):
        _coerce_value("val3", Literal["val1", "val2"], path="test")

    # Tuple
    assert _coerce_value(["a", "b"], tuple[str, ...], path="test") == ("a", "b")
    with pytest.raises(TypedInputDecoderError, match="must be a JSON array"):
        _coerce_value("not an array", tuple[str, ...], path="test")

    # Enum
    class StatusEnum(str, Enum):
        ACTIVE = "active"

    assert _coerce_value("active", StatusEnum, path="test") == StatusEnum.ACTIVE
    with pytest.raises(TypedInputDecoderError, match="must be a string enum"):
        _coerce_value(123, StatusEnum, path="test")
    with pytest.raises(TypedInputDecoderError, match="unknown enum value"):
        _coerce_value("inactive", StatusEnum, path="test")

    # Primitives
    assert _coerce_value("  str  ", str, path="test") == "str"
    with pytest.raises(TypedInputDecoderError, match="non-empty bounded string"):
        _coerce_value("", str, path="test")
    with pytest.raises(TypedInputDecoderError, match="non-empty bounded string"):
        _coerce_value("str\x00bad", str, path="test")

    assert _coerce_value(True, bool, path="test") is True
    with pytest.raises(TypedInputDecoderError, match="must be a boolean"):
        _coerce_value("true", bool, path="test")

    assert _coerce_value(42, int, path="test") == 42
    with pytest.raises(TypedInputDecoderError, match="must be an integer"):
        _coerce_value(True, int, path="test")


def test_decode_dataclass():
    @dataclass(frozen=True)
    class SampleDTO:
        name: str
        count: int = 1

    # Valid
    decoded = _decode_dataclass({"name": "item"}, SampleDTO, path="sample")
    assert decoded.name == "item"
    assert decoded.count == 1

    # Unknown field
    with pytest.raises(TypedInputDecoderError, match="unknown fields"):
        _decode_dataclass({"name": "item", "unknown": 123}, SampleDTO, path="sample")

    # Missing required field
    with pytest.raises(TypedInputDecoderError, match="name is required"):
        _decode_dataclass({}, SampleDTO, path="sample")


def test_typed_input_decoder_registry():
    registry = TypedInputDecoderRegistry()
    assert len(registry._decoders) == 20

    # Duplicate registration
    with pytest.raises(DuplicateTypedInputDecoder):
        registry.register_exact("plugin:payload_keying", "octopus:input:payload_keying:2.0", PayloadKeyingInputV2)

    # Not registered
    with pytest.raises(TypedInputDecoderNotRegistered):
        registry.require_decoder("unknown_action", "unknown_schema")

    # Decode valid
    payload = _make_payload(
        "octopus:input:payload_keying:2.0",
        {
            "payload_ref": "artifact://p1",
            "profile_id": "keying://hostname",
            "target_metadata_ref": None,
        },
    )
    dto = registry.decode("plugin:payload_keying", payload)
    assert dto.profile_id == "keying://hostname"
    assert len(registry.bindings()) == 20

    # C2EnrollmentIssueInput bounds validation
    enroll_payload = _make_payload(
        "octopus:input:c2_enroll:2.0",
        {
            "channel_ref": "channel://chan-1",
            "target": "10.0.0.1",
            "profile_id": "deployment://go-agent",
            "agent_protocol_version": "12.0",
            "ttl_seconds": 1,  # below ttl_min_seconds (60)
            "max_uses": 1,
        },
    )
    with pytest.raises(TypedInputDecoderError, match="ttl_seconds is outside configured bounds"):
        registry.decode("c2:c2_enroll", enroll_payload)
