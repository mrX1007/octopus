"""Exact V2 typed-input decoder registry contracts."""

from __future__ import annotations

import hashlib
import json

import pytest

from core.actions.input_contracts import PayloadKeyingInputV2, PayloadKeyingProfileId
from core.actions.request_v2 import BoundedTypedInputPayloadV2
from core.actions.schema_bindings import get_all_v2_schema_bindings
from core.actions.typed_input_decoders import (
    DuplicateTypedInputDecoder,
    TypedInputDecoderError,
    TypedInputDecoderNotRegistered,
    TypedInputDecoderRegistry,
    get_typed_input_decoder_registry,
)

pytestmark = pytest.mark.unit


def _payload(schema_id: str, data: dict[str, object]) -> BoundedTypedInputPayloadV2:
    body = json.dumps({"schema_id": schema_id, **data}, sort_keys=True, separators=(",", ":")).encode()
    return BoundedTypedInputPayloadV2(
        schema_id=schema_id,
        canonical_json=body,
        byte_length=len(body),
        sha256_digest="sha256:" + hashlib.sha256(body).hexdigest(),
    )


def test_decoder_registry_decodes_v2_schema() -> None:
    registry = get_typed_input_decoder_registry()
    decoded = registry.decode(
        "plugin:payload_keying",
        _payload(
            "octopus:input:payload_keying:2.0",
            {
                "payload_ref": "artifact://payload/1",
                "profile_id": "keying://hostname",
                "target_metadata_ref": None,
            },
        ),
    )
    assert decoded == PayloadKeyingInputV2(
        payload_ref="artifact://payload/1",
        profile_id=PayloadKeyingProfileId.HOSTNAME,
        target_metadata_ref=None,
    )


def test_input_schema_matrix_matches_decoder_registry() -> None:
    registry = get_typed_input_decoder_registry()
    bindings = registry.bindings()
    assert len(bindings) == 20
    assert {(action_id, schema_id) for action_id, schema_id, _ in bindings} == {
        (binding.action_id, binding.input_schema_id) for binding in get_all_v2_schema_bindings()
    }


def test_unknown_v2_action_decoder_denied() -> None:
    with pytest.raises(TypedInputDecoderNotRegistered):
        get_typed_input_decoder_registry().decode(
            "unknown:action",
            _payload(
                "octopus:input:payload_keying:2.0",
                {
                    "payload_ref": "artifact://payload/1",
                    "profile_id": "keying://hostname",
                    "target_metadata_ref": None,
                },
            ),
        )


def test_decoder_rejects_caller_created_dataclass() -> None:
    caller_created = PayloadKeyingInputV2(
        payload_ref="artifact://payload/1",
        profile_id=PayloadKeyingProfileId.HOSTNAME,
        target_metadata_ref=None,
    )
    with pytest.raises(TypedInputDecoderError, match="bounded typed-input"):
        get_typed_input_decoder_registry().decode(
            "plugin:payload_keying",
            caller_created,  # type: ignore[arg-type]
        )


def test_unknown_fields_rejected() -> None:
    with pytest.raises(TypedInputDecoderError, match="unknown fields"):
        get_typed_input_decoder_registry().decode(
            "plugin:payload_keying",
            _payload(
                "octopus:input:payload_keying:2.0",
                {
                    "payload_ref": "artifact://payload/1",
                    "profile_id": "keying://hostname",
                    "target_metadata_ref": None,
                    "command": "forbidden",
                },
            ),
        )


def test_decoder_rejects_tampered_length_and_digest() -> None:
    good = _payload(
        "octopus:input:payload_keying:2.0",
        {
            "payload_ref": "artifact://payload/1",
            "profile_id": "keying://hostname",
            "target_metadata_ref": None,
        },
    )
    with pytest.raises(TypedInputDecoderError, match="byte length"):
        get_typed_input_decoder_registry().decode(
            "plugin:payload_keying",
            BoundedTypedInputPayloadV2(good.schema_id, good.canonical_json, good.byte_length + 1, good.sha256_digest),
        )
    with pytest.raises(TypedInputDecoderError, match="digest"):
        get_typed_input_decoder_registry().decode(
            "plugin:payload_keying",
            BoundedTypedInputPayloadV2(good.schema_id, good.canonical_json, good.byte_length, "sha256:wrong"),
        )


def test_duplicate_decoder_registration_rejected() -> None:
    registry = TypedInputDecoderRegistry(register_defaults=False)
    registry.register_exact(
        "plugin:payload_keying",
        "octopus:input:payload_keying:2.0",
        PayloadKeyingInputV2,
    )
    with pytest.raises(DuplicateTypedInputDecoder):
        registry.register_exact(
            "plugin:payload_keying",
            "octopus:input:payload_keying:2.0",
            PayloadKeyingInputV2,
        )
