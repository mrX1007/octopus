"""Unit tests for edge cases and validations in request_v2.py."""

from __future__ import annotations

import json
import pytest

from core.actions.request_v2 import (
    ACTION_REQUEST_V2_MAX_ENVELOPE_BYTES,
    ACTION_REQUEST_V2_MAX_ITEMS,
    ACTION_REQUEST_V2_MAX_STRING_BYTES,
    ActionRequestV2EnvelopeDecoder,
    ActionRequestV2EnvelopeValidationError,
    _required_bounded_string,
    _validate_json_bounds,
)

pytestmark = pytest.mark.unit


def test_decoder_top_level_validations():
    # Exceeds max envelope bytes
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Envelope exceeds maximum size limit"):
        ActionRequestV2EnvelopeDecoder.decode(b"x" * (ACTION_REQUEST_V2_MAX_ENVELOPE_BYTES + 1))

    # Top level is list
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Envelope top-level must be a JSON object"):
        ActionRequestV2EnvelopeDecoder.decode(b"[]")

    # precondition_fact_refs not list
    payload = {
        "schema_version": "2.0",
        "request_id": "req-1",
        "mission_ref": "mis-1",
        "approval_ref": None,
        "precondition_fact_refs": "not_a_list",
        "idempotency_key": None,
        "typed_input": {"schema_id": "test.v1"},
    }
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="precondition_fact_refs must be a list"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(payload).encode("utf-8"))

    # precondition_fact_refs duplicate
    payload["precondition_fact_refs"] = ["f1", "f1"]
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="precondition_fact_refs contains duplicates"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(payload).encode("utf-8"))

    # typed_input not dict
    payload["precondition_fact_refs"] = []
    payload["typed_input"] = "not_a_dict"
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="typed_input object is required"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(payload).encode("utf-8"))


def test_string_and_bounds_helpers():
    # Empty string
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="test_field is required"):
        _required_bounded_string("   ", field_name="test_field", max_bytes=100)

    # Exceeds max bytes
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="test_field exceeds string limit"):
        _required_bounded_string("a" * 20, field_name="test_field", max_bytes=10)

    # Control char
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="test_field contains a control character"):
        _required_bounded_string("hello\x01world", field_name="test_field", max_bytes=100)

    # _validate_json_bounds oversized string
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Envelope contains an oversized string"):
        _validate_json_bounds("x" * (ACTION_REQUEST_V2_MAX_STRING_BYTES + 1))
