"""Tests for ActionRequestV2EnvelopeDecoder and envelope bounds."""

from __future__ import annotations

import json

import pytest

from core.actions.request_v2 import (
    ActionRequestV2EnvelopeDecoder,
    ActionRequestV2EnvelopeValidationError,
)

pytestmark = pytest.mark.unit


def test_v2_envelope_exact_schema() -> None:
    payload = {
        "schema_version": "2.0",
        "request_id": "req-123",
        "mission_ref": "mission-456",
        "approval_ref": "approval-789",
        "precondition_fact_refs": ["fact-1"],
        "idempotency_key": "idem-1",
        "typed_input": {
            "schema_id": "octopus:input:test:2.0",
            "foo": "bar",
        },
    }
    raw_bytes = json.dumps(payload).encode("utf-8")
    envelope = ActionRequestV2EnvelopeDecoder.decode_and_validate(raw_bytes)
    assert envelope.request_id == "req-123"
    assert envelope.mission_ref == "mission-456"
    assert envelope.approval_ref == "approval-789"
    assert envelope.precondition_fact_refs == ("fact-1",)
    assert envelope.idempotency_key == "idem-1"
    assert envelope.typed_input_payload.schema_id == "octopus:input:test:2.0"
    assert envelope.typed_input_payload.sha256_digest.startswith("sha256:")


def test_v2_envelope_rejects_unknown_authority_fields() -> None:
    payload = {
        "schema_version": "2.0",
        "request_id": "req-123",
        "mission_ref": "mission-456",
        "principal_ref": "hacked-principal",
        "typed_input": {"schema_id": "octopus:input:test:2.0"},
    }
    raw_bytes = json.dumps(payload).encode("utf-8")
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Forbidden authority field"):
        ActionRequestV2EnvelopeDecoder.decode_and_validate(raw_bytes)


def _minimal_payload() -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "request_id": "req-1",
        "mission_ref": "mission-1",
        "approval_ref": None,
        "precondition_fact_refs": [],
        "idempotency_key": None,
        "typed_input": {"schema_id": "octopus:input:test:2.0"},
    }


def test_v2_envelope_rejects_unknown_business_field() -> None:
    payload = _minimal_payload()
    payload["surprise"] = True
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Unknown envelope fields"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(payload).encode())


def test_v2_envelope_rejects_duplicate_json_fields() -> None:
    raw = (
        b'{"schema_version":"2.0","request_id":"req-1","request_id":"req-2",'
        b'"mission_ref":"mission-1","approval_ref":null,"precondition_fact_refs":[],'
        b'"idempotency_key":null,"typed_input":{"schema_id":"octopus:input:test:2.0"}}'
    )
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="duplicate JSON field"):
        ActionRequestV2EnvelopeDecoder.decode(raw)


def test_v2_envelope_size_depth_and_item_limits() -> None:
    payload = _minimal_payload()
    nested: object = "leaf"
    for _ in range(18):
        nested = {"nested": nested}
    typed_input = payload["typed_input"]
    assert isinstance(typed_input, dict)
    typed_input["value"] = nested
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="nesting depth"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(payload).encode())


def test_v2_envelope_does_not_coerce_scalar_types() -> None:
    payload = _minimal_payload()
    payload["request_id"] = 123
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="request_id must be a string"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(payload).encode())
