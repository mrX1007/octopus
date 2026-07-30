"""Hermetic edge coverage for canonical execution-result normalization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import pytest

from core.execution import results
from core.execution.results import (
    ExecutionResult,
    ExecutionStatus,
    adapt_execution_result,
)

pytestmark = pytest.mark.unit


class NumericEnum(Enum):
    ONE = 1


@dataclass
class DataclassPayload:
    value: int


class StringPayload:
    def __str__(self) -> str:
        return "string-payload"


class MappingDecision:
    def to_dict(self):
        return {"command": "fixture --safe", "allowed": True}


class NonMappingDecision:
    def to_dict(self):
        return ["not", "a", "mapping"]


def test_json_safe_covers_floats_enums_dataclasses_and_recursive_mappings() -> None:
    recursive = {}
    recursive["self"] = recursive

    assert results._json_safe(1.5) == 1.5
    assert results._json_safe(float("inf")) is None
    assert results._json_safe(NumericEnum.ONE) == 1
    assert results._json_safe(DataclassPayload(7)) == {"value": 7}
    assert results._json_safe(recursive) == {"self": "<recursive>"}
    assert results._json_safe(StringPayload()) == "string-payload"


def test_legacy_redactor_signatures_fall_back_without_losing_json_safety() -> None:
    text_calls = []
    data_calls = []

    def text_redactor(value):
        text_calls.append(value)
        return f"safe:{value}"

    def data_redactor(value):
        data_calls.append(value)
        return {"safe": value}

    assert results._redact_text(text_redactor, b"value", kind="fixture") == (
        "safe:value"
    )
    assert results._redact_data(data_redactor, {"value": b"bytes"}) == {
        "safe": {"value": "bytes"}
    }
    assert text_calls == ["value"]
    assert data_calls == [{"value": "bytes"}]


def test_small_output_and_json_budgets_cover_single_stream_boundaries() -> None:
    assert results._bounded_outputs("", "diagnostic", 3) == ("", "dia", True)
    assert results._bounded_outputs("output", "", 3) == ("out", "", True)
    assert results._bounded_json_string("value", 1) == ("", True)
    assert results._coerce_int("not-an-integer") is None


def test_status_and_artifact_scalar_fallbacks() -> None:
    assert results._status_from_value(
        "unknown-status",
        success=False,
        exit_code=None,
        error="",
    ) is ExecutionStatus.FAILED
    assert results._artifact_values("artifact.txt") == ("artifact.txt",)
    assert results._artifact_values(b"artifact-bytes") == ("artifact-bytes",)
    assert results._artifact_values(Path("artifact-path")) == ("artifact-path",)
    scalar = object()
    assert results._artifact_values(scalar) == (str(scalar),)


def test_artifact_and_metadata_defensive_size_boundaries(monkeypatch) -> None:
    monkeypatch.setattr(results, "MAX_ARTIFACT_BYTES", 2)

    bounded, truncated, count = results._bounded_artifact_refs(
        ("artifact",),
        None,
    )

    assert bounded == ()
    assert truncated is True
    assert count == 1
    assert results._bounded_metadata(["legacy", "metadata"]) == {
        "legacy_metadata": ["legacy", "metadata"]
    }


def test_audit_facades_cover_absent_mapping_and_nonmapping_decisions() -> None:
    without_decision = ExecutionResult(
        request_id="request",
        execution_id="execution",
        stdout="output",
        stderr="error",
    )
    assert without_decision.audit_command == ""
    assert without_decision.to_audit_dict()["decision"] is None

    mapping = ExecutionResult(decision=MappingDecision(), stdout="output")
    assert mapping.audit_command == "fixture --safe"
    assert mapping.to_audit_dict()["decision"] == {
        "command": "fixture --safe",
        "allowed": True,
    }

    nonmapping = ExecutionResult(decision=NonMappingDecision())
    assert nonmapping.audit_command == ""


def test_canonical_readaptation_preserves_fields_and_source_decision() -> None:
    decision = MappingDecision()
    canonical = ExecutionResult(
        status=ExecutionStatus.FAILED,
        request_id="canonical-request",
        execution_id="canonical-execution",
        tool_name="canonical-tool",
        stdout="canonical-output",
        stderr="canonical-error",
        artifact_refs=("artifact",),
        exit_code=9,
        duration=1.25,
        error_class="FixtureError",
        error_message="fixture failure",
        partial=True,
        metadata={"fixture": True},
        executed=True,
        decision=decision,
    )

    adapted = adapt_execution_result(canonical)

    assert adapted.status is ExecutionStatus.FAILED
    assert adapted.request_id == "canonical-request"
    assert adapted.execution_id == "canonical-execution"
    assert adapted.tool_name == "canonical-tool"
    assert adapted.artifact_refs == ("artifact",)
    assert adapted.error_class == "FixtureError"
    assert adapted.error_message == "fixture failure"
    assert adapted.metadata == {
        "fixture": True,
        "execution_id": "canonical-execution",
    }
    assert adapted.decision is decision


def test_mapping_error_shape_and_generated_ids_are_canonical() -> None:
    mapped = adapt_execution_result(
        {
            "status": "failed",
            "error": {"class": "MappedError", "message": "mapped failure"},
        }
    )

    assert mapped.error_class == "MappedError"
    assert mapped.error_message == "mapped failure"
    assert len(mapped.request_id) == 32
    assert len(mapped.execution_id) == 32
    assert mapped.request_id != mapped.execution_id
