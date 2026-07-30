"""Remaining replay entry-normalization coverage."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.ai.pipeline_replay import PipelineReplayMixin
from core.execution import ExecutionResult

pytestmark = pytest.mark.contract


class _Harness(PipelineReplayMixin):
    def __init__(self):
        self.runtime = SimpleNamespace(validate_result_schema=lambda _payload: "1.0")


def test_raw_output_mapping_is_promoted_to_legacy_output_field():
    payload, schema, request_supplied, execution_supplied, tool = _Harness()._prepare_replay_entry(
        {"result": {"raw_output": "fixture", "tool_name": "probe"}}
    )

    assert payload == {"output": "fixture", "tool_name": "probe"}
    assert schema == "1.0"
    assert request_supplied is False
    assert execution_supplied is False
    assert tool == "probe"


def test_canonical_execution_result_preserves_supplied_identity_and_tool():
    canonical = ExecutionResult(
        request_id="request",
        execution_id="execution",
        tool_name="probe",
        stdout="fixture",
    )

    payload, schema, request_supplied, execution_supplied, tool = _Harness()._prepare_replay_entry(
        {"result": canonical}
    )

    assert payload is canonical
    assert schema == "1.0"
    assert request_supplied is True
    assert execution_supplied is True
    assert tool == "probe"
