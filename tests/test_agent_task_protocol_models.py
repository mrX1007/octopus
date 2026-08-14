"""Exact closed-model contracts for the V12 agent task protocol."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

from core.c2.agent_result_models import AgentIdentityTaskOutputV12, AgentTaskResultV12
from core.c2.agent_task_models import (
    AgentIdentityTaskPayloadV12,
    AgentTaskEnvelopeV12,
    AgentTaskStatus,
)
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId

pytestmark = pytest.mark.unit


def _envelope() -> AgentTaskEnvelopeV12:
    return AgentTaskEnvelopeV12(
        schema_version="12.0",
        task_id="task-1",
        operation_id=C2TaskOperationId.IDENTITY,
        payload_schema_version=AgentPayloadSchemaIdV12.IDENTITY_V1,
        result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
        expected_agent_capabilities_revision=1,
        expected_agent_capabilities_digest="c" * 64,
        expected_agent_artifact_binding_digest="a" * 64,
        payload=AgentIdentityTaskPayloadV12(),
        issued_at=100.0,
        expires_at=200.0,
        delivery_attempt=1,
    )


def test_agent_task_envelope_exact_fields_and_frozen() -> None:
    envelope = _envelope()
    assert tuple(item.name for item in fields(AgentTaskEnvelopeV12)) == (
        "schema_version",
        "task_id",
        "operation_id",
        "payload_schema_version",
        "result_schema_version",
        "expected_agent_capabilities_revision",
        "expected_agent_capabilities_digest",
        "expected_agent_artifact_binding_digest",
        "payload",
        "issued_at",
        "expires_at",
        "delivery_attempt",
    )
    with pytest.raises(FrozenInstanceError):
        envelope.task_id = "changed"  # type: ignore[misc]


def test_result_status_invariants_fail_closed() -> None:
    with pytest.raises(ValueError, match="SUCCEEDED requires output"):
        AgentTaskResultV12(
            schema_version="12.0",
            result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
            result_id="result-1",
            task_id="task-1",
            operation_id=C2TaskOperationId.IDENTITY,
            status=AgentTaskStatus.SUCCEEDED,
            output=None,
            error_code=None,
            completed_at=150.0,
        )

    result = AgentTaskResultV12(
        schema_version="12.0",
        result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
        result_id="result-1",
        task_id="task-1",
        operation_id=C2TaskOperationId.IDENTITY,
        status=AgentTaskStatus.SUCCEEDED,
        output=AgentIdentityTaskOutputV12(
            hostname="host-1",
            os=C2TargetOS.LINUX,
            arch=C2TargetArch.AMD64,
            user="agent-user",
            process_id=10,
        ),
        error_code=None,
        completed_at=150.0,
    )
    assert result.output.output_kind == "identity"
