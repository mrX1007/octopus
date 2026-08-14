"""Canonical ownership tests for the historical enrollment import surface."""

from __future__ import annotations

from dataclasses import fields

import pytest

import core.c2.agent_task_models as canonical
import core.c2.enrollment_models as compatibility
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.task_catalog import C2TaskOperationId

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "name",
    (
        "AgentIdentityTaskPayloadV12",
        "AgentHostInventoryTaskPayloadV12",
        "AgentNetworkInventoryTaskPayloadV12",
        "AgentServiceInventoryTaskPayloadV12",
        "AgentTaskEnvelopeV12",
        "AgentTaskDeliveryAckV12",
    ),
)
def test_enrollment_models_reexports_canonical_pr15_owner(name: str) -> None:
    exported = getattr(compatibility, name)
    assert exported is getattr(canonical, name)
    assert exported.__module__ == "core.c2.agent_task_models"


def test_enrollment_import_surface_builds_exact_canonical_envelope() -> None:
    payload = compatibility.AgentIdentityTaskPayloadV12()
    envelope = compatibility.AgentTaskEnvelopeV12(
        schema_version="12.0",
        task_id="task-1",
        operation_id=C2TaskOperationId.IDENTITY,
        payload_schema_version=AgentPayloadSchemaIdV12.IDENTITY_V1,
        result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
        expected_agent_capabilities_revision=1,
        expected_agent_capabilities_digest="capability-digest",
        expected_agent_artifact_binding_digest="artifact-binding-digest",
        payload=payload,
        issued_at=1.0,
        expires_at=2.0,
        delivery_attempt=1,
    )
    assert tuple(field.name for field in fields(envelope)) == (
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
