"""Tests for closed V12 task compilation."""

from __future__ import annotations

from dataclasses import asdict

import pytest

from core.c2.agent_protocol_v12 import AgentCapabilitySetV12
from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
    AgentTaskEnvelopeV12,
)
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.task_catalog import (
    C2TaskOperationId,
    C2TaskPayload,
    HostInventoryTaskPayload,
    IdentityTaskPayload,
    NetworkInventoryTaskPayload,
    ServiceInventoryTaskPayload,
)
from core.c2.task_compiler import C2TaskCompiler

pytestmark = pytest.mark.unit


def _capabilities(
    *,
    operations: tuple[C2TaskOperationId, ...] = tuple(C2TaskOperationId),
    payload_schemas: tuple[AgentPayloadSchemaIdV12, ...] = tuple(AgentPayloadSchemaIdV12),
    result_schemas: tuple[AgentResultSchemaIdV12, ...] = tuple(AgentResultSchemaIdV12),
) -> AgentCapabilitySetV12:
    return AgentCapabilitySetV12.create(
        supported_operation_ids=operations,
        supported_payload_schema_versions=payload_schemas,
        supported_result_schema_versions=result_schemas,
    )


@pytest.mark.parametrize(
    ("operation_id", "control_payload", "wire_type", "payload_schema", "result_schema"),
    (
        (
            C2TaskOperationId.IDENTITY,
            IdentityTaskPayload(),
            AgentIdentityTaskPayloadV12,
            AgentPayloadSchemaIdV12.IDENTITY_V1,
            AgentResultSchemaIdV12.IDENTITY_V1,
        ),
        (
            C2TaskOperationId.HOST_INVENTORY,
            HostInventoryTaskPayload(include_processes=True, include_services=False, max_items=64),
            AgentHostInventoryTaskPayloadV12,
            AgentPayloadSchemaIdV12.HOST_INVENTORY_V1,
            AgentResultSchemaIdV12.HOST_INVENTORY_V1,
        ),
        (
            C2TaskOperationId.NETWORK_INVENTORY,
            NetworkInventoryTaskPayload(include_routes=True, include_connections=False, max_items=32),
            AgentNetworkInventoryTaskPayloadV12,
            AgentPayloadSchemaIdV12.NETWORK_INVENTORY_V1,
            AgentResultSchemaIdV12.NETWORK_INVENTORY_V1,
        ),
        (
            C2TaskOperationId.SERVICE_INVENTORY,
            ServiceInventoryTaskPayload(service_names=("nginx", "sshd"), include_status=True),
            AgentServiceInventoryTaskPayloadV12,
            AgentPayloadSchemaIdV12.SERVICE_INVENTORY_V1,
            AgentResultSchemaIdV12.SERVICE_INVENTORY_V1,
        ),
    ),
)
def test_task_compiler_selects_advertised_payload_and_result_schemas(
    operation_id: C2TaskOperationId,
    control_payload: C2TaskPayload,
    wire_type: type[object],
    payload_schema: AgentPayloadSchemaIdV12,
    result_schema: AgentResultSchemaIdV12,
) -> None:
    envelope = C2TaskCompiler().compile(
        operation_id,
        control_payload,
        agent_capabilities=_capabilities(),
        expected_agent_capabilities_revision=7,
        expected_agent_artifact_binding_digest="a" * 64,
        task_id="task-1",
        issued_at=100.0,
        ttl_seconds=25.0,
    )

    assert type(envelope) is AgentTaskEnvelopeV12
    assert envelope.operation_id is operation_id
    assert envelope.payload_schema_version is payload_schema
    assert envelope.result_schema_version is result_schema
    assert type(envelope.payload) is wire_type
    assert envelope.expected_agent_capabilities_revision == 7
    assert envelope.expected_agent_capabilities_digest == _capabilities().capabilities_digest
    assert envelope.expected_agent_artifact_binding_digest == "a" * 64
    assert envelope.issued_at == 100.0
    assert envelope.expires_at == 125.0


@pytest.mark.parametrize(
    ("capabilities", "message"),
    (
        (
            _capabilities(operations=(C2TaskOperationId.HOST_INVENTORY,)),
            "selected operation",
        ),
        (
            _capabilities(payload_schemas=(AgentPayloadSchemaIdV12.HOST_INVENTORY_V1,)),
            "payload schema",
        ),
        (
            _capabilities(result_schemas=(AgentResultSchemaIdV12.HOST_INVENTORY_V1,)),
            "result schema",
        ),
    ),
)
def test_task_requires_advertised_operation_payload_and_result_schemas(
    capabilities: AgentCapabilitySetV12,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        C2TaskCompiler().compile(
            C2TaskOperationId.IDENTITY,
            IdentityTaskPayload(),
            agent_capabilities=capabilities,
            expected_agent_capabilities_revision=1,
            expected_agent_artifact_binding_digest="binding-digest",
        )


def test_task_compiler_rejects_open_or_mismatched_inputs() -> None:
    compiler = C2TaskCompiler()
    with pytest.raises(TypeError, match="canonical C2TaskOperationId"):
        compiler.compile(
            "identity",  # type: ignore[arg-type]
            IdentityTaskPayload(),
            agent_capabilities=_capabilities(),
            expected_agent_capabilities_revision=1,
            expected_agent_artifact_binding_digest="binding-digest",
        )
    with pytest.raises(ValueError, match="payload variant mismatch"):
        compiler.compile(
            C2TaskOperationId.IDENTITY,
            HostInventoryTaskPayload(True, True, 1),
            agent_capabilities=_capabilities(),
            expected_agent_capabilities_revision=1,
            expected_agent_artifact_binding_digest="binding-digest",
        )
    with pytest.raises(ValueError, match="payload variant mismatch"):
        compiler.compile(
            C2TaskOperationId.IDENTITY,
            {"payload_kind": "identity"},  # type: ignore[arg-type]
            agent_capabilities=_capabilities(),
            expected_agent_capabilities_revision=1,
            expected_agent_artifact_binding_digest="binding-digest",
        )


def test_task_compiler_emits_v12_envelope_without_raw_command_fields() -> None:
    envelope = C2TaskCompiler().compile(
        C2TaskOperationId.IDENTITY,
        IdentityTaskPayload(),
        agent_capabilities=_capabilities(),
        expected_agent_capabilities_revision=1,
        expected_agent_artifact_binding_digest="binding-digest",
    )
    encoded = asdict(envelope)
    assert envelope.schema_version == "12.0"
    assert envelope.task_id.startswith("t_")
    assert "command" not in encoded
    assert "argv" not in encoded


def test_task_compiler_rejects_non_finite_or_non_positive_time_bounds() -> None:
    compiler = C2TaskCompiler()
    with pytest.raises(ValueError, match="issued_at"):
        compiler.compile(
            C2TaskOperationId.IDENTITY,
            IdentityTaskPayload(),
            agent_capabilities=_capabilities(),
            expected_agent_capabilities_revision=1,
            expected_agent_artifact_binding_digest="binding-digest",
            issued_at=float("nan"),
        )
    with pytest.raises(ValueError, match="ttl_seconds"):
        compiler.compile(
            C2TaskOperationId.IDENTITY,
            IdentityTaskPayload(),
            agent_capabilities=_capabilities(),
            expected_agent_capabilities_revision=1,
            expected_agent_artifact_binding_digest="binding-digest",
            ttl_seconds=0.0,
        )
