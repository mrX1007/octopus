"""Exact canonical mapping tests for the V12 agent task catalog."""

from __future__ import annotations

import pytest

from core.c2.agent_result_models import (
    AgentHostInventoryTaskOutputV12,
    AgentIdentityTaskOutputV12,
    AgentNetworkInventoryTaskOutputV12,
    AgentServiceInventoryTaskOutputV12,
)
from core.c2.agent_task_catalog import AgentTaskCatalogV12
from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
)
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.task_catalog import C2TaskOperationId

pytestmark = pytest.mark.unit


def test_agent_task_catalog_has_only_four_closed_operations() -> None:
    assert AgentTaskCatalogV12.list_supported_operations() == (
        C2TaskOperationId.IDENTITY,
        C2TaskOperationId.HOST_INVENTORY,
        C2TaskOperationId.NETWORK_INVENTORY,
        C2TaskOperationId.SERVICE_INVENTORY,
    )
    assert not AgentTaskCatalogV12.is_supported("exec")
    assert not AgentTaskCatalogV12.is_supported("file_read")


@pytest.mark.parametrize(
    ("operation", "payload_schema", "result_schema", "payload_type", "output_type"),
    (
        (
            C2TaskOperationId.IDENTITY,
            AgentPayloadSchemaIdV12.IDENTITY_V1,
            AgentResultSchemaIdV12.IDENTITY_V1,
            AgentIdentityTaskPayloadV12,
            AgentIdentityTaskOutputV12,
        ),
        (
            C2TaskOperationId.HOST_INVENTORY,
            AgentPayloadSchemaIdV12.HOST_INVENTORY_V1,
            AgentResultSchemaIdV12.HOST_INVENTORY_V1,
            AgentHostInventoryTaskPayloadV12,
            AgentHostInventoryTaskOutputV12,
        ),
        (
            C2TaskOperationId.NETWORK_INVENTORY,
            AgentPayloadSchemaIdV12.NETWORK_INVENTORY_V1,
            AgentResultSchemaIdV12.NETWORK_INVENTORY_V1,
            AgentNetworkInventoryTaskPayloadV12,
            AgentNetworkInventoryTaskOutputV12,
        ),
        (
            C2TaskOperationId.SERVICE_INVENTORY,
            AgentPayloadSchemaIdV12.SERVICE_INVENTORY_V1,
            AgentResultSchemaIdV12.SERVICE_INVENTORY_V1,
            AgentServiceInventoryTaskPayloadV12,
            AgentServiceInventoryTaskOutputV12,
        ),
    ),
)
def test_agent_task_catalog_mapping_is_exact(
    operation: C2TaskOperationId,
    payload_schema: AgentPayloadSchemaIdV12,
    result_schema: AgentResultSchemaIdV12,
    payload_type: type[object],
    output_type: type[object],
) -> None:
    spec = AgentTaskCatalogV12.require_spec(operation)
    assert spec.payload_schema_version is payload_schema
    assert spec.result_schema_version is result_schema
    assert spec.payload_type is payload_type
    assert spec.output_type is output_type


def test_unknown_operation_or_payload_schema_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        AgentTaskCatalogV12.require_spec("unknown")
