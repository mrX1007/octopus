"""Immutable canonical operation/payload/result mapping for V12 agents."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from core.c2.agent_result_models import (
    AgentHostInventoryTaskOutputV12,
    AgentIdentityTaskOutputV12,
    AgentNetworkInventoryTaskOutputV12,
    AgentServiceInventoryTaskOutputV12,
)
from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
    AgentTaskEnvelopeV12,
)
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.task_catalog import C2TaskOperationId


@dataclass(frozen=True)
class TaskOperationSpecV12:
    operation_id: C2TaskOperationId
    payload_schema_version: AgentPayloadSchemaIdV12
    result_schema_version: AgentResultSchemaIdV12
    payload_type: type[object]
    output_type: type[object]

    @property
    def payload_schema_id(self) -> str:
        """Compatibility projection for the pre-V12 compiler migration."""

        return self.payload_schema_version.value

    @property
    def result_schema_id(self) -> str:
        """Compatibility projection for the pre-V12 compiler migration."""

        return self.result_schema_version.value


_SPECS = MappingProxyType(
    {
        C2TaskOperationId.IDENTITY: TaskOperationSpecV12(
            operation_id=C2TaskOperationId.IDENTITY,
            payload_schema_version=AgentPayloadSchemaIdV12.IDENTITY_V1,
            result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
            payload_type=AgentIdentityTaskPayloadV12,
            output_type=AgentIdentityTaskOutputV12,
        ),
        C2TaskOperationId.HOST_INVENTORY: TaskOperationSpecV12(
            operation_id=C2TaskOperationId.HOST_INVENTORY,
            payload_schema_version=AgentPayloadSchemaIdV12.HOST_INVENTORY_V1,
            result_schema_version=AgentResultSchemaIdV12.HOST_INVENTORY_V1,
            payload_type=AgentHostInventoryTaskPayloadV12,
            output_type=AgentHostInventoryTaskOutputV12,
        ),
        C2TaskOperationId.NETWORK_INVENTORY: TaskOperationSpecV12(
            operation_id=C2TaskOperationId.NETWORK_INVENTORY,
            payload_schema_version=AgentPayloadSchemaIdV12.NETWORK_INVENTORY_V1,
            result_schema_version=AgentResultSchemaIdV12.NETWORK_INVENTORY_V1,
            payload_type=AgentNetworkInventoryTaskPayloadV12,
            output_type=AgentNetworkInventoryTaskOutputV12,
        ),
        C2TaskOperationId.SERVICE_INVENTORY: TaskOperationSpecV12(
            operation_id=C2TaskOperationId.SERVICE_INVENTORY,
            payload_schema_version=AgentPayloadSchemaIdV12.SERVICE_INVENTORY_V1,
            result_schema_version=AgentResultSchemaIdV12.SERVICE_INVENTORY_V1,
            payload_type=AgentServiceInventoryTaskPayloadV12,
            output_type=AgentServiceInventoryTaskOutputV12,
        ),
    }
)


class AgentTaskCatalogV12:
    """Read-only catalog for the four closed inventory V12 operations."""

    @staticmethod
    def get_spec(operation_id: C2TaskOperationId | str) -> TaskOperationSpecV12 | None:
        try:
            canonical = (
                C2TaskOperationId(operation_id)
                if type(operation_id) is str
                else operation_id
            )
        except ValueError:
            return None
        if type(canonical) is not C2TaskOperationId:
            return None
        return _SPECS.get(canonical)

    @classmethod
    def require_spec(cls, operation_id: C2TaskOperationId | str) -> TaskOperationSpecV12:
        spec = cls.get_spec(operation_id)
        if spec is None:
            raise ValueError(f"unsupported V12 agent operation: {operation_id!r}")
        return spec

    @classmethod
    def is_supported(cls, operation_id: C2TaskOperationId | str) -> bool:
        return cls.get_spec(operation_id) is not None

    @staticmethod
    def list_supported_operations() -> tuple[C2TaskOperationId, ...]:
        return tuple(_SPECS)

    @classmethod
    def validate_envelope(cls, envelope: AgentTaskEnvelopeV12) -> TaskOperationSpecV12:
        if type(envelope) is not AgentTaskEnvelopeV12:
            raise TypeError("expected an AgentTaskEnvelopeV12")
        spec = cls.require_spec(envelope.operation_id)
        if envelope.payload_schema_version is not spec.payload_schema_version:
            raise ValueError("operation/payload schema mapping is not canonical")
        if envelope.result_schema_version is not spec.result_schema_version:
            raise ValueError("operation/result schema mapping is not canonical")
        if type(envelope.payload) is not spec.payload_type:
            raise ValueError("operation/payload variant mapping is not canonical")
        if envelope.payload.schema_version != spec.payload_schema_version.value:
            raise ValueError("payload DTO schema does not match the envelope")
        return spec

    @classmethod
    def validate_output(
        cls,
        *,
        operation_id: C2TaskOperationId,
        result_schema_version: AgentResultSchemaIdV12,
        output: object,
    ) -> None:
        spec = cls.require_spec(operation_id)
        if result_schema_version is not spec.result_schema_version:
            raise ValueError("operation/result schema mapping is not canonical")
        if type(output) is not spec.output_type:
            raise ValueError("operation/output variant mapping is not canonical")
        if getattr(output, "schema_version", None) != result_schema_version.value:
            raise ValueError("output DTO schema does not match the result schema")


__all__ = [
    "AgentTaskCatalogV12",
    "C2TaskOperationId",
    "TaskOperationSpecV12",
]
