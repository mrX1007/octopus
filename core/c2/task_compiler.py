"""Closed control-plane to V12 agent-wire task compilation."""

from __future__ import annotations

import math
import time
import uuid

from typing_extensions import assert_never

from core.c2.agent_protocol_v12 import AgentCapabilitySetV12
from core.c2.agent_task_catalog import AgentTaskCatalogV12
from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
    AgentTaskEnvelopeV12,
    AgentTaskPayloadV12,
)
from core.c2.agent_task_protocol import C2_TASK_SCHEMA_V12
from core.c2.task_catalog import (
    C2TaskOperationId,
    C2TaskPayload,
    HostInventoryTaskPayload,
    IdentityTaskPayload,
    NetworkInventoryTaskPayload,
    ServiceInventoryTaskPayload,
    TaskOperationCatalog,
)


class C2TaskCompiler:
    """Compile one of the four closed control DTOs into an exact V12 envelope."""

    def __init__(self, catalog: AgentTaskCatalogV12 | None = None) -> None:
        self._agent_catalog = catalog if catalog is not None else AgentTaskCatalogV12()
        self._control_catalog = TaskOperationCatalog()

    def compile(
        self,
        operation_id: C2TaskOperationId,
        payload: C2TaskPayload,
        *,
        agent_capabilities: AgentCapabilitySetV12,
        expected_agent_capabilities_revision: int,
        expected_agent_artifact_binding_digest: str,
        task_id: str | None = None,
        issued_at: float | None = None,
        ttl_seconds: float = 600.0,
        delivery_attempt: int = 1,
    ) -> AgentTaskEnvelopeV12:
        """Select the canonical triple and fail if the agent did not advertise it."""

        if type(operation_id) is not C2TaskOperationId:
            raise TypeError("operation_id must be a canonical C2TaskOperationId")
        if type(agent_capabilities) is not AgentCapabilitySetV12:
            raise TypeError("agent_capabilities must be AgentCapabilitySetV12")
        self._control_catalog.validate(operation_id, payload)
        spec = self._agent_catalog.require_spec(operation_id)

        if operation_id not in agent_capabilities.supported_operation_ids:
            raise ValueError("agent does not advertise the selected operation")
        if spec.payload_schema_version not in agent_capabilities.supported_payload_schema_versions:
            raise ValueError("agent does not advertise the selected payload schema")
        if spec.result_schema_version not in agent_capabilities.supported_result_schema_versions:
            raise ValueError("agent does not advertise the selected result schema")

        now = time.time() if issued_at is None else _require_finite_number(issued_at, "issued_at")
        ttl = _require_finite_number(ttl_seconds, "ttl_seconds")
        if ttl <= 0:
            raise ValueError("ttl_seconds must be greater than zero")

        envelope = AgentTaskEnvelopeV12(
            schema_version=C2_TASK_SCHEMA_V12,
            task_id=task_id if task_id is not None else f"t_{uuid.uuid4().hex}",
            operation_id=operation_id,
            payload_schema_version=spec.payload_schema_version,
            result_schema_version=spec.result_schema_version,
            expected_agent_capabilities_revision=expected_agent_capabilities_revision,
            expected_agent_capabilities_digest=agent_capabilities.capabilities_digest,
            expected_agent_artifact_binding_digest=expected_agent_artifact_binding_digest,
            payload=_compile_payload(payload),
            issued_at=now,
            expires_at=now + ttl,
            delivery_attempt=delivery_attempt,
        )
        self._agent_catalog.validate_envelope(envelope)
        return envelope


def _require_finite_number(value: object, field_name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{field_name} must be a finite number")
    assert isinstance(value, (int, float))
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError(f"{field_name} must be a finite number")
    return normalized


def _compile_payload(payload: C2TaskPayload) -> AgentTaskPayloadV12:
    if isinstance(payload, IdentityTaskPayload):
        if type(payload) is not IdentityTaskPayload:
            raise TypeError("control payload must be an exact closed variant")
        return AgentIdentityTaskPayloadV12()
    if isinstance(payload, HostInventoryTaskPayload):
        if type(payload) is not HostInventoryTaskPayload:
            raise TypeError("control payload must be an exact closed variant")
        return AgentHostInventoryTaskPayloadV12(
            include_processes=payload.include_processes,
            include_services=payload.include_services,
            max_items=payload.max_items,
        )
    if isinstance(payload, NetworkInventoryTaskPayload):
        if type(payload) is not NetworkInventoryTaskPayload:
            raise TypeError("control payload must be an exact closed variant")
        return AgentNetworkInventoryTaskPayloadV12(
            include_routes=payload.include_routes,
            include_connections=payload.include_connections,
            max_items=payload.max_items,
        )
    if isinstance(payload, ServiceInventoryTaskPayload):
        if type(payload) is not ServiceInventoryTaskPayload:
            raise TypeError("control payload must be an exact closed variant")
        return AgentServiceInventoryTaskPayloadV12(
            service_names=payload.service_names,
            include_status=payload.include_status,
        )
    assert_never(payload)


__all__ = ["C2TaskCompiler"]
