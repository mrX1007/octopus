"""Tests for agent capabilities re-export and canonical V12 definitions."""

from __future__ import annotations

import pytest

from core.c2.agent_capabilities import (
    AgentCapabilitySetV12,
    AgentProtocolNegotiatorV12,
    compute_capabilities_digest,
)
from core.c2.agent_task_protocol import (
    C2_AGENT_PROTOCOL_V11,
    C2_AGENT_PROTOCOL_V12,
    AgentPayloadSchemaIdV12,
    AgentResultSchemaIdV12,
)
from core.c2.task_catalog import C2TaskOperationId

pytestmark = pytest.mark.unit


def test_capability_set_canonical_create():
    caps = AgentCapabilitySetV12.create(
        supported_operation_ids=(
            C2TaskOperationId.IDENTITY,
            C2TaskOperationId.HOST_INVENTORY,
        ),
        supported_payload_schema_versions=(
            AgentPayloadSchemaIdV12.IDENTITY_V1,
            AgentPayloadSchemaIdV12.HOST_INVENTORY_V1,
        ),
        supported_result_schema_versions=(
            AgentResultSchemaIdV12.IDENTITY_V1,
            AgentResultSchemaIdV12.HOST_INVENTORY_V1,
        ),
    )
    assert C2TaskOperationId.IDENTITY in caps.supported_operation_ids
    assert C2TaskOperationId.HOST_INVENTORY in caps.supported_operation_ids
    expected_digest = compute_capabilities_digest(
        supported_operation_ids=caps.supported_operation_ids,
        supported_payload_schema_versions=caps.supported_payload_schema_versions,
        supported_result_schema_versions=caps.supported_result_schema_versions,
    )
    assert caps.capabilities_digest == expected_digest


def test_agent_protocol_negotiator_v12_reexport():
    negotiator = AgentProtocolNegotiatorV12()
    assert negotiator.negotiate_protocol([C2_AGENT_PROTOCOL_V11, C2_AGENT_PROTOCOL_V12]) == C2_AGENT_PROTOCOL_V12
    assert negotiator.negotiate_protocol([C2_AGENT_PROTOCOL_V11]) == C2_AGENT_PROTOCOL_V11
    with pytest.raises(ValueError, match="no compatible agent protocol version"):
        negotiator.negotiate_protocol(["9.0"])
