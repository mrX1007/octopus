"""Tests for C2 agent capability negotiation and protocol V12 (§15.1)."""

from __future__ import annotations

import pytest

from core.c2.agent_capabilities import AgentCapabilitySetV12, AgentProtocolNegotiatorV12
from core.c2.agent_task_protocol import (
    C2_AGENT_PROTOCOL_V11,
    C2_AGENT_PROTOCOL_V12,
    AgentPayloadSchemaIdV12,
    AgentResultSchemaIdV12,
)
from core.c2.task_catalog import C2TaskOperationId

pytestmark = pytest.mark.unit


def test_agent_capability_negotiation_profile():
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

    neg = AgentProtocolNegotiatorV12()
    assert neg.negotiate_protocol([C2_AGENT_PROTOCOL_V11, C2_AGENT_PROTOCOL_V12]) == C2_AGENT_PROTOCOL_V12
    assert neg.negotiate_protocol([C2_AGENT_PROTOCOL_V11]) == C2_AGENT_PROTOCOL_V11
