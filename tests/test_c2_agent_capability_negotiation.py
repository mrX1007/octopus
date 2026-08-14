"""Tests for C2 agent capability negotiation and protocol V12 (§15.1)."""

from __future__ import annotations

import pytest
from core.c2.agent_capabilities import AgentCapabilityNegotiatorV12, AgentCapabilitySetV12
from core.c2.task_catalog import C2TaskOperationId

pytestmark = pytest.mark.unit


def test_agent_capability_negotiation_profile():
    caps = AgentCapabilitySetV12(
        supported_operations=(C2TaskOperationId.IDENTITY.value, C2TaskOperationId.HOST_INVENTORY.value),
        supported_transports=("https", "dns"),
        platform="linux",
        arch="x86_64",
    )
    assert C2TaskOperationId.IDENTITY.value in caps.supported_operations
    assert "https" in caps.supported_transports

    neg = AgentCapabilityNegotiatorV12()
    ops = neg.negotiate_operations(caps, [C2TaskOperationId.IDENTITY.value])
    assert ops == (C2TaskOperationId.IDENTITY.value,)
