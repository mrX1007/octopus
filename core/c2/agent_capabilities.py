"""Agent capabilities re-exported from canonical V12 protocol owner."""

from __future__ import annotations

from core.c2.agent_protocol_v12 import (
    AgentCapabilitySetV12,
    AgentProtocolNegotiatorV12,
    AgentRegistrationV12,
    compute_capabilities_digest,
)

__all__ = [
    "AgentCapabilitySetV12",
    "AgentProtocolNegotiatorV12",
    "AgentRegistrationV12",
    "compute_capabilities_digest",
]
