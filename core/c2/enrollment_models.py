"""Compatibility import surface for canonical PR-15 agent-wire DTOs.

The definitions live only in :mod:`core.c2.agent_task_models`. This module
retains the historical import path without creating a second model owner.
"""

from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
    AgentTaskDeliveryAckV12,
    AgentTaskEnvelopeV12,
    AgentTaskPayloadV12,
)

__all__ = [
    "AgentHostInventoryTaskPayloadV12",
    "AgentIdentityTaskPayloadV12",
    "AgentNetworkInventoryTaskPayloadV12",
    "AgentServiceInventoryTaskPayloadV12",
    "AgentTaskDeliveryAckV12",
    "AgentTaskEnvelopeV12",
    "AgentTaskPayloadV12",
]
