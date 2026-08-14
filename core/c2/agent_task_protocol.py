"""Canonical protocol and schema identifiers for the V12 agent wire.

This PR-6-owned module deliberately contains identifiers only. The task,
result, delivery, and framing DTOs are owned by the PR-15 modules and import
these definitions rather than declaring aliases.
"""

from __future__ import annotations

from enum import Enum
from typing import Final, Literal

C2_AGENT_PROTOCOL_V11: Final[Literal["11.0"]] = "11.0"
C2_AGENT_PROTOCOL_V12: Final[Literal["12.0"]] = "12.0"
C2_TASK_SCHEMA_V12: Final[Literal["12.0"]] = "12.0"


class AgentPayloadSchemaIdV12(str, Enum):
    IDENTITY_V1 = "c2-agent-payload/identity/1"
    HOST_INVENTORY_V1 = "c2-agent-payload/host-inventory/1"
    NETWORK_INVENTORY_V1 = "c2-agent-payload/network-inventory/1"
    SERVICE_INVENTORY_V1 = "c2-agent-payload/service-inventory/1"


class AgentResultSchemaIdV12(str, Enum):
    IDENTITY_V1 = "c2-agent-result/identity/1"
    HOST_INVENTORY_V1 = "c2-agent-result/host-inventory/1"
    NETWORK_INVENTORY_V1 = "c2-agent-result/network-inventory/1"
    SERVICE_INVENTORY_V1 = "c2-agent-result/service-inventory/1"


__all__ = [
    "C2_AGENT_PROTOCOL_V11",
    "C2_AGENT_PROTOCOL_V12",
    "C2_TASK_SCHEMA_V12",
    "AgentPayloadSchemaIdV12",
    "AgentResultSchemaIdV12",
]
