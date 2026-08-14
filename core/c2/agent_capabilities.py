"""Agent capabilities."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentCapabilitySetV12:
    supported_operations: tuple[str, ...]
    supported_transports: tuple[str, ...]
    platform: str
    arch: str
    max_payload_bytes: int = 1_048_576


class AgentCapabilityNegotiatorV12:
    """Negotiates capabilities between agent and C2 server."""

    def negotiate_operations(
        self, agent_caps: AgentCapabilitySetV12, server_supported_ops: tuple[str, ...] | list[str]
    ) -> tuple[str, ...]:
        """Intersect supported operations."""
        server_set = set(server_supported_ops)
        negotiated = [op for op in agent_caps.supported_operations if op in server_set]
        return tuple(negotiated)

    def negotiate_transports(
        self, agent_caps: AgentCapabilitySetV12, server_transports: tuple[str, ...] | list[str]
    ) -> tuple[str, ...]:
        """Intersect supported transport mechanisms."""
        server_set = set(server_transports)
        negotiated = [t for t in agent_caps.supported_transports if t in server_set]
        return tuple(negotiated)
