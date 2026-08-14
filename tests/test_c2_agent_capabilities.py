"""Tests for agent capabilities negotiation."""

from __future__ import annotations

import pytest

from core.c2.agent_capabilities import (
    AgentCapabilityNegotiatorV12,
    AgentCapabilitySetV12,
)

pytestmark = pytest.mark.unit


def test_capability_set_dataclass():
    caps = AgentCapabilitySetV12(
        supported_operations=("exec", "file_read", "cleanup"),
        supported_transports=("http", "dns"),
        platform="darwin",
        arch="arm64",
    )
    assert caps.platform == "darwin"
    assert caps.arch == "arm64"
    assert "exec" in caps.supported_operations


def test_negotiate_operations():
    negotiator = AgentCapabilityNegotiatorV12()
    agent_caps = AgentCapabilitySetV12(
        supported_operations=("exec", "file_read", "custom_op"),
        supported_transports=("http",),
        platform="linux",
        arch="amd64",
    )
    server_ops = ("exec", "file_read", "file_write")

    agreed = negotiator.negotiate_operations(agent_caps, server_ops)
    assert agreed == ("exec", "file_read")
    assert "custom_op" not in agreed


def test_negotiate_transports():
    negotiator = AgentCapabilityNegotiatorV12()
    agent_caps = AgentCapabilitySetV12(
        supported_operations=("exec",),
        supported_transports=("http", "dns", "icmp"),
        platform="windows",
        arch="amd64",
    )
    server_transports = ("http", "dns")

    agreed = negotiator.negotiate_transports(agent_caps, server_transports)
    assert agreed == ("http", "dns")
    assert "icmp" not in agreed
