"""Exact executor-owned V2 target extraction tests."""

from __future__ import annotations

import pytest

from core.actions.input_contracts import RemoteForwardInputV2, SSHChainHopInputV2, SSHChainInputV2
from core.actions.target_extraction import get_action_target_extractor_registry
from core.actions.target_scope import NetworkProtocol, TargetRole

pytestmark = pytest.mark.unit


def test_each_v2_input_has_target_schema() -> None:
    assert len(get_action_target_extractor_registry().bindings()) == 20


def test_nested_hops_target_schema() -> None:
    request = SSHChainInputV2(
        (
            SSHChainHopInputV2("jump1.example.test", "credential://ssh/1"),
            SSHChainHopInputV2("jump2.example.test", "credential://ssh/2", 2222),
        )
    )
    targets = get_action_target_extractor_registry().extract_checked(
        action_id="killchain:pivot_ssh_chain",
        input_schema_id="octopus:input:pivot_ssh_chain:2.0",
        decoded_input=request,
        reference_snapshots=(),
    )
    hops = tuple(target for target in targets if target.role is TargetRole.HOP)
    assert tuple(target.normalized_value for target in hops) == ("jump1.example.test", "jump2.example.test")
    assert tuple(target.port for target in hops) == (22, 2222)
    assert all(target.protocol is NetworkProtocol.SSH for target in hops)


def test_destination_target_schema() -> None:
    request = RemoteForwardInputV2("session://1", "jump.example.test", 8080, "dest.example.test", 443)
    targets = get_action_target_extractor_registry().extract_checked(
        action_id="killchain:pivot_remote_forward",
        input_schema_id="octopus:input:pivot_remote_forward:2.0",
        decoded_input=request,
        reference_snapshots=(),
    )
    destination = next(target for target in targets if target.role is TargetRole.DESTINATION)
    assert (destination.normalized_value, destination.port) == ("dest.example.test", 443)


def test_target_registry_rejects_wrong_runtime_type() -> None:
    registry = get_action_target_extractor_registry()
    with pytest.raises(TypeError, match="runtime type mismatch"):
        registry.extract_checked(
            action_id="killchain:pivot_remote_forward",
            input_schema_id="octopus:input:pivot_remote_forward:2.0",
            decoded_input={"target": "forged"},
            reference_snapshots=(),
        )
