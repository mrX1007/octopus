"""Tests for ActionDescriptorV1 and ActionDescriptorV2 model isolation."""

from __future__ import annotations

import pytest

from core.actions.models import (
    ActionDescriptor,
    ActionDescriptorV2,
    ActionKind,
    CheckPolicyV2,
    ExecutionNodeKind,
    LegacyActionDescriptorV1,
    VerifyPolicyV2,
)

pytestmark = pytest.mark.unit


def test_legacy_action_descriptor_v1_alias() -> None:
    assert LegacyActionDescriptorV1 is ActionDescriptor


def test_action_descriptor_v2_has_no_provider_fields() -> None:
    v2 = ActionDescriptorV2(
        schema_version="2.0",
        action_id="plugin:payload_keying",
        name="Payload Keying",
        aliases=(),
        input_schema_id="octopus:input:payload_keying:2.0",
        result_schema_id="octopus:result:payload_keying:2.0",
        kind=ActionKind.PLUGIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="evasion",
        risk_class="high",
        required_fact_type_ids=(),
        killchain_stage="weaponization",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    )

    assert v2.schema_version == "2.0"
    assert v2.action_id == "plugin:payload_keying"
    assert not hasattr(v2, "provider")
    assert not hasattr(v2, "provider_mounted")
