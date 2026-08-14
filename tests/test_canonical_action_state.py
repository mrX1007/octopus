"""PR-2 static state plus PR-3 readiness composition tests."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest

from core.actions.canonical_state import CanonicalActionState, CanonicalActionStaticState
from core.actions.models import ActionDescriptorV2
from core.actions.provider_mounts import get_provider_mount_registry
from core.actions.readiness_registry import get_readiness_registry
from core.actions.schema_bindings import get_v2_schema_binding
from core.actions.semantic_bindings import get_v2_semantic_binding

pytestmark = pytest.mark.unit


def _descriptor(action_id: str) -> ActionDescriptorV2:
    semantic = get_v2_semantic_binding(action_id)
    schema = get_v2_schema_binding(action_id)
    return ActionDescriptorV2(
        schema_version="2.0",
        action_id=semantic.action_id,
        name=semantic.name,
        aliases=semantic.aliases,
        input_schema_id=schema.input_schema_id,
        result_schema_id=schema.result_schema_id,
        kind=semantic.kind,
        execution_node_kind=semantic.execution_node_kind,
        capability_class=semantic.capability_class,
        risk_class=semantic.risk_class,
        required_fact_type_ids=semantic.required_fact_type_ids,
        killchain_stage=semantic.killchain_stage,
        manual_gate=semantic.manual_gate,
        check_policy=semantic.check_policy,
        verify_policy=semantic.verify_policy,
    )


def test_canonical_action_state_has_exact_composition_fields() -> None:
    assert tuple(field.name for field in fields(CanonicalActionStaticState)) == ("descriptor", "mount")
    assert tuple(field.name for field in fields(CanonicalActionState)) == ("static", "readiness")

    mount = get_provider_mount_registry().require_v2("plugin:payload_keying")
    static = CanonicalActionStaticState(descriptor=_descriptor(mount.spec.action_id), mount=mount)
    readiness = get_readiness_registry().probe(mount)
    state = CanonicalActionState(static=static, readiness=readiness)
    assert state.static.mount == mount


def test_canonical_static_state_rejects_action_mismatch() -> None:
    mount = get_provider_mount_registry().require_v2("plugin:payload_keying")
    descriptor = replace(_descriptor(mount.spec.action_id), action_id="killchain:pass_the_hash")
    with pytest.raises(ValueError, match="canonical_static_state_action_mismatch"):
        CanonicalActionStaticState(descriptor=descriptor, mount=mount)


def test_canonical_state_rejects_readiness_from_another_mount() -> None:
    mounts = get_provider_mount_registry()
    payload_mount = mounts.require_v2("plugin:payload_keying")
    task_mount = mounts.require_v2("c2:c2_task")
    static = CanonicalActionStaticState(descriptor=_descriptor(payload_mount.spec.action_id), mount=payload_mount)
    readiness = get_readiness_registry().probe(task_mount)
    with pytest.raises(ValueError, match="canonical_readiness_state_binding_mismatch"):
        CanonicalActionState(static=static, readiness=readiness)
