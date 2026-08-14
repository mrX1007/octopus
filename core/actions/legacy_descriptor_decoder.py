"""Explicit decoder migrating legacy V1 ActionDescriptor to ActionDescriptorV2."""

from __future__ import annotations

from core.actions.models import ActionDescriptorV2, LegacyActionDescriptorV1
from core.actions.provider_mounts import ProviderMountSpec, get_provider_mount_registry
from core.actions.schema_bindings import get_v2_schema_binding
from core.actions.semantic_bindings import get_v2_semantic_binding


def decode_legacy_descriptor_to_v2(
    legacy: LegacyActionDescriptorV1,
) -> tuple[ActionDescriptorV2, ProviderMountSpec]:
    """Decode V1 descriptor to V2 ActionDescriptorV2 and ProviderMountSpec.

    Discards legacy provider/provider_mounted fields and resolves V2 semantics
    and mount spec strictly via action_id. Rejects any action_id not registered
    in the 20-entry V2 registry.
    """
    semantic = get_v2_semantic_binding(legacy.action_id)
    schema_binding = get_v2_schema_binding(semantic.action_id)
    mount_registry = get_provider_mount_registry()
    mount_snapshot = mount_registry.require_v2(semantic.action_id)

    descriptor_v2 = ActionDescriptorV2(
        schema_version="2.0",
        action_id=semantic.action_id,
        name=semantic.name,
        aliases=semantic.aliases,
        input_schema_id=schema_binding.input_schema_id,
        result_schema_id=schema_binding.result_schema_id,
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
    return descriptor_v2, mount_snapshot.spec


__all__ = [
    "decode_legacy_descriptor_to_v2",
]
