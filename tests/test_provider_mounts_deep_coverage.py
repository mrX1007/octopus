"""Unit tests for provider_mounts.py validations and branch coverage."""

from __future__ import annotations

import pytest

from core.actions.provider_mounts import (
    DefaultProviderMountRegistry,
    ProviderExecutionModeV2,
    ProviderMountSnapshotV2,
    ProviderMountSpec,
    ProviderTransport,
)

pytestmark = pytest.mark.unit


def test_provider_mount_spec_validations():
    base_spec = ProviderMountSpec(
        schema_version="2.0",
        action_id="act.1",
        adapter_class="Adapter1",
        adapter_api_version=2,
        provider_owner="owner1",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:1",
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=False,
    )

    # Duplicate action id
    with pytest.raises(ValueError, match="duplicate_v2_action_id"):
        DefaultProviderMountRegistry(mount_specs=(base_spec, base_spec))

    # Duplicate readiness probe id
    spec2 = ProviderMountSpec(
        schema_version="2.0",
        action_id="act.2",
        adapter_class="Adapter2",
        adapter_api_version=2,
        provider_owner="owner2",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:1",  # duplicate probe
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=False,
    )
    with pytest.raises(ValueError, match="duplicate_readiness_probe_id"):
        DefaultProviderMountRegistry(mount_specs=(base_spec, spec2))

    # Duplicate adapter class
    spec3 = ProviderMountSpec(
        schema_version="2.0",
        action_id="act.3",
        adapter_class="Adapter1",  # duplicate adapter
        adapter_api_version=2,
        provider_owner="owner3",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:3",
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=False,
    )
    with pytest.raises(ValueError, match="duplicate_v2_adapter_owner"):
        DefaultProviderMountRegistry(mount_specs=(base_spec, spec3))

    # Duplicate provider owner
    spec4 = ProviderMountSpec(
        schema_version="2.0",
        action_id="act.4",
        adapter_class="Adapter4",
        adapter_api_version=2,
        provider_owner="owner1",  # duplicate owner
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:4",
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=False,
    )
    with pytest.raises(ValueError, match="duplicate_v2_provider_owner"):
        DefaultProviderMountRegistry(mount_specs=(base_spec, spec4))

    # Typed action not supported
    spec_not_typed = ProviderMountSpec(
        schema_version="2.0",
        action_id="act.5",
        adapter_class="Adapter5",
        adapter_api_version=2,
        provider_owner="owner5",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:5",
        configured=True,
        mounted=False,
        typed_action_supported=False,
        raw_command_supported=False,
    )
    with pytest.raises(ValueError, match="v2_provider_must_support_typed_action"):
        DefaultProviderMountRegistry(mount_specs=(spec_not_typed,))

    # Raw command supported
    spec_raw = ProviderMountSpec(
        schema_version="2.0",
        action_id="act.6",
        adapter_class="Adapter6",
        adapter_api_version=2,
        provider_owner="owner6",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:6",
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=True,
    )
    with pytest.raises(ValueError, match="v2_provider_raw_command_forbidden"):
        DefaultProviderMountRegistry(mount_specs=(spec_raw,))


def test_provider_mount_assert_current_stale():
    reg = DefaultProviderMountRegistry()
    first_snap = reg.snapshots()[0]

    # Stale snapshot with modified revision
    stale_snap = ProviderMountSnapshotV2(
        spec=first_snap.spec,
        revision=999,
        mount_digest=first_snap.mount_digest,
    )
    with pytest.raises(ValueError):
        reg.assert_current(stale_snap)
