"""Deep unit test coverage for ProviderMountRegistry, ProviderMountSpec validations, and ReadinessRegistry."""

from __future__ import annotations

import pytest

from core.actions.provider_mounts import (
    DefaultProviderMountRegistry,
    ProviderExecutionModeV2,
    ProviderMountSnapshotV2,
    ProviderMountSpec,
    ProviderTransport,
    V2ActionNotFoundInMountRegistry,
    get_provider_mount_registry,
)
from core.actions.readiness import (
    ProviderReadinessSnapshot,
    seal_provider_readiness_snapshot,
)
from core.actions.readiness_registry import (
    ReadinessRegistry,
)

pytestmark = pytest.mark.unit


def test_provider_mount_spec_validation_errors():
    # Invalid schema
    spec_bad_schema = ProviderMountSpec(
        schema_version="1.0",
        action_id="test:act",
        adapter_class="TestAdapter",
        adapter_api_version=2,
        provider_owner="test",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:test",
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=False,
    )
    with pytest.raises(ValueError, match="invalid_provider_mount_schema"):
        DefaultProviderMountRegistry._validate_spec(spec_bad_schema)

    # Invalid adapter API version
    spec_bad_api = ProviderMountSpec(
        schema_version="2.0",
        action_id="test:act",
        adapter_class="TestAdapter",
        adapter_api_version=1,  # type: ignore
        provider_owner="test",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="probe:test",
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=False,
    )
    with pytest.raises(ValueError, match="invalid_provider_adapter_api"):
        DefaultProviderMountRegistry._validate_spec(spec_bad_api)

    # Invalid probe ID prefix
    spec_bad_probe = ProviderMountSpec(
        schema_version="2.0",
        action_id="test:act",
        adapter_class="TestAdapter",
        adapter_api_version=2,
        provider_owner="test",
        provider_transport=ProviderTransport.IN_PROCESS,
        execution_mode=ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS,
        readiness_probe_id="invalid_probe_prefix",
        configured=True,
        mounted=False,
        typed_action_supported=True,
        raw_command_supported=False,
    )
    with pytest.raises(ValueError, match="invalid_readiness_probe_id"):
        DefaultProviderMountRegistry._validate_spec(spec_bad_probe)


def test_provider_mount_registry_require_and_assert():
    registry = get_provider_mount_registry()
    snaps = registry.snapshots()
    assert len(snaps) == 20

    # Nonexistent action
    with pytest.raises(V2ActionNotFoundInMountRegistry):
        registry.require_v2("nonexistent:action")

    # Stale mount snapshot assert_current
    first = snaps[0]
    tampered = ProviderMountSnapshotV2(
        spec=first.spec,
        revision=999,  # Stale revision
        mount_digest=first.mount_digest,
    )
    with pytest.raises(ValueError, match="invalid_provider_mount_digest"):
        registry.assert_current(tampered)


def test_readiness_registry_unregistered_and_cache():
    mount_reg = get_provider_mount_registry()
    registry = ReadinessRegistry(
        mount_registry=mount_reg,
        register_defaults=True,
    )
    mount = mount_reg.require_v2("killchain:ad_dump_lsass")

    # Probe snapshot evaluation
    snap = registry.probe(mount)
    assert snap.available is False

    # assert_current passes
    registry.assert_current(snap, mount)

    # Expiry validation
    expired_snap = ProviderReadinessSnapshot(
        action_id=snap.action_id,
        provider_id=snap.provider_id,
        mount_revision=snap.mount_revision,
        mount_digest=snap.mount_digest,
        probe_version=snap.probe_version,
        provider_generation=snap.provider_generation,
        daemon_instance_id=snap.daemon_instance_id,
        available=snap.available,
        checked_at_monotonic=snap.checked_at_monotonic,
        expires_at_monotonic=0.0,  # Expired
        dependency_states=snap.dependency_states,
        reason_codes=snap.reason_codes,
        snapshot_digest="",
    )

    sealed_expired = seal_provider_readiness_snapshot(expired_snap)
    with pytest.raises(ValueError, match="expired_readiness_snapshot"):
        registry.assert_current(sealed_expired, mount)
