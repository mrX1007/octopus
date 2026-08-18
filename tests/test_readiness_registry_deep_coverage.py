"""Unit tests for edge cases and branch coverage in readiness_registry.py."""

from __future__ import annotations

import pytest

from core.actions.provider_mounts import DefaultProviderMountRegistry
from core.actions.readiness_probes import _ReadinessProbeBase
from core.actions.readiness_registry import ReadinessRegistry

pytestmark = pytest.mark.unit


def test_readiness_registry_registration_and_errors():
    mount_reg = DefaultProviderMountRegistry()
    mount = mount_reg.snapshots()[0]

    registry = ReadinessRegistry(mount_registry=mount_reg, register_defaults=False)

    # Binding mismatch
    bad_probe = _ReadinessProbeBase("probe:WRONG", mount.spec.action_id)
    with pytest.raises(ValueError, match="readiness_probe_binding_mismatch"):
        registry.register_probe(bad_probe)

    # Valid registration
    valid_probe = _ReadinessProbeBase(mount.spec.readiness_probe_id, mount.spec.action_id)
    registry.register_probe(valid_probe)

    # Duplicate action registration without replace
    with pytest.raises(ValueError, match="duplicate_readiness_action_registration"):
        registry.register_probe(valid_probe, replace=False)

    # Replace registration
    registry.register_probe(valid_probe, replace=True)

    # Unregistered snapshot evaluation
    registry_empty = ReadinessRegistry(mount_registry=mount_reg, register_defaults=False)
    unreg_snap = registry_empty.probe(mount)
    assert unreg_snap.available is False
    assert "unregistered_readiness_probe" in unreg_snap.reason_codes

    # get_snapshot
    snap1 = registry.get_snapshot(mount.spec.action_id, force_recheck=False)
    snap2 = registry.get_snapshot(mount.spec.action_id, force_recheck=True)
    assert snap1.action_id == mount.spec.action_id
    assert snap2.action_id == mount.spec.action_id
