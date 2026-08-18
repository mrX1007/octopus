"""Canonical mount registry and generated-manifest rollout tests."""

from __future__ import annotations

import importlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.actions.provider_mounts import (
    DefaultProviderMountRegistry,
    ProviderMountSnapshotV2,
    V2ActionNotFoundInMountRegistry,
    canonical_provider_mount_snapshot_digest,
    get_provider_mount_registry,
)
from core.actions.schema_bindings import get_all_v2_schema_bindings
from scripts.quality.provider_mount_gate import generate_mount_manifest

pytestmark = pytest.mark.unit


def test_provider_mount_registry_has_20_v2_entries() -> None:
    registry = get_provider_mount_registry()
    snapshots = registry.snapshots()
    assert len(snapshots) == 20
    assert {snapshot.spec.action_id for snapshot in snapshots} == {
        binding.action_id for binding in get_all_v2_schema_bindings()
    }
    assert all(snapshot.spec.adapter_api_version == 2 for snapshot in snapshots)
    assert all(snapshot.spec.configured for snapshot in snapshots)
    assert all(snapshot.spec.typed_action_supported for snapshot in snapshots)
    assert not any(snapshot.spec.raw_command_supported for snapshot in snapshots)


def test_provider_rollout_does_not_claim_premature_mounts() -> None:
    snapshots = get_provider_mount_registry().snapshots()
    mounted_actions = {snapshot.spec.action_id for snapshot in snapshots if snapshot.spec.mounted}
    assert mounted_actions == {
        "c2:c2_enroll",
        "c2:c2_deploy",
        "c2:c2_task",
        "c2:c2_cleanup",
    }
    assert not any(
        snapshot.spec.action_id in ("c2:dns_c2_channel", "c2:c2_channel_create") and snapshot.spec.mounted
        for snapshot in snapshots
    )


def test_mount_revisions_digests_and_current_checks_are_exact() -> None:
    registry = get_provider_mount_registry()
    snapshots = registry.snapshots()
    assert len({snapshot.revision for snapshot in snapshots}) == 20
    assert len({snapshot.mount_digest for snapshot in snapshots}) == 20
    for snapshot in snapshots:
        assert snapshot.mount_digest == canonical_provider_mount_snapshot_digest(snapshot)
        registry.assert_current(snapshot)

    original = snapshots[0]
    forged = ProviderMountSnapshotV2(
        spec=replace(original.spec, provider_owner="forged-owner"),
        revision=original.revision,
        mount_digest=original.mount_digest,
    )
    with pytest.raises(ValueError, match="invalid_provider_mount_digest"):
        registry.assert_current(forged)


def test_provider_mount_adapter_wiring_resolves_exact_class() -> None:
    for snapshot in get_provider_mount_registry().snapshots():
        module_name, class_name = snapshot.spec.adapter_class.rsplit(".", 1)
        module = importlib.import_module(module_name)
        assert getattr(module, class_name).__name__ == class_name


def test_registry_rejects_v1_action_id() -> None:
    registry = get_provider_mount_registry()
    with pytest.raises(V2ActionNotFoundInMountRegistry, match="not_v2_action"):
        registry.require_v2("nmap")


def test_mounted_provider_cannot_be_unconfigured() -> None:
    original = get_provider_mount_registry().snapshots()[0].spec
    invalid = replace(original, configured=False, mounted=True)
    with pytest.raises(ValueError, match="mounted_provider_must_be_configured"):
        DefaultProviderMountRegistry((invalid,))


def test_manifest_snapshot_matches_runtime_registry() -> None:
    manifest_path = Path(__file__).resolve().parent.parent / "quality" / "provider-mounts.json"
    checked_in = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert checked_in == generate_mount_manifest()
    assert checked_in["entry_count"] == 20
    assert sum(1 for entry in checked_in["entries"] if entry["spec"]["mounted"]) == 4
    assert not any("available" in entry["spec"] for entry in checked_in["entries"])
