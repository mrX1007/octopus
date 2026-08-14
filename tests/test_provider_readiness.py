"""Exact provider-readiness value and environment probe tests."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.actions.provider_mounts import get_provider_mount_registry
from core.actions.readiness import (
    DependencyKindV2,
    DependencyReadiness,
    DependencyStateV2,
    ProviderReadinessSnapshot,
    canonical_provider_readiness_digest,
)
from core.actions.readiness_probes import (
    BinaryProbe,
    CompositeLeafProbe,
    DaemonProtocolProbe,
    PlatformProbe,
    PythonImportProbe,
)

pytestmark = pytest.mark.unit


def test_readiness_contract_has_exact_fields_and_enum_values() -> None:
    assert {item.value for item in DependencyKindV2} == {
        "python_import",
        "system_binary",
        "platform",
        "daemon_protocol",
        "provider_initialization",
    }
    assert {item.value for item in DependencyStateV2} == {
        "available",
        "missing",
        "incompatible",
        "error",
    }
    assert tuple(field.name for field in fields(DependencyReadiness)) == (
        "dependency_id",
        "kind",
        "state",
        "observed_version",
        "required_version",
        "reason_codes",
    )
    assert tuple(field.name for field in fields(ProviderReadinessSnapshot)) == (
        "action_id",
        "provider_id",
        "mount_revision",
        "mount_digest",
        "probe_version",
        "provider_generation",
        "daemon_instance_id",
        "available",
        "checked_at_monotonic",
        "expires_at_monotonic",
        "dependency_states",
        "reason_codes",
        "snapshot_digest",
    )


def test_python_import_probe_missing_required_dependency() -> None:
    mount = get_provider_mount_registry().require_v2("plugin:payload_keying")
    probe = PythonImportProbe(
        mount.spec.readiness_probe_id,
        mount.spec.action_id,
        ("octopus_module_that_does_not_exist",),
    )
    snapshot = probe.evaluate(mount)
    assert snapshot.available is False
    assert snapshot.reason_codes == ("missing_python_import:octopus_module_that_does_not_exist",)
    assert snapshot.snapshot_digest == canonical_provider_readiness_digest(snapshot)


@pytest.mark.parametrize("probe_type", [PythonImportProbe, BinaryProbe])
def test_empty_dependency_probe_fails_closed(probe_type: type[PythonImportProbe] | type[BinaryProbe]) -> None:
    mount = get_provider_mount_registry().require_v2("plugin:payload_keying")
    probe = probe_type(mount.spec.readiness_probe_id, mount.spec.action_id, ())
    snapshot = probe.evaluate(mount)
    assert snapshot.available is False
    assert snapshot.reason_codes == ("empty_dependency_probe",)
    assert snapshot.dependency_states[0].kind is DependencyKindV2.PROVIDER_INITIALIZATION


def test_missing_binary_is_readiness_failure() -> None:
    mount = get_provider_mount_registry().require_v2("killchain:kerberos_crack_tickets")
    probe = BinaryProbe(
        mount.spec.readiness_probe_id,
        mount.spec.action_id,
        ("octopus-binary-that-does-not-exist",),
    )
    assert probe.evaluate(mount).available is False


def test_daemon_without_authenticated_status_supplier_is_unavailable() -> None:
    mount = get_provider_mount_registry().require_v2("c2:c2_task")
    probe = DaemonProtocolProbe(
        mount.spec.readiness_probe_id,
        mount.spec.action_id,
        "12.0",
        None,
    )
    snapshot = probe.evaluate(mount)
    assert snapshot.available is False
    assert snapshot.reason_codes == ("daemon_protocol_unverified",)


def test_composite_readiness_from_leafs() -> None:
    mount = get_provider_mount_registry().require_v2("killchain:ad_remote_execution")
    unavailable = PlatformProbe("probe:leaf-a", "leaf:a", ("supported",), platform_supplier=lambda: "other")
    available = PlatformProbe("probe:leaf-b", "leaf:b", ("supported",), platform_supplier=lambda: "supported")
    composite = CompositeLeafProbe(
        mount.spec.readiness_probe_id,
        mount.spec.action_id,
        (unavailable, available),
    )
    assert composite.evaluate(mount).available is True


def test_readiness_probe_id_must_match_mount_exactly() -> None:
    mount = get_provider_mount_registry().require_v2("plugin:payload_keying")
    probe = PythonImportProbe("probe:wrong", mount.spec.action_id, ("sys",))
    with pytest.raises(ValueError, match="readiness_probe_binding_mismatch"):
        probe.evaluate(mount)
