"""Unit tests for readiness_probes.py coverage."""

from __future__ import annotations

import pytest

from core.actions.readiness_probes import (
    CompositeLeafProbe,
    DaemonProtocolProbe,
    DaemonProtocolStatus,
    ProbeObservation,
    _ReadinessProbeBase,
)

pytestmark = pytest.mark.unit


def test_readiness_probe_base_validations():
    with pytest.raises(ValueError, match="invalid_readiness_probe_id"):
        _ReadinessProbeBase("not_a_probe", "act-1")

    with pytest.raises(ValueError, match="readiness_action_id_required"):
        _ReadinessProbeBase("probe:1", "")

    with pytest.raises(ValueError, match="readiness_probe_version_required"):
        _ReadinessProbeBase("probe:1", "act-1", probe_version="")

    with pytest.raises(ValueError, match="readiness_ttl_must_be_positive"):
        _ReadinessProbeBase("probe:1", "act-1", ttl_seconds=0.0)

    # Empty provider generation
    probe = _ReadinessProbeBase("probe:1", "act-1", provider_generation="")
    with pytest.raises(ValueError, match="empty_provider_generation"):
        probe._generation()


def test_readiness_probe_evaluate_exception():
    from core.actions.provider_mounts import DefaultProviderMountRegistry

    class ExceptionProbe(_ReadinessProbeBase):
        def inspect(self) -> ProbeObservation:
            raise RuntimeError("probe exploded")

    registry = DefaultProviderMountRegistry()
    first_mount = registry.snapshots()[0]

    probe = ExceptionProbe(first_mount.spec.readiness_probe_id, first_mount.spec.action_id)
    snapshot = probe.evaluate(first_mount)
    assert snapshot.available is False
    assert any("probe_error:RuntimeError" in r for r in snapshot.reason_codes)


def test_daemon_protocol_readiness_probe_branches():
    with pytest.raises(ValueError, match="daemon_protocol_version_required"):
        DaemonProtocolProbe("probe:c2", "act-1", required_protocol_version="", status_supplier=None)

    # Reachable but incompatible version
    status_incompat = DaemonProtocolStatus(
        reachable=True,
        protocol_version="1.0",
        daemon_instance_id="inst-1",
        provider_generation="gen-1",
    )
    probe_incompat = DaemonProtocolProbe(
        "probe:c2",
        "act-1",
        required_protocol_version="2.0",
        status_supplier=lambda: status_incompat,
    )
    obs = probe_incompat.inspect()
    assert obs.available is False
    assert "daemon_protocol_incompatible" in obs.reason_codes

    # Reachable with matching version but missing instance id
    status_no_inst = DaemonProtocolStatus(
        reachable=True,
        protocol_version="2.0",
        daemon_instance_id="",
        provider_generation="gen-1",
    )
    probe_no_inst = DaemonProtocolProbe(
        "probe:c2",
        "act-1",
        required_protocol_version="2.0",
        status_supplier=lambda: status_no_inst,
    )
    obs_no_inst = probe_no_inst.inspect()
    assert obs_no_inst.available is False
    assert "daemon_instance_id_missing" in obs_no_inst.reason_codes


def test_composite_leaf_probe_empty():
    composite = CompositeLeafProbe("probe:comp", "act-1", leaf_probes=())
    obs = composite.inspect()
    assert obs.available is False
    assert "empty_dependency_probe" in obs.reason_codes
