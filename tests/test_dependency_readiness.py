"""Dependency readiness is closed, immutable and environment-only."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from core.actions.provider_mounts import get_provider_mount_registry
from core.actions.readiness import DependencyKindV2, DependencyReadiness, DependencyStateV2
from core.actions.readiness_registry import get_readiness_registry

pytestmark = pytest.mark.unit


def test_dependency_readiness_creation() -> None:
    dependency = DependencyReadiness(
        dependency_id="python3",
        kind=DependencyKindV2.SYSTEM_BINARY,
        state=DependencyStateV2.AVAILABLE,
        observed_version="present",
        required_version=None,
        reason_codes=(),
    )
    assert dependency.dependency_id == "python3"
    with pytest.raises(FrozenInstanceError):
        dependency.state = DependencyStateV2.MISSING  # type: ignore[misc]


def test_missing_request_resource_is_not_readiness_failure() -> None:
    mount = get_provider_mount_registry().require_v2("killchain:pivot_remote_forward")
    snapshot = get_readiness_registry().recheck(mount)
    serialized = repr(snapshot).casefold()
    assert "session_ref" not in serialized
    assert "route_ref" not in serialized
    assert "credential_ref" not in serialized
    assert all(
        dependency.kind
        in {
            DependencyKindV2.PYTHON_IMPORT,
            DependencyKindV2.SYSTEM_BINARY,
            DependencyKindV2.PLATFORM,
            DependencyKindV2.DAEMON_PROTOCOL,
            DependencyKindV2.PROVIDER_INITIALIZATION,
        }
        for dependency in snapshot.dependency_states
    )
