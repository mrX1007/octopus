"""TTL, freshness, generation and concurrency tests for readiness registry."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from core.actions.provider_mounts import ProviderMountSnapshotV2, get_provider_mount_registry
from core.actions.readiness_probes import PlatformProbe
from core.actions.readiness_registry import ReadinessRegistry

pytestmark = pytest.mark.unit


def _platform_registry(
    *,
    clock: list[float],
    observed: list[str],
    generation: list[str],
) -> tuple[ReadinessRegistry, ProviderMountSnapshotV2]:
    mounts = get_provider_mount_registry()
    mount = mounts.require_v2("plugin:payload_keying")
    registry = ReadinessRegistry(mount_registry=mounts, register_defaults=False, clock=lambda: clock[0])
    registry.register_probe(
        PlatformProbe(
            mount.spec.readiness_probe_id,
            mount.spec.action_id,
            ("ready",),
            ttl_seconds=5.0,
            platform_supplier=lambda: observed[0],
            provider_generation=lambda: generation[0],
            clock=lambda: clock[0],
        )
    )
    return registry, mount


def test_readiness_is_dynamic() -> None:
    now, observed, generation = [10.0], ["ready"], ["generation-1"]
    registry, mount = _platform_registry(clock=now, observed=observed, generation=generation)
    first = registry.probe(mount)
    observed[0] = "not-ready"
    generation[0] = "generation-2"
    second = registry.recheck(mount)
    assert first.available is True
    assert second.available is False
    assert second.provider_generation == "generation-2"
    with pytest.raises(ValueError, match="stale_readiness_snapshot"):
        registry.assert_current(first, mount)


def test_readiness_cache_expires() -> None:
    now, observed, generation = [10.0], ["ready"], ["generation-1"]
    registry, mount = _platform_registry(clock=now, observed=observed, generation=generation)
    first = registry.probe(mount)
    observed[0] = "not-ready"
    assert registry.probe(mount) is first
    now[0] = 16.0
    after_expiry = registry.probe(mount)
    assert after_expiry is not first
    assert after_expiry.available is False


def test_assert_current_recomputes_digest_and_rejects_tampering() -> None:
    now, observed, generation = [10.0], ["ready"], ["generation-1"]
    registry, mount = _platform_registry(clock=now, observed=observed, generation=generation)
    snapshot = registry.probe(mount)
    tampered = replace(snapshot, available=False)
    with pytest.raises(ValueError, match="invalid_readiness_snapshot_digest"):
        registry.assert_current(tampered, mount)


def test_readiness_cache_is_thread_safe() -> None:
    now, observed, generation = [10.0], ["ready"], ["generation-1"]
    registry, mount = _platform_registry(clock=now, observed=observed, generation=generation)
    with ThreadPoolExecutor(max_workers=8) as executor:
        snapshots = tuple(executor.map(lambda _index: registry.probe(mount), range(32)))
    assert len({id(snapshot) for snapshot in snapshots}) == 1


def test_wrong_mount_snapshot_is_rejected_before_probe() -> None:
    now, observed, generation = [10.0], ["ready"], ["generation-1"]
    registry, mount = _platform_registry(clock=now, observed=observed, generation=generation)
    forged = replace(mount, revision=mount.revision + 1)
    with pytest.raises(ValueError):
        registry.probe(forged)
