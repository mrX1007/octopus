"""Thread-safe PR-3 readiness registry with monotonic TTL caching."""

from __future__ import annotations

import hmac
import sys
import time
from collections.abc import Callable
from threading import RLock
from typing import Protocol, runtime_checkable

from core.actions.provider_mounts import (
    DefaultProviderMountRegistry,
    ProviderMountSnapshotV2,
    get_provider_mount_registry,
)
from core.actions.readiness import (
    DependencyKindV2,
    DependencyReadiness,
    DependencyStateV2,
    ProviderReadinessSnapshot,
    canonical_provider_readiness_digest,
    seal_provider_readiness_snapshot,
)
from core.actions.readiness_probes import (
    BinaryProbe,
    CompositeLeafProbe,
    DaemonProtocolProbe,
    PlatformProbe,
    ProviderReadinessProbe,
    PythonImportProbe,
)


@runtime_checkable
class ProviderReadinessRegistryV2(Protocol):
    def probe(self, mount: ProviderMountSnapshotV2) -> ProviderReadinessSnapshot: ...

    def assert_current(
        self,
        snapshot: ProviderReadinessSnapshot,
        mount: ProviderMountSnapshotV2,
    ) -> None: ...


class ReadinessRegistry:
    def __init__(
        self,
        *,
        mount_registry: DefaultProviderMountRegistry | None = None,
        register_defaults: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._mount_registry = mount_registry or get_provider_mount_registry()
        self._clock = clock
        self._lock = RLock()
        self._probes_by_action: dict[str, ProviderReadinessProbe] = {}
        self._action_by_probe_id: dict[str, str] = {}
        self._cache: dict[str, ProviderReadinessSnapshot] = {}
        if register_defaults:
            for readiness_probe in _default_probes():
                self.register_probe(readiness_probe)

    def register_probe(self, readiness_probe: ProviderReadinessProbe, *, replace: bool = False) -> None:
        mount = self._mount_registry.require_v2(readiness_probe.action_id)
        if mount.spec.readiness_probe_id != readiness_probe.probe_id:
            raise ValueError(
                f"readiness_probe_binding_mismatch:{readiness_probe.action_id}:"
                f"{readiness_probe.probe_id}:{mount.spec.readiness_probe_id}"
            )
        with self._lock:
            existing = self._probes_by_action.get(readiness_probe.action_id)
            owner = self._action_by_probe_id.get(readiness_probe.probe_id)
            if existing is not None and not replace:
                raise ValueError(f"duplicate_readiness_action_registration:{readiness_probe.action_id}")
            if owner is not None and owner != readiness_probe.action_id:
                raise ValueError(f"duplicate_readiness_probe_id:{readiness_probe.probe_id}")
            if existing is not None:
                self._action_by_probe_id.pop(existing.probe_id, None)
            self._probes_by_action[readiness_probe.action_id] = readiness_probe
            self._action_by_probe_id[readiness_probe.probe_id] = readiness_probe.action_id
            self._cache.pop(readiness_probe.action_id, None)

    def probe(self, mount: ProviderMountSnapshotV2) -> ProviderReadinessSnapshot:
        self._mount_registry.assert_current(mount)
        now = self._clock()
        with self._lock:
            cached = self._cache.get(mount.spec.action_id)
            if cached is not None and self._cache_entry_matches(cached, mount, now):
                return cached
            return self._evaluate_locked(mount)

    def recheck(self, mount: ProviderMountSnapshotV2) -> ProviderReadinessSnapshot:
        """Perform a fresh full probe, bypassing the TTL cache."""

        self._mount_registry.assert_current(mount)
        with self._lock:
            return self._evaluate_locked(mount)

    def get_snapshot(self, action_id: str, force_recheck: bool = False) -> ProviderReadinessSnapshot:
        """Compatibility wrapper; new code passes an authenticated mount snapshot."""

        mount = self._mount_registry.require_v2(action_id)
        return self.recheck(mount) if force_recheck else self.probe(mount)

    def assert_current(
        self,
        snapshot: ProviderReadinessSnapshot,
        mount: ProviderMountSnapshotV2 | None = None,
    ) -> None:
        resolved_mount = mount or self._mount_registry.require_v2(snapshot.action_id)
        self._mount_registry.assert_current(resolved_mount)
        expected_digest = canonical_provider_readiness_digest(snapshot)
        if not hmac.compare_digest(snapshot.snapshot_digest, expected_digest):
            raise ValueError(f"invalid_readiness_snapshot_digest:{snapshot.action_id}")
        if (
            snapshot.action_id != resolved_mount.spec.action_id
            or snapshot.provider_id != resolved_mount.spec.provider_owner
            or snapshot.mount_revision != resolved_mount.revision
            or snapshot.mount_digest != resolved_mount.mount_digest
        ):
            raise ValueError(f"readiness_mount_binding_mismatch:{snapshot.action_id}")
        if snapshot.expires_at_monotonic <= self._clock():
            raise ValueError(f"expired_readiness_snapshot:{snapshot.action_id}")
        with self._lock:
            readiness_probe = self._probes_by_action.get(snapshot.action_id)
            if readiness_probe is None:
                raise ValueError(f"unregistered_readiness_probe:{snapshot.action_id}")
            if readiness_probe.probe_id != resolved_mount.spec.readiness_probe_id:
                raise ValueError(f"readiness_probe_binding_mismatch:{snapshot.action_id}")
            current = self._cache.get(snapshot.action_id)
            if current is None or current != snapshot:
                raise ValueError(f"stale_readiness_snapshot:{snapshot.action_id}")

    @staticmethod
    def _cache_entry_matches(
        cached: ProviderReadinessSnapshot,
        mount: ProviderMountSnapshotV2,
        now: float,
    ) -> bool:
        return (
            now < cached.expires_at_monotonic
            and cached.action_id == mount.spec.action_id
            and cached.provider_id == mount.spec.provider_owner
            and cached.mount_revision == mount.revision
            and cached.mount_digest == mount.mount_digest
            and cached.snapshot_digest == canonical_provider_readiness_digest(cached)
        )

    def _evaluate_locked(self, mount: ProviderMountSnapshotV2) -> ProviderReadinessSnapshot:
        readiness_probe = self._probes_by_action.get(mount.spec.action_id)
        snapshot = (
            self._unregistered_snapshot(mount)
            if readiness_probe is None
            else readiness_probe.evaluate(mount)
        )
        self._cache[mount.spec.action_id] = snapshot
        return snapshot

    def _unregistered_snapshot(self, mount: ProviderMountSnapshotV2) -> ProviderReadinessSnapshot:
        now = self._clock()
        reason = "unregistered_readiness_probe"
        return seal_provider_readiness_snapshot(
            ProviderReadinessSnapshot(
                action_id=mount.spec.action_id,
                provider_id=mount.spec.provider_owner,
                mount_revision=mount.revision,
                mount_digest=mount.mount_digest,
                probe_version="unregistered",
                provider_generation="unregistered",
                daemon_instance_id=None,
                available=False,
                checked_at_monotonic=now,
                expires_at_monotonic=now + 1.0,
                dependency_states=(
                    DependencyReadiness(
                        dependency_id=mount.spec.readiness_probe_id,
                        kind=DependencyKindV2.PROVIDER_INITIALIZATION,
                        state=DependencyStateV2.ERROR,
                        observed_version=None,
                        required_version=None,
                        reason_codes=(reason,),
                    ),
                ),
                reason_codes=(reason,),
                snapshot_digest="",
            )
        )


def _default_probes() -> tuple[ProviderReadinessProbe, ...]:
    payload = PythonImportProbe(
        "probe:payload_keying",
        "plugin:payload_keying",
        ("cryptography",),
    )
    kerberos_extract = PythonImportProbe(
        "probe:kerberos_extract_tickets",
        "killchain:kerberos_extract_tickets",
        ("impacket",),
    )
    kerberos_crack = BinaryProbe(
        "probe:kerberos_crack_tickets",
        "killchain:kerberos_crack_tickets",
        ("hashcat", "john"),
        require_all=False,
    )
    pass_the_ticket = PythonImportProbe(
        "probe:ad_pass_the_ticket",
        "killchain:ad_pass_the_ticket",
        ("impacket",),
    )
    pass_the_hash = PythonImportProbe(
        "probe:pass_the_hash",
        "killchain:pass_the_hash",
        ("impacket",),
    )
    dump_lsass = PythonImportProbe(
        "probe:ad_dump_lsass",
        "killchain:ad_dump_lsass",
        ("impacket",),
        optional_module_names=("pypykatz",),
    )
    sam_dump = PythonImportProbe(
        "probe:ad_sam_dump",
        "killchain:ad_sam_dump",
        ("impacket",),
    )
    smbexec = PythonImportProbe(
        "probe:ad_smbexec",
        "killchain:ad_smbexec",
        ("impacket",),
    )
    winrm = PythonImportProbe(
        "probe:ad_winrm_exec",
        "killchain:ad_winrm_exec",
        ("winrm",),
    )
    dcom = PythonImportProbe(
        "probe:ad_dcom_exec",
        "killchain:ad_dcom_exec",
        ("impacket",),
    )
    remote_router = CompositeLeafProbe(
        "probe:ad_remote_execution",
        "killchain:ad_remote_execution",
        (smbexec, winrm, dcom),
    )
    remote_forward = PythonImportProbe(
        "probe:pivot_remote_forward",
        "killchain:pivot_remote_forward",
        ("paramiko",),
    )
    ssh_chain = PythonImportProbe(
        "probe:pivot_ssh_chain",
        "killchain:pivot_ssh_chain",
        ("paramiko",),
    )
    proxy_scan = PlatformProbe(
        "probe:pivot_proxy_scan",
        "killchain:pivot_proxy_scan",
        ("linux", "darwin", "win32"),
        platform_supplier=lambda: sys.platform,
    )
    dns = DaemonProtocolProbe(
        "probe:dns_c2_channel",
        "c2:dns_c2_channel",
        "12.0",
        None,
    )
    enroll = DaemonProtocolProbe(
        "probe:c2_enroll",
        "c2:c2_enroll",
        "12.0",
        None,
    )
    deploy_daemon_component = DaemonProtocolProbe(
        "probe:c2_deploy:daemon",
        "c2:c2_deploy",
        "12.0",
        None,
    )
    deploy_ssh_component = PythonImportProbe(
        "probe:c2_deploy:ssh",
        "c2:c2_deploy",
        ("paramiko",),
    )
    deploy = CompositeLeafProbe(
        "probe:c2_deploy",
        "c2:c2_deploy",
        (deploy_daemon_component, deploy_ssh_component),
        require_all=True,
    )
    channel_router = CompositeLeafProbe(
        "probe:c2_channel_create",
        "c2:c2_channel_create",
        (dns,),
    )
    task = DaemonProtocolProbe(
        "probe:c2_task",
        "c2:c2_task",
        "12.0",
        None,
    )
    cleanup = DaemonProtocolProbe(
        "probe:c2_cleanup",
        "c2:c2_cleanup",
        "12.0",
        None,
    )
    return (
        payload,
        kerberos_extract,
        kerberos_crack,
        pass_the_ticket,
        pass_the_hash,
        dump_lsass,
        sam_dump,
        smbexec,
        winrm,
        dcom,
        remote_router,
        remote_forward,
        ssh_chain,
        proxy_scan,
        dns,
        enroll,
        deploy,
        channel_router,
        task,
        cleanup,
    )


_GLOBAL_READINESS_REGISTRY = ReadinessRegistry()


def get_readiness_registry() -> ReadinessRegistry:
    return _GLOBAL_READINESS_REGISTRY


__all__ = [
    "ProviderReadinessRegistryV2",
    "ReadinessRegistry",
    "get_readiness_registry",
]
