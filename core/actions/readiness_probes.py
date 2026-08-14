"""Environment-only readiness probes used by the PR-3 registry."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import shutil
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, Union

from core.actions.provider_mounts import ProviderMountSnapshotV2
from core.actions.readiness import (
    DependencyKindV2,
    DependencyReadiness,
    DependencyStateV2,
    ProviderReadinessSnapshot,
    seal_provider_readiness_snapshot,
)


@dataclass(frozen=True)
class ProbeObservation:
    available: bool
    dependency_states: tuple[DependencyReadiness, ...]
    reason_codes: tuple[str, ...]
    provider_generation: str
    daemon_instance_id: str | None = None


class ProviderReadinessProbe(Protocol):
    probe_id: str
    action_id: str
    probe_version: str
    ttl_seconds: float

    def inspect(self) -> ProbeObservation: ...

    def evaluate(self, mount: ProviderMountSnapshotV2) -> ProviderReadinessSnapshot: ...


GenerationSource = Union[str, Callable[[], str]]


class _ReadinessProbeBase:
    def __init__(
        self,
        probe_id: str,
        action_id: str,
        *,
        probe_version: str = "1.0",
        provider_generation: GenerationSource = "1",
        ttl_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not probe_id.startswith("probe:"):
            raise ValueError("invalid_readiness_probe_id")
        if not action_id:
            raise ValueError("readiness_action_id_required")
        if not probe_version:
            raise ValueError("readiness_probe_version_required")
        if ttl_seconds <= 0:
            raise ValueError("readiness_ttl_must_be_positive")
        self.probe_id = probe_id
        self.action_id = action_id
        self.probe_version = probe_version
        self.ttl_seconds = ttl_seconds
        self._provider_generation = provider_generation
        self._clock = clock

    def _generation(self) -> str:
        generation = self._provider_generation() if callable(self._provider_generation) else self._provider_generation
        if not generation:
            raise ValueError("empty_provider_generation")
        return generation

    def _empty_observation(self) -> ProbeObservation:
        reason = "empty_dependency_probe"
        return ProbeObservation(
            available=False,
            dependency_states=(
                DependencyReadiness(
                    dependency_id=f"{self.probe_id}:configuration",
                    kind=DependencyKindV2.PROVIDER_INITIALIZATION,
                    state=DependencyStateV2.ERROR,
                    observed_version=None,
                    required_version=None,
                    reason_codes=(reason,),
                ),
            ),
            reason_codes=(reason,),
            provider_generation=self._safe_generation(),
        )

    def _safe_generation(self) -> str:
        try:
            return self._generation()
        except Exception:
            return "generation-error"

    def inspect(self) -> ProbeObservation:
        raise NotImplementedError

    def evaluate(self, mount: ProviderMountSnapshotV2) -> ProviderReadinessSnapshot:
        if mount.spec.action_id != self.action_id:
            raise ValueError(f"readiness_action_binding_mismatch:{self.action_id}:{mount.spec.action_id}")
        if mount.spec.readiness_probe_id != self.probe_id:
            raise ValueError(f"readiness_probe_binding_mismatch:{self.probe_id}:{mount.spec.readiness_probe_id}")
        checked_at = self._clock()
        try:
            observation = self.inspect()
        except Exception as exc:
            reason = f"probe_error:{type(exc).__name__}"
            observation = ProbeObservation(
                available=False,
                dependency_states=(
                    DependencyReadiness(
                        dependency_id=self.probe_id,
                        kind=DependencyKindV2.PROVIDER_INITIALIZATION,
                        state=DependencyStateV2.ERROR,
                        observed_version=None,
                        required_version=None,
                        reason_codes=(reason,),
                    ),
                ),
                reason_codes=(reason,),
                provider_generation=self._safe_generation(),
            )
        if not observation.dependency_states:
            observation = self._empty_observation()
        unsigned = ProviderReadinessSnapshot(
            action_id=mount.spec.action_id,
            provider_id=mount.spec.provider_owner,
            mount_revision=mount.revision,
            mount_digest=mount.mount_digest,
            probe_version=self.probe_version,
            provider_generation=observation.provider_generation,
            daemon_instance_id=observation.daemon_instance_id,
            available=observation.available,
            checked_at_monotonic=checked_at,
            expires_at_monotonic=checked_at + self.ttl_seconds,
            dependency_states=observation.dependency_states,
            reason_codes=observation.reason_codes,
            snapshot_digest="",
        )
        return seal_provider_readiness_snapshot(unsigned)


class PythonImportProbe(_ReadinessProbeBase):
    def __init__(
        self,
        probe_id: str,
        action_id: str,
        module_names: tuple[str, ...],
        ttl_seconds: float = 60.0,
        *,
        optional_module_names: tuple[str, ...] = (),
        required_versions: Mapping[str, str] | None = None,
        provider_generation: GenerationSource = "1",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            probe_id,
            action_id,
            provider_generation=provider_generation,
            ttl_seconds=ttl_seconds,
            clock=clock,
        )
        self.module_names = module_names
        self.optional_module_names = optional_module_names
        self.required_versions = dict(required_versions or {})

    @staticmethod
    def _distribution_version(module_name: str) -> str | None:
        distribution = module_name.split(".", 1)[0].replace("_", "-")
        try:
            return importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            return None

    def inspect(self) -> ProbeObservation:
        if not self.module_names and not self.optional_module_names:
            return self._empty_observation()
        dependencies: list[DependencyReadiness] = []
        reasons: list[str] = []
        available = True
        optional = set(self.optional_module_names)
        for module_name in (*self.module_names, *self.optional_module_names):
            required_version = self.required_versions.get(module_name)
            try:
                present = importlib.util.find_spec(module_name) is not None
            except (ImportError, ModuleNotFoundError, ValueError):
                present = False
            observed_version = self._distribution_version(module_name) if present else None
            state = DependencyStateV2.AVAILABLE if present else DependencyStateV2.MISSING
            dependency_reasons: tuple[str, ...] = ()
            if not present:
                reason_prefix = "optional_python_import_missing" if module_name in optional else "missing_python_import"
                reason = f"{reason_prefix}:{module_name}"
                dependency_reasons = (reason,)
                reasons.append(reason)
                if module_name not in optional:
                    available = False
            dependencies.append(
                DependencyReadiness(
                    dependency_id=module_name,
                    kind=DependencyKindV2.PYTHON_IMPORT,
                    state=state,
                    observed_version=observed_version,
                    required_version=required_version,
                    reason_codes=dependency_reasons,
                )
            )
        return ProbeObservation(
            available=available,
            dependency_states=tuple(dependencies),
            reason_codes=tuple(reasons),
            provider_generation=self._generation(),
        )


class BinaryProbe(_ReadinessProbeBase):
    def __init__(
        self,
        probe_id: str,
        action_id: str,
        binary_names: tuple[str, ...],
        ttl_seconds: float = 60.0,
        *,
        require_all: bool = True,
        provider_generation: GenerationSource = "1",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            probe_id,
            action_id,
            provider_generation=provider_generation,
            ttl_seconds=ttl_seconds,
            clock=clock,
        )
        self.binary_names = binary_names
        self.require_all = require_all

    def inspect(self) -> ProbeObservation:
        if not self.binary_names:
            return self._empty_observation()
        dependencies: list[DependencyReadiness] = []
        reasons: list[str] = []
        states: list[bool] = []
        for binary_name in self.binary_names:
            present = shutil.which(binary_name) is not None
            states.append(present)
            reason_codes = () if present else (f"missing_system_binary:{binary_name}",)
            reasons.extend(reason_codes)
            dependencies.append(
                DependencyReadiness(
                    dependency_id=binary_name,
                    kind=DependencyKindV2.SYSTEM_BINARY,
                    state=DependencyStateV2.AVAILABLE if present else DependencyStateV2.MISSING,
                    observed_version="present" if present else None,
                    required_version=None,
                    reason_codes=reason_codes,
                )
            )
        available = all(states) if self.require_all else any(states)
        if not available and not self.require_all:
            reasons.append("no_alternative_system_binary_available")
        return ProbeObservation(
            available=available,
            dependency_states=tuple(dependencies),
            reason_codes=tuple(reasons),
            provider_generation=self._generation(),
        )


class PlatformProbe(_ReadinessProbeBase):
    def __init__(
        self,
        probe_id: str,
        action_id: str,
        supported_platforms: tuple[str, ...],
        ttl_seconds: float = 60.0,
        *,
        platform_supplier: Callable[[], str] = lambda: sys.platform,
        provider_generation: GenerationSource = "1",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            probe_id,
            action_id,
            provider_generation=provider_generation,
            ttl_seconds=ttl_seconds,
            clock=clock,
        )
        self.supported_platforms = supported_platforms
        self._platform_supplier = platform_supplier

    def inspect(self) -> ProbeObservation:
        if not self.supported_platforms:
            return self._empty_observation()
        observed = self._platform_supplier()
        available = observed in self.supported_platforms
        reason_codes = () if available else (f"unsupported_platform:{observed}",)
        return ProbeObservation(
            available=available,
            dependency_states=(
                DependencyReadiness(
                    dependency_id="runtime_platform",
                    kind=DependencyKindV2.PLATFORM,
                    state=DependencyStateV2.AVAILABLE if available else DependencyStateV2.INCOMPATIBLE,
                    observed_version=observed,
                    required_version="|".join(self.supported_platforms),
                    reason_codes=reason_codes,
                ),
            ),
            reason_codes=reason_codes,
            provider_generation=self._generation(),
        )


@dataclass(frozen=True)
class DaemonProtocolStatus:
    reachable: bool
    protocol_version: str | None
    daemon_instance_id: str | None
    provider_generation: str


class DaemonProtocolProbe(_ReadinessProbeBase):
    def __init__(
        self,
        probe_id: str,
        action_id: str,
        required_protocol_version: str,
        status_supplier: Callable[[], DaemonProtocolStatus] | None,
        ttl_seconds: float = 10.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(probe_id, action_id, ttl_seconds=ttl_seconds, clock=clock)
        if not required_protocol_version:
            raise ValueError("daemon_protocol_version_required")
        self.required_protocol_version = required_protocol_version
        self._status_supplier = status_supplier

    def inspect(self) -> ProbeObservation:
        if self._status_supplier is None:
            reason = "daemon_protocol_unverified"
            return ProbeObservation(
                available=False,
                dependency_states=(
                    DependencyReadiness(
                        dependency_id="c2_control_protocol",
                        kind=DependencyKindV2.DAEMON_PROTOCOL,
                        state=DependencyStateV2.ERROR,
                        observed_version=None,
                        required_version=self.required_protocol_version,
                        reason_codes=(reason,),
                    ),
                ),
                reason_codes=(reason,),
                provider_generation="daemon-unverified",
            )
        status = self._status_supplier()
        version_matches = status.protocol_version == self.required_protocol_version
        available = status.reachable and version_matches and bool(status.daemon_instance_id)
        reasons: list[str] = []
        if not status.reachable:
            reasons.append("daemon_unreachable")
        if status.reachable and not version_matches:
            reasons.append("daemon_protocol_incompatible")
        if status.reachable and not status.daemon_instance_id:
            reasons.append("daemon_instance_id_missing")
        if available:
            state = DependencyStateV2.AVAILABLE
        elif status.reachable and not version_matches:
            state = DependencyStateV2.INCOMPATIBLE
        else:
            state = DependencyStateV2.MISSING
        return ProbeObservation(
            available=available,
            dependency_states=(
                DependencyReadiness(
                    dependency_id="c2_control_protocol",
                    kind=DependencyKindV2.DAEMON_PROTOCOL,
                    state=state,
                    observed_version=status.protocol_version,
                    required_version=self.required_protocol_version,
                    reason_codes=tuple(reasons),
                ),
            ),
            reason_codes=tuple(reasons),
            provider_generation=status.provider_generation,
            daemon_instance_id=status.daemon_instance_id,
        )


class CompositeLeafProbe(_ReadinessProbeBase):
    def __init__(
        self,
        probe_id: str,
        action_id: str,
        leaf_probes: tuple[ProviderReadinessProbe, ...],
        ttl_seconds: float = 30.0,
        *,
        require_all: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(probe_id, action_id, ttl_seconds=ttl_seconds, clock=clock)
        self.leaf_probes = leaf_probes
        self.require_all = require_all

    def inspect(self) -> ProbeObservation:
        if not self.leaf_probes:
            return self._empty_observation()
        observations = tuple(probe.inspect() for probe in self.leaf_probes)
        available_states = tuple(observation.available for observation in observations)
        available = all(available_states) if self.require_all else any(available_states)
        dependencies = tuple(dependency for observation in observations for dependency in observation.dependency_states)
        reasons = tuple(reason for observation in observations for reason in observation.reason_codes)
        generation_body = "|".join(observation.provider_generation for observation in observations).encode("utf-8")
        generation = f"composite:{hashlib.sha256(generation_body).hexdigest()}"
        daemon_ids = {observation.daemon_instance_id for observation in observations if observation.daemon_instance_id}
        daemon_instance_id = next(iter(daemon_ids)) if len(daemon_ids) == 1 else None
        if not available:
            reasons = (*reasons, "composite_leafs_unavailable")
        return ProbeObservation(
            available=available,
            dependency_states=dependencies,
            reason_codes=reasons,
            provider_generation=generation,
            daemon_instance_id=daemon_instance_id,
        )


__all__ = [
    "BinaryProbe",
    "CompositeLeafProbe",
    "DaemonProtocolProbe",
    "DaemonProtocolStatus",
    "PlatformProbe",
    "ProbeObservation",
    "ProviderReadinessProbe",
    "PythonImportProbe",
]
