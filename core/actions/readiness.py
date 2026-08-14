"""Exact PR-3 provider-readiness value objects and canonical digest."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

_READINESS_DIGEST_SCHEMA = "octopus:provider-readiness-snapshot:2.0"


class DependencyKindV2(str, Enum):
    PYTHON_IMPORT = "python_import"
    SYSTEM_BINARY = "system_binary"
    PLATFORM = "platform"
    DAEMON_PROTOCOL = "daemon_protocol"
    PROVIDER_INITIALIZATION = "provider_initialization"


class DependencyStateV2(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass(frozen=True)
class DependencyReadiness:
    dependency_id: str
    kind: DependencyKindV2
    state: DependencyStateV2
    observed_version: str | None
    required_version: str | None
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class ProviderReadinessSnapshot:
    action_id: str
    provider_id: str
    mount_revision: int
    mount_digest: str
    probe_version: str
    provider_generation: str
    daemon_instance_id: str | None
    available: bool
    checked_at_monotonic: float
    expires_at_monotonic: float
    dependency_states: tuple[DependencyReadiness, ...]
    reason_codes: tuple[str, ...]
    snapshot_digest: str


def canonical_provider_readiness_digest(snapshot: ProviderReadinessSnapshot) -> str:
    """Digest every canonical field except ``snapshot_digest`` itself."""

    payload = {
        "digest_schema": _READINESS_DIGEST_SCHEMA,
        "action_id": snapshot.action_id,
        "provider_id": snapshot.provider_id,
        "mount_revision": snapshot.mount_revision,
        "mount_digest": snapshot.mount_digest,
        "probe_version": snapshot.probe_version,
        "provider_generation": snapshot.provider_generation,
        "daemon_instance_id": snapshot.daemon_instance_id,
        "available": snapshot.available,
        "checked_at_monotonic": snapshot.checked_at_monotonic,
        "expires_at_monotonic": snapshot.expires_at_monotonic,
        "dependency_states": [
            {
                "dependency_id": dependency.dependency_id,
                "kind": dependency.kind.value,
                "state": dependency.state.value,
                "observed_version": dependency.observed_version,
                "required_version": dependency.required_version,
                "reason_codes": list(dependency.reason_codes),
            }
            for dependency in snapshot.dependency_states
        ],
        "reason_codes": list(snapshot.reason_codes),
    }
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def seal_provider_readiness_snapshot(snapshot: ProviderReadinessSnapshot) -> ProviderReadinessSnapshot:
    """Return an equivalent immutable snapshot carrying its canonical digest."""

    if snapshot.snapshot_digest:
        raise ValueError("readiness_snapshot_already_sealed")
    return ProviderReadinessSnapshot(
        action_id=snapshot.action_id,
        provider_id=snapshot.provider_id,
        mount_revision=snapshot.mount_revision,
        mount_digest=snapshot.mount_digest,
        probe_version=snapshot.probe_version,
        provider_generation=snapshot.provider_generation,
        daemon_instance_id=snapshot.daemon_instance_id,
        available=snapshot.available,
        checked_at_monotonic=snapshot.checked_at_monotonic,
        expires_at_monotonic=snapshot.expires_at_monotonic,
        dependency_states=snapshot.dependency_states,
        reason_codes=snapshot.reason_codes,
        snapshot_digest=canonical_provider_readiness_digest(snapshot),
    )


__all__ = [
    "DependencyKindV2",
    "DependencyReadiness",
    "DependencyStateV2",
    "ProviderReadinessSnapshot",
    "canonical_provider_readiness_digest",
    "seal_provider_readiness_snapshot",
]
