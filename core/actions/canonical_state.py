"""Single-owner composition of canonical V2 static and readiness state."""

from __future__ import annotations

from dataclasses import dataclass

from core.actions.models import ActionDescriptorV2
from core.actions.provider_mounts import ProviderMountSnapshotV2
from core.actions.readiness import ProviderReadinessSnapshot


@dataclass(frozen=True)
class CanonicalActionStaticState:
    descriptor: ActionDescriptorV2
    mount: ProviderMountSnapshotV2

    def __post_init__(self) -> None:
        if self.descriptor.action_id != self.mount.spec.action_id:
            raise ValueError("canonical_static_state_action_mismatch")


@dataclass(frozen=True)
class CanonicalActionState:
    static: CanonicalActionStaticState
    readiness: ProviderReadinessSnapshot

    def __post_init__(self) -> None:
        mount = self.static.mount
        if (
            self.readiness.action_id != self.static.descriptor.action_id
            or self.readiness.provider_id != mount.spec.provider_owner
            or self.readiness.mount_revision != mount.revision
            or self.readiness.mount_digest != mount.mount_digest
        ):
            raise ValueError("canonical_readiness_state_binding_mismatch")


__all__ = [
    "CanonicalActionState",
    "CanonicalActionStaticState",
]
