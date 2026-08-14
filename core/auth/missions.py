"""Canonical mission authorization snapshots."""

from __future__ import annotations

import math
from dataclasses import dataclass

from core.actions.target_scope import TargetScopeSnapshot


@dataclass(frozen=True)
class MissionAuthorizationSnapshot:
    schema_version: str
    mission_ref: str
    revision: int
    mission_id: str
    active: bool
    permitted_subject_ids: tuple[str, ...]
    target_scope: TargetScopeSnapshot
    permitted_capabilities: tuple[str, ...]
    permitted_stages: tuple[str, ...]
    expires_at: float | None

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("mission snapshot schema version is unsupported")
        for name in ("mission_ref", "mission_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("mission revision must be positive")
        if type(self.active) is not bool or type(self.target_scope) is not TargetScopeSnapshot:
            raise ValueError("mission active/scope state must be canonical")
        for name in ("permitted_subject_ids", "permitted_capabilities", "permitted_stages"):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(value) is not str or not value for value in values):
                raise ValueError(f"{name} must be a tuple of non-empty strings")
            if len(values) != len(set(values)):
                raise ValueError(f"{name} contains duplicates")
        if self.expires_at is not None and not math.isfinite(self.expires_at):
            raise ValueError("mission expiry must be finite")


__all__ = [
    "MissionAuthorizationSnapshot",
]
