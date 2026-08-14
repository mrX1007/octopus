"""Canonical principal authorization snapshots resolved from ingress."""

from __future__ import annotations

import math
from dataclasses import dataclass

from core.auth.types import SubjectType


@dataclass(frozen=True)
class PrincipalAuthorizationSnapshot:
    schema_version: str
    principal_ref: str
    revision: int
    subject_id: str
    subject_type: SubjectType
    active: bool
    roles: tuple[str, ...]
    capabilities: tuple[str, ...]
    authenticated_at: float
    expires_at: float | None

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("principal snapshot schema version is unsupported")
        for name in ("principal_ref", "subject_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("principal revision must be positive")
        if type(self.subject_type) is not SubjectType or type(self.active) is not bool:
            raise ValueError("principal subject/active state must be canonical")
        for name in ("roles", "capabilities"):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(value) is not str or not value for value in values):
                raise ValueError(f"{name} must be a tuple of non-empty strings")
            if len(values) != len(set(values)):
                raise ValueError(f"{name} contains duplicates")
        if not math.isfinite(self.authenticated_at):
            raise ValueError("principal authentication timestamp must be finite")
        if self.expires_at is not None and (
            not math.isfinite(self.expires_at) or self.expires_at <= self.authenticated_at
        ):
            raise ValueError("principal expiry must follow authentication")


__all__ = [
    "PrincipalAuthorizationSnapshot",
]
