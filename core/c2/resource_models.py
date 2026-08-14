"""Managed C2 resource models and lifecycle definitions (§14.6A, §16.1)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ManagedC2ResourceKind(str, Enum):
    ENROLLMENT = "enrollment"
    TASK = "task"
    CHANNEL = "channel"
    DEPLOYMENT = "deployment"


@dataclass(frozen=True)
class ManagedC2ResourceStateV1:
    resource_ref: str
    resource_kind: ManagedC2ResourceKind
    mission_id: str
    subject_id: str
    status: str
    revision: int
    metadata_digest: str
    created_at: float
