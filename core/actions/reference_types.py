"""Canonical closed state/kind types for PR-4 reference metadata.

This module is the single owner of these enums. Domain stores may re-export
them for compatibility, but must never create local look-alikes.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from typing_extensions import TypeAlias


class SessionState(str, Enum):
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"
    EXPIRED = "expired"
    FAILED = "failed"


class ArtifactKind(str, Enum):
    GENERIC = "generic"
    PAYLOAD = "payload"
    PAYLOAD_LOADER = "payload_loader"
    KERBEROS_TICKET = "kerberos_ticket"
    WORDLIST = "wordlist"
    LSASS_DUMP = "lsass_dump"
    SAM_HIVE = "sam_hive"
    SYSTEM_HIVE = "system_hive"
    SECURITY_HIVE = "security_hive"
    C2_AGENT = "c2_agent"
    C2_REBIND_MANIFEST = "c2_rebind_manifest"
    TARGET_METADATA = "target_metadata"


class RouteState(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"
    EXPIRED = "expired"
    FAILED = "failed"


class C2ResourceKind(str, Enum):
    CHANNEL = "channel"
    AGENT = "agent"
    TASK = "task"


NonEnrollmentC2ResourceKindV2: TypeAlias = Literal[
    C2ResourceKind.CHANNEL,
    C2ResourceKind.AGENT,
    C2ResourceKind.TASK,
]


class C2ResourceState(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    CLOSED = "closed"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"
    CANCELLED = "cancelled"


class DeploymentState(str, Enum):
    PREALLOCATED = "preallocated"
    BUILDING = "building"
    STAGED = "staged"
    UPLOADING = "uploading"
    START_DISPATCHING = "start_dispatching"
    ACTIVE = "active"
    IN_DOUBT = "in_doubt"
    CLEANING = "cleaning"
    CLOSED = "closed"
    ORPHANED = "orphaned"
    FAILED = "failed"


__all__ = [
    "ArtifactKind",
    "C2ResourceKind",
    "C2ResourceState",
    "DeploymentState",
    "NonEnrollmentC2ResourceKindV2",
    "RouteState",
    "SessionState",
]
