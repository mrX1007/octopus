"""Metadata-only session reference store facade."""

from __future__ import annotations

from core.actions.reference_resolvers import _MetadataSnapshotStore
from core.actions.reference_snapshots import SessionReferenceSnapshot
from core.actions.reference_types import SessionState


class SessionStore(_MetadataSnapshotStore[SessionReferenceSnapshot]):
    _snapshot_types = (SessionReferenceSnapshot,)


__all__ = ["SessionState", "SessionStore"]
