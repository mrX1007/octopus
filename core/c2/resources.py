"""Metadata-only C2 resource reference store facade."""

from __future__ import annotations

from core.actions.reference_resolvers import _MetadataSnapshotStore
from core.actions.reference_snapshots import C2ReferenceSnapshot
from core.actions.reference_types import C2ResourceKind, C2ResourceState


class C2ResourceStore(_MetadataSnapshotStore[C2ReferenceSnapshot]):
    _snapshot_types = (C2ReferenceSnapshot,)


__all__ = ["C2ResourceKind", "C2ResourceState", "C2ResourceStore"]
