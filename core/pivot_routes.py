"""Metadata-only pivot-route reference store facade."""

from __future__ import annotations

from core.actions.reference_resolvers import _MetadataSnapshotStore
from core.actions.reference_snapshots import PivotRouteReferenceSnapshot
from core.actions.reference_types import RouteState


class PivotRouteStore(_MetadataSnapshotStore[PivotRouteReferenceSnapshot]):
    _snapshot_types = (PivotRouteReferenceSnapshot,)


__all__ = ["PivotRouteStore", "RouteState"]
