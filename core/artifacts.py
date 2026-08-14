"""Metadata-only artifact reference store facade."""

from __future__ import annotations

from typing import Union

from core.actions.reference_resolvers import _MetadataSnapshotStore
from core.actions.reference_snapshots import (
    NonSensitiveArtifactReferenceSnapshot,
    SensitiveArtifactReferenceSnapshot,
)
from core.actions.reference_types import ArtifactKind


class ArtifactStore(
    _MetadataSnapshotStore[
        Union[
            NonSensitiveArtifactReferenceSnapshot,
            SensitiveArtifactReferenceSnapshot,
        ]
    ]
):
    _snapshot_types = (
        NonSensitiveArtifactReferenceSnapshot,
        SensitiveArtifactReferenceSnapshot,
    )


__all__ = ["ArtifactKind", "ArtifactStore"]
