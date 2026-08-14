"""Closed request model for reviewed prebuilt artifact rebinding."""

from __future__ import annotations

from dataclasses import dataclass

from core.c2.build_models import C2ArtifactBuildBinding


@dataclass(frozen=True)
class C2ArtifactRebindingRequest:
    source_artifact_ref: str
    rebind_manifest_ref: str
    binding: C2ArtifactBuildBinding


__all__ = ["C2ArtifactRebindingRequest"]
