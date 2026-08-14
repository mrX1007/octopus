"""Artifact builder."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class C2ArtifactBuildSpecV1:
    build_id: str
    target_os: str
    target_arch: str
    config_params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class C2ArtifactBuildResultV1:
    build_id: str
    artifact_bytes: bytes
    artifact_digest: str
    built_at: float


class C2ArtifactBuilderV1:
    """Builder for generating agent artifact binaries."""

    def build_artifact(self, spec: C2ArtifactBuildSpecV1) -> C2ArtifactBuildResultV1:
        """Build agent binary artifact from build spec."""
        header = f"OCT_AGENT_V12:{spec.target_os}:{spec.target_arch}\n"
        body = json.dumps(spec.config_params, sort_keys=True)
        raw_bytes = (header + body).encode("utf-8")
        digest = hashlib.sha256(raw_bytes).hexdigest()

        return C2ArtifactBuildResultV1(
            build_id=spec.build_id,
            artifact_bytes=raw_bytes,
            artifact_digest=digest,
            built_at=time.time(),
        )
