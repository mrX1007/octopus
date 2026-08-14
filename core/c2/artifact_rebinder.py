"""Artifact rebinder."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RebindManifestV1:
    manifest_id: str
    target_agent_ref: str
    binding_keys: dict[str, Any] = field(default_factory=dict)


class C2ArtifactRebinderV1:
    """Rebinds existing agent artifact binaries to new target agent identities."""

    def rebind_artifact(self, artifact_bytes: bytes, manifest: RebindManifestV1) -> tuple[bytes, str]:
        """Inject rebind manifest into artifact binary bytes and return (rebound_bytes, new_digest)."""
        rebind_header = f"\nREBIND:{manifest.manifest_id}:{manifest.target_agent_ref}\n".encode()
        manifest_payload = json.dumps(manifest.binding_keys, sort_keys=True).encode("utf-8")

        rebound_bytes = artifact_bytes + rebind_header + manifest_payload
        new_digest = hashlib.sha256(rebound_bytes).hexdigest()

        return rebound_bytes, new_digest
