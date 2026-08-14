"""Canonical artifact binding models and deterministic binding digest (§10.8, §15.6)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass


BINDING_DIGEST_SCHEMA = "octopus:artifact-binding-digest:1.0"


@dataclass(frozen=True)
class C2ArtifactBindingV1:
    deployment_ref: str
    enrollment_ref: str
    channel_ref: str
    target_id: str
    profile_id: str
    method_id: str
    protocol_version: str
    source_digest: str
    content_digest: str


def compute_artifact_binding_digest(binding: C2ArtifactBindingV1) -> str:
    """Compute the single canonical non-self-referential RFC-8785 binding digest."""
    payload = {
        "digest_schema": BINDING_DIGEST_SCHEMA,
        "deployment_ref": binding.deployment_ref,
        "enrollment_ref": binding.enrollment_ref,
        "channel_ref": binding.channel_ref,
        "target_id": binding.target_id,
        "profile_id": binding.profile_id,
        "method_id": binding.method_id,
        "protocol_version": binding.protocol_version,
        "source_digest": binding.source_digest,
        "content_digest": binding.content_digest,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_json).hexdigest()}"
