"""PR-5 Module: Sensitive artifact envelope and staging models (§8.3)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from core.actions.sensitive_integrity_runtime import SensitiveIntegrityTagV2


@dataclass(frozen=True)
class SensitiveArtifactEnvelopeV2:
    artifact_id: str
    encrypted_payload: bytes
    encryption_algorithm: str
    integrity_tag: SensitiveIntegrityTagV2
    envelope_digest: str = ""

    def __post_init__(self) -> None:
        if not self.envelope_digest:
            raw = self.artifact_id.encode() + self.encrypted_payload
            object.__setattr__(self, "envelope_digest", f"sha256:{hashlib.sha256(raw).hexdigest()}")


__all__ = [
    "SensitiveArtifactEnvelopeV2",
]
