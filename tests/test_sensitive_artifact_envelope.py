"""Tests for SensitiveArtifactEnvelopeV2."""

import pytest

from core.actions.sensitive_artifact_envelope import SensitiveArtifactEnvelopeV2
from core.actions.sensitive_integrity_runtime import SensitiveIntegrityTagV2


@pytest.mark.unit
def test_sensitive_envelope():
    tag = SensitiveIntegrityTagV2(
        key_id="k1",
        algorithm="hmac-sha256-v2",
        domain="sensitive-artifact/1",
        tag="tagval",
    )
    env = SensitiveArtifactEnvelopeV2(
        artifact_id="art-1",
        encrypted_payload=b"encdata",
        encryption_algorithm="AES-256-GCM",
        integrity_tag=tag,
    )
    assert env.envelope_digest.startswith("sha256:")
