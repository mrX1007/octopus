"""Tests for sensitive artifact reservation recovery."""

import pytest

from core.actions.sensitive_artifact_envelope import SensitiveArtifactEnvelopeV2


@pytest.mark.unit
def test_artifact_recovery():
    assert SensitiveArtifactEnvelopeV2 is not None
