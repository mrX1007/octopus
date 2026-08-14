"""Tests for C2 artifact rebinder."""

from __future__ import annotations

import pytest

from core.c2.artifact_rebinder import C2ArtifactRebinderV1, RebindManifestV1

pytestmark = pytest.mark.unit


def test_artifact_rebinder_rebind():
    rebinder = C2ArtifactRebinderV1()
    original_bytes = b"ORIGINAL_AGENT_BINARY_PAYLOAD"
    manifest = RebindManifestV1(
        manifest_id="m1",
        target_agent_ref="agent_new",
        binding_keys={"session_key": "abc123secret"},
    )

    rebound_bytes, new_digest = rebinder.rebind_artifact(original_bytes, manifest)
    assert rebound_bytes.startswith(original_bytes)
    assert b"REBIND:m1:agent_new" in rebound_bytes
    assert len(new_digest) == 64


def test_artifact_rebinder_different_manifest_results_in_different_digest():
    rebinder = C2ArtifactRebinderV1()
    original_bytes = b"BASE_BINARY"

    m1 = RebindManifestV1("m1", "agent_1", {"key": "val1"})
    m2 = RebindManifestV1("m2", "agent_2", {"key": "val2"})

    bytes1, digest1 = rebinder.rebind_artifact(original_bytes, m1)
    bytes2, digest2 = rebinder.rebind_artifact(original_bytes, m2)

    assert digest1 != digest2
    assert bytes1 != bytes2
