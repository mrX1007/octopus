"""Tests for artifact builder."""

from __future__ import annotations

import pytest

from core.c2.artifact_builder import (
    C2ArtifactBuilderV1,
    C2ArtifactBuildResultV1,
    C2ArtifactBuildSpecV1,
)

pytestmark = pytest.mark.unit


def test_artifact_builder_build():
    builder = C2ArtifactBuilderV1()
    spec = C2ArtifactBuildSpecV1(
        build_id="b1",
        target_os="linux",
        target_arch="amd64",
        config_params={"c2_server": "127.0.0.1:8443"},
    )

    result = builder.build_artifact(spec)
    assert isinstance(result, C2ArtifactBuildResultV1)
    assert result.build_id == "b1"
    assert len(result.artifact_bytes) > 0
    assert len(result.artifact_digest) == 64


def test_artifact_builder_deterministic_digest():
    builder = C2ArtifactBuilderV1()
    spec1 = C2ArtifactBuildSpecV1("b1", "darwin", "arm64", {"key": "val"})
    spec2 = C2ArtifactBuildSpecV1("b1", "darwin", "arm64", {"key": "val"})

    res1 = builder.build_artifact(spec1)
    res2 = builder.build_artifact(spec2)

    assert res1.artifact_digest == res2.artifact_digest
    assert res1.artifact_bytes == res2.artifact_bytes


def test_artifact_builder_different_params_different_digest():
    builder = C2ArtifactBuilderV1()
    spec1 = C2ArtifactBuildSpecV1("b1", "linux", "amd64", {"param": 1})
    spec2 = C2ArtifactBuildSpecV1("b2", "linux", "amd64", {"param": 2})

    res1 = builder.build_artifact(spec1)
    res2 = builder.build_artifact(spec2)

    assert res1.artifact_digest != res2.artifact_digest
