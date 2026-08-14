"""Exact C2 artifact binding and staging DTO contracts."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.actions.reference_types import ArtifactKind
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.c2.build_models import (
    BuildTemplateSource,
    C2ArtifactBindingHasherV1,
    C2ArtifactBuildBinding,
    C2ArtifactBuildOutput,
    C2ArtifactIntegrityMismatch,
    C2ArtifactStageRequestV1,
)
from core.c2.deployment_profiles import (
    C2DeploymentMethod,
    C2DeploymentProfileId,
    C2TargetArch,
    C2TargetOS,
)

pytestmark = pytest.mark.unit


def _binding() -> C2ArtifactBuildBinding:
    return C2ArtifactBuildBinding(
        schema_version="1.0",
        deployment_ref="deployment://one",
        enrollment_ref="c2-enrollment://one",
        channel_ref="c2-channel://one",
        target="host.example.test",
        target_os=C2TargetOS.LINUX,
        target_arch=C2TargetArch.AMD64,
        profile_id=C2DeploymentProfileId.GO_AGENT,
        method=C2DeploymentMethod.SSH_SESSION,
        agent_protocol_version="12.0",
        mission_id="mission://one",
        owner_subject_id="subject://one",
        source_binding_digest="sha256:source",
    )


def _tag() -> SensitiveIntegrityTagV2:
    return SensitiveIntegrityTagV2(
        key_id="key-one",
        algorithm="hmac-sha256-v2",
        domain="octopus/c2-agent-artifact/v1",
        tag="hmac:opaque",
    )


def _request(*, digest: str | None = None) -> C2ArtifactStageRequestV1:
    binding = _binding()
    tag = _tag()
    expected = C2ArtifactBindingHasherV1.digest(
        binding=binding,
        sealed_record_digest="sha256:sealed",
        integrity_tag=tag,
    )
    return C2ArtifactStageRequestV1(
        transient_id="transient://one",
        artifact_kind=ArtifactKind.C2_AGENT,
        sealed_record_digest="sha256:sealed",
        integrity_tag=tag,
        size=4096,
        media_type="application/octet-stream",
        source=BuildTemplateSource(
            template_ref="template://go-agent",
            target_os=C2TargetOS.LINUX,
            target_arch=C2TargetArch.AMD64,
        ),
        binding=binding,
        artifact_binding_digest=digest or expected,
        metadata_digest="sha256:metadata",
    )


def test_c2_artifact_binding_digest_computed_before_staging() -> None:
    request = _request()
    assert request.artifact_binding_digest == C2ArtifactBindingHasherV1.digest(
        binding=request.binding,
        sealed_record_digest=request.sealed_record_digest,
        integrity_tag=request.integrity_tag,
    )
    with pytest.raises(C2ArtifactIntegrityMismatch, match="artifact_binding_digest"):
        _request(digest="sha256:forged")


def test_c2_artifact_stage_request_contains_full_binding_and_digest() -> None:
    assert tuple(field.name for field in fields(C2ArtifactStageRequestV1)) == (
        "transient_id",
        "artifact_kind",
        "sealed_record_digest",
        "integrity_tag",
        "size",
        "media_type",
        "source",
        "binding",
        "artifact_binding_digest",
        "metadata_digest",
    )
    request = _request()
    assert request.binding.deployment_ref == "deployment://one"
    assert request.artifact_kind is ArtifactKind.C2_AGENT


def test_stage_c2_artifact_never_accepts_build_output() -> None:
    assert "build_output" not in {field.name for field in fields(C2ArtifactStageRequestV1)}
    assert C2ArtifactStageRequestV1.__annotations__["source"] == "C2DeploymentSource"
    with pytest.raises(TypeError):
        C2ArtifactBuildOutput()  # type: ignore[call-arg]
