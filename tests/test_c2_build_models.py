"""Closed C2 artifact build model tests."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.c2.build_models import (
    BuildTemplateSource,
    C2ArtifactBuildBinding,
    C2ArtifactBuildRequest,
    PrebuiltArtifactSource,
)
from core.c2.deployment_profiles import (
    C2DeploymentMethod,
    C2DeploymentProfileId,
    C2TargetArch,
    C2TargetOS,
)
from core.c2.rebind_models import C2ArtifactRebindingRequest

pytestmark = pytest.mark.unit


def _binding() -> C2ArtifactBuildBinding:
    return C2ArtifactBuildBinding(
        schema_version="1.0",
        deployment_ref="deployment://1",
        enrollment_ref="c2-enrollment://1",
        channel_ref="c2-channel://1",
        target="host.example.test",
        target_os=C2TargetOS.LINUX,
        target_arch=C2TargetArch.AMD64,
        profile_id=C2DeploymentProfileId.GO_AGENT,
        method=C2DeploymentMethod.SSH_SESSION,
        agent_protocol_version="12.0",
        mission_id="mission://1",
        owner_subject_id="subject://1",
        source_binding_digest="sha256:source",
    )


def test_prebuilt_artifact_binding_fields_required() -> None:
    assert tuple(item.name for item in fields(PrebuiltArtifactSource)) == (
        "artifact_ref",
        "rebind_manifest_ref",
    )


def test_c2_artifact_rebinding_request_exact_fields() -> None:
    request = C2ArtifactRebindingRequest("artifact://1", "rebind://1", _binding())
    assert request.binding.deployment_ref == "deployment://1"


def test_build_request_keeps_source_and_binding_closed() -> None:
    source = BuildTemplateSource("template://go", C2TargetOS.LINUX, C2TargetArch.AMD64)
    assert C2ArtifactBuildRequest(source, _binding()).source is source
