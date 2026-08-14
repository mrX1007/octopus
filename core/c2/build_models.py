"""Closed C2 deployment source and artifact build request models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal, Protocol, Union, runtime_checkable

from typing_extensions import TypeAlias, assert_never

from core.actions.execution_budget import ExecutionBudget, ExecutionLineage
from core.actions.provider_invocation import (
    PhaseBoundTransientRefV2,
    ProviderExecutePhaseLeaseV2,
    ProviderInvocationScopeV2,
)
from core.actions.reference_types import ArtifactKind
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.c2.deployment_profiles import (
    C2DeploymentMethod,
    C2DeploymentProfileId,
    C2TargetArch,
    C2TargetOS,
)


@dataclass(frozen=True)
class PrebuiltArtifactSource:
    artifact_ref: str
    rebind_manifest_ref: str


@dataclass(frozen=True)
class BuildTemplateSource:
    template_ref: str
    target_os: C2TargetOS
    target_arch: C2TargetArch


C2DeploymentSource: TypeAlias = Union[PrebuiltArtifactSource, BuildTemplateSource]


class C2ArtifactIntegrityMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class C2ArtifactBuildBinding:
    schema_version: Literal["1.0"]
    deployment_ref: str
    enrollment_ref: str
    channel_ref: str
    target: str
    target_os: C2TargetOS
    target_arch: C2TargetArch
    profile_id: C2DeploymentProfileId
    method: C2DeploymentMethod
    agent_protocol_version: Literal["12.0"]
    mission_id: str
    owner_subject_id: str
    source_binding_digest: str


@dataclass(frozen=True)
class C2ArtifactBuildRequest:
    source: BuildTemplateSource
    binding: C2ArtifactBuildBinding


class _C2ArtifactBuildOutputConstructionTokenV1:
    pass


_C2_ARTIFACT_BUILD_OUTPUT_TOKEN = _C2ArtifactBuildOutputConstructionTokenV1()


@dataclass(frozen=True, repr=False, init=False)
class C2ArtifactBuildOutput:
    transient_ref: PhaseBoundTransientRefV2 = field(repr=False, compare=False)
    artifact_kind: ArtifactKind
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    source_binding_digest: str
    metadata_digest: str

    def __init__(self) -> None:
        raise TypeError("C2 artifact build output is sink-issued only")

    @classmethod
    def _from_sink(
        cls,
        *,
        transient_ref: PhaseBoundTransientRefV2,
        artifact_kind: ArtifactKind,
        sealed_record_digest: str,
        integrity_tag: SensitiveIntegrityTagV2,
        size: int,
        media_type: str,
        source_binding_digest: str,
        metadata_digest: str,
        _token: _C2ArtifactBuildOutputConstructionTokenV1,
    ) -> C2ArtifactBuildOutput:
        if _token is not _C2_ARTIFACT_BUILD_OUTPUT_TOKEN:
            raise TypeError("C2 artifact build output is sink-issued only")
        if type(transient_ref) is not PhaseBoundTransientRefV2:
            raise TypeError("C2 artifact build output requires an exact transient ref")
        if artifact_kind is not ArtifactKind.C2_AGENT:
            raise ValueError("C2 agent build output must be a sensitive C2 agent artifact")
        if type(integrity_tag) is not SensitiveIntegrityTagV2:
            raise TypeError("C2 artifact build output requires an exact integrity tag")
        if type(size) is not int or size <= 0:
            raise ValueError("C2 artifact build output size must be positive")
        for name, value in (
            ("sealed_record_digest", sealed_record_digest),
            ("media_type", media_type),
            ("source_binding_digest", source_binding_digest),
            ("metadata_digest", metadata_digest),
        ):
            if type(value) is not str or not value:
                raise ValueError(f"{name} must be a non-empty string")
        instance = object.__new__(cls)
        object.__setattr__(instance, "transient_ref", transient_ref)
        object.__setattr__(instance, "artifact_kind", artifact_kind)
        object.__setattr__(instance, "sealed_record_digest", sealed_record_digest)
        object.__setattr__(instance, "integrity_tag", integrity_tag)
        object.__setattr__(instance, "size", size)
        object.__setattr__(instance, "media_type", media_type)
        object.__setattr__(instance, "source_binding_digest", source_binding_digest)
        object.__setattr__(instance, "metadata_digest", metadata_digest)
        return instance


@runtime_checkable
class C2SensitiveArtifactBuildSinkV1(Protocol):
    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...

    def write_chunk(self, source: memoryview) -> None: ...

    def finalize(
        self,
        *,
        artifact_kind: ArtifactKind,
        media_type: str,
        source_binding_digest: str,
        metadata_digest: str,
    ) -> C2ArtifactBuildOutput: ...

    def abort_and_destroy(self) -> None: ...


@dataclass(frozen=True, repr=False)
class C2ArtifactBuildContext:
    scope: ProviderInvocationScopeV2 = field(repr=False, compare=False)
    artifact_sink: C2SensitiveArtifactBuildSinkV1 = field(
        repr=False,
        compare=False,
    )
    budget: ExecutionBudget
    lineage: ExecutionLineage


class C2ArtifactBindingHasherV1:
    @staticmethod
    def digest(
        *,
        binding: C2ArtifactBuildBinding,
        sealed_record_digest: str,
        integrity_tag: SensitiveIntegrityTagV2,
    ) -> str:
        if type(binding) is not C2ArtifactBuildBinding:
            raise TypeError("artifact binding must be exact")
        if type(integrity_tag) is not SensitiveIntegrityTagV2:
            raise TypeError("artifact integrity tag must be exact")
        if type(sealed_record_digest) is not str or not sealed_record_digest:
            raise ValueError("sealed record digest must be non-empty")
        payload = {
            "schema_version": "c2-artifact-binding-v1",
            "sealed_record_digest": sealed_record_digest,
            "integrity_tag": {
                "key_id": integrity_tag.key_id,
                "algorithm": integrity_tag.algorithm,
                "domain": integrity_tag.domain,
                "tag": integrity_tag.tag,
            },
            "deployment_ref": binding.deployment_ref,
            "enrollment_ref": binding.enrollment_ref,
            "channel_ref": binding.channel_ref,
            "target": binding.target,
            "profile_id": binding.profile_id.value,
            "method": binding.method.value,
            "agent_protocol_version": binding.agent_protocol_version,
            "mission_id": binding.mission_id,
            "owner_subject_id": binding.owner_subject_id,
            "source_binding_digest": binding.source_binding_digest,
            "target_os": binding.target_os.value,
            "target_arch": binding.target_arch.value,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class C2ArtifactStageRequestV1:
    transient_id: str
    artifact_kind: ArtifactKind
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    source: C2DeploymentSource
    binding: C2ArtifactBuildBinding
    artifact_binding_digest: str
    metadata_digest: str

    def __post_init__(self) -> None:
        if self.artifact_kind is not ArtifactKind.C2_AGENT:
            raise ValueError("only sensitive C2 agent artifacts can use C2 staging")
        expected = C2ArtifactBindingHasherV1.digest(
            binding=self.binding,
            sealed_record_digest=self.sealed_record_digest,
            integrity_tag=self.integrity_tag,
        )
        if self.artifact_binding_digest != expected:
            raise C2ArtifactIntegrityMismatch("artifact_binding_digest")
        if type(self.size) is not int or self.size <= 0:
            raise ValueError("C2 artifact stage size must be positive")
        for name in (
            "transient_id",
            "sealed_record_digest",
            "media_type",
            "metadata_digest",
        ):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be a non-empty string")


def deployment_source_kind(
    source: C2DeploymentSource,
) -> Literal["prebuilt_artifact", "build_template"]:
    if isinstance(source, PrebuiltArtifactSource):
        if type(source) is not PrebuiltArtifactSource:
            raise TypeError("deployment source must be an exact closed variant")
        return "prebuilt_artifact"
    if isinstance(source, BuildTemplateSource):
        if type(source) is not BuildTemplateSource:
            raise TypeError("deployment source must be an exact closed variant")
        return "build_template"
    assert_never(source)


__all__ = [
    "BuildTemplateSource",
    "C2ArtifactBindingHasherV1",
    "C2ArtifactBuildBinding",
    "C2ArtifactBuildContext",
    "C2ArtifactBuildOutput",
    "C2ArtifactBuildRequest",
    "C2ArtifactIntegrityMismatch",
    "C2ArtifactStageRequestV1",
    "C2DeploymentSource",
    "C2SensitiveArtifactBuildSinkV1",
    "PrebuiltArtifactSource",
    "deployment_source_kind",
]
