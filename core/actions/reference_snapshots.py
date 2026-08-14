"""Exact frozen PR-4 reference metadata snapshot union."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Union

from typing_extensions import TypeAlias

from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_types import (
    ArtifactKind,
    C2ResourceKind,
    C2ResourceState,
    DeploymentState,
    NonEnrollmentC2ResourceKindV2,
    RouteState,
    SessionState,
)
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.actions.target_scope import ExtractedActionTarget, TargetScopeSnapshot
from core.credentials import CredentialAuthKind


def _require_reference_header(
    reference: object,
    revision: object,
    authorization: object,
) -> None:
    if type(reference) is not str or not reference:
        raise ValueError("reference_invalid")
    if type(revision) is not int or revision < 1:
        raise ValueError("reference_metadata_revision_invalid")
    if type(authorization) is not ReferenceAuthorizationSnapshot:
        raise ValueError("reference_authorization_snapshot_invalid")
    if reference != authorization.reference:
        raise ValueError("reference_authorization_identity_mismatch")


def _require_string(name: str, value: object, *, allow_empty: bool = False) -> None:
    if type(value) is not str or (not allow_empty and not value):
        raise ValueError(f"reference_{name}_invalid")


def _require_optional_string(name: str, value: object) -> None:
    if value is not None:
        _require_string(name, value)


def _require_expiry(value: object) -> None:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
    ):
        raise ValueError("reference_expiry_invalid")


@dataclass(frozen=True)
class CredentialReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    target: str
    service: str
    username: str
    domain: str
    auth_kind: CredentialAuthKind
    port: int | None
    verified: bool
    expires_at: float | None

    def __post_init__(self) -> None:
        _require_reference_header(self.reference, self.revision, self.authorization)
        for name in ("target", "service", "username"):
            _require_string(name, getattr(self, name))
        _require_string("domain", self.domain, allow_empty=True)
        if type(self.auth_kind) is not CredentialAuthKind:
            raise ValueError("reference_credential_auth_kind_invalid")
        if isinstance(self.port, bool) or (self.port is not None and not 1 <= self.port <= 65535):
            raise ValueError("reference_credential_port_invalid")
        if type(self.verified) is not bool:
            raise ValueError("reference_credential_verified_invalid")
        _require_expiry(self.expires_at)


@dataclass(frozen=True)
class SessionReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    target: str
    service: str
    connected_peer: str
    state: SessionState
    created_at: float
    expires_at: float | None

    def __post_init__(self) -> None:
        _require_reference_header(self.reference, self.revision, self.authorization)
        for name in ("target", "service", "connected_peer"):
            _require_string(name, getattr(self, name))
        if type(self.state) is not SessionState:
            raise ValueError("reference_session_state_invalid")
        if (
            isinstance(self.created_at, bool)
            or not isinstance(self.created_at, (int, float))
            or not math.isfinite(self.created_at)
        ):
            raise ValueError("reference_session_created_at_invalid")
        _require_expiry(self.expires_at)


@dataclass(frozen=True)
class NonSensitiveArtifactReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    artifact_kind: ArtifactKind
    target: str | None
    content_digest: str
    size: int
    media_type: str
    expires_at: float | None

    def __post_init__(self) -> None:
        _require_reference_header(self.reference, self.revision, self.authorization)
        if type(self.artifact_kind) is not ArtifactKind:
            raise ValueError("reference_artifact_kind_invalid")
        _require_optional_string("artifact_target", self.target)
        _require_string("artifact_content_digest", self.content_digest)
        if type(self.size) is not int or self.size < 0:
            raise ValueError("reference_artifact_size_invalid")
        _require_string("artifact_media_type", self.media_type)
        _require_expiry(self.expires_at)


@dataclass(frozen=True)
class SensitiveArtifactReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    artifact_kind: ArtifactKind
    target: str | None
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    expires_at: float | None

    def __post_init__(self) -> None:
        _require_reference_header(self.reference, self.revision, self.authorization)
        if type(self.artifact_kind) is not ArtifactKind:
            raise ValueError("reference_artifact_kind_invalid")
        _require_optional_string("artifact_target", self.target)
        _require_string("artifact_sealed_record_digest", self.sealed_record_digest)
        if type(self.integrity_tag) is not SensitiveIntegrityTagV2:
            raise ValueError("reference_artifact_integrity_tag_invalid")
        if type(self.size) is not int or self.size < 0:
            raise ValueError("reference_artifact_size_invalid")
        _require_string("artifact_media_type", self.media_type)
        _require_expiry(self.expires_at)


ArtifactReferenceSnapshot: TypeAlias = Union[
    NonSensitiveArtifactReferenceSnapshot,
    SensitiveArtifactReferenceSnapshot,
]


@dataclass(frozen=True)
class PivotRouteReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    session_ref: str
    source_fact_ref: str
    proxy_endpoint: ExtractedActionTarget
    allowed_scope: TargetScopeSnapshot
    state: RouteState
    expires_at: float | None

    def __post_init__(self) -> None:
        _require_reference_header(self.reference, self.revision, self.authorization)
        _require_string("route_session_ref", self.session_ref)
        _require_string("route_source_fact_ref", self.source_fact_ref)
        if type(self.proxy_endpoint) is not ExtractedActionTarget:
            raise ValueError("reference_route_proxy_endpoint_invalid")
        if type(self.allowed_scope) is not TargetScopeSnapshot:
            raise ValueError("reference_route_allowed_scope_invalid")
        if type(self.state) is not RouteState:
            raise ValueError("reference_route_state_invalid")
        _require_expiry(self.expires_at)


@dataclass(frozen=True)
class C2ReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    resource_kind: NonEnrollmentC2ResourceKindV2
    target: str | None
    daemon_instance_id: str | None
    state: C2ResourceState
    expires_at: float | None

    def __post_init__(self) -> None:
        _require_reference_header(self.reference, self.revision, self.authorization)
        if type(self.resource_kind) is not C2ResourceKind:
            raise ValueError("reference_c2_resource_kind_invalid")
        _require_optional_string("c2_target", self.target)
        _require_optional_string("c2_daemon_instance_id", self.daemon_instance_id)
        if type(self.state) is not C2ResourceState:
            raise ValueError("reference_c2_resource_state_invalid")
        _require_expiry(self.expires_at)


@dataclass(frozen=True)
class DeploymentReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    target: str
    lifecycle_owner: str
    state: DeploymentState
    deployment_attempt_id: str
    artifact_binding_digest: str
    expires_at: float | None

    def __post_init__(self) -> None:
        _require_reference_header(self.reference, self.revision, self.authorization)
        for name in ("target", "lifecycle_owner", "deployment_attempt_id", "artifact_binding_digest"):
            _require_string(name, getattr(self, name))
        if type(self.state) is not DeploymentState:
            raise ValueError("reference_deployment_state_invalid")
        _require_expiry(self.expires_at)


ReferenceMetadataSnapshot: TypeAlias = Union[
    CredentialReferenceSnapshot,
    SessionReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    SensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    C2ReferenceSnapshot,
    DeploymentReferenceSnapshot,
]


REFERENCE_METADATA_SNAPSHOT_TYPES = (
    CredentialReferenceSnapshot,
    SessionReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    SensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    C2ReferenceSnapshot,
    DeploymentReferenceSnapshot,
)


def reference_has_active_state(snapshot: ReferenceMetadataSnapshot) -> bool:
    """Compatibility predicate for the pre-coordinator checkout placeholder."""

    if type(snapshot) is SessionReferenceSnapshot:
        return snapshot.state is SessionState.ACTIVE
    if type(snapshot) is PivotRouteReferenceSnapshot:
        return snapshot.state is RouteState.ACTIVE
    if type(snapshot) is C2ReferenceSnapshot:
        return snapshot.state is C2ResourceState.ACTIVE
    if type(snapshot) is DeploymentReferenceSnapshot:
        return snapshot.state is DeploymentState.ACTIVE
    return True


__all__ = [
    "REFERENCE_METADATA_SNAPSHOT_TYPES",
    "ArtifactReferenceSnapshot",
    "C2ReferenceSnapshot",
    "CredentialReferenceSnapshot",
    "DeploymentReferenceSnapshot",
    "NonSensitiveArtifactReferenceSnapshot",
    "PivotRouteReferenceSnapshot",
    "ReferenceMetadataSnapshot",
    "SensitiveArtifactReferenceSnapshot",
    "SessionReferenceSnapshot",
    "reference_has_active_state",
]
