"""Exact PR-4 reference metadata snapshot contracts."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, asdict, fields
from typing import get_args

import pytest

from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_snapshots import (
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    ReferenceMetadataSnapshot,
    SensitiveArtifactReferenceSnapshot,
    SessionReferenceSnapshot,
)
from core.actions.reference_types import (
    ArtifactKind,
    C2ResourceKind,
    C2ResourceState,
    DeploymentState,
    RouteState,
    SessionState,
)
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.actions.target_scope import (
    NetworkProtocol,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def _scope() -> TargetScopeSnapshot:
    return TargetScopeSnapshot(
        schema_version="2.0",
        revision=3,
        rules=(
            TargetScopeRule(
                role=TargetRole.PRIMARY,
                kind=TargetKind.IPV4,
                normalized_value="192.0.2.10",
                port=22,
                protocol=NetworkProtocol.SSH,
            ),
        ),
    )


def _authorization(reference: str) -> ReferenceAuthorizationSnapshot:
    return ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference=reference,
        authorization_revision=2,
        mission_id="mission-1",
        owner_subject_id="operator-1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("operator-2",),
        permitted_action_ids=("ssh:connect",),
        permitted_capabilities=("remote_session",),
        authorization_scope=_scope(),
        created_by_request_id="request-1",
        delegated_by_subject_id=None,
        expires_at=200.0,
    )


def _snapshots() -> tuple[ReferenceMetadataSnapshot, ...]:
    endpoint = TargetScopeCanonicalizer.canonicalize(
        "192.0.2.10",
        role=TargetRole.PRIMARY,
        port=22,
        protocol=NetworkProtocol.SSH,
    )
    tag = SensitiveIntegrityTagV2(
        key_id="integrity-key-1",
        algorithm="hmac-sha256-v2",
        domain="artifact-envelope",
        tag="opaque-keyed-tag",
    )
    return (
        CredentialReferenceSnapshot(
            reference="credential://one",
            revision=1,
            authorization=_authorization("credential://one"),
            target="192.0.2.10",
            service="ssh",
            username="alice",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified=True,
            expires_at=180.0,
        ),
        SessionReferenceSnapshot(
            reference="session://one",
            revision=1,
            authorization=_authorization("session://one"),
            target="192.0.2.10",
            service="ssh",
            connected_peer="peer-1",
            state=SessionState.ACTIVE,
            created_at=50.0,
            expires_at=180.0,
        ),
        NonSensitiveArtifactReferenceSnapshot(
            reference="artifact://one",
            revision=1,
            authorization=_authorization("artifact://one"),
            artifact_kind=ArtifactKind.GENERIC,
            target="192.0.2.10",
            content_digest="sha256:content",
            size=4,
            media_type="application/octet-stream",
            expires_at=180.0,
        ),
        SensitiveArtifactReferenceSnapshot(
            reference="artifact://sensitive",
            revision=1,
            authorization=_authorization("artifact://sensitive"),
            artifact_kind=ArtifactKind.KERBEROS_TICKET,
            target="192.0.2.10",
            sealed_record_digest="sha256:sealed-record",
            integrity_tag=tag,
            size=8,
            media_type="application/x-ccache",
            expires_at=180.0,
        ),
        PivotRouteReferenceSnapshot(
            reference="route://one",
            revision=1,
            authorization=_authorization("route://one"),
            session_ref="session://one",
            source_fact_ref="fact://one",
            proxy_endpoint=endpoint,
            allowed_scope=_scope(),
            state=RouteState.ACTIVE,
            expires_at=180.0,
        ),
        C2ReferenceSnapshot(
            reference="c2://one",
            revision=1,
            authorization=_authorization("c2://one"),
            resource_kind=C2ResourceKind.CHANNEL,
            target="192.0.2.10",
            daemon_instance_id="daemon-1",
            state=C2ResourceState.ACTIVE,
            expires_at=180.0,
        ),
        DeploymentReferenceSnapshot(
            reference="deployment://one",
            revision=1,
            authorization=_authorization("deployment://one"),
            target="192.0.2.10",
            lifecycle_owner="executor",
            state=DeploymentState.ACTIVE,
            deployment_attempt_id="attempt-1",
            artifact_binding_digest="sha256:binding",
            expires_at=180.0,
        ),
    )


def test_reference_metadata_snapshot_union_is_exactly_seven_variants() -> None:
    assert get_args(ReferenceMetadataSnapshot) == tuple(type(snapshot) for snapshot in _snapshots())
    assert all("Enrollment" not in variant.__name__ for variant in get_args(ReferenceMetadataSnapshot))


def test_snapshot_exact_fields() -> None:
    assert tuple(field.name for field in fields(CredentialReferenceSnapshot)) == (
        "reference",
        "revision",
        "authorization",
        "target",
        "service",
        "username",
        "domain",
        "auth_kind",
        "port",
        "verified",
        "expires_at",
    )
    assert tuple(field.name for field in fields(SessionReferenceSnapshot)) == (
        "reference",
        "revision",
        "authorization",
        "target",
        "service",
        "connected_peer",
        "state",
        "created_at",
        "expires_at",
    )


def test_snapshot_is_frozen_and_json_safe() -> None:
    for snapshot in _snapshots():
        with pytest.raises(FrozenInstanceError):
            snapshot.revision = 9  # type: ignore[misc]
        encoded = json.dumps(asdict(snapshot), sort_keys=True)
        assert snapshot.reference in encoded


def test_snapshot_never_contains_path_or_live_handle_fields() -> None:
    forbidden = {"path", "local_path", "handle", "socket", "transport", "plaintext", "secret_ref"}
    for snapshot in _snapshots():
        assert forbidden.isdisjoint(field.name for field in fields(snapshot))
        assert "/tmp/" not in repr(snapshot)


def test_metadata_authorization_identity_match_is_required() -> None:
    with pytest.raises(ValueError, match="reference_authorization_identity_mismatch"):
        CredentialReferenceSnapshot(
            reference="credential://one",
            revision=1,
            authorization=_authorization("credential://other"),
            target="192.0.2.10",
            service="ssh",
            username="alice",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified=True,
            expires_at=None,
        )


def test_sensitive_integrity_tag_has_exact_keyed_metadata() -> None:
    assert tuple(field.name for field in fields(SensitiveIntegrityTagV2)) == (
        "key_id",
        "algorithm",
        "domain",
        "tag",
    )
    with pytest.raises(ValueError, match="algorithm"):
        SensitiveIntegrityTagV2(
            key_id="key",
            algorithm="sha256",  # type: ignore[arg-type]
            domain="test",
            tag="tag",
        )


def test_snapshot_validations_and_predicates() -> None:
    from core.actions.reference_snapshots import reference_has_active_state

    # _require_reference_header errors
    with pytest.raises(ValueError, match="reference_invalid"):
        CredentialReferenceSnapshot(
            reference="",
            revision=1,
            authorization=_authorization("credential://one"),
            target="192.0.2.10",
            service="ssh",
            username="alice",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified=True,
            expires_at=None,
        )

    with pytest.raises(ValueError, match="reference_metadata_revision_invalid"):
        CredentialReferenceSnapshot(
            reference="credential://one",
            revision=0,
            authorization=_authorization("credential://one"),
            target="192.0.2.10",
            service="ssh",
            username="alice",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified=True,
            expires_at=None,
        )

    with pytest.raises(ValueError, match="reference_authorization_snapshot_invalid"):
        CredentialReferenceSnapshot(
            reference="credential://one",
            revision=1,
            authorization="not_a_snapshot",  # type: ignore
            target="192.0.2.10",
            service="ssh",
            username="alice",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified=True,
            expires_at=None,
        )

    # Expiry validation
    with pytest.raises(ValueError, match="reference_expiry_invalid"):
        CredentialReferenceSnapshot(
            reference="credential://one",
            revision=1,
            authorization=_authorization("credential://one"),
            target="192.0.2.10",
            service="ssh",
            username="alice",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified=True,
            expires_at=True,  # type: ignore
        )

    # Predicate testing
    for snap in _snapshots():
        assert reference_has_active_state(snap) is True
