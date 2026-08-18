"""Unit tests for reference_snapshots.py validation branches."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_snapshots import (
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    SensitiveArtifactReferenceSnapshot,
    SessionReferenceSnapshot,
    _require_expiry,
    _require_reference_header,
    reference_has_active_state,
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
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def test_reference_header_and_expiry_errors():
    with pytest.raises(ValueError, match="reference_invalid"):
        _require_reference_header("", 1, MagicMock())

    with pytest.raises(ValueError, match="reference_metadata_revision_invalid"):
        _require_reference_header("ref://1", 0, MagicMock())

    with pytest.raises(ValueError, match="reference_authorization_snapshot_invalid"):
        _require_reference_header("ref://1", 1, "not_auth_snapshot")

    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )
    auth = ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference="ref://DIFF",
        authorization_revision=1,
        mission_id="m-1",
        owner_subject_id="s-1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("s-1",),
        permitted_action_ids=("act-1",),
        permitted_capabilities=("cap1",),
        authorization_scope=scope,
        created_by_request_id="req-1",
        delegated_by_subject_id=None,
        expires_at=2000.0,
    )
    with pytest.raises(ValueError, match="reference_authorization_identity_mismatch"):
        _require_reference_header("ref://1", 1, auth)

    with pytest.raises(ValueError, match="reference_expiry_invalid"):
        _require_expiry(float("nan"))

    with pytest.raises(ValueError, match="reference_expiry_invalid"):
        _require_expiry(True)


def test_snapshot_variants_and_active_predicate():
    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )
    auth = ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference="ref://1",
        authorization_revision=1,
        mission_id="m-1",
        owner_subject_id="s-1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("s-1",),
        permitted_action_ids=("act-1",),
        permitted_capabilities=("cap1",),
        authorization_scope=scope,
        created_by_request_id="req-1",
        delegated_by_subject_id=None,
        expires_at=2000.0,
    )

    # Credential port and auth kind errors
    with pytest.raises(ValueError, match="reference_credential_auth_kind_invalid"):
        CredentialReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            target="10.0.0.1",
            service="ssh",
            username="root",
            domain="",
            auth_kind="not_auth_kind",  # type: ignore
            port=22,
            verified=True,
            expires_at=2000.0,
        )

    with pytest.raises(ValueError, match="reference_credential_port_invalid"):
        CredentialReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            target="10.0.0.1",
            service="ssh",
            username="root",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=99999,  # invalid port
            verified=True,
            expires_at=2000.0,
        )

    # Session state error & active predicate
    with pytest.raises(ValueError, match="reference_session_state_invalid"):
        SessionReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            target="10.0.0.1",
            service="ssh",
            connected_peer="10.0.0.2",
            state="not_state",  # type: ignore
            created_at=100.0,
            expires_at=2000.0,
        )

    sess = SessionReferenceSnapshot(
        reference="ref://1",
        revision=1,
        authorization=auth,
        target="10.0.0.1",
        service="ssh",
        connected_peer="10.0.0.2",
        state=SessionState.ACTIVE,
        created_at=100.0,
        expires_at=2000.0,
    )
    assert reference_has_active_state(sess) is True

    # Artifact errors
    with pytest.raises(ValueError, match="reference_artifact_size_invalid"):
        NonSensitiveArtifactReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            artifact_kind=ArtifactKind.GENERIC,
            target=None,
            content_digest="sha256:d",
            size=-1,
            media_type="text/plain",
            expires_at=2000.0,
        )

    tag = SensitiveIntegrityTagV2(key_id="k1", algorithm="hmac-sha256-v2", domain="dom", tag="sha256:d")
    with pytest.raises(ValueError, match="reference_artifact_integrity_tag_invalid"):
        SensitiveArtifactReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            artifact_kind=ArtifactKind.GENERIC,
            target=None,
            sealed_record_digest="sha256:d",
            integrity_tag="not_a_tag",  # type: ignore
            size=10,
            media_type="text/plain",
            expires_at=2000.0,
        )

    # Pivot route errors & active predicate
    target = ExtractedActionTarget(role=TargetRole.PRIMARY, kind=TargetKind.IPV4, normalized_value="10.0.0.1")
    pivot = PivotRouteReferenceSnapshot(
        reference="ref://1",
        revision=1,
        authorization=auth,
        session_ref="sess://1",
        source_fact_ref="fact://1",
        proxy_endpoint=target,
        allowed_scope=scope,
        state=RouteState.ACTIVE,
        expires_at=2000.0,
    )
    assert reference_has_active_state(pivot) is True

    # C2 resource & active predicate
    c2 = C2ReferenceSnapshot(
        reference="ref://1",
        revision=1,
        authorization=auth,
        resource_kind=C2ResourceKind.AGENT,
        target="10.0.0.1",
        daemon_instance_id="d-1",
        state=C2ResourceState.ACTIVE,
        expires_at=2000.0,
    )
    assert reference_has_active_state(c2) is True

    # Deployment & active predicate
    dep = DeploymentReferenceSnapshot(
        reference="ref://1",
        revision=1,
        authorization=auth,
        target="10.0.0.1",
        lifecycle_owner="admin",
        state=DeploymentState.ACTIVE,
        deployment_attempt_id="att-1",
        artifact_binding_digest="sha256:d",
        expires_at=2000.0,
    )
    assert reference_has_active_state(dep) is True

    # Artifact kind invalid
    with pytest.raises(ValueError, match="reference_artifact_kind_invalid"):
        NonSensitiveArtifactReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            artifact_kind="NOT_A_KIND",  # type: ignore
            target=None,
            content_digest="sha256:d",
            size=10,
            media_type="text/plain",
            expires_at=2000.0,
        )

    # Credential verified invalid
    with pytest.raises(ValueError, match="reference_credential_verified_invalid"):
        CredentialReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            target="10.0.0.1",
            service="ssh",
            username="root",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified="not_bool",  # type: ignore
            expires_at=2000.0,
        )

    # Session created_at invalid
    with pytest.raises(ValueError, match="reference_session_created_at_invalid"):
        SessionReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            target="10.0.0.1",
            service="ssh",
            connected_peer="peer-1",
            state=SessionState.ACTIVE,
            created_at=float("nan"),
            expires_at=2000.0,
        )

    # Sensitive artifact invalid size and media type
    with pytest.raises(ValueError, match="reference_artifact_size_invalid"):
        SensitiveArtifactReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            artifact_kind=ArtifactKind.GENERIC,
            target=None,
            sealed_record_digest="sha256:d",
            integrity_tag=tag,
            size=-1,
            media_type="text/plain",
            expires_at=2000.0,
        )

    with pytest.raises(ValueError, match="reference_artifact_media_type_invalid"):
        SensitiveArtifactReferenceSnapshot(
            reference="ref://1",
            revision=1,
            authorization=auth,
            artifact_kind=ArtifactKind.GENERIC,
            target=None,
            sealed_record_digest="sha256:d",
            integrity_tag=tag,
            size=10,
            media_type="",
            expires_at=2000.0,
        )
