"""Unit tests for core/actions/reference_resolvers.py."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_resolvers import (
    ArtifactReferenceResolver,
    C2ReferenceResolver,
    CredentialMetadataStore,
    CredentialReferenceResolver,
    DeploymentReferenceResolver,
    PivotRouteReferenceResolver,
    ReferenceResolverRegistry,
    SessionReferenceResolver,
    _require_reference,
)
from core.actions.reference_snapshots import (
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
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
from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind, CredentialRef

pytestmark = pytest.mark.unit


def _make_auth(ref: str, rev: int = 1) -> ReferenceAuthorizationSnapshot:
    return ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference=ref,
        authorization_revision=rev,
        mission_id="mission_1",
        owner_subject_id="subj_1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("subj_1",),
        permitted_action_ids=("act_1",),
        permitted_capabilities=("cap_1",),
        authorization_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(
                TargetScopeRule(
                    role=None,
                    kind=TargetKind.IPV4,
                    normalized_value="10.0.0.1",
                ),
            ),
        ),
        created_by_request_id="req_1",
        delegated_by_subject_id=None,
        expires_at=None,
    )


def _make_cred_snapshot(ref: str = "cred://c1", rev: int = 1, auth_rev: int = 1) -> CredentialReferenceSnapshot:
    return CredentialReferenceSnapshot(
        reference=ref,
        revision=rev,
        authorization=_make_auth(ref, auth_rev),
        target="10.0.0.1",
        service="ssh",
        username="admin",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=None,
    )


def test_require_reference():
    assert _require_reference("valid://ref") == "valid://ref"
    with pytest.raises(ValueError, match="reference_invalid"):
        _require_reference("")
    with pytest.raises(ValueError, match="reference_invalid"):
        _require_reference(123)
    with pytest.raises(ValueError, match="reference_invalid"):
        _require_reference("bad\x00ref")


def test_metadata_snapshot_store_generic():
    store = CredentialMetadataStore()
    s2 = _make_cred_snapshot("cred://1", rev=2, auth_rev=2)

    # Type mismatch
    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        store.register_metadata("not a snapshot")  # type: ignore[arg-type]

    # Success register & resolve
    store.register_metadata(s2)
    assert store.resolve_metadata("cred://1") == s2

    # Assert current success
    assert (
        store.assert_current(reference="cred://1", expected_metadata_revision=2, expected_authorization_revision=2)
        == s2
    )

    # Assert current mismatch
    with pytest.raises(ValueError, match="reference_metadata_revision_mismatch"):
        store.assert_current(reference="cred://1", expected_metadata_revision=3, expected_authorization_revision=2)

    with pytest.raises(ValueError, match="reference_authorization_revision_mismatch"):
        store.assert_current(reference="cred://1", expected_metadata_revision=2, expected_authorization_revision=3)

    # Revision rollback
    s_old = _make_cred_snapshot("cred://1", rev=1, auth_rev=2)
    with pytest.raises(ValueError, match="reference_metadata_revision_rollback"):
        store.register_metadata(s_old)

    # Auth revision rollback
    s_old_auth = _make_cred_snapshot("cred://1", rev=2, auth_rev=1)
    with pytest.raises(ValueError, match="reference_authorization_revision_rollback"):
        store.register_metadata(s_old_auth)

    # Revision conflict (same rev, different content)
    s_conflict = CredentialReferenceSnapshot(
        reference="cred://1",
        revision=2,
        authorization=_make_auth("cred://1", 2),
        target="10.0.0.2",
        service="ssh",
        username="admin",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=None,
    )
    with pytest.raises(ValueError, match="reference_metadata_revision_conflict"):
        store.register_metadata(s_conflict)

    # Resolve not found
    with pytest.raises(KeyError, match="reference_not_found"):
        store.resolve_metadata("cred://nonexistent")


def test_credential_reference_resolver():
    mock_cred_store = MagicMock()
    mock_entry = CredentialRef(
        handle="cred://1",
        target="10.0.0.1",
        service="ssh",
        username="admin",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
    )
    mock_cred_store.resolve.return_value = mock_entry

    resolver = CredentialReferenceResolver(mock_cred_store)
    snap = _make_cred_snapshot("cred://1")
    resolver.register_metadata(snap)

    res = resolver.resolve_metadata("cred://1")
    assert res == snap

    # Missing in credential store
    mock_cred_store.resolve.return_value = None
    with pytest.raises(KeyError, match="credential_reference_not_found"):
        resolver.resolve_metadata("cred://1")

    with pytest.raises(KeyError, match="credential_reference_not_found"):
        resolver.register_metadata(_make_cred_snapshot("cred://missing"))

    # Metadata mismatch
    mismatch_entry = CredentialRef(
        handle="cred://mismatch",
        target="10.0.0.99",
        service="ssh",
        username="admin",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
    )
    mock_cred_store.resolve.return_value = mismatch_entry
    with pytest.raises(ValueError, match="credential_reference_metadata_mismatch"):
        resolver.register_metadata(_make_cred_snapshot("cred://mismatch"))


def test_typed_resolvers_delegation():
    mock_store = MagicMock()

    # Session
    sess_snap = SessionReferenceSnapshot(
        reference="session://1",
        revision=1,
        authorization=_make_auth("session://1"),
        target="10.0.0.1",
        service="ssh",
        connected_peer="peer_1",
        state=SessionState.ACTIVE,
        created_at=100.0,
        expires_at=None,
    )
    mock_store.resolve_metadata.return_value = sess_snap
    sess_res = SessionReferenceResolver(mock_store)
    assert sess_res.resolve_metadata("session://1") == sess_snap

    mock_store.resolve_metadata.return_value = _make_cred_snapshot()
    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        sess_res.resolve_metadata("session://1")

    # Artifact
    art_snap = NonSensitiveArtifactReferenceSnapshot(
        reference="artifact://1",
        revision=1,
        authorization=_make_auth("artifact://1"),
        artifact_kind=ArtifactKind.GENERIC,
        target="10.0.0.1",
        content_digest="sha256:abc",
        size=10,
        media_type="text/plain",
        expires_at=None,
    )
    mock_store.resolve_metadata.return_value = art_snap
    art_res = ArtifactReferenceResolver(mock_store)
    assert art_res.resolve_metadata("artifact://1") == art_snap

    # Pivot Route
    pivot_snap = PivotRouteReferenceSnapshot(
        reference="pivot://1",
        revision=1,
        authorization=_make_auth("pivot://1"),
        session_ref="session://1",
        source_fact_ref="fact://1",
        proxy_endpoint=TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY),
        allowed_scope=TargetScopeSnapshot(schema_version="2.0", revision=1, rules=()),
        state=RouteState.ACTIVE,
        expires_at=None,
    )
    mock_store.resolve_metadata.return_value = pivot_snap
    pivot_res = PivotRouteReferenceResolver(mock_store)
    assert pivot_res.resolve_metadata("pivot://1") == pivot_snap

    # C2
    c2_snap = C2ReferenceSnapshot(
        reference="c2://1",
        revision=1,
        authorization=_make_auth("c2://1"),
        resource_kind=C2ResourceKind.AGENT,
        target="10.0.0.1",
        daemon_instance_id=None,
        state=C2ResourceState.ACTIVE,
        expires_at=None,
    )
    mock_store.resolve_metadata.return_value = c2_snap
    c2_res = C2ReferenceResolver(mock_store)
    assert c2_res.resolve_metadata("c2://1") == c2_snap

    # Deployment
    dep_snap = DeploymentReferenceSnapshot(
        reference="deploy://1",
        revision=1,
        authorization=_make_auth("deploy://1"),
        target="10.0.0.1",
        lifecycle_owner="owner_1",
        state=DeploymentState.ACTIVE,
        deployment_attempt_id="att_1",
        artifact_binding_digest="sha256:bind",
        expires_at=None,
    )
    mock_store.resolve_metadata.return_value = dep_snap
    dep_res = DeploymentReferenceResolver(mock_store)
    assert dep_res.resolve_metadata("deploy://1") == dep_snap


def test_reference_resolver_registry():
    registry = ReferenceResolverRegistry()

    # Direct registration
    snap = _make_cred_snapshot("cred://direct")
    registry.register(snap)
    assert registry.resolve("cred://direct") == snap

    # Custom prefix resolver registration
    mock_prefix_resolver = MagicMock()
    snap_custom = _make_cred_snapshot("custom://item")
    mock_prefix_resolver.resolve_metadata.return_value = snap_custom

    # Invalid prefix
    with pytest.raises(ValueError, match="reference_prefix_invalid"):
        registry.register_resolver("invalid_prefix", mock_prefix_resolver)

    # Invalid resolver type
    with pytest.raises(TypeError, match="reference_resolver_invalid"):
        registry.register_resolver("valid://", "not a resolver")  # type: ignore[arg-type]

    # Register valid
    registry.register_resolver("custom://", mock_prefix_resolver)

    # Duplicate prefix
    with pytest.raises(ValueError, match="reference_resolver_duplicate"):
        registry.register_resolver("custom://", mock_prefix_resolver)

    # Resolve via prefix
    assert registry.resolve("custom://item") == snap_custom

    # Resolve not found
    with pytest.raises(KeyError, match="reference_not_found"):
        registry.resolve("other://notfound")

    # Prefix resolver returns mismatched reference
    mock_bad_resolver = MagicMock()
    mock_bad_resolver.resolve_metadata.return_value = _make_cred_snapshot("bad://other")
    registry.register_resolver("bad://", mock_bad_resolver)
    with pytest.raises(ValueError, match="reference_resolver_identity_mismatch"):
        registry.resolve("bad://item")

    # Authorized resolution success
    auth_snap = registry.resolve_authorized(
        "cred://direct",
        expected_metadata_revision=1,
        expected_authorization_revision=1,
        mission_id="mission_1",
        subject_id="subj_1",
        action_id="act_1",
        required_capability="cap_1",
        targets=(TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY),),
    )
    assert auth_snap == snap
