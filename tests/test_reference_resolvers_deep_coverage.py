"""Unit tests for reference_resolvers.py."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_resolvers import (
    CredentialMetadataStore,
    ReferenceResolverRegistry,
    _require_reference,
)
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.target_scope import TargetKind, TargetScopeRule, TargetScopeSnapshot
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def test_metadata_store_validations():
    with pytest.raises(ValueError, match="reference_invalid"):
        _require_reference("")

    with pytest.raises(ValueError, match="reference_invalid"):
        _require_reference("ref://\x01test")

    store = CredentialMetadataStore()

    # Wrong type
    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        store.register_metadata("not_a_snapshot")  # type: ignore

    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )
    auth1 = ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference="cred://1",
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
    snap1 = CredentialReferenceSnapshot(
        reference="cred://1",
        revision=1,
        authorization=auth1,
        target="10.0.0.1",
        service="ssh",
        username="root",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=2000.0,
    )
    store.register_metadata(snap1)

    # Resolve not found
    with pytest.raises(KeyError, match="reference_not_found"):
        store.resolve_metadata("cred://nonexistent")

    # Assert current mismatch
    with pytest.raises(ValueError, match="reference_metadata_revision_mismatch"):
        store.assert_current(
            reference="cred://1",
            expected_metadata_revision=2,
            expected_authorization_revision=1,
        )

    with pytest.raises(ValueError, match="reference_authorization_revision_mismatch"):
        store.assert_current(
            reference="cred://1",
            expected_metadata_revision=1,
            expected_authorization_revision=2,
        )


def test_reference_resolver_registry_errors():
    reg = ReferenceResolverRegistry()

    # Invalid prefix
    with pytest.raises(ValueError, match="reference_prefix_invalid"):
        reg.register_resolver("not_a_valid_prefix", MagicMock())

    # Invalid resolver
    with pytest.raises(TypeError, match="reference_resolver_invalid"):
        reg.register_resolver("custom://", "not_a_resolver")  # type: ignore

    # Duplicate prefix
    class DummyResolver:
        def resolve_metadata(self, reference: str):
            return None

    dummy = DummyResolver()
    reg.register_resolver("custom://", dummy)
    with pytest.raises(ValueError, match="reference_resolver_duplicate"):
        reg.register_resolver("custom://", dummy)


def test_domain_resolvers_type_mismatch():
    from core.actions.reference_resolvers import (
        ArtifactReferenceResolver,
        C2ReferenceResolver,
        DeploymentReferenceResolver,
        PivotRouteReferenceResolver,
        SessionReferenceResolver,
    )

    mock_store = MagicMock()
    mock_store.resolve_metadata.return_value = "not_the_expected_snapshot"

    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        SessionReferenceResolver(mock_store).resolve_metadata("sess://1")

    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        ArtifactReferenceResolver(mock_store).resolve_metadata("art://1")

    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        PivotRouteReferenceResolver(mock_store).resolve_metadata("route://1")

    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        C2ReferenceResolver(mock_store).resolve_metadata("c2://1")

    with pytest.raises(TypeError, match="reference_metadata_type_mismatch"):
        DeploymentReferenceResolver(mock_store).resolve_metadata("dep://1")
