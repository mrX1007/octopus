"""Deep unit test coverage for ReferenceCheckoutCoordinator and all validation fences."""

from __future__ import annotations

import hmac
import pytest
from unittest.mock import MagicMock

from core.actions.checkout_models import (
    ApprovalCheckoutRequest,
    FactCheckoutRequest,
    IngressSessionAuthorizationSnapshot,
    IngressSessionCheckoutRequest,
    MissionAuthorizationSnapshot,
    MissionCheckoutRequest,
    PrincipalAuthorizationSnapshot,
    PrincipalCheckoutRequest,
    ReferenceAccessMode,
    ReferenceCheckout,
    ReferenceCheckoutRequest,
    ReferenceKind,
    ReferenceLeaseToken,
)
from core.actions.reference_authorization import (
    ReferenceAuthorizationError,
    ReferenceAuthorizationSnapshot,
)
from core.actions.reference_checkout import (
    ReferenceCheckoutCoordinator,
    ReferenceCheckoutError,
)
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.actions.trusted_facts import (
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
    TrustedFactSnapshot,
    TrustedFactTrustLevelV2,
    TrustedFactType,
)
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.types import (
    AuthenticationMethod,
    IngressKind,
    PrincipalRole,
    SubjectType,
)
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def _dummy_coordinator():
    ingress_store = MagicMock()
    ingress_store.checkout_lock_order_key = "01:ingress"
    principal_store = MagicMock()
    principal_store.checkout_lock_order_key = "02:principal"
    mission_store = MagicMock()
    mission_store.checkout_lock_order_key = "03:mission"
    approval_store = MagicMock()
    approval_store.checkout_lock_order_key = "04:approval"
    fact_store = MagicMock()
    fact_store.checkout_lock_order_key = "05:fact"

    coord = ReferenceCheckoutCoordinator(
        ingress_store=ingress_store,
        principal_store=principal_store,
        mission_store=mission_store,
        approval_store=approval_store,
        fact_store=fact_store,
        reference_stores={},
        clock=lambda: 1000.0,
    )
    return coord


def test_validate_ingress_fences():
    coord = _dummy_coordinator()
    req = IngressSessionCheckoutRequest(
        lease_id="l-1",
        lease_revision=1,
        bound_request_id="req-1",
        ingress_session_ref="sess-1",
        expected_session_revision=1,
        principal_ref="p-1",
        expected_principal_revision=1,
        transport_instance_id="tty-1",
        transport_binding_digest="sha256:tb",
    )
    snap = IngressSessionAuthorizationSnapshot(
        schema_version="2.0",
        ingress_session_ref="sess-1",
        revision=1,
        principal_ref="p-1",
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        authentication_method=AuthenticationMethod.API_KEY,
        ingress_kind=IngressKind.INTERACTIVE_CLI,
        authenticated_peer_id="peer-1",
        transport_binding_digest="sha256:tb",
        issued_at=500.0,
        expires_at=1500.0,
        revoked_at=None,
    )
    # Valid
    coord._validate_ingress(req, snap)

    # Inactive - expired
    expired_snap = IngressSessionAuthorizationSnapshot(
        schema_version="2.0",
        ingress_session_ref="sess-1",
        revision=1,
        principal_ref="p-1",
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        authentication_method=AuthenticationMethod.API_KEY,
        ingress_kind=IngressKind.INTERACTIVE_CLI,
        authenticated_peer_id="peer-1",
        transport_binding_digest="sha256:tb",
        issued_at=500.0,
        expires_at=800.0,  # now is 1000.0
        revoked_at=None,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_inactive"):
        coord._validate_ingress(req, expired_snap)

    # Mismatch
    mismatch_req = IngressSessionCheckoutRequest(
        lease_id="l-1",
        lease_revision=1,
        bound_request_id="req-1",
        ingress_session_ref="sess-2",
        expected_session_revision=1,
        principal_ref="p-1",
        expected_principal_revision=1,
        transport_instance_id="tty-1",
        transport_binding_digest="sha256:tb",
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_identity_mismatch"):
        coord._validate_ingress(mismatch_req, snap)


def test_validate_principal_fences():
    coord = _dummy_coordinator()
    req = PrincipalCheckoutRequest(
        principal_ref="p-1",
        expected_revision=1,
        subject_id="s-1",
    )
    ingress_snap = IngressSessionAuthorizationSnapshot(
        schema_version="2.0",
        ingress_session_ref="sess-1",
        revision=1,
        principal_ref="p-1",
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        authentication_method=AuthenticationMethod.API_KEY,
        ingress_kind=IngressKind.INTERACTIVE_CLI,
        authenticated_peer_id="peer-1",
        transport_binding_digest="sha256:tb",
        issued_at=500.0,
        expires_at=1500.0,
        revoked_at=None,
    )
    p_snap = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p-1",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=500.0,
        expires_at=1500.0,
    )
    coord._validate_principal(req, p_snap, ingress_snap)

    # Inactive
    inactive_snap = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p-1",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=False,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=500.0,
        expires_at=1500.0,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_principal_inactive"):
        coord._validate_principal(req, inactive_snap, ingress_snap)


def test_validate_fact_fences():
    coord = _dummy_coordinator()
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    req = FactCheckoutRequest(
        fact_ref="fact-1",
        expected_revision=1,
        expected_payload_digest="sha256:d",
        required_fact_type="confirmed_ad_access",
        target=target,
    )
    mission = MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="m-1",
        revision=1,
        mission_id="m-1",
        permitted_subject_ids=("s-1",),
        permitted_capabilities=("cap1",),
        permitted_stages=("recon",),
        target_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
        ),
        active=True,
        expires_at=1500.0,
    )
    snap = TrustedFactSnapshot(
        schema_version="2.0",
        fact_ref="fact-1",
        revision=1,
        payload_digest="sha256:d",
        mission_id="m-1",
        target="10.0.0.1",
        fact_type=TrustedFactType.CONFIRMED_AD_ACCESS,
        assessment_status=AssessmentStatus.VERIFIED,
        trust_level=TrustedFactTrustLevelV2.TRUSTED,
        freshness_status=FactFreshnessStatus.FRESH,
        coverage_status=EvidenceCoverageStatus.COMPLETE,
        source_execution_ids=("exec-1",),
        expires_at=1500.0,
    )

    coord._validate_fact(req, snap, mission, checkout_targets=(target,))

    # Target not in checkout_targets
    with pytest.raises(ReferenceCheckoutError, match="checkout_fact_target_not_extracted"):
        coord._validate_fact(req, snap, mission, checkout_targets=())

    # Untrusted fact
    untrusted_snap = TrustedFactSnapshot(
        schema_version="2.0",
        fact_ref="fact-1",
        revision=1,
        payload_digest="sha256:d",
        mission_id="m-1",
        target="10.0.0.1",
        fact_type=TrustedFactType.CONFIRMED_AD_ACCESS,
        assessment_status=AssessmentStatus.CONTRADICTED,
        trust_level=TrustedFactTrustLevelV2.UNTRUSTED,
        freshness_status=FactFreshnessStatus.FRESH,
        coverage_status=EvidenceCoverageStatus.COMPLETE,
        source_execution_ids=("exec-1",),
        expires_at=1500.0,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_fact_not_trusted"):
        coord._validate_fact(req, untrusted_snap, mission, checkout_targets=(target,))


def test_validate_approval_fences():
    coord = _dummy_coordinator()
    req = ApprovalCheckoutRequest(
        approval_ref="app-1",
        expected_revision=1,
        approval_graph_lease_id="lease-app-1",
        execution_graph_id="graph-1",
        root_action_id="root-act",
        concrete_action_id="conc-act",
    )
    lease = ApprovalExecutionLease._from_store(
        lease_id="lease-app-1",
        graph_revision=1,
        approval_ref="app-1",
        approval_revision=1,
        execution_graph_id="graph-1",
        root_action_id="root-act",
        mission_id="m-1",
        subject_id="s-1",
        store=MagicMock(),
    )
    mission = MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="m-1",
        revision=1,
        mission_id="m-1",
        permitted_subject_ids=("s-1",),
        permitted_capabilities=("cap1",),
        permitted_stages=("recon",),
        target_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
        ),
        active=True,
        expires_at=1500.0,
    )
    p_snap = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p-1",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=500.0,
        expires_at=1500.0,
    )

    coord._validate_approval(req, lease, mission, p_snap)

    # Lease mismatch
    bad_lease = ApprovalExecutionLease._from_store(
        lease_id="lease-app-WRONG",
        graph_revision=1,
        approval_ref="app-1",
        approval_revision=1,
        execution_graph_id="graph-1",
        root_action_id="root-act",
        mission_id="m-1",
        subject_id="s-1",
        store=MagicMock(),
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_approval_graph_identity_mismatch"):
        coord._validate_approval(req, bad_lease, mission, p_snap)


def test_validate_mission_fences():
    coord = _dummy_coordinator()
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    req_bundle = MagicMock()
    req_bundle.mission = MissionCheckoutRequest(
        mission_ref="m-1",
        expected_revision=1,
        subject_id="s-1",
    )
    req_bundle.targets = (target,)
    req_bundle.references = ()

    p_snap = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p-1",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=500.0,
        expires_at=1500.0,
    )
    mission = MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="m-1",
        revision=1,
        mission_id="m-1",
        permitted_subject_ids=("s-1",),
        permitted_capabilities=("cap1",),
        permitted_stages=("recon",),
        target_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
        ),
        active=True,
        expires_at=1500.0,
    )

    coord._validate_mission(req_bundle, mission, p_snap)

    # Inactive mission
    inactive_mission = MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="m-1",
        revision=1,
        mission_id="m-1",
        permitted_subject_ids=("s-1",),
        permitted_capabilities=("cap1",),
        permitted_stages=("recon",),
        target_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
        ),
        active=False,
        expires_at=1500.0,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_mission_inactive"):
        coord._validate_mission(req_bundle, inactive_mission, p_snap)


def test_validate_reference_fences():
    coord = _dummy_coordinator()
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    req = ReferenceCheckoutRequest(
        reference="cred://1",
        expected_kind=ReferenceKind.CREDENTIAL,
        expected_metadata_revision=1,
        expected_authorization_revision=1,
        required_action_id="act-1",
        required_capability="cap1",
        targets=(target,),
        access_mode=ReferenceAccessMode.METADATA_ONLY,
    )
    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )
    auth = ReferenceAuthorizationSnapshot(
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
    metadata = CredentialReferenceSnapshot(
        reference="cred://1",
        revision=1,
        authorization=auth,
        target="10.0.0.1",
        service="ssh",
        username="root",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=2000.0,
    )
    token = ReferenceLeaseToken(
        reference="cred://1",
        metadata_revision=1,
        authorization_revision=1,
        fence_generation=1,
        checkout_id="chk-1",
    )
    receipt = ReferenceCheckout(
        metadata=metadata,
        lease_token=token,
    )

    mission = MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="m-1",
        revision=1,
        mission_id="m-1",
        permitted_subject_ids=("s-1",),
        permitted_capabilities=("cap1",),
        permitted_stages=("recon",),
        target_scope=scope,
        active=True,
        expires_at=1500.0,
    )
    p_snap = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p-1",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=500.0,
        expires_at=1500.0,
    )

    coord._validate_reference(
        req,
        receipt,
        mission=mission,
        principal=p_snap,
        checkout_targets=(target,),
    )

    # Target not in checkout targets
    with pytest.raises(ReferenceCheckoutError, match="checkout_reference_target_not_extracted"):
        coord._validate_reference(
            req,
            receipt,
            mission=mission,
            principal=p_snap,
            checkout_targets=(),
        )


def test_reference_checkout_helpers_and_store_unavailable():
    from core.actions.reference_checkout import (
        _metadata_matches_kind,
        _require_lock_key,
    )

    # _require_lock_key error
    bad_part = MagicMock()
    bad_part.checkout_lock_order_key = ""
    with pytest.raises(ReferenceCheckoutError, match="checkout_lock_order_key_invalid"):
        _require_lock_key(bad_part)

    # _metadata_matches_kind
    from core.actions.reference_snapshots import (
        C2ReferenceSnapshot,
        CredentialReferenceSnapshot,
        DeploymentReferenceSnapshot,
        NonSensitiveArtifactReferenceSnapshot,
        PivotRouteReferenceSnapshot,
        SessionReferenceSnapshot,
    )

    assert _metadata_matches_kind(object.__new__(CredentialReferenceSnapshot), ReferenceKind.CREDENTIAL) is True
    assert _metadata_matches_kind(object.__new__(SessionReferenceSnapshot), ReferenceKind.SESSION) is True
    assert _metadata_matches_kind(object.__new__(NonSensitiveArtifactReferenceSnapshot), ReferenceKind.ARTIFACT) is True
    assert _metadata_matches_kind(object.__new__(PivotRouteReferenceSnapshot), ReferenceKind.PIVOT_ROUTE) is True
    assert _metadata_matches_kind(object.__new__(C2ReferenceSnapshot), ReferenceKind.C2_RESOURCE) is True
    assert _metadata_matches_kind(object.__new__(DeploymentReferenceSnapshot), ReferenceKind.DEPLOYMENT) is True
    assert _metadata_matches_kind(MagicMock(), ReferenceKind.CREDENTIAL) is False

    coord = _dummy_coordinator()
    coord._approval_store = None
    coord._fact_store = None
    req_bundle = MagicMock()
    req_bundle.approval = MagicMock()
    req_bundle.facts = (MagicMock(),)

    # _checkout_approval without store raises
    with pytest.raises(ReferenceCheckoutError, match="checkout_approval_store_unavailable"):
        coord._checkout_approval(req_bundle, MagicMock(), MagicMock(), MagicMock())

    # _checkout_facts without store raises
    with pytest.raises(ReferenceCheckoutError, match="checkout_fact_store_unavailable"):
        coord._checkout_facts(req_bundle, MagicMock(), MagicMock())

    # _reference_store_pairs missing store raises
    ref_req = MagicMock()
    ref_req.expected_kind = ReferenceKind.DEPLOYMENT  # not in _dummy_coordinator reference_stores
    with pytest.raises(ReferenceCheckoutError, match="checkout_reference_store_unavailable"):
        coord._reference_store_pairs((ref_req,))
