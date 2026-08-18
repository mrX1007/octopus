"""Comprehensive unit test coverage for checkout_models.py error branches and validations."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.checkout_models import (
    ApprovalCheckoutRequest,
    CheckoutRecoveryRefV2,
    ExecutionAttemptGroup,
    ExecutorCheckoutBundle,
    ExecutorCheckoutRequestBundle,
    FactCheckoutRequest,
    IngressSessionCheckoutRequest,
    MissionCheckoutRequest,
    PrincipalCheckoutRequest,
    ReferenceAccessMode,
    ReferenceCheckout,
    ReferenceCheckoutRequest,
    ReferenceKind,
    ReferenceLeaseToken,
)
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
)
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.ingress import AuthenticationMethod, IngressKind, IngressSessionAuthorizationSnapshot
from core.auth.missions import MissionAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def test_checkout_helpers_and_reference_request_errors():
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)

    # Invalid kind
    with pytest.raises(ValueError, match="checkout_reference_kind_invalid"):
        ReferenceCheckoutRequest(
            reference="cred://1",
            expected_kind="not_a_kind",  # type: ignore
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            required_action_id="act-1",
            required_capability="cap1",
            targets=(target,),
            access_mode=ReferenceAccessMode.METADATA_ONLY,
        )

    # Invalid access mode
    with pytest.raises(ValueError, match="checkout_reference_access_mode_invalid"):
        ReferenceCheckoutRequest(
            reference="cred://1",
            expected_kind=ReferenceKind.CREDENTIAL,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            required_action_id="act-1",
            required_capability="cap1",
            targets=(target,),
            access_mode="invalid_mode",  # type: ignore
        )

    # Invalid revisions
    with pytest.raises(ValueError, match="checkout_metadata_revision_invalid"):
        ReferenceCheckoutRequest(
            reference="cred://1",
            expected_kind=ReferenceKind.CREDENTIAL,
            expected_metadata_revision=0,
            expected_authorization_revision=1,
            required_action_id="act-1",
            required_capability="cap1",
            targets=(target,),
            access_mode=ReferenceAccessMode.METADATA_ONLY,
        )

    # Duplicate targets
    with pytest.raises(ValueError, match="checkout_reference_targets_duplicate"):
        ReferenceCheckoutRequest(
            reference="cred://1",
            expected_kind=ReferenceKind.CREDENTIAL,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            required_action_id="act-1",
            required_capability="cap1",
            targets=(target, target),
            access_mode=ReferenceAccessMode.METADATA_ONLY,
        )


def test_ingress_session_checkout_request_errors():
    with pytest.raises(ValueError, match="checkout_lease_id_invalid"):
        IngressSessionCheckoutRequest(
            lease_id="",
            lease_revision=1,
            bound_request_id="req-1",
            ingress_session_ref="sess-1",
            expected_session_revision=1,
            principal_ref="p-1",
            expected_principal_revision=1,
            transport_instance_id="trans-1",
            transport_binding_digest="sha256:d",
        )

    with pytest.raises(ValueError, match="checkout_lease_revision_invalid"):
        IngressSessionCheckoutRequest(
            lease_id="lease-1",
            lease_revision=0,
            bound_request_id="req-1",
            ingress_session_ref="sess-1",
            expected_session_revision=1,
            principal_ref="p-1",
            expected_principal_revision=1,
            transport_instance_id="trans-1",
            transport_binding_digest="sha256:d",
        )


def test_executor_checkout_request_bundle_mismatches():
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    ingress = IngressSessionCheckoutRequest(
        lease_id="lease-1",
        lease_revision=1,
        bound_request_id="req-1",
        ingress_session_ref="sess-1",
        expected_session_revision=1,
        principal_ref="p-1",
        expected_principal_revision=1,
        transport_instance_id="trans-1",
        transport_binding_digest="sha256:d",
    )
    principal = PrincipalCheckoutRequest(
        principal_ref="p-1",
        expected_revision=1,
        subject_id="s-1",
    )
    mission = MissionCheckoutRequest(
        mission_ref="m-1",
        expected_revision=1,
        subject_id="s-1",
    )
    attempt_group = ExecutionAttemptGroup(
        attempt_group_id="ag-1",
        root_execution_id="root-1",
        execution_graph_id="graph-1",
    )

    # Ingress principal mismatch
    bad_ingress = IngressSessionCheckoutRequest(
        lease_id="lease-1",
        lease_revision=1,
        bound_request_id="req-1",
        ingress_session_ref="sess-1",
        expected_session_revision=1,
        principal_ref="p-WRONG",
        expected_principal_revision=1,
        transport_instance_id="trans-1",
        transport_binding_digest="sha256:d",
    )
    with pytest.raises(ValueError, match="checkout_ingress_principal_identity_mismatch"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=bad_ingress,
            principal=principal,
            mission=mission,
            approval=None,
            facts=(),
            targets=(target,),
            attempt_group=attempt_group,
        )

    # Principal mission subject mismatch
    bad_mission = MissionCheckoutRequest(
        mission_ref="m-1",
        expected_revision=1,
        subject_id="s-OTHER",
    )
    with pytest.raises(ValueError, match="checkout_principal_mission_subject_mismatch"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=ingress,
            principal=principal,
            mission=bad_mission,
            approval=None,
            facts=(),
            targets=(target,),
            attempt_group=attempt_group,
        )

    # Approval execution graph mismatch
    bad_app = ApprovalCheckoutRequest(
        approval_ref="app-1",
        expected_revision=1,
        approval_graph_lease_id="lease-app",
        execution_graph_id="graph-WRONG",
        root_action_id="act-1",
        concrete_action_id="act-1",
    )
    with pytest.raises(ValueError, match="checkout_approval_execution_graph_mismatch"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=ingress,
            principal=principal,
            mission=mission,
            approval=bad_app,
            facts=(),
            targets=(target,),
            attempt_group=attempt_group,
        )


def test_reference_checkout_receipt_and_token():
    token = ReferenceLeaseToken(
        reference="cred://1",
        metadata_revision=1,
        authorization_revision=1,
        fence_generation=1,
        checkout_id="chk-1",
    )
    assert token.reference == "cred://1"

    rec = CheckoutRecoveryRefV2(
        checkout_id="chk-1",
        fence_generation=1,
        journal_ref="jour://1",
        journal_digest="sha256:j",
    )
    assert rec.checkout_id == "chk-1"


def test_checkout_bundle_and_recovery_ref_deep():
    # Direct init
    with pytest.raises(TypeError, match="coordinator-issued only"):
        ExecutorCheckoutBundle()

    # Recovery ref validations
    with pytest.raises(ValueError, match="recovery_checkout_id_invalid"):
        CheckoutRecoveryRefV2(
            checkout_id="",
            fence_generation=1,
            journal_ref="jou://1",
            journal_digest="sha256:d",
        )

    # Reference checkout reduce
    token = ReferenceLeaseToken(
        reference="cred://1",
        metadata_revision=1,
        authorization_revision=1,
        fence_generation=1,
        checkout_id="chk-1",
    )
    meta = MagicMock()
    meta.reference = "cred://1"
    meta.revision = 1
    meta.authorization.reference = "cred://1"
    meta.authorization.authorization_revision = 1

    rc = ReferenceCheckout(metadata=meta, lease_token=token)
    with pytest.raises(TypeError, match="non-serializable"):
        rc.__reduce__()
    with pytest.raises(TypeError, match="non-serializable"):
        rc.__reduce_ex__(2)

    # ReferenceCheckout token type error
    with pytest.raises(ValueError, match="checkout_reference_lease_token_invalid"):
        ReferenceCheckout(metadata=meta, lease_token="not_a_token")  # type: ignore

    # ReferenceCheckout identity mismatch
    bad_token = ReferenceLeaseToken(
        reference="cred://DIFFERENT",
        metadata_revision=1,
        authorization_revision=1,
        fence_generation=1,
        checkout_id="chk-1",
    )
    with pytest.raises(ValueError, match="checkout_reference_lease_identity_mismatch"):
        ReferenceCheckout(metadata=meta, lease_token=bad_token)

    # _from_coordinator validation errors
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    issuer = MagicMock()

    with pytest.raises(ValueError, match="checkout_ingress_snapshot_invalid"):
        ExecutorCheckoutBundle._from_coordinator(
            checkout_id="chk-1",
            ingress_session="bad",  # type: ignore
            principal=MagicMock(),
            mission=MagicMock(),
            approval_graph_lease=None,
            facts=(),
            references=(),
            targets=(target,),
            fence_generation=1,
            issuer=issuer,
        )

    # Bundle reduce
    dummy_bundle = object.__new__(ExecutorCheckoutBundle)
    with pytest.raises(TypeError, match="non-serializable"):
        dummy_bundle.__reduce__()
    with pytest.raises(TypeError, match="non-serializable"):
        dummy_bundle.__reduce_ex__(2)

    # ExecutorCheckoutRequestBundle validation errors
    req_ing = IngressSessionCheckoutRequest(
        lease_id="l1",
        lease_revision=1,
        bound_request_id="req-1",
        ingress_session_ref="ing://1",
        expected_session_revision=1,
        principal_ref="p://1",
        expected_principal_revision=1,
        transport_instance_id="t-1",
        transport_binding_digest="sha256:d",
    )
    req_princ = PrincipalCheckoutRequest(
        principal_ref="p://1",
        expected_revision=1,
        subject_id="s-1",
    )
    req_miss = MissionCheckoutRequest(
        mission_ref="m://1",
        expected_revision=1,
        subject_id="s-1",
    )
    grp = ExecutionAttemptGroup(
        attempt_group_id="att-1",
        root_execution_id="r-1",
        execution_graph_id="g-1",
    )

    with pytest.raises(ValueError, match="checkout_references_invalid"):
        ExecutorCheckoutRequestBundle(
            references=("not_a_ref_req",),  # type: ignore
            ingress_session=req_ing,
            principal=req_princ,
            mission=req_miss,
            approval=None,
            facts=(),
            targets=(target,),
            attempt_group=grp,
        )

    with pytest.raises(ValueError, match="checkout_ingress_request_invalid"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session="not_ing",  # type: ignore
            principal=req_princ,
            mission=req_miss,
            approval=None,
            facts=(),
            targets=(target,),
            attempt_group=grp,
        )

    with pytest.raises(ValueError, match="checkout_principal_request_invalid"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=req_ing,
            principal="not_princ",  # type: ignore
            mission=req_miss,
            approval=None,
            facts=(),
            targets=(target,),
            attempt_group=grp,
        )

    with pytest.raises(ValueError, match="checkout_mission_request_invalid"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=req_ing,
            principal=req_princ,
            mission="not_miss",  # type: ignore
            approval=None,
            facts=(),
            targets=(target,),
            attempt_group=grp,
        )

    with pytest.raises(ValueError, match="checkout_approval_request_invalid"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=req_ing,
            principal=req_princ,
            mission=req_miss,
            approval="not_approval",  # type: ignore
            facts=(),
            targets=(target,),
            attempt_group=grp,
        )

    with pytest.raises(ValueError, match="checkout_facts_invalid"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=req_ing,
            principal=req_princ,
            mission=req_miss,
            approval=None,
            facts=("not_a_fact",),  # type: ignore
            targets=(target,),
            attempt_group=grp,
        )

    fact_req = FactCheckoutRequest(
        fact_ref="fact://1",
        expected_revision=1,
        required_fact_type="host",
        target=target,
        expected_payload_digest="sha256:d",
    )
    with pytest.raises(ValueError, match="checkout_fact_duplicate"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=req_ing,
            principal=req_princ,
            mission=req_miss,
            approval=None,
            facts=(fact_req, fact_req),
            targets=(target,),
            attempt_group=grp,
        )

    with pytest.raises(ValueError, match="checkout_attempt_group_invalid"):
        ExecutorCheckoutRequestBundle(
            references=(),
            ingress_session=req_ing,
            principal=req_princ,
            mission=req_miss,
            approval=None,
            facts=(fact_req,),
            targets=(target,),
            attempt_group="not_attempt_group",  # type: ignore
        )

    # Bundle constructor direct errors
    snap_ing = IngressSessionAuthorizationSnapshot(
        schema_version="2.0",
        ingress_session_ref="ing://1",
        revision=1,
        principal_ref="p://1",
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        authentication_method=AuthenticationMethod.PASSWORD,
        ingress_kind=IngressKind.INTERACTIVE_CLI,
        authenticated_peer_id="peer-1",
        transport_binding_digest="sha256:d",
        issued_at=100.0,
        expires_at=2000.0,
        revoked_at=None,
    )
    snap_princ = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p://1",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=100.0,
        expires_at=2000.0,
    )

    with pytest.raises(ValueError, match="checkout_principal_snapshot_invalid"):
        ExecutorCheckoutBundle._from_coordinator(
            checkout_id="chk-1",
            ingress_session=snap_ing,
            principal="not_a_snapshot",  # type: ignore
            mission=MagicMock(),
            approval_graph_lease=None,
            facts=(),
            references=(),
            targets=(target,),
            fence_generation=1,
            issuer=MagicMock(),
        )

    with pytest.raises(ValueError, match="checkout_mission_snapshot_invalid"):
        ExecutorCheckoutBundle._from_coordinator(
            checkout_id="chk-1",
            ingress_session=snap_ing,
            principal=snap_princ,
            mission="not_a_mission",  # type: ignore
            approval_graph_lease=None,
            facts=(),
            references=(),
            targets=(target,),
            fence_generation=1,
            issuer=MagicMock(),
        )

    snap_miss = object.__new__(MissionAuthorizationSnapshot)
    with pytest.raises(ValueError, match="checkout_approval_graph_lease_invalid"):
        ExecutorCheckoutBundle._from_coordinator(
            checkout_id="chk-1",
            ingress_session=snap_ing,
            principal=snap_princ,
            mission=snap_miss,
            approval_graph_lease="not_a_lease",  # type: ignore
            facts=(),
            references=(),
            targets=(target,),
            fence_generation=1,
            issuer=MagicMock(),
        )
