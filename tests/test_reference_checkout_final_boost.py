"""Targeted unit tests for all remaining branches in reference_checkout.py."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.actions.checkout_models import (
    ExecutionAttemptGroup,
    ExecutorCheckoutBundle,
    ExecutorCheckoutRequestBundle,
    IngressSessionCheckoutRequest,
    MissionCheckoutRequest,
    PrincipalCheckoutRequest,
    ReferenceKind,
)
from core.actions.reference_checkout import (
    CheckoutLockParticipantV2,
    ReferenceCheckoutCoordinator,
    ReferenceCheckoutError,
)
from core.actions.target_scope import (
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.ingress import AuthenticationMethod, IngressKind, IngressSessionAuthorizationSnapshot
from core.auth.missions import MissionAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot
from core.auth.types import SubjectType

pytestmark = pytest.mark.unit


class MockParticipant(CheckoutLockParticipantV2):
    def acquire_checkout_lock(self) -> None:
        pass

    def release_checkout_lock(self) -> None:
        pass


def test_coordinator_constructor_validations():
    part = MockParticipant()
    # Invalid stores
    with pytest.raises(TypeError, match="checkout_ingress_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store="bad",  # type: ignore
            principal_store=part,
            mission_store=part,
            reference_stores={},
        )

    with pytest.raises(TypeError, match="checkout_principal_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store="bad",  # type: ignore
            mission_store=part,
            reference_stores={},
        )

    with pytest.raises(TypeError, match="checkout_mission_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store="bad",  # type: ignore
            reference_stores={},
        )

    with pytest.raises(TypeError, match="checkout_approval_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            approval_store="bad",  # type: ignore
            reference_stores={},
        )

    with pytest.raises(TypeError, match="checkout_fact_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            fact_store="bad",  # type: ignore
            reference_stores={},
        )

    with pytest.raises(TypeError, match="checkout_clock_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            clock="not_callable",  # type: ignore
            reference_stores={},
        )

    with pytest.raises(TypeError, match="checkout_reference_store_kind_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            reference_stores={"not_a_kind": part},  # type: ignore
        )

    with pytest.raises(TypeError, match="checkout_reference_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            reference_stores={ReferenceKind.CREDENTIAL: "bad_store"},  # type: ignore
        )


def test_coordinator_validation_errors():
    part = MockParticipant()
    coord = ReferenceCheckoutCoordinator(
        ingress_store=part,
        principal_store=part,
        mission_store=part,
        reference_stores={},
    )

    # checkout_many not bundle
    with pytest.raises(TypeError, match="checkout_request_bundle_invalid"):
        coord.checkout_many("not_a_bundle")  # type: ignore

    # Recovery ref validations
    with pytest.raises(TypeError, match="checkout_recovery_ref_invalid"):
        coord.checkpoint_existing_recovery_state(MagicMock(), "not_a_ref")  # type: ignore

    with pytest.raises(TypeError, match="checkout_recovery_ref_invalid"):
        coord.reopen_fenced("not_a_ref")  # type: ignore

    # Ingress snapshot invalid
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
    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_snapshot_invalid"):
        coord._validate_ingress(req_ing, "not_a_snapshot")  # type: ignore

    # Ingress identity mismatch
    snap_mismatch = IngressSessionAuthorizationSnapshot(
        schema_version="2.0",
        ingress_session_ref="ing://DIFF",
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
    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_identity_mismatch"):
        coord._validate_ingress(req_ing, snap_mismatch)

    # Inactive ingress
    snap_inactive = IngressSessionAuthorizationSnapshot(
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
        expires_at=200.0,  # expired
        revoked_at=None,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_inactive"):
        coord._validate_ingress(req_ing, snap_inactive)

    # Require record error
    with pytest.raises(TypeError, match="checkout_bundle_invalid"):
        coord._require_record("not_a_bundle")  # type: ignore

    with pytest.raises(TypeError, match="checkout_fact_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            fact_store="bad",  # type: ignore
            reference_stores={},
        )

    with pytest.raises(TypeError, match="checkout_clock_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            reference_stores={},
            clock="not_callable",  # type: ignore
        )

    with pytest.raises(TypeError, match="checkout_reference_store_kind_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            reference_stores={"not_a_kind": part},  # type: ignore
        )

    with pytest.raises(TypeError, match="checkout_reference_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=part,
            principal_store=part,
            mission_store=part,
            reference_stores={ReferenceKind.CREDENTIAL: "bad_store"},  # type: ignore
        )


def test_coordinator_validation_helper_branches():
    part = MockParticipant()
    coord = ReferenceCheckoutCoordinator(
        ingress_store=part,
        principal_store=part,
        mission_store=part,
        reference_stores={},
        clock=lambda: float("nan"),
    )

    # _now() clock validation
    with pytest.raises(ReferenceCheckoutError, match="checkout_clock_value_invalid"):
        coord._now()

    # _require_record error
    with pytest.raises(TypeError, match="checkout_bundle_invalid"):
        coord._require_record("not_a_bundle")  # type: ignore

    # _release_reference_receipts with failing store
    class FailingStore(MockParticipant):
        def release_reference_checkout(self, receipt):
            raise RuntimeError("release fail")

    failing_store = FailingStore()
    with pytest.raises(ReferenceCheckoutError, match="checkout_reference_release_failed"):
        coord._release_reference_receipts([(failing_store, MagicMock())], suppress=False)

    # _close_material_handles with failing handle
    class FailingHandle:
        def close_checkout(self):
            raise RuntimeError("close handle fail")

    failures = coord._close_material_handles((FailingHandle(),))  # type: ignore
    assert len(failures) == 1

    # _bundle_fence empty
    fence_id, gen = coord._bundle_fence([])
    assert fence_id.startswith("checkout://")
    assert gen == 1

    # _validate_ingress errors
    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_snapshot_invalid"):
        coord._validate_ingress(MagicMock(), "not_a_snapshot")  # type: ignore

    # _validate_principal errors
    with pytest.raises(ReferenceCheckoutError, match="checkout_principal_snapshot_invalid"):
        coord._validate_principal(MagicMock(), "not_a_snapshot", MagicMock())  # type: ignore

    # _validate_mission errors
    with pytest.raises(ReferenceCheckoutError, match="checkout_mission_snapshot_invalid"):
        coord._validate_mission(MagicMock(), "not_a_snapshot", MagicMock())  # type: ignore

    # _validate_approval errors
    with pytest.raises(ReferenceCheckoutError, match="checkout_approval_graph_lease_invalid"):
        coord._validate_approval(MagicMock(), "not_a_lease", MagicMock(), MagicMock())  # type: ignore

    # _validate_fact errors
    with pytest.raises(ReferenceCheckoutError, match="checkout_fact_snapshot_invalid"):
        coord._validate_fact(MagicMock(), "not_a_snapshot", MagicMock(), checkout_targets=())  # type: ignore

    # _validate_reference errors
    with pytest.raises(ReferenceCheckoutError, match="checkout_reference_receipt_invalid"):
        coord._validate_reference(
            MagicMock(),
            "not_a_receipt",  # type: ignore
            mission=MagicMock(),
            principal=MagicMock(),
            checkout_targets=(),
        )


def test_coordinator_metadata_matches_kind():
    from core.actions.reference_checkout import _metadata_matches_kind
    from core.actions.reference_snapshots import DeploymentReferenceSnapshot

    dep = object.__new__(DeploymentReferenceSnapshot)
    assert _metadata_matches_kind(dep, ReferenceKind.DEPLOYMENT) is True
    assert _metadata_matches_kind(dep, "not_a_kind") is False  # type: ignore


def test_coordinator_deep_validation_branches():
    part = MockParticipant()
    coord = ReferenceCheckoutCoordinator(
        ingress_store=part,
        principal_store=part,
        mission_store=part,
        reference_stores={},
        clock=lambda: 1000.0,
    )

    req_princ = PrincipalCheckoutRequest(
        principal_ref="p://1",
        expected_revision=1,
        subject_id="s-1",
    )
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

    # Principal identity mismatch
    snap_princ_bad = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p://DIFF",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=100.0,
        expires_at=2000.0,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_principal_identity_mismatch"):
        coord._validate_principal(req_princ, snap_princ_bad, snap_ing)

    # Principal inactive (not active)
    snap_princ_inactive = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p://1",
        revision=1,
        subject_id="s-1",
        subject_type=SubjectType.OPERATOR,
        active=False,
        roles=("operator",),
        capabilities=("cap1",),
        authenticated_at=100.0,
        expires_at=2000.0,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_principal_inactive"):
        coord._validate_principal(req_princ, snap_princ_inactive, snap_ing)

    snap_princ_valid = PrincipalAuthorizationSnapshot(
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

    # Mission inactive
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    req_bundle = ExecutorCheckoutRequestBundle(
        references=(),
        ingress_session=IngressSessionCheckoutRequest(
            lease_id="l1",
            lease_revision=1,
            bound_request_id="req-1",
            ingress_session_ref="ing://1",
            expected_session_revision=1,
            principal_ref="p://1",
            expected_principal_revision=1,
            transport_instance_id="t-1",
            transport_binding_digest="sha256:d",
        ),
        principal=req_princ,
        mission=MissionCheckoutRequest(
            mission_ref="m://1",
            expected_revision=1,
            subject_id="s-1",
        ),
        approval=None,
        facts=(),
        targets=(target,),
        attempt_group=ExecutionAttemptGroup("att-1", "r-1", "g-1"),
    )

    snap_miss_expired = MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="m://1",
        revision=1,
        mission_id="m-1",
        active=True,
        permitted_subject_ids=("s-1",),
        target_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(TargetRole.PRIMARY, TargetKind.IPV4, "10.0.0.1"),),
        ),
        permitted_capabilities=("cap1",),
        permitted_stages=("exploitation",),
        expires_at=500.0,  # expired before now=1000
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_mission_inactive"):
        coord._validate_mission(req_bundle, snap_miss_expired, snap_princ_valid)


def test_coordinator_reopen_and_record_branches():
    from core.actions.checkout_models import CheckoutRecoveryRefV2

    part = MockParticipant()
    coord = ReferenceCheckoutCoordinator(
        ingress_store=part,
        principal_store=part,
        mission_store=part,
        reference_stores={},
    )

    rec_ref_not_found = CheckoutRecoveryRefV2(
        journal_ref="jour://1",
        journal_digest="sha256:d",
        checkout_id="chk-1",
        fence_generation=1,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_recovery_ref_not_found"):
        coord.reopen_fenced(rec_ref_not_found)

    # Fence group mismatch in _bundle_fence
    b1 = MagicMock()
    b1.checkout.lease_token.checkout_id = "chk-1"
    b1.checkout.lease_token.fence_generation = 1
    b2 = MagicMock()
    b2.checkout.lease_token.checkout_id = "chk-DIFF"
    b2.checkout.lease_token.fence_generation = 1

    with pytest.raises(ReferenceCheckoutError, match="checkout_reference_fence_group_mismatch"):
        coord._bundle_fence([b1, b2])

    # _require_record error when not in records
    bundle_fake = object.__new__(ExecutorCheckoutBundle)
    object.__setattr__(bundle_fake, "checkout_id", "chk-nonexistent")

    with pytest.raises(ReferenceCheckoutError, match="checkout_bundle_not_canonical"):
        coord._require_record(bundle_fake)

    # checkpoint_existing_recovery_state fence mismatch
    record_mock = MagicMock()
    record_mock.bundle = bundle_fake
    record_mock.closed = False
    record_mock.participants = ()
    coord._records["chk-fake"] = record_mock
    object.__setattr__(bundle_fake, "checkout_id", "chk-fake")
    object.__setattr__(bundle_fake, "fence_generation", 1)

    rec_ref_mismatch = CheckoutRecoveryRefV2(
        journal_ref="jour://1",
        journal_digest="sha256:d",
        checkout_id="chk-fake",
        fence_generation=999,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_recovery_fence_mismatch"):
        coord.checkpoint_existing_recovery_state(bundle_fake, rec_ref_mismatch)

    # checkpoint_existing_recovery_state conflict
    rec_ref_valid = CheckoutRecoveryRefV2(
        journal_ref="jour://1",
        journal_digest="sha256:d",
        checkout_id="chk-fake",
        fence_generation=1,
    )
    coord._assert_record_current_locked = MagicMock()
    coord._recovery_bindings[("jour://1", "sha256:d")] = "different_bundle"  # type: ignore
    with pytest.raises(ReferenceCheckoutError, match="checkout_recovery_ref_conflict"):
        coord.checkpoint_existing_recovery_state(bundle_fake, rec_ref_valid)
