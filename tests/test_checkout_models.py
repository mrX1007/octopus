from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

import core.actions.checkout_models as checkout_models
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
from tests.checkout_test_support import build_fixture

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("model", "expected"),
    (
        (
            ReferenceCheckoutRequest,
            (
                "reference",
                "expected_kind",
                "expected_metadata_revision",
                "expected_authorization_revision",
                "required_action_id",
                "required_capability",
                "targets",
                "access_mode",
            ),
        ),
        (
            IngressSessionCheckoutRequest,
            (
                "lease_id",
                "lease_revision",
                "bound_request_id",
                "ingress_session_ref",
                "expected_session_revision",
                "principal_ref",
                "expected_principal_revision",
                "transport_instance_id",
                "transport_binding_digest",
            ),
        ),
        (PrincipalCheckoutRequest, ("principal_ref", "expected_revision", "subject_id")),
        (MissionCheckoutRequest, ("mission_ref", "expected_revision", "subject_id")),
        (
            ApprovalCheckoutRequest,
            (
                "approval_ref",
                "expected_revision",
                "approval_graph_lease_id",
                "execution_graph_id",
                "root_action_id",
                "concrete_action_id",
            ),
        ),
        (
            FactCheckoutRequest,
            (
                "fact_ref",
                "expected_revision",
                "expected_payload_digest",
                "required_fact_type",
                "target",
            ),
        ),
        (
            ExecutionAttemptGroup,
            ("attempt_group_id", "root_execution_id", "execution_graph_id"),
        ),
        (
            ExecutorCheckoutRequestBundle,
            (
                "references",
                "ingress_session",
                "principal",
                "mission",
                "approval",
                "facts",
                "targets",
                "attempt_group",
            ),
        ),
        (
            ReferenceLeaseToken,
            (
                "reference",
                "metadata_revision",
                "authorization_revision",
                "fence_generation",
                "checkout_id",
            ),
        ),
        (ReferenceCheckout, ("metadata", "lease_token")),
        (
            ExecutorCheckoutBundle,
            (
                "checkout_id",
                "ingress_session",
                "principal",
                "mission",
                "approval_graph_lease",
                "facts",
                "references",
                "targets",
                "fence_generation",
            ),
        ),
        (
            CheckoutRecoveryRefV2,
            ("checkout_id", "fence_generation", "journal_ref", "journal_digest"),
        ),
    ),
)
def test_checkout_request_models_are_frozen_and_closed(
    model: type[object],
    expected: tuple[str, ...],
) -> None:
    assert tuple(field.name for field in fields(model)) == expected


def test_reference_kind_and_access_mode_have_exact_values() -> None:
    assert tuple(item.value for item in ReferenceKind) == (
        "credential",
        "session",
        "artifact",
        "pivot_route",
        "c2_resource",
        "c2_enrollment",
        "deployment",
    )
    assert tuple(item.value for item in ReferenceAccessMode) == (
        "metadata_only",
        "material",
    )


def test_short_alias_ingress_checkout_request_is_absent() -> None:
    assert not hasattr(checkout_models, "IngressCheckoutRequest")


def test_checkout_request_is_immutable() -> None:
    fixture = build_fixture()
    with pytest.raises(FrozenInstanceError):
        fixture.request.references[0].reference = "credential://forged"  # type: ignore[misc]


def test_bundle_rejects_duplicate_references() -> None:
    fixture = build_fixture()
    item = fixture.request.references[0]
    with pytest.raises(ValueError, match="checkout_reference_duplicate"):
        ExecutorCheckoutRequestBundle(
            references=(item, item),
            ingress_session=fixture.request.ingress_session,
            principal=fixture.request.principal,
            mission=fixture.request.mission,
            approval=None,
            facts=(),
            targets=fixture.request.targets,
            attempt_group=fixture.request.attempt_group,
        )


def test_ingress_and_principal_identity_must_match() -> None:
    fixture = build_fixture()
    with pytest.raises(ValueError, match="checkout_ingress_principal_identity_mismatch"):
        ExecutorCheckoutRequestBundle(
            references=fixture.request.references,
            ingress_session=fixture.request.ingress_session,
            principal=PrincipalCheckoutRequest("principal-2", 1, "operator-1"),
            mission=fixture.request.mission,
            approval=None,
            facts=(),
            targets=fixture.request.targets,
            attempt_group=fixture.request.attempt_group,
        )


def test_reference_checkout_lease_identity_is_exact() -> None:
    fixture = build_fixture()
    snapshot = fixture.reference_store.snapshots["credential://test/0"]
    with pytest.raises(ValueError, match="checkout_reference_lease_identity_mismatch"):
        ReferenceCheckout(
            snapshot,
            ReferenceLeaseToken("credential://other", 1, 1, 1, "checkout://test-1"),
        )


def test_executor_checkout_bundle_is_coordinator_issued_only() -> None:
    with pytest.raises(TypeError, match="coordinator-issued"):
        ExecutorCheckoutBundle()
