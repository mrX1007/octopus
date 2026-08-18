"""Comprehensive edge case tests for PR-4 reference checkout coordinator."""

from __future__ import annotations

import pytest

from core.actions.checkout_models import (
    ApprovalCheckoutRequest,
    FactCheckoutRequest,
    ReferenceKind,
)
from core.actions.reference_checkout import (
    ReferenceCheckoutCoordinator,
    ReferenceCheckoutError,
    _metadata_matches_kind,
)
from tests.checkout_test_support import build_fixture

pytestmark = pytest.mark.unit


def test_metadata_matches_kind_all():
    assert _metadata_matches_kind(object(), ReferenceKind.CREDENTIAL) is False


def test_fact_store_unavailable():
    fixture = build_fixture()
    # Fact requested but fact_store not provided
    fact_req = FactCheckoutRequest(
        fact_ref="fact://1",
        expected_revision=1,
        expected_payload_digest="sha256:f",
        required_fact_type="host_info",
        target=fixture.request.targets[0],
    )
    req = fixture.request
    req = type(req)(
        references=req.references,
        ingress_session=req.ingress_session,
        principal=req.principal,
        mission=req.mission,
        approval=req.approval,
        facts=(fact_req,),
        targets=req.targets,
        attempt_group=req.attempt_group,
    )

    coord = ReferenceCheckoutCoordinator(
        ingress_store=fixture.authority,
        principal_store=fixture.authority,
        mission_store=fixture.authority,
        reference_stores={ReferenceKind.CREDENTIAL: fixture.reference_store},
        approval_store=fixture.authority,
        fact_store=None,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_fact_store_unavailable"):
        coord.checkout_many(req)


def test_approval_store_unavailable():
    fixture = build_fixture()
    app_req = ApprovalCheckoutRequest(
        approval_ref="app://1",
        expected_revision=1,
        approval_graph_lease_id="lease-1",
        execution_graph_id=fixture.request.attempt_group.execution_graph_id,
        root_action_id="act-1",
        concrete_action_id=fixture.request.references[0].required_action_id,
    )
    req = fixture.request
    req = type(req)(
        references=req.references,
        ingress_session=req.ingress_session,
        principal=req.principal,
        mission=req.mission,
        approval=app_req,
        facts=req.facts,
        targets=req.targets,
        attempt_group=req.attempt_group,
    )

    coord = ReferenceCheckoutCoordinator(
        ingress_store=fixture.authority,
        principal_store=fixture.authority,
        mission_store=fixture.authority,
        reference_stores={ReferenceKind.CREDENTIAL: fixture.reference_store},
        approval_store=None,
        fact_store=fixture.authority,
    )
    with pytest.raises(ReferenceCheckoutError, match="checkout_approval_store_unavailable"):
        coord.checkout_many(req)


def test_coordinator_constructor_type_errors():
    fixture = build_fixture()
    with pytest.raises(TypeError, match="checkout_ingress_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store="not_a_participant",  # type: ignore
            principal_store=fixture.authority,
            mission_store=fixture.authority,
            reference_stores={ReferenceKind.CREDENTIAL: fixture.reference_store},
        )
    with pytest.raises(TypeError, match="checkout_clock_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=fixture.authority,
            principal_store=fixture.authority,
            mission_store=fixture.authority,
            reference_stores={ReferenceKind.CREDENTIAL: fixture.reference_store},
            clock="not_callable",  # type: ignore
        )
