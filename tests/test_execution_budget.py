"""Normative executor-owned budget authority tests."""

from __future__ import annotations

import json
import pickle

import pytest

from core.actions.execution_budget import (
    ExecutionBudgetExhaustedError,
    ExecutionBudgetLeaseV2,
    OwnedExecutionBudgetAuthorityV2,
)
from core.actions.request_v2 import ActionRequestV2EnvelopeDecoder
from core.auth.ingress import IngressSession
from core.auth.ingress_store import IngressSessionStore
from core.auth.types import IngressChannelBinding, Principal, PrincipalRole

pytestmark = pytest.mark.unit


def _root_authority(*, max_child_depth: int = 3):
    binding = IngressChannelBinding(
        peer_uid=1000,
        peer_gid=1000,
        peer_pid=42,
        transport_instance="tty-1",
        channel_binding="channel-1",
    )
    store = IngressSessionStore()
    store.register_session(
        IngressSession(
            session_id="session-1",
            principal=Principal(
                principal_id="principal-1",
                name="operator",
                role=PrincipalRole.OPERATOR,
            ),
            channel_binding=binding,
        )
    )
    lease = store.issue_invocation_lease("session-1", "request-1", binding)
    store.resolve_invocation_lease(lease, "request-1", binding)
    envelope = ActionRequestV2EnvelopeDecoder.decode(
        json.dumps(
            {
                "schema_version": "2.0",
                "request_id": "request-1",
                "mission_ref": "mission-1",
                "approval_ref": None,
                "precondition_fact_refs": [],
                "idempotency_key": None,
                "typed_input": {"schema_id": "octopus:input:test:2.0"},
            }
        ).encode()
    )
    authority = OwnedExecutionBudgetAuthorityV2(
        max_runtime_seconds=60,
        max_output_bytes=1000,
        max_child_depth=max_child_depth,
    )
    bundle = authority.issue_root(ingress_lease=lease, bounded_envelope=envelope)
    return authority, bundle, lease


def test_child_budget_can_only_shrink() -> None:
    authority, bundle, _ = _root_authority(max_child_depth=3)
    child = authority.narrow_child(
        parent=bundle.budget_lease,
        child_request_id="child-request-1",
        child_action_id="c2:dns_c2_channel",
    )

    parent_budget = bundle.budget_lease.budget
    assert child.budget.absolute_deadline_monotonic <= parent_budget.absolute_deadline_monotonic
    assert child.budget.max_output_bytes <= parent_budget.max_output_bytes
    assert child.budget.max_child_depth == parent_budget.max_child_depth - 1
    assert child.budget.cancellation_token is parent_budget.cancellation_token


def test_child_budget_depth_exhausted() -> None:
    authority, bundle, _ = _root_authority(max_child_depth=0)
    with pytest.raises(ExecutionBudgetExhaustedError):
        authority.narrow_child(
            parent=bundle.budget_lease,
            child_request_id="child-request-1",
            child_action_id="c2:dns_c2_channel",
        )


def test_caller_cannot_construct_or_serialize_budget_lease() -> None:
    with pytest.raises(TypeError):
        ExecutionBudgetLeaseV2()  # type: ignore[call-arg]

    _, bundle, _ = _root_authority()
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(bundle.budget_lease)


def test_root_authority_bundle_binds_one_controller_and_token() -> None:
    authority, bundle, ingress_lease = _root_authority()
    budget = authority.validate_root(
        bundle.budget_lease,
        ingress_lease=ingress_lease,
        request_id="request-1",
    )
    assert budget.cancellation_token is bundle.cancellation_controller.token
