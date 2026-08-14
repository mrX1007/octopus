"""Store-only construction and immutable approval lease contracts."""

from __future__ import annotations

import pickle
from dataclasses import FrozenInstanceError

import pytest

from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.approval_leases import (
    ApprovalAttemptLease,
    ApprovalExecutionLease,
    AttemptLeaseState,
)
from core.auth.approval_store import ApprovalLeaseStateError, ApprovalStore
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.types import ApprovalStatus

pytestmark = pytest.mark.unit


def _authorized_graph() -> tuple[ApprovalStore, ApprovalExecutionLease]:
    target = ExtractedActionTarget(TargetRole.PRIMARY, TargetKind.HOST, "host-1")
    store = ApprovalStore()
    store.register_approval(
        ApprovalAuthorizationSnapshot(
            schema_version="2.0",
            approval_ref="approval://lease-test",
            revision=4,
            approval_id="lease-test",
            mission_id="mission-1",
            subject_id="operator-1",
            approver_subject_id="approver-1",
            permitted_root_action_ids=("plugin:router",),
            permitted_concrete_action_ids=("plugin:leaf",),
            permitted_capabilities=("capability-1",),
            permitted_killchain_stages=("stage-1",),
            target_scope=TargetScopeSnapshot(
                "2.0",
                1,
                (TargetScopeRule(TargetRole.PRIMARY, TargetKind.HOST, "host-1"),),
            ),
            permitted_operation_ids=("run",),
            status=ApprovalStatus.ACTIVE,
            issued_at=1.0,
            expires_at=100.0,
            max_uses=1,
            remaining_uses=1,
        )
    )
    graph = ApprovalExecutionLease.open_graph(
        store=store,
        approval_ref="approval://lease-test",
        approval_revision=4,
        execution_graph_id="graph-1",
        root_action_id="plugin:router",
        mission_id="mission-1",
        subject_id="operator-1",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(target,),
        now=2.0,
    )
    return store, graph


def test_attempt_lease_state_values_are_exact_and_single_owner() -> None:
    assert tuple(AttemptLeaseState) == (
        AttemptLeaseState.PENDING,
        AttemptLeaseState.STARTED,
        AttemptLeaseState.RELEASED,
    )
    assert [state.value for state in AttemptLeaseState] == [
        "pending",
        "started",
        "released",
    ]


def test_caller_cannot_construct_approval_leases() -> None:
    with pytest.raises(TypeError, match="store-issued"):
        ApprovalExecutionLease()
    with pytest.raises(TypeError, match="store-issued"):
        ApprovalAttemptLease()


def test_store_issued_leases_are_frozen_and_non_serializable() -> None:
    _store, graph = _authorized_graph()
    attempt = graph.reserve_attempt(
        attempt_group_id="attempt-1",
        concrete_action_id="plugin:leaf",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(ExtractedActionTarget(TargetRole.PRIMARY, TargetKind.HOST, "host-1"),),
        now=2.0,
    )

    with pytest.raises(FrozenInstanceError):
        graph.approval_revision = 99  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        attempt.concrete_action_id = "plugin:other"  # type: ignore[misc]
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(graph)
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(attempt)


def test_forged_store_handle_is_denied() -> None:
    store, graph = _authorized_graph()
    forged = ApprovalExecutionLease._from_store(
        lease_id=graph.lease_id,
        graph_revision=graph.graph_revision,
        execution_graph_id=graph.execution_graph_id,
        root_action_id=graph.root_action_id,
        approval_ref=graph.approval_ref,
        approval_revision=graph.approval_revision,
        mission_id=graph.mission_id,
        subject_id=graph.subject_id,
        store=store,
    )

    with pytest.raises(ApprovalLeaseStateError, match="forged_or_unknown"):
        forged.close_graph()


def test_close_graph_releases_pending_and_is_idempotent() -> None:
    _store, graph = _authorized_graph()
    attempt = graph.reserve_attempt(
        attempt_group_id="pending",
        concrete_action_id="plugin:leaf",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(ExtractedActionTarget(TargetRole.PRIMARY, TargetKind.HOST, "host-1"),),
        now=2.0,
    )

    graph.close_graph()
    graph.close_graph()
    assert attempt.state() is AttemptLeaseState.RELEASED
    with pytest.raises(ApprovalLeaseStateError, match="closed"):
        graph.reserve_attempt(
            attempt_group_id="after-close",
            concrete_action_id="plugin:leaf",
            capability="capability-1",
            killchain_stage="stage-1",
            operation_id="run",
            targets=(ExtractedActionTarget(TargetRole.PRIMARY, TargetKind.HOST, "host-1"),),
            now=2.0,
        )
