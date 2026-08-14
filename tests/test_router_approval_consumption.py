"""Router approval edges share one graph and consume zero uses."""

from __future__ import annotations

import pytest

from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.approval_store import ApprovalStore
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.types import ApprovalStatus

pytestmark = pytest.mark.unit


def _target() -> ExtractedActionTarget:
    return ExtractedActionTarget(TargetRole.PRIMARY, TargetKind.HOST, "host-1")


def _graph() -> tuple[ApprovalStore, ApprovalExecutionLease]:
    store = ApprovalStore()
    store.register_approval(
        ApprovalAuthorizationSnapshot(
            schema_version="2.0",
            approval_ref="approval://router",
            revision=1,
            approval_id="router-approval",
            mission_id="mission-1",
            subject_id="operator-1",
            approver_subject_id="approver-1",
            permitted_root_action_ids=("plugin:root-router",),
            permitted_concrete_action_ids=("plugin:nested-router", "plugin:leaf"),
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
        approval_ref="approval://router",
        approval_revision=1,
        execution_graph_id="graph-router",
        root_action_id="plugin:root-router",
        mission_id="mission-1",
        subject_id="operator-1",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=2.0,
    )
    return store, graph


def _remaining(store: ApprovalStore) -> int:
    snapshot = store.get_approval("approval://router", now=2.0)
    assert snapshot is not None
    return snapshot.remaining_uses


def test_router_parent_consumes_zero_uses() -> None:
    store, graph = _graph()

    graph.authorize_router_step(
        action_id="plugin:root-router",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=2.0,
    )
    assert _remaining(store) == 1


def test_nested_router_consumes_zero_additional_uses() -> None:
    store, graph = _graph()
    graph.authorize_router_step(
        action_id="plugin:root-router",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=2.0,
    )
    graph.authorize_router_step(
        action_id="plugin:nested-router",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=2.0,
    )

    assert _remaining(store) == 1
    attempt = graph.reserve_attempt(
        attempt_group_id="selected-leaf",
        concrete_action_id="plugin:leaf",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=2.0,
    )
    assert _remaining(store) == 1
    attempt.start(now=2.0)
    assert _remaining(store) == 0
