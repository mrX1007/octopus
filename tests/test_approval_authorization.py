"""Approval snapshot shape and fail-closed authorization bindings."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.approval_store import (
    ApprovalAuthorizationError,
    ApprovalExpiredError,
    ApprovalRevisionError,
    ApprovalStore,
)
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.types import ApprovalStatus

pytestmark = pytest.mark.unit


def _target(host: str = "allowed.example") -> ExtractedActionTarget:
    return ExtractedActionTarget(TargetRole.PRIMARY, TargetKind.FQDN, host)


def _scope() -> TargetScopeSnapshot:
    return TargetScopeSnapshot(
        schema_version="2.0",
        revision=7,
        rules=(
            TargetScopeRule(
                role=TargetRole.PRIMARY,
                kind=TargetKind.FQDN,
                normalized_value="allowed.example",
            ),
        ),
    )


def _snapshot(
    *,
    status: ApprovalStatus = ApprovalStatus.ACTIVE,
    expires_at: float = 200.0,
) -> ApprovalAuthorizationSnapshot:
    return ApprovalAuthorizationSnapshot(
        schema_version="2.0",
        approval_ref="approval://reviewed-1",
        revision=3,
        approval_id="approval-id-1",
        mission_id="mission-1",
        subject_id="operator-1",
        approver_subject_id="approver-1",
        permitted_root_action_ids=("plugin:router",),
        permitted_concrete_action_ids=("plugin:leaf", "plugin:nested-router"),
        permitted_capabilities=("remote-execution",),
        permitted_killchain_stages=("lateral-movement",),
        target_scope=_scope(),
        permitted_operation_ids=("run",),
        status=status,
        issued_at=10.0,
        expires_at=expires_at,
        max_uses=2,
        remaining_uses=2,
    )


def _open(store: ApprovalStore, *, graph_id: str = "graph-1") -> ApprovalExecutionLease:
    return ApprovalExecutionLease.open_graph(
        store=store,
        approval_ref="approval://reviewed-1",
        approval_revision=3,
        execution_graph_id=graph_id,
        root_action_id="plugin:router",
        mission_id="mission-1",
        subject_id="operator-1",
        capability="remote-execution",
        killchain_stage="lateral-movement",
        operation_id="run",
        targets=(_target(),),
        now=20.0,
    )


def test_approval_authorization_snapshot_exact_fields_and_frozen() -> None:
    snapshot = _snapshot()

    assert [field.name for field in fields(snapshot)] == [
        "schema_version",
        "approval_ref",
        "revision",
        "approval_id",
        "mission_id",
        "subject_id",
        "approver_subject_id",
        "permitted_root_action_ids",
        "permitted_concrete_action_ids",
        "permitted_capabilities",
        "permitted_killchain_stages",
        "target_scope",
        "permitted_operation_ids",
        "status",
        "issued_at",
        "expires_at",
        "max_uses",
        "remaining_uses",
    ]
    with pytest.raises(FrozenInstanceError):
        snapshot.remaining_uses = 0  # type: ignore[misc]


def test_missing_inactive_cross_mission_denials() -> None:
    missing_store = ApprovalStore()
    with pytest.raises(ApprovalAuthorizationError):
        _open(missing_store)

    inactive_store = ApprovalStore()
    inactive_store.register_approval(_snapshot(status=ApprovalStatus.REVOKED))
    with pytest.raises(ApprovalAuthorizationError, match="approval_not_active"):
        _open(inactive_store)

    store = ApprovalStore()
    store.register_approval(_snapshot())
    with pytest.raises(ApprovalAuthorizationError, match="approval_mission_mismatch"):
        ApprovalExecutionLease.open_graph(
            store=store,
            approval_ref="approval://reviewed-1",
            approval_revision=3,
            execution_graph_id="wrong-mission-graph",
            root_action_id="plugin:router",
            mission_id="mission-other",
            subject_id="operator-1",
            capability="remote-execution",
            killchain_stage="lateral-movement",
            operation_id="run",
            targets=(_target(),),
            now=20.0,
        )


def test_approval_action_capability_stage_operation_target_bindings() -> None:
    store = ApprovalStore()
    store.register_approval(_snapshot())

    denied_cases = (
        {"root_action_id": "plugin:other"},
        {"capability": "other-capability"},
        {"killchain_stage": "other-stage"},
        {"operation_id": "other-operation"},
        {"targets": (_target("outside.example"),)},
        {"subject_id": "operator-other"},
    )
    base: dict[str, object] = {
        "store": store,
        "approval_ref": "approval://reviewed-1",
        "approval_revision": 3,
        "root_action_id": "plugin:router",
        "mission_id": "mission-1",
        "subject_id": "operator-1",
        "capability": "remote-execution",
        "killchain_stage": "lateral-movement",
        "operation_id": "run",
        "targets": (_target(),),
        "now": 20.0,
    }
    for index, overrides in enumerate(denied_cases):
        kwargs = {**base, **overrides, "execution_graph_id": f"denied-{index}"}
        with pytest.raises(ApprovalAuthorizationError):
            ApprovalExecutionLease.open_graph(**kwargs)  # type: ignore[arg-type]

    graph = _open(store, graph_id="authorized")
    with pytest.raises(ApprovalAuthorizationError, match="approval_action_denied"):
        graph.reserve_attempt(
            attempt_group_id="wrong-child",
            concrete_action_id="plugin:other",
            capability="remote-execution",
            killchain_stage="lateral-movement",
            operation_id="run",
            targets=(_target(),),
            now=20.0,
        )


def test_expiry_revocation_and_revision_races_fail_closed() -> None:
    expired_store = ApprovalStore()
    expired_store.register_approval(_snapshot(expires_at=30.0))
    with pytest.raises(ApprovalExpiredError):
        ApprovalExecutionLease.open_graph(
            store=expired_store,
            approval_ref="approval://reviewed-1",
            approval_revision=3,
            execution_graph_id="expired",
            root_action_id="plugin:router",
            mission_id="mission-1",
            subject_id="operator-1",
            capability="remote-execution",
            killchain_stage="lateral-movement",
            operation_id="run",
            targets=(_target(),),
            now=30.0,
        )

    store = ApprovalStore()
    store.register_approval(_snapshot())
    graph = _open(store)
    store.revoke_approval("approval://reviewed-1", expected_revision=3)
    with pytest.raises(ApprovalRevisionError):
        graph.authorize_router_step(
            action_id="plugin:router",
            capability="remote-execution",
            killchain_stage="lateral-movement",
            operation_id="run",
            targets=(_target(),),
            now=20.0,
        )
