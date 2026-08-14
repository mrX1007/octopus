"""Exact root/child execution bridge contracts."""

from __future__ import annotations

import hashlib
import pickle

import pytest

from core.actions.child_execution import ChildExecutionBridge, RootExecutionBridge
from core.actions.execution_budget import ExecutionLineage, OwnedExecutionBudgetAuthorityV2
from core.actions.request_v2 import BoundedActionRequestV2Envelope, BoundedTypedInputPayloadV2
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
from core.auth.ingress import IngressSession
from core.auth.ingress_store import IngressSessionStore
from core.auth.types import (
    ApprovalStatus,
    IngressChannelBinding,
    Principal,
    PrincipalRole,
)

pytestmark = [pytest.mark.unit, pytest.mark.contract]


def _target() -> ExtractedActionTarget:
    return ExtractedActionTarget(
        role=TargetRole.PRIMARY,
        kind=TargetKind.FQDN,
        normalized_value="target.example",
    )


def _approval_graph() -> ApprovalExecutionLease:
    store = ApprovalStore()
    store.register_approval(
        ApprovalAuthorizationSnapshot(
            schema_version="2.0",
            approval_ref="approval://one",
            revision=1,
            approval_id="approval-one",
            mission_id="mission-1",
            subject_id="subject-1",
            approver_subject_id="approver-1",
            permitted_root_action_ids=("plugin:router",),
            permitted_concrete_action_ids=("plugin:leaf",),
            permitted_capabilities=("capability-1",),
            permitted_killchain_stages=("stage-1",),
            target_scope=TargetScopeSnapshot(
                schema_version="2.0",
                revision=1,
                rules=(
                    TargetScopeRule(
                        role=TargetRole.PRIMARY,
                        kind=TargetKind.FQDN,
                        normalized_value="target.example",
                    ),
                ),
            ),
            permitted_operation_ids=("run",),
            status=ApprovalStatus.ACTIVE,
            issued_at=10.0,
            expires_at=100.0,
            max_uses=1,
            remaining_uses=1,
        )
    )
    return ApprovalExecutionLease.open_graph(
        store=store,
        approval_ref="approval://one",
        approval_revision=1,
        execution_graph_id="graph-1",
        root_action_id="plugin:router",
        mission_id="mission-1",
        subject_id="subject-1",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=20.0,
    )


def _bridges() -> tuple[RootExecutionBridge, ChildExecutionBridge]:
    binding = IngressChannelBinding(
        peer_uid=1000,
        peer_gid=1000,
        peer_pid=123,
        transport_instance="cli-1",
        channel_binding="binding-1",
    )
    session_store = IngressSessionStore(clock=lambda: 20.0)
    session_store.register_session(
        IngressSession(
            session_id="session-1",
            principal=Principal(
                principal_id="subject-1",
                name="operator",
                role=PrincipalRole.OPERATOR,
                revision=1,
            ),
            channel_binding=binding,
        )
    )
    root_ingress = session_store.issue_invocation_lease(
        "session-1",
        "request-root",
        binding,
        invocation_nonce="nonce-root",
    )
    session_store.resolve_invocation_lease(
        root_ingress,
        "request-root",
        binding,
        invocation_nonce="nonce-root",
    )

    payload = BoundedTypedInputPayloadV2(
        schema_id="schema:test",
        canonical_json=b"{}",
        byte_length=2,
        sha256_digest=hashlib.sha256(b"{}").hexdigest(),
    )
    envelope = BoundedActionRequestV2Envelope(
        request_id="request-root",
        mission_ref="mission-1",
        approval_ref="approval://one",
        precondition_fact_refs=(),
        idempotency_key=None,
        typed_input_payload=payload,
    )
    authority = OwnedExecutionBudgetAuthorityV2(max_child_depth=2)
    root_authority = authority.issue_root(
        ingress_lease=root_ingress,
        bounded_envelope=envelope,
    )
    root_lineage = ExecutionLineage(
        root_execution_id="execution-root",
        parent_execution_id=None,
        execution_graph_id="graph-1",
        child_depth=0,
    )
    root_bridge = RootExecutionBridge(
        ingress_lease=root_ingress,
        authority=root_authority,
        lineage=root_lineage,
    )

    child_ingress = session_store.derive_child_invocation_lease(
        root_ingress,
        child_request_id="request-child",
        root_execution_id="execution-root",
        parent_execution_id="execution-root",
        execution_graph_id="graph-1",
        child_depth=1,
    )
    child_budget = authority.narrow_child(
        parent=root_authority.budget_lease,
        child_request_id="request-child",
        child_action_id="plugin:leaf",
    )
    child_bridge = ChildExecutionBridge(
        ingress_lease=child_ingress,
        budget_lease=child_budget,
        lineage=ExecutionLineage(
            root_execution_id="execution-root",
            parent_execution_id="execution-root",
            execution_graph_id="graph-1",
            child_depth=1,
        ),
        approval_graph_lease=_approval_graph(),
        selected_child_action_id="plugin:leaf",
        parent_decision_trace_ref="trace://parent",
    )
    authority.validate_child(
        child_budget,
        parent=root_authority.budget_lease,
        child_lease=child_ingress,
        child_action_id="plugin:leaf",
    )
    return root_bridge, child_bridge


def test_child_ingress_lease_initialization() -> None:
    _, child = _bridges()
    assert child.ingress_lease.bound_child_request_id == "request-child"
    assert child.ingress_lease.child_depth == 1
    with pytest.raises(TypeError):
        type(child.ingress_lease)()


def test_child_execution_bridge_initialization() -> None:
    _, child = _bridges()
    assert set(child.__dataclass_fields__) == {
        "ingress_lease",
        "budget_lease",
        "lineage",
        "approval_graph_lease",
        "selected_child_action_id",
        "parent_decision_trace_ref",
    }
    assert child.budget_lease.budget.max_child_depth == 1
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(child)


def test_root_execution_bridge_initialization() -> None:
    root, _ = _bridges()
    assert set(root.__dataclass_fields__) == {"ingress_lease", "authority", "lineage"}
    assert root.lineage.child_depth == 0
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(root)
