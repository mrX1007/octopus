"""Atomic max-use accounting for concrete approval attempts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

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
from core.auth.approval_store import (
    ApprovalExhaustedError,
    ApprovalLeaseStateError,
    ApprovalStore,
)
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.types import ApprovalStatus

pytestmark = pytest.mark.unit


def _target() -> ExtractedActionTarget:
    return ExtractedActionTarget(
        role=TargetRole.PRIMARY,
        kind=TargetKind.FQDN,
        normalized_value="target.example",
    )


def _store(*, max_uses: int = 1) -> ApprovalStore:
    store = ApprovalStore()
    store.register_approval(
        ApprovalAuthorizationSnapshot(
            schema_version="2.0",
            approval_ref="approval://one",
            revision=1,
            approval_id="approval-one",
            mission_id="mission-1",
            subject_id="operator-1",
            approver_subject_id="approver-1",
            permitted_root_action_ids=("plugin:router", "plugin:leaf"),
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
            max_uses=max_uses,
            remaining_uses=max_uses,
        )
    )
    return store


def _graph(store: ApprovalStore, *, graph_id: str = "graph-1") -> ApprovalExecutionLease:
    return ApprovalExecutionLease.open_graph(
        store=store,
        approval_ref="approval://one",
        approval_revision=1,
        execution_graph_id=graph_id,
        root_action_id="plugin:router",
        mission_id="mission-1",
        subject_id="operator-1",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=20.0,
    )


def _reserve(graph: ApprovalExecutionLease, attempt_group_id: str) -> ApprovalAttemptLease:
    return graph.reserve_attempt(
        attempt_group_id=attempt_group_id,
        concrete_action_id="plugin:leaf",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=20.0,
    )


def test_concrete_root_consumes_one_use() -> None:
    store = _store()
    graph = ApprovalExecutionLease.open_graph(
        store=store,
        approval_ref="approval://one",
        approval_revision=1,
        execution_graph_id="root-leaf-graph",
        root_action_id="plugin:leaf",
        mission_id="mission-1",
        subject_id="operator-1",
        capability="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
        targets=(_target(),),
        now=20.0,
    )
    attempt = _reserve(graph, "root-attempt")

    assert attempt.state() is AttemptLeaseState.PENDING
    assert store.get_approval("approval://one", now=20.0).remaining_uses == 1  # type: ignore[union-attr]
    attempt.start(now=20.0)
    assert attempt.state() is AttemptLeaseState.STARTED
    assert store.get_approval("approval://one", now=20.0).remaining_uses == 0  # type: ignore[union-attr]


def test_selected_child_reserves_before_final_readiness() -> None:
    store = _store()
    graph = _graph(store)
    attempt = _reserve(graph, "child-attempt")

    assert attempt.state() is AttemptLeaseState.PENDING
    with pytest.raises(ApprovalExhaustedError):
        _reserve(graph, "fallback-while-pending")
    assert store.get_approval("approval://one", now=20.0).remaining_uses == 1  # type: ignore[union-attr]


def test_selected_child_consumes_one_use_only_on_start() -> None:
    store = _store()
    attempt = _reserve(_graph(store), "child-attempt")

    assert store.get_approval("approval://one", now=20.0).remaining_uses == 1  # type: ignore[union-attr]
    attempt.start(now=20.0)
    assert store.get_approval("approval://one", now=20.0).remaining_uses == 0  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "test_name",
    ("final-readiness", "pre-attempt-failure"),
)
def test_pre_start_failure_releases_pending_reservation(test_name: str) -> None:
    store = _store()
    graph = _graph(store)
    attempt = _reserve(graph, test_name)

    attempt.release_before_start()
    assert attempt.state() is AttemptLeaseState.RELEASED
    replacement = _reserve(graph, f"replacement-{test_name}")
    assert replacement.state() is AttemptLeaseState.PENDING


def test_final_readiness_failure_releases_pending_reservation() -> None:
    test_pre_start_failure_releases_pending_reservation("final-readiness-direct")


def test_pre_attempt_failure_releases_pending_reservation() -> None:
    test_pre_start_failure_releases_pending_reservation("pre-attempt-direct")


def test_attempt_failure_keeps_consumed_use() -> None:
    store = _store()
    graph = _graph(store)
    attempt = _reserve(graph, "started-attempt")
    attempt.start(now=20.0)

    with pytest.raises(ApprovalLeaseStateError, match="cannot_be_released"):
        attempt.release_before_start()
    with pytest.raises(ApprovalExhaustedError):
        _reserve(graph, "fallback-after-start")
    assert store.get_approval("approval://one", now=20.0).remaining_uses == 0  # type: ignore[union-attr]


def test_no_active_fallback_after_attempt_start() -> None:
    test_attempt_failure_keeps_consumed_use()


def test_two_children_race_max_uses_one_exactly_one_wins() -> None:
    store = _store()
    graph = _graph(store)
    barrier = Barrier(2)

    def compete(index: int) -> ApprovalAttemptLease | ApprovalExhaustedError:
        barrier.wait()
        try:
            return _reserve(graph, f"racer-{index}")
        except ApprovalExhaustedError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(compete, (1, 2)))

    winners = [outcome for outcome in outcomes if isinstance(outcome, ApprovalAttemptLease)]
    losers = [outcome for outcome in outcomes if isinstance(outcome, ApprovalExhaustedError)]
    assert len(winners) == 1
    assert len(losers) == 1
    assert winners[0].state() is AttemptLeaseState.PENDING
    winners[0].start(now=20.0)
    assert store.get_approval("approval://one", now=20.0).remaining_uses == 0  # type: ignore[union-attr]
