"""Thread-safe authority for approval graphs and attempt-use accounting."""

from __future__ import annotations

import math
import threading
import time
import uuid
from dataclasses import dataclass, replace

from core.actions.target_scope import ExtractedActionTarget, TargetScopePolicy
from core.auth.approval_leases import (
    ApprovalAttemptLease,
    ApprovalExecutionLease,
    AttemptLeaseState,
)
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.types import ApprovalStatus


class ApprovalStoreError(RuntimeError):
    """Base class for fail-closed approval authority failures."""


class ApprovalAuthorizationError(ApprovalStoreError):
    pass


class ApprovalNotFoundError(ApprovalAuthorizationError):
    pass


class ApprovalRevisionError(ApprovalAuthorizationError):
    pass


class ApprovalExpiredError(ApprovalAuthorizationError):
    pass


class ApprovalExhaustedError(ApprovalAuthorizationError):
    pass


class ApprovalLeaseStateError(ApprovalStoreError):
    pass


@dataclass
class _ApprovalRecord:
    snapshot: ApprovalAuthorizationSnapshot
    consumed_uses: int
    pending_attempt_ids: set[str]


@dataclass
class _GraphRecord:
    lease: ApprovalExecutionLease
    approval_ref: str
    approval_revision: int
    graph_revision: int
    execution_graph_id: str
    root_action_id: str
    mission_id: str
    subject_id: str
    root_capability: str
    root_killchain_stage: str
    root_operation_id: str | None
    root_targets: tuple[ExtractedActionTarget, ...]
    attempt_lease_ids: set[str]
    open: bool = True


@dataclass
class _AttemptRecord:
    lease: ApprovalAttemptLease
    graph_lease_id: str
    approval_ref: str
    attempt_group_id: str
    concrete_action_id: str
    capability: str
    killchain_stage: str
    operation_id: str | None
    targets: tuple[ExtractedActionTarget, ...]
    state: AttemptLeaseState


class ApprovalStore:
    """Own all mutable approval state behind one process-wide lock.

    Snapshot objects and lease handles are immutable projections. Every
    mutating transition re-resolves its registered handle by object identity,
    checks the pinned approval revision, and executes under ``_lock``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._approvals: dict[str, _ApprovalRecord] = {}
        self._graphs: dict[str, _GraphRecord] = {}
        self._graph_ids: set[str] = set()
        self._attempts: dict[str, _AttemptRecord] = {}
        self._attempt_group_ids: set[str] = set()

    def register_approval(self, snapshot: ApprovalAuthorizationSnapshot) -> None:
        """Register a new immutable authorization revision.

        Re-registering a stable reference is deliberately denied: changing
        policy uses :meth:`revoke_approval` or a separate reviewed update path,
        so an open graph can never be silently rebound to different authority.
        """

        if type(snapshot) is not ApprovalAuthorizationSnapshot:
            raise TypeError("approval snapshot must be canonical")
        with self._lock:
            if snapshot.approval_ref in self._approvals:
                raise ApprovalRevisionError("approval_ref_already_registered")
            consumed_uses = snapshot.max_uses - snapshot.remaining_uses
            self._approvals[snapshot.approval_ref] = _ApprovalRecord(
                snapshot=snapshot,
                consumed_uses=consumed_uses,
                pending_attempt_ids=set(),
            )

    def get_approval(
        self,
        approval_ref: str,
        *,
        now: float | None = None,
    ) -> ApprovalAuthorizationSnapshot | None:
        """Return a fresh frozen, non-authoritative current snapshot."""

        timestamp = self._timestamp(now)
        with self._lock:
            record = self._approvals.get(approval_ref)
            if record is None:
                return None
            remaining = max(0, record.snapshot.max_uses - record.consumed_uses)
            status = record.snapshot.status
            if status is ApprovalStatus.ACTIVE and timestamp >= record.snapshot.expires_at:
                status = ApprovalStatus.EXPIRED
            elif status is ApprovalStatus.ACTIVE and remaining == 0:
                status = ApprovalStatus.EXHAUSTED
            return replace(record.snapshot, status=status, remaining_uses=remaining)

    def revoke_approval(
        self,
        approval_ref: str,
        *,
        expected_revision: int,
    ) -> ApprovalAuthorizationSnapshot:
        """Revoke and revision-bump an approval, invalidating every open graph."""

        with self._lock:
            record = self._require_approval(approval_ref)
            if record.snapshot.revision != expected_revision:
                raise ApprovalRevisionError("approval_revision_mismatch")
            remaining = max(0, record.snapshot.max_uses - record.consumed_uses)
            record.snapshot = replace(
                record.snapshot,
                revision=record.snapshot.revision + 1,
                status=ApprovalStatus.REVOKED,
                remaining_uses=remaining,
            )
            return record.snapshot

    def _open_graph(
        self,
        *,
        approval_ref: str,
        approval_revision: int,
        execution_graph_id: str,
        root_action_id: str,
        mission_id: str,
        subject_id: str,
        capability: str,
        killchain_stage: str,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        now: float | None,
    ) -> ApprovalExecutionLease:
        timestamp = self._timestamp(now)
        self._require_non_empty("execution_graph_id", execution_graph_id)
        self._require_non_empty("root_action_id", root_action_id)
        self._require_non_empty("mission_id", mission_id)
        self._require_non_empty("subject_id", subject_id)
        with self._lock:
            if execution_graph_id in self._graph_ids:
                raise ApprovalLeaseStateError("execution_graph_id_already_used")
            approval = self._require_approval(approval_ref)
            self._validate_current_authority(
                approval,
                expected_revision=approval_revision,
                mission_id=mission_id,
                subject_id=subject_id,
                action_id=root_action_id,
                root_action=True,
                capability=capability,
                killchain_stage=killchain_stage,
                operation_id=operation_id,
                targets=targets,
                now=timestamp,
            )
            self._require_budget_available(approval)
            lease_id = f"approval-graph://{uuid.uuid4()}"
            graph_revision = 1
            lease = ApprovalExecutionLease._from_store(
                lease_id=lease_id,
                graph_revision=graph_revision,
                execution_graph_id=execution_graph_id,
                root_action_id=root_action_id,
                approval_ref=approval_ref,
                approval_revision=approval_revision,
                mission_id=mission_id,
                subject_id=subject_id,
                store=self,
            )
            self._graphs[lease_id] = _GraphRecord(
                lease=lease,
                approval_ref=approval_ref,
                approval_revision=approval_revision,
                graph_revision=graph_revision,
                execution_graph_id=execution_graph_id,
                root_action_id=root_action_id,
                mission_id=mission_id,
                subject_id=subject_id,
                root_capability=capability,
                root_killchain_stage=killchain_stage,
                root_operation_id=operation_id,
                root_targets=targets,
                attempt_lease_ids=set(),
            )
            self._graph_ids.add(execution_graph_id)
            return lease

    def _authorize_router_step(
        self,
        lease: ApprovalExecutionLease,
        *,
        action_id: str,
        capability: str,
        killchain_stage: str,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        now: float | None,
    ) -> None:
        timestamp = self._timestamp(now)
        with self._lock:
            graph = self._require_open_graph(lease)
            approval = self._require_approval(graph.approval_ref)
            if action_id == graph.root_action_id and (
                capability != graph.root_capability
                or killchain_stage != graph.root_killchain_stage
                or operation_id != graph.root_operation_id
                or targets != graph.root_targets
            ):
                raise ApprovalAuthorizationError("approval_graph_root_binding_mismatch")
            self._validate_current_authority(
                approval,
                expected_revision=graph.approval_revision,
                mission_id=graph.mission_id,
                subject_id=graph.subject_id,
                action_id=action_id,
                root_action=action_id == graph.root_action_id,
                capability=capability,
                killchain_stage=killchain_stage,
                operation_id=operation_id,
                targets=targets,
                now=timestamp,
            )
            self._require_budget_available(approval)

    def _reserve_attempt(
        self,
        graph_lease: ApprovalExecutionLease,
        *,
        attempt_group_id: str,
        concrete_action_id: str,
        capability: str,
        killchain_stage: str,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        now: float | None,
    ) -> ApprovalAttemptLease:
        timestamp = self._timestamp(now)
        self._require_non_empty("attempt_group_id", attempt_group_id)
        with self._lock:
            graph = self._require_open_graph(graph_lease)
            if attempt_group_id in self._attempt_group_ids:
                raise ApprovalLeaseStateError("attempt_group_id_already_used")
            approval = self._require_approval(graph.approval_ref)
            self._validate_current_authority(
                approval,
                expected_revision=graph.approval_revision,
                mission_id=graph.mission_id,
                subject_id=graph.subject_id,
                action_id=concrete_action_id,
                root_action=False,
                capability=capability,
                killchain_stage=killchain_stage,
                operation_id=operation_id,
                targets=targets,
                now=timestamp,
            )
            self._require_budget_available(approval)

            lease_id = f"approval-attempt://{uuid.uuid4()}"
            attempt_lease = ApprovalAttemptLease._from_store(
                lease_id=lease_id,
                graph_lease_id=graph.lease.lease_id,
                graph_revision=graph.graph_revision,
                attempt_group_id=attempt_group_id,
                concrete_action_id=concrete_action_id,
                approval_ref=graph.approval_ref,
                approval_revision=graph.approval_revision,
                store=self,
            )
            self._attempts[lease_id] = _AttemptRecord(
                lease=attempt_lease,
                graph_lease_id=graph.lease.lease_id,
                approval_ref=graph.approval_ref,
                attempt_group_id=attempt_group_id,
                concrete_action_id=concrete_action_id,
                capability=capability,
                killchain_stage=killchain_stage,
                operation_id=operation_id,
                targets=targets,
                state=AttemptLeaseState.PENDING,
            )
            graph.attempt_lease_ids.add(lease_id)
            approval.pending_attempt_ids.add(lease_id)
            self._attempt_group_ids.add(attempt_group_id)
            return attempt_lease

    def _start_attempt(self, lease: ApprovalAttemptLease, *, now: float | None) -> None:
        timestamp = self._timestamp(now)
        with self._lock:
            attempt = self._require_attempt(lease)
            if attempt.state is not AttemptLeaseState.PENDING:
                raise ApprovalLeaseStateError(f"attempt_not_pending:{attempt.state.value}")
            graph = self._require_open_graph_by_id(attempt.graph_lease_id)
            approval = self._require_approval(attempt.approval_ref)
            self._validate_current_authority(
                approval,
                expected_revision=graph.approval_revision,
                mission_id=graph.mission_id,
                subject_id=graph.subject_id,
                action_id=attempt.concrete_action_id,
                root_action=False,
                capability=attempt.capability,
                killchain_stage=attempt.killchain_stage,
                operation_id=attempt.operation_id,
                targets=attempt.targets,
                now=timestamp,
            )
            if lease.lease_id not in approval.pending_attempt_ids:
                raise ApprovalLeaseStateError("pending_reservation_missing")
            if approval.consumed_uses >= approval.snapshot.max_uses:
                raise ApprovalExhaustedError("approval_budget_exhausted")

            approval.pending_attempt_ids.remove(lease.lease_id)
            approval.consumed_uses += 1
            attempt.state = AttemptLeaseState.STARTED

    def _release_attempt_before_start(self, lease: ApprovalAttemptLease) -> None:
        with self._lock:
            attempt = self._require_attempt(lease)
            if attempt.state is AttemptLeaseState.RELEASED:
                return
            if attempt.state is AttemptLeaseState.STARTED:
                raise ApprovalLeaseStateError("started_attempt_cannot_be_released")
            approval = self._require_approval(attempt.approval_ref)
            if lease.lease_id not in approval.pending_attempt_ids:
                raise ApprovalLeaseStateError("pending_reservation_missing")
            approval.pending_attempt_ids.remove(lease.lease_id)
            attempt.state = AttemptLeaseState.RELEASED

    def _attempt_state(self, lease: ApprovalAttemptLease) -> AttemptLeaseState:
        with self._lock:
            return self._require_attempt(lease).state

    def _close_graph(self, lease: ApprovalExecutionLease) -> None:
        with self._lock:
            graph = self._require_graph(lease)
            if not graph.open:
                return
            for lease_id in tuple(graph.attempt_lease_ids):
                attempt = self._attempts[lease_id]
                if attempt.state is AttemptLeaseState.PENDING:
                    approval = self._require_approval(attempt.approval_ref)
                    approval.pending_attempt_ids.discard(lease_id)
                    attempt.state = AttemptLeaseState.RELEASED
            graph.open = False

    def _require_approval(self, approval_ref: str) -> _ApprovalRecord:
        record = self._approvals.get(approval_ref)
        if record is None:
            raise ApprovalNotFoundError("approval_not_found")
        return record

    def _require_graph(self, lease: ApprovalExecutionLease) -> _GraphRecord:
        graph = self._graphs.get(getattr(lease, "lease_id", ""))
        if graph is None or graph.lease is not lease:
            raise ApprovalLeaseStateError("forged_or_unknown_graph_lease")
        if (
            graph.graph_revision != lease.graph_revision
            or graph.approval_revision != lease.approval_revision
            or graph.approval_ref != lease.approval_ref
            or graph.execution_graph_id != lease.execution_graph_id
            or graph.root_action_id != lease.root_action_id
            or graph.mission_id != lease.mission_id
            or graph.subject_id != lease.subject_id
        ):
            raise ApprovalLeaseStateError("graph_lease_binding_mismatch")
        return graph

    def _require_open_graph(self, lease: ApprovalExecutionLease) -> _GraphRecord:
        graph = self._require_graph(lease)
        if not graph.open:
            raise ApprovalLeaseStateError("approval_graph_closed")
        return graph

    def _require_open_graph_by_id(self, lease_id: str) -> _GraphRecord:
        graph = self._graphs.get(lease_id)
        if graph is None or not graph.open:
            raise ApprovalLeaseStateError("approval_graph_closed")
        return graph

    def _require_attempt(self, lease: ApprovalAttemptLease) -> _AttemptRecord:
        attempt = self._attempts.get(getattr(lease, "lease_id", ""))
        if attempt is None or attempt.lease is not lease:
            raise ApprovalLeaseStateError("forged_or_unknown_attempt_lease")
        if (
            attempt.graph_lease_id != lease.graph_lease_id
            or attempt.approval_ref != lease.approval_ref
            or attempt.attempt_group_id != lease.attempt_group_id
            or attempt.concrete_action_id != lease.concrete_action_id
        ):
            raise ApprovalLeaseStateError("attempt_lease_binding_mismatch")
        graph = self._graphs.get(attempt.graph_lease_id)
        if (
            graph is None
            or graph.graph_revision != lease.graph_revision
            or graph.approval_revision != lease.approval_revision
        ):
            raise ApprovalLeaseStateError("attempt_graph_revision_mismatch")
        return attempt

    def _validate_current_authority(
        self,
        approval: _ApprovalRecord,
        *,
        expected_revision: int,
        mission_id: str,
        subject_id: str,
        action_id: str,
        root_action: bool,
        capability: str,
        killchain_stage: str,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        now: float,
    ) -> None:
        self._validate_graph_authority_is_current_revision(approval, expected_revision, now)
        snapshot = approval.snapshot
        if snapshot.mission_id != mission_id:
            raise ApprovalAuthorizationError("approval_mission_mismatch")
        if snapshot.subject_id != subject_id:
            raise ApprovalAuthorizationError("approval_subject_mismatch")
        permitted_actions = (
            snapshot.permitted_root_action_ids if root_action else snapshot.permitted_concrete_action_ids
        )
        if action_id not in permitted_actions:
            raise ApprovalAuthorizationError("approval_action_denied")
        if capability not in snapshot.permitted_capabilities:
            raise ApprovalAuthorizationError("approval_capability_denied")
        if killchain_stage not in snapshot.permitted_killchain_stages:
            raise ApprovalAuthorizationError("approval_killchain_stage_denied")
        if operation_id is not None and operation_id not in snapshot.permitted_operation_ids:
            raise ApprovalAuthorizationError("approval_operation_denied")
        if type(targets) is not tuple or any(type(target) is not ExtractedActionTarget for target in targets):
            raise ApprovalAuthorizationError("approval_targets_invalid")
        scope_decision = TargetScopePolicy.evaluate(targets, snapshot.target_scope)
        if not scope_decision.allowed:
            raise ApprovalAuthorizationError(scope_decision.reason)

    @staticmethod
    def _require_budget_available(approval: _ApprovalRecord) -> None:
        if approval.consumed_uses + len(approval.pending_attempt_ids) >= approval.snapshot.max_uses:
            raise ApprovalExhaustedError("approval_budget_exhausted")

    @staticmethod
    def _validate_graph_authority_is_current_revision(
        approval: _ApprovalRecord,
        expected_revision: int,
        now: float,
    ) -> None:
        snapshot = approval.snapshot
        if snapshot.revision != expected_revision:
            raise ApprovalRevisionError("approval_revision_mismatch")
        if snapshot.status is not ApprovalStatus.ACTIVE:
            raise ApprovalAuthorizationError(f"approval_not_active:{snapshot.status.value}")
        if now >= snapshot.expires_at:
            raise ApprovalExpiredError("approval_expired")

    @staticmethod
    def _require_non_empty(field_name: str, value: str) -> None:
        if type(value) is not str or not value:
            raise ApprovalAuthorizationError(f"{field_name}_missing")

    @staticmethod
    def _timestamp(value: float | None) -> float:
        timestamp = time.time() if value is None else value
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
            raise ApprovalAuthorizationError("approval_time_invalid")
        return timestamp


_GLOBAL_APPROVAL_STORE = ApprovalStore()


def get_approval_store() -> ApprovalStore:
    return _GLOBAL_APPROVAL_STORE


__all__ = [
    "ApprovalAuthorizationError",
    "ApprovalExhaustedError",
    "ApprovalExpiredError",
    "ApprovalLeaseStateError",
    "ApprovalNotFoundError",
    "ApprovalRevisionError",
    "ApprovalStore",
    "ApprovalStoreError",
    "get_approval_store",
]
