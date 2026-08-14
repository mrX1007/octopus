"""Store-issued approval graph and concrete-attempt leases."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, NoReturn, SupportsIndex

from core.actions.target_scope import ExtractedActionTarget

if TYPE_CHECKING:
    from core.auth.approval_store import ApprovalStore


class AttemptLeaseState(str, Enum):
    PENDING = "pending"
    STARTED = "started"
    RELEASED = "released"


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ApprovalExecutionLease:
    """Immutable handle for one executor-owned approval execution graph."""

    lease_id: str
    graph_revision: int
    execution_graph_id: str
    root_action_id: str
    approval_ref: str
    approval_revision: int
    mission_id: str
    subject_id: str
    _store: ApprovalStore = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ApprovalExecutionLease is store-issued only")

    @classmethod
    def open_graph(
        cls,
        *,
        store: ApprovalStore,
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
        now: float | None = None,
    ) -> ApprovalExecutionLease:
        """Open an authorized graph without reserving or consuming a use."""

        return store._open_graph(
            approval_ref=approval_ref,
            approval_revision=approval_revision,
            execution_graph_id=execution_graph_id,
            root_action_id=root_action_id,
            mission_id=mission_id,
            subject_id=subject_id,
            capability=capability,
            killchain_stage=killchain_stage,
            operation_id=operation_id,
            targets=targets,
            now=now,
        )

    def authorize_router_step(
        self,
        *,
        action_id: str,
        capability: str,
        killchain_stage: str,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        now: float | None = None,
    ) -> None:
        """Authorize a root/nested router edge while consuming zero uses."""

        self._store._authorize_router_step(
            self,
            action_id=action_id,
            capability=capability,
            killchain_stage=killchain_stage,
            operation_id=operation_id,
            targets=targets,
            now=now,
        )

    def reserve_attempt(
        self,
        *,
        attempt_group_id: str,
        concrete_action_id: str,
        capability: str,
        killchain_stage: str,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        now: float | None = None,
    ) -> ApprovalAttemptLease:
        """Atomically reserve capacity for exactly one selected concrete leaf."""

        return self._store._reserve_attempt(
            self,
            attempt_group_id=attempt_group_id,
            concrete_action_id=concrete_action_id,
            capability=capability,
            killchain_stage=killchain_stage,
            operation_id=operation_id,
            targets=targets,
            now=now,
        )

    def close_graph(self) -> None:
        """Idempotently close the graph and release any PENDING reservations."""

        self._store._close_graph(self)

    @classmethod
    def _from_store(
        cls,
        *,
        lease_id: str,
        graph_revision: int,
        execution_graph_id: str,
        root_action_id: str,
        approval_ref: str,
        approval_revision: int,
        mission_id: str,
        subject_id: str,
        store: ApprovalStore,
    ) -> ApprovalExecutionLease:
        instance = object.__new__(cls)
        object.__setattr__(instance, "lease_id", lease_id)
        object.__setattr__(instance, "graph_revision", graph_revision)
        object.__setattr__(instance, "execution_graph_id", execution_graph_id)
        object.__setattr__(instance, "root_action_id", root_action_id)
        object.__setattr__(instance, "approval_ref", approval_ref)
        object.__setattr__(instance, "approval_revision", approval_revision)
        object.__setattr__(instance, "mission_id", mission_id)
        object.__setattr__(instance, "subject_id", subject_id)
        object.__setattr__(instance, "_store", store)
        return instance

    def __reduce__(self) -> NoReturn:
        raise TypeError("ApprovalExecutionLease is non-serializable")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ApprovalExecutionLease is non-serializable")


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ApprovalAttemptLease:
    """Immutable handle whose state is held atomically by the approval store."""

    lease_id: str
    graph_lease_id: str
    graph_revision: int
    attempt_group_id: str
    concrete_action_id: str
    approval_ref: str
    approval_revision: int
    _store: ApprovalStore = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ApprovalAttemptLease is store-issued only")

    def start(self, *, now: float | None = None) -> None:
        """Atomically move PENDING to STARTED and consume exactly one use."""

        self._store._start_attempt(self, now=now)

    def release_before_start(self) -> None:
        """Move PENDING to RELEASED without consuming a use."""

        self._store._release_attempt_before_start(self)

    def state(self) -> AttemptLeaseState:
        return self._store._attempt_state(self)

    @classmethod
    def _from_store(
        cls,
        *,
        lease_id: str,
        graph_lease_id: str,
        graph_revision: int,
        attempt_group_id: str,
        concrete_action_id: str,
        approval_ref: str,
        approval_revision: int,
        store: ApprovalStore,
    ) -> ApprovalAttemptLease:
        instance = object.__new__(cls)
        object.__setattr__(instance, "lease_id", lease_id)
        object.__setattr__(instance, "graph_lease_id", graph_lease_id)
        object.__setattr__(instance, "graph_revision", graph_revision)
        object.__setattr__(instance, "attempt_group_id", attempt_group_id)
        object.__setattr__(instance, "concrete_action_id", concrete_action_id)
        object.__setattr__(instance, "approval_ref", approval_ref)
        object.__setattr__(instance, "approval_revision", approval_revision)
        object.__setattr__(instance, "_store", store)
        return instance

    def __reduce__(self) -> NoReturn:
        raise TypeError("ApprovalAttemptLease is non-serializable")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ApprovalAttemptLease is non-serializable")


__all__ = [
    "ApprovalAttemptLease",
    "ApprovalExecutionLease",
    "AttemptLeaseState",
]
