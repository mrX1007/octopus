"""Exact root/child V2 execution bridges."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn

from core.actions.cancellation import ExecutorCancellationController
from core.actions.execution_budget import ExecutionBudgetLeaseV2, ExecutionLineage
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.ingress_leases import ChildIngressLease, IngressInvocationLease


@dataclass(frozen=True, init=False, repr=False)
class RootExecutionAuthorityBundleV2:
    """Private root-authority output; never accepted from ingress input."""

    budget_lease: ExecutionBudgetLeaseV2
    cancellation_controller: ExecutorCancellationController = field(
        repr=False,
        compare=False,
    )

    def __init__(self) -> None:
        raise TypeError("root execution authority is executor-issued only")

    @classmethod
    def _from_authority(
        cls,
        *,
        budget_lease: ExecutionBudgetLeaseV2,
        cancellation_controller: ExecutorCancellationController,
    ) -> RootExecutionAuthorityBundleV2:
        if type(cancellation_controller) is not ExecutorCancellationController:
            raise TypeError("root authority requires the concrete executor controller")
        if budget_lease.budget.cancellation_token is not cancellation_controller.token:
            raise ValueError("root authority budget/controller mismatch")
        instance = object.__new__(cls)
        object.__setattr__(instance, "budget_lease", budget_lease)
        object.__setattr__(instance, "cancellation_controller", cancellation_controller)
        return instance

    def __reduce__(self) -> NoReturn:
        raise TypeError("RootExecutionAuthorityBundleV2 is non-serializable")


@dataclass(frozen=True, repr=False)
class RootExecutionBridge:
    ingress_lease: IngressInvocationLease
    authority: RootExecutionAuthorityBundleV2
    lineage: ExecutionLineage

    def __reduce__(self) -> NoReturn:
        raise TypeError("RootExecutionBridge is non-serializable")


@dataclass(frozen=True, repr=False)
class ChildExecutionBridge:
    ingress_lease: ChildIngressLease
    budget_lease: ExecutionBudgetLeaseV2
    lineage: ExecutionLineage
    approval_graph_lease: ApprovalExecutionLease
    selected_child_action_id: str
    parent_decision_trace_ref: str

    def __reduce__(self) -> NoReturn:
        raise TypeError("ChildExecutionBridge is non-serializable")


__all__ = [
    "ChildExecutionBridge",
    "RootExecutionAuthorityBundleV2",
    "RootExecutionBridge",
]
