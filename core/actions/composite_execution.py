"""PR-12 / PR-5 Module: Composite router execution context, child executor re-entry, and shared approval lease (§4.0, §12.0)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable

from core.actions.execution_results_v2 import ActionExecutionReportV2
from core.actions.request_v2 import BoundedActionRequestV2Envelope


@dataclass(frozen=True)
class CompositeExecutionTracker:
    graph_id: str
    root_action_id: str


@dataclass(frozen=True)
class CompositeChildExecutionReceiptV2:
    parent_execution_id: str
    child_execution_id: str
    child_action_id: str
    report: ActionExecutionReportV2


@runtime_checkable
class ChildActionExecutorReentry(Protocol):
    def run_v2(self, envelope: BoundedActionRequestV2Envelope) -> ActionExecutionReportV2: ...


class CompositeRouterContext:
    """Context provided to composite routers for dispatching child leaf actions through ActionExecutor re-entry."""

    def __init__(
        self,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        input_dto: Any,
        executor: ChildActionExecutorReentry,
        approval_lease: Any = None,
    ) -> None:
        self.execution_id = execution_id
        self.action_id = action_id
        self.transaction_id = transaction_id
        self.input_dto = input_dto
        self._executor = executor
        self.approval_lease = approval_lease
        self._child_reports: list[ActionExecutionReportV2] = []

    def dispatch_child(
        self,
        child_envelope: BoundedActionRequestV2Envelope,
    ) -> ActionExecutionReportV2:
        """Dispatches a child action through ActionExecutor re-entry."""
        report = self._executor.run_v2(child_envelope)
        self._child_reports.append(report)
        return report

    @property
    def child_reports(self) -> tuple[ActionExecutionReportV2, ...]:
        return tuple(self._child_reports)


__all__ = [
    "ChildActionExecutorReentry",
    "CompositeChildExecutionReceiptV2",
    "CompositeExecutionTracker",
    "CompositeRouterContext",
]
