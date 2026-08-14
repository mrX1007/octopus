"""PR-5 Module: Execution result store protocol and implementation (§8.5)."""

from __future__ import annotations

from typing import Dict, Optional, Protocol, runtime_checkable

from core.actions.execution_results_v2 import (
    CommittedExecutionResultBindingV2,
    ExecutionResultDraftRefV2,
    ExecutionResultRefV2,
    ExecutionResultV2,
    _CommittedBindingConstructionTokenV2,
    canonical_execution_result_digest,
)


@runtime_checkable
class ExecutionResultStoreV2(Protocol):
    def stage_draft(self, result: ExecutionResultV2, transaction_id: str) -> ExecutionResultDraftRefV2: ...

    def commit(
        self,
        transaction_id: str,
        coordinator_revision: int,
        committed_marker_ref: str,
        committed_marker_digest: str,
    ) -> CommittedExecutionResultBindingV2: ...

    def get(self, execution_id: str) -> Optional[ExecutionResultV2]: ...


class DefaultExecutionResultStoreV2:
    """Production implementation of ExecutionResultStoreV2."""

    def __init__(self) -> None:
        self._drafts: Dict[str, ExecutionResultV2] = {}
        self._committed: Dict[str, ExecutionResultV2] = {}
        self._bindings: Dict[str, CommittedExecutionResultBindingV2] = {}
        self._token = _CommittedBindingConstructionTokenV2()

    def stage_draft(self, result: ExecutionResultV2, transaction_id: str) -> ExecutionResultDraftRefV2:
        self._drafts[transaction_id] = result
        digest = canonical_execution_result_digest(result)
        return ExecutionResultDraftRefV2(
            transaction_id=transaction_id,
            draft_id=f"draft-{result.execution_id}",
            execution_id=result.execution_id,
            action_id=result.action_id,
            normalized_draft_digest=digest,
        )

    def commit(
        self,
        transaction_id: str,
        coordinator_revision: int,
        committed_marker_ref: str,
        committed_marker_digest: str,
    ) -> CommittedExecutionResultBindingV2:
        result = self._drafts.get(transaction_id)
        if result is None:
            raise KeyError(f"No staged execution result found for transaction '{transaction_id}'")
        self._committed[result.execution_id] = result
        result_digest = canonical_execution_result_digest(result)
        result_ref = ExecutionResultRefV2(
            reference=f"res:{result.execution_id}",
            revision=1,
            execution_id=result.execution_id,
            action_id=result.action_id,
            result_digest=result_digest,
        )
        binding = CommittedExecutionResultBindingV2._from_committed_marker(
            token=self._token,
            transaction_id=transaction_id,
            coordinator_revision=coordinator_revision,
            execution_result_ref=result_ref,
            canonical_result_digest=result_digest,
            committed_marker_ref=committed_marker_ref,
            committed_marker_digest=committed_marker_digest,
        )
        self._bindings[result.execution_id] = binding
        return binding

    def get(self, execution_id: str) -> Optional[ExecutionResultV2]:
        return self._committed.get(execution_id)

    def get_binding(self, execution_id: str) -> Optional[CommittedExecutionResultBindingV2]:
        return self._bindings.get(execution_id)


_GLOBAL_EXECUTION_RESULT_STORE = DefaultExecutionResultStoreV2()


def get_execution_result_store() -> DefaultExecutionResultStoreV2:
    return _GLOBAL_EXECUTION_RESULT_STORE


__all__ = [
    "DefaultExecutionResultStoreV2",
    "ExecutionResultStoreV2",
    "get_execution_result_store",
]
