"""PR-5 Module: Execution commit participant contracts and lifecycle types (§8.2)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class ParticipantKindV2(str, Enum):
    LOCAL_STORE = "local_store"
    MANAGED_RESOURCE = "managed_resource"
    CROSS_PROCESS_RESOURCE = "cross_process_resource"
    CROSS_PROCESS_CONTROL = "cross_process_control"
    EXTERNAL_EFFECT = "external_effect"
    EXECUTION_RESULT = "execution_result"
    AUDIT_OUTBOX = "audit_outbox"


class ParticipantStateV2(str, Enum):
    REGISTERED = "registered"
    PREPARED = "prepared"
    IN_DOUBT = "in_doubt"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED = "finalized"
    ROLLED_BACK = "rolled_back"
    ABORTED_UNPREPARED = "aborted_unprepared"
    RECONCILIATION_FAILED = "reconciliation_failed"


class ParticipantVisibilityModeV2(str, Enum):
    COORDINATOR_FENCE = "coordinator_fence"
    EXPLICIT_FINALIZE = "explicit_finalize"


@dataclass(frozen=True)
class ParticipantPrepareResultV2:
    participant_id: str
    state: ParticipantStateV2
    prepared_digest: str
    can_commit: bool = True
    error_message: str | None = None


@dataclass(frozen=True)
class ParticipantCommitReceiptV2:
    participant_id: str
    committed_digest: str


@dataclass(frozen=True)
class ParticipantFinalizeReceiptV2:
    participant_id: str
    finalized_digest: str


@dataclass(frozen=True)
class ParticipantRollbackReceiptV2:
    participant_id: str
    rolled_back: bool


@runtime_checkable
class ExecutionCommitParticipant(Protocol):
    @property
    def participant_id(self) -> str: ...

    @property
    def kind(self) -> ParticipantKindV2: ...

    @property
    def visibility_mode(self) -> ParticipantVisibilityModeV2: ...

    def prepare(self, transaction_id: str) -> ParticipantPrepareResultV2: ...

    def commit_hidden(self, transaction_id: str) -> ParticipantCommitReceiptV2: ...

    def finalize_visibility(self, transaction_id: str) -> ParticipantFinalizeReceiptV2: ...

    def rollback(self, transaction_id: str) -> ParticipantRollbackReceiptV2: ...

    def reconcile(self, transaction_id: str) -> ParticipantStateV2: ...


class ExecutionResultStoreParticipant(ExecutionCommitParticipant):
    """Participant that stages and commits ExecutionResultV2 into the ExecutionResultStore."""

    def __init__(self, result_store: Any, exec_res: Any, transaction_id: str):
        self._result_store = result_store
        self._exec_res = exec_res
        self._transaction_id = transaction_id
        self._draft_ref = None

    @property
    def participant_id(self) -> str:
        return f"res-store-{self._transaction_id}"

    @property
    def kind(self) -> ParticipantKindV2:
        return ParticipantKindV2.EXECUTION_RESULT

    @property
    def visibility_mode(self) -> ParticipantVisibilityModeV2:
        return ParticipantVisibilityModeV2.EXPLICIT_FINALIZE

    def prepare(self, transaction_id: str) -> ParticipantPrepareResultV2:
        draft_ref = self._result_store.stage_draft(self._exec_res, transaction_id)
        if draft_ref is None:
            raise RuntimeError("execution result store returned no staged draft reference")
        self._draft_ref = draft_ref
        return ParticipantPrepareResultV2(
            participant_id=self.participant_id,
            state=ParticipantStateV2.PREPARED,
            prepared_digest=draft_ref.normalized_draft_digest,
        )

    def commit_hidden(self, transaction_id: str) -> ParticipantCommitReceiptV2:
        self._result_store.commit(
            transaction_id=transaction_id,
            coordinator_revision=1,
            committed_marker_ref=f"marker:{transaction_id}",
            committed_marker_digest=self._draft_ref.normalized_draft_digest if self._draft_ref else "sha256:error",
        )
        return ParticipantCommitReceiptV2(
            participant_id=self.participant_id,
            committed_digest=self._draft_ref.normalized_draft_digest if self._draft_ref else "sha256:error",
        )

    def finalize_visibility(self, transaction_id: str) -> ParticipantFinalizeReceiptV2:
        return ParticipantFinalizeReceiptV2(
            participant_id=self.participant_id,
            finalized_digest=self._draft_ref.normalized_draft_digest if self._draft_ref else "sha256:error",
        )

    def rollback(self, transaction_id: str) -> ParticipantRollbackReceiptV2:
        return ParticipantRollbackReceiptV2(participant_id=self.participant_id, rolled_back=True)

    def reconcile(self, transaction_id: str) -> ParticipantStateV2:
        return ParticipantStateV2.ROLLED_BACK


__all__ = [
    "ExecutionCommitParticipant",
    "ExecutionResultStoreParticipant",
    "ParticipantCommitReceiptV2",
    "ParticipantFinalizeReceiptV2",
    "ParticipantKindV2",
    "ParticipantPrepareResultV2",
    "ParticipantRollbackReceiptV2",
    "ParticipantStateV2",
    "ParticipantVisibilityModeV2",
]
