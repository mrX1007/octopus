"""Tests for ExecutionCommitCoordinator 2PC protocol."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

from core.actions.execution_commit import CommitStateV2, ExecutionCommitCoordinator
from core.actions.execution_commit_participants import (
    ParticipantKindV2,
    ParticipantPrepareResultV2,
    ParticipantCommitReceiptV2,
    ParticipantFinalizeReceiptV2,
    ParticipantRollbackReceiptV2,
    ParticipantStateV2,
    ParticipantVisibilityModeV2,
)


class DummyParticipant:
    def __init__(self, participant_id: str = "p-1", prepare_success: bool = True) -> None:
        self.participant_id = participant_id
        self.prepare_success = prepare_success
        self.kind = ParticipantKindV2.LOCAL_STORE
        self.visibility_mode = ParticipantVisibilityModeV2.COORDINATOR_FENCE
        self.prepared = False
        self.committed = False
        self.aborted = False

    def prepare(self, tx_id: str) -> ParticipantPrepareResultV2:
        self.prepared = self.prepare_success
        state = (
            ParticipantStateV2.PREPARED
            if self.prepare_success
            else ParticipantStateV2.ABORTED_UNPREPARED
        )
        return ParticipantPrepareResultV2(
            participant_id=self.participant_id,
            state=state,
            prepared_digest=f"sha256:prep:{self.participant_id}",
            can_commit=self.prepare_success,
        )

    def commit_hidden(self, tx_id: str) -> ParticipantCommitReceiptV2:
        self.committed = True
        return ParticipantCommitReceiptV2(
            participant_id=self.participant_id,
            committed_digest=f"sha256:commit:{self.participant_id}",
        )

    def finalize_visibility(self, tx_id: str) -> ParticipantFinalizeReceiptV2:
        return ParticipantFinalizeReceiptV2(
            participant_id=self.participant_id,
            finalized_digest=f"sha256:final:{self.participant_id}",
        )

    def rollback(self, tx_id: str) -> ParticipantRollbackReceiptV2:
        self.aborted = True
        return ParticipantRollbackReceiptV2(
            participant_id=self.participant_id,
            rolled_back=True,
        )

    def reconcile(self, tx_id: str) -> ParticipantStateV2:
        return ParticipantStateV2.COMMITTED if self.committed else ParticipantStateV2.ROLLED_BACK


def test_2pc_successful_commit() -> None:
    coord = ExecutionCommitCoordinator("tx-1")
    p1 = DummyParticipant("p-1", prepare_success=True)
    p2 = DummyParticipant("p-2", prepare_success=True)

    coord.register_participant(p1)
    coord.register_participant(p2)

    success = coord.execute_commit_protocol()
    assert success is True
    assert coord.state == CommitStateV2.COMMITTED
    assert p1.committed is True
    assert p2.committed is True


def test_2pc_failed_prepare_aborts() -> None:
    coord = ExecutionCommitCoordinator("tx-2")
    p1 = DummyParticipant("p-1", prepare_success=True)
    p2 = DummyParticipant("p-2", prepare_success=False)

    coord.register_participant(p1)
    coord.register_participant(p2)

    success = coord.execute_commit_protocol()
    assert success is False
    assert coord.state == CommitStateV2.ROLLED_BACK
    assert p1.aborted is True
    assert p2.aborted is True
