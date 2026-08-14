"""Tests for ExecutionCommitParticipant protocol."""
import pytest
from core.actions.execution_commit_participants import ExecutionCommitParticipant, ParticipantKindV2, ParticipantVisibilityModeV2, ParticipantStateV2, ParticipantPrepareResultV2, ParticipantCommitReceiptV2, ParticipantFinalizeReceiptV2, ParticipantRollbackReceiptV2

class SampleParticipant:
    participant_id = "part-1"
    kind = ParticipantKindV2.LOCAL_STORE
    visibility_mode = ParticipantVisibilityModeV2.COORDINATOR_FENCE
    def prepare(self, tx_id): return ParticipantPrepareResultV2(self.participant_id, ParticipantStateV2.PREPARED, "sha256:prep")
    def commit_hidden(self, tx_id): return ParticipantCommitReceiptV2(self.participant_id, "sha256:commit")
    def finalize_visibility(self, tx_id): return ParticipantFinalizeReceiptV2(self.participant_id, "sha256:final")
    def rollback(self, tx_id): return ParticipantRollbackReceiptV2(self.participant_id, True)
    def reconcile(self, tx_id): return ParticipantStateV2.COMMITTED_HIDDEN

@pytest.mark.unit
def test_participant_protocol():
    p = SampleParticipant()
    assert isinstance(p, ExecutionCommitParticipant)
