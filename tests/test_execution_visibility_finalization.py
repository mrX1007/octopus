"""Tests for visibility finalization in coordinator."""
import pytest
from core.actions.execution_commit import ExecutionCommitCoordinator
from tests.test_execution_commit_participant_protocol import SampleParticipant

@pytest.mark.unit
def test_coordinator_lifecycle():
    coord = ExecutionCommitCoordinator("tx-coord-1")
    coord.register_participant(SampleParticipant())
    ok = coord.execute_commit_protocol()
    assert ok
    assert coord.state.value == "committed"
