"""Tests for in-doubt recovery rollback without marker."""
import pytest
from core.actions.execution_reconciler import ExecutionReconcilerV2, ReconciliationDispositionV2
from core.actions.execution_commit_types import ExecutionCommitStateV2

@pytest.mark.unit
def test_commit_recovery_roll_back():
    rec = ExecutionReconcilerV2()
    dec = rec.evaluate_in_doubt("tx-rec-2", ExecutionCommitStateV2.IN_DOUBT, has_committed_marker=False)
    assert dec.disposition == ReconciliationDispositionV2.ROLL_BACK
