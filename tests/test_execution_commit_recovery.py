"""Tests for commit recovery reconciler."""

import pytest

from core.actions.execution_commit_types import ExecutionCommitStateV2
from core.actions.execution_reconciler import ExecutionReconcilerV2, ReconciliationDispositionV2


@pytest.mark.unit
def test_commit_recovery_roll_forward():
    rec = ExecutionReconcilerV2()
    dec = rec.evaluate_in_doubt("tx-rec-1", ExecutionCommitStateV2.IN_DOUBT, has_committed_marker=True)
    assert dec.disposition == ReconciliationDispositionV2.ROLL_FORWARD
