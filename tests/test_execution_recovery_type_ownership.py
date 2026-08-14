"""Tests for execution recovery types ownership."""

import pytest

from core.actions.execution_recovery_types import ExecutionCommitRecoveryRefV2


@pytest.mark.unit
def test_recovery_types():
    ref = ExecutionCommitRecoveryRefV2(
        reference="ref:rec:1",
        revision=1,
        transaction_id="tx-1",
        coordinator_state="in_doubt",
        recovery_digest="sha256:rec",
    )
    assert ref.transaction_id == "tx-1"
