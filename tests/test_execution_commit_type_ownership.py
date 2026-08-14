"""Tests for execution commit types ownership."""

import pytest

from core.actions.execution_commit_types import ExecutionCommitStateV2


@pytest.mark.unit
def test_execution_commit_states():
    assert ExecutionCommitStateV2.COMMITTED == "committed"
    assert ExecutionCommitStateV2.ROLLED_BACK == "rolled_back"
