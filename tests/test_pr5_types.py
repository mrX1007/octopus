import pytest
from core.actions.execution_commit_types import ExecutionCommitStateV2

pytestmark = pytest.mark.unit

def test_enum():
    assert ExecutionCommitStateV2.OPEN == "open"
