"""Tests for finalization fences."""

import pytest

from core.actions.execution_finalization import ExecutionFinalizationFenceAuthorityV2


@pytest.mark.unit
def test_fence_authority():
    auth = ExecutionFinalizationFenceAuthorityV2()
    assert auth is not None
