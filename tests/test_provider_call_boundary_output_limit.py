"""Tests for ProviderCallBoundary output limits."""
import pytest
from core.actions.provider_call_boundary import ProviderCallBoundary, BoundProviderInvocationContext

class LargeOutputProvider:
    def execute_bound(self, ctx): return "x" * 50

@pytest.mark.unit
def test_output_tracking():
    boundary = ProviderCallBoundary()
    ctx = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="test:output",
        transaction_id="tx-1",
        input_dto={},
    )
    res, outcome = boundary.invoke_execute(ctx, LargeOutputProvider())
    assert outcome.raw_output_bytes_count >= 50
