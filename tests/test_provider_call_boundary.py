"""Tests for ProviderCallBoundary execution."""

import pytest

from core.actions.provider_call_boundary import BoundProviderInvocationContext, ProviderCallBoundary


class DummyProvider:
    def check_bound(self, ctx):
        return True

    def execute_bound(self, ctx):
        return {"status": "ok"}

    def verify_bound(self, ctx, res):
        return True


@pytest.mark.unit
def test_call_boundary_execution():
    boundary = ProviderCallBoundary()
    ctx = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="test:dummy",
        transaction_id="tx-1",
        input_dto={},
    )
    boundary.invoke_check(ctx, DummyProvider())
    res, outcome = boundary.invoke_execute(ctx, DummyProvider())
    assert res == {"status": "ok"}
    assert outcome.termination_reason.value == "completed"
