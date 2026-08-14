"""Tests for ProviderCallBoundary timeout enforcement."""

import time

import pytest

from core.actions.provider_call_boundary import (
    BoundProviderInvocationContext,
    ProviderCallBoundary,
    ProviderExecutionTimeoutError,
)


class SlowProvider:
    def execute_bound(self, ctx):
        time.sleep(0.05)
        return "done"


@pytest.mark.unit
def test_call_boundary_timeout():
    boundary = ProviderCallBoundary()
    ctx = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="test:slow",
        transaction_id="tx-1",
        input_dto={},
        deadline_monotonic=time.monotonic() - 1.0,
    )
    with pytest.raises(ProviderExecutionTimeoutError):
        boundary.invoke_execute(ctx, SlowProvider())
