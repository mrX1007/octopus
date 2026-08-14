"""Tests for ProviderCallBoundary cancellation."""

import pytest

from core.actions.cancellation import ExecutorCancellationController
from core.actions.provider_call_boundary import (
    BoundProviderInvocationContext,
    ProviderCallBoundary,
    ProviderExecutionCancelledError,
)


class DummyProvider:
    def execute_bound(self, ctx):
        return "ok"


@pytest.mark.unit
def test_call_boundary_cancellation():
    ctrl = ExecutorCancellationController("tok-cancel")
    ctrl.cancel(reason_code="test_cancel")
    boundary = ProviderCallBoundary()
    ctx = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="test:cancel",
        transaction_id="tx-1",
        input_dto={},
        cancellation_token=ctrl.token,
    )
    with pytest.raises(ProviderExecutionCancelledError):
        boundary.invoke_execute(ctx, DummyProvider())
