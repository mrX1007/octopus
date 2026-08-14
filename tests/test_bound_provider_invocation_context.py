"""Tests for BoundProviderInvocationContext."""

import pytest

from core.actions.cancellation import ExecutorCancellationController
from core.actions.provider_call_boundary import BoundProviderInvocationContext


@pytest.mark.unit
def test_invocation_context_creation():
    ctrl = ExecutorCancellationController("tok-1")
    ctx = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        input_dto={"key": "val"},
        cancellation_token=ctrl.token,
    )
    assert ctx.execution_id == "exec-1"
    assert not ctx.cancellation_token.is_cancelled()
