"""Unit tests for provider_call_boundary.py."""

from __future__ import annotations

import time
from unittest.mock import MagicMock
import pytest

from core.actions.cancellation import ExecutorCancellationController
from core.actions.provider_call_boundary import (
    BoundProviderInvocationContext,
    ProviderCallBoundary,
    ProviderExecutionCancelledError,
    ProviderExecutionTimeoutError,
    _ProviderExecutePhaseLeaseControllerV2,
)

pytestmark = pytest.mark.unit


def test_lease_controller():
    ctrl = _ProviderExecutePhaseLeaseControllerV2()
    assert ctrl.lease.active is False
    ctrl.activate()
    assert ctrl.lease.active is True
    ctrl.revoke()
    assert ctrl.lease.active is False
    with pytest.raises(RuntimeError, match="not active"):
        ctrl.lease.require_active()


def test_provider_call_boundary_all_phases():
    boundary = ProviderCallBoundary()

    # Cancelled before start
    canc_ctrl = ExecutorCancellationController("canc-1")
    canc_ctrl.cancel(reason_code="test_cancel")
    ctx_canc = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        input_dto={},
        cancellation_token=canc_ctrl.token,
    )
    with pytest.raises(ProviderExecutionCancelledError, match="Execution cancelled before provider start"):
        boundary.invoke_execute(ctx_canc, provider=MagicMock())

    # Expired deadline before start
    ctx_exp = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        input_dto={},
        deadline_monotonic=time.monotonic() - 10.0,
    )
    with pytest.raises(ProviderExecutionTimeoutError, match="Execution deadline exceeded before start"):
        boundary.invoke_execute(ctx_exp, provider=MagicMock())

    # Provider lacking execute_bound
    ctx_valid = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        input_dto={},
    )
    with pytest.raises(AttributeError, match="does not implement execute_bound"):
        boundary.invoke_execute(ctx_valid, provider=object())

    # Provider raising TimeoutError
    class TimeoutProvider:
        def execute_bound(self, ctx):
            raise TimeoutError("inner timeout")

    with pytest.raises(TimeoutError, match="inner timeout"):
        boundary.invoke_execute(ctx_valid, provider=TimeoutProvider())

    # Provider cancelled during execution
    canc_ctrl2 = ExecutorCancellationController("canc-2")
    ctx_canc2 = BoundProviderInvocationContext(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        input_dto={},
        cancellation_token=canc_ctrl2.token,
    )

    class CancellingProvider:
        def execute_bound(self, ctx):
            canc_ctrl2.cancel(reason_code="mid_exec")
            return "done"

    with pytest.raises(ProviderExecutionCancelledError, match="Execution cancelled during provider execution"):
        boundary.invoke_execute(ctx_canc2, provider=CancellingProvider())

    # Check and verify without methods
    dummy = object()
    assert boundary.invoke_check(ctx_valid, dummy) is None
    assert boundary.invoke_verify(ctx_valid, dummy, "res") is None

    # Route without route_bound
    with pytest.raises(AttributeError, match="does not implement route_bound"):
        boundary.invoke_route(ctx_valid, dummy)

    # Route with route_bound
    class RoutingProvider:
        def route_bound(self, ctx):
            return "routed"

    assert boundary.invoke_route(ctx_valid, RoutingProvider()) == "routed"
