from __future__ import annotations

import pytest

from core.actions.cancellation import ExecutorCancellationController, ExecutorCancellationToken

pytestmark = pytest.mark.unit


def test_cancellation_controller_initialization():
    controller = ExecutorCancellationController("test-token-1")
    token = controller.token
    assert isinstance(token, ExecutorCancellationToken)
    assert not token.is_cancelled()
    assert token.token_id == "test-token-1"


def test_caller_cannot_construct_cancellation_token() -> None:
    with pytest.raises(TypeError):
        ExecutorCancellationToken()  # type: ignore[call-arg]


def test_cancellation_controller_cancel():
    controller = ExecutorCancellationController("test-token-2")
    token = controller.token

    assert not token.is_cancelled()
    controller.cancel(reason_code="user_requested")
    assert token.is_cancelled()
    assert token.reason_code == "user_requested"


def test_cancellation_token_hierarchy():
    # The new pattern does not support explicit token hierarchy via `parent=`
    # We test that the wait() condition works instead since parent relationships are removed
    controller = ExecutorCancellationController("test-token-3")
    token = controller.token

    assert not token.is_cancelled()

    # Check wait returns False on timeout
    assert not token.wait(0.01)

    controller.cancel(reason_code="shutdown")
    assert token.is_cancelled()

    # Check wait returns True immediately when cancelled
    assert token.wait(0.01)
