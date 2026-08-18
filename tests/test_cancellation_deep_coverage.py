"""Unit tests for cancellation.py."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.actions.cancellation import (
    CancelledException,
    ExecutorCancellationController,
    _ExecutorCancellationToken,
)

pytestmark = pytest.mark.unit


def test_cancellation_tokens_and_controller_deep():
    with pytest.raises(TypeError, match="cancellation tokens are issued only by ExecutorCancellationController"):
        _ExecutorCancellationToken(MagicMock(), _factory_key=object())  # type: ignore

    ctrl = ExecutorCancellationController("canc-1")
    token = ctrl.token
    assert token.is_cancelled() is False
    assert token.cancelled_at is None
    assert token.reason_code is None
    token.raise_if_cancelled()

    # Wait with timeout
    assert token.wait(timeout_seconds=0.01) is False

    with pytest.raises(TypeError, match="non-serializable"):
        token.__reduce__()

    # Cancel once
    assert ctrl.cancel(reason_code="user_cancelled") is True
    assert token.is_cancelled() is True
    assert token.reason_code == "user_cancelled"
    assert token.wait(timeout_seconds=0.01) is True

    # Cancel second time returns False
    assert ctrl.cancel(reason_code="user_cancelled") is False

    # raise_if_cancelled
    with pytest.raises(CancelledException, match="Execution cancelled: canc-1 reason=user_cancelled"):
        token.raise_if_cancelled()
