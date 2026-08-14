"""Tests for cancellation recovery."""

import pytest

from core.actions.cancellation_recovery import CancellationRecoveryManager


@pytest.mark.unit
def test_cancellation_recovery():
    mgr = CancellationRecoveryManager()
    assert mgr is not None
