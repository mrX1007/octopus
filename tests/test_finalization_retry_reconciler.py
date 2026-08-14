"""Tests for finalization retry reconciler."""

import pytest

from core.actions.execution_finalization import FinalizationRetryReconcilerV2


@pytest.mark.unit
def test_retry_reconciler():
    rec = FinalizationRetryReconcilerV2()
    assert rec is not None
