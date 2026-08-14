"""Tests for execution continuation recovery."""
import pytest
from core.actions.execution_finalization import FinalizationRetryStoreV2

@pytest.mark.unit
def test_retry_store():
    store = FinalizationRetryStoreV2()
    assert store is not None
