"""Tests for ExecutionCancellationService."""
import pytest
from core.actions.execution_cancellation_service import ExecutionCancellationService

@pytest.mark.unit
def test_cancellation_service():
    svc = ExecutionCancellationService()
    assert svc is not None
