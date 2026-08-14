"""Tests for detached provider call claims."""
import pytest
from core.actions.provider_call_recovery import DetachedCallClaimStore

@pytest.mark.unit
def test_detached_claim_store():
    store = DetachedCallClaimStore()
    assert store is not None
