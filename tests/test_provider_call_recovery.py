"""Tests for provider call recovery."""

import pytest

from core.actions.provider_call_recovery import ProviderCallRecoveryManager


@pytest.mark.unit
def test_call_recovery():
    mgr = ProviderCallRecoveryManager()
    assert mgr is not None
