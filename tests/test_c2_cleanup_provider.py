"""Tests for C2 cleanup provider."""

from __future__ import annotations

import pytest

from core.providers.c2_cleanup import C2CleanupProvider

pytestmark = pytest.mark.unit


def test_cleanup_provider_validation():
    provider = C2CleanupProvider()
    assert provider.validate_input({"mission_id": "m1"}) is True
    assert provider.validate_input({}) is False


def test_cleanup_provider_readiness():
    provider = C2CleanupProvider()
    assert provider.check_readiness() is True


def test_cleanup_provider_execute():
    provider = C2CleanupProvider()
    res = provider.execute({"mission_id": "mission_omega"})
    assert res["status"] == "cleaned"
    assert res["mission_id"] == "mission_omega"
    assert res["cleanup_id"].startswith("cln_")


def test_cleanup_provider_execute_invalid_raises():
    provider = C2CleanupProvider()
    with pytest.raises(ValueError, match="Invalid cleanup parameters"):
        provider.execute({})
