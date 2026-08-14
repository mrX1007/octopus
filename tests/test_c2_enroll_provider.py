"""Tests for C2 enrollment provider."""

from __future__ import annotations

import pytest

from core.providers.c2_enroll import C2EnrollProvider

pytestmark = pytest.mark.unit


def test_enroll_provider_validation():
    provider = C2EnrollProvider()
    assert provider.validate_input({"mission_id": "m1", "agent_ref": "a1"}) is True
    assert provider.validate_input({"mission_id": "m1"}) is False
    assert provider.validate_input("not_a_dict") is False


def test_enroll_provider_readiness():
    provider = C2EnrollProvider()
    assert provider.check_readiness() is True


def test_enroll_provider_execute():
    provider = C2EnrollProvider()
    res = provider.execute({"mission_id": "mission_alpha", "agent_ref": "agent_007"})
    assert res["status"] == "enrolled"
    assert res["mission_id"] == "mission_alpha"
    assert res["agent_ref"] == "agent_007"
    assert res["enrollment_id"].startswith("enr_")


def test_enroll_provider_execute_invalid_raises():
    provider = C2EnrollProvider()
    with pytest.raises(ValueError, match="Invalid enrollment parameters"):
        provider.execute({})
