"""Tests for C2 task provider."""

from __future__ import annotations

import pytest

from core.providers.c2_task import C2TaskProvider

pytestmark = pytest.mark.unit


def test_task_provider_validation():
    provider = C2TaskProvider()
    assert provider.validate_input({"agent_ref": "a1", "operation_id": "exec"}) is True
    assert provider.validate_input({"agent_ref": "a1"}) is False


def test_task_provider_readiness():
    provider = C2TaskProvider()
    assert provider.check_readiness() is True


def test_task_provider_execute():
    provider = C2TaskProvider()
    res = provider.execute({"agent_ref": "agent_x", "operation_id": "file_read"})
    assert res["status"] == "dispatched"
    assert res["agent_ref"] == "agent_x"
    assert res["operation_id"] == "file_read"
    assert res["task_id"].startswith("task_")


def test_task_provider_execute_invalid_raises():
    provider = C2TaskProvider()
    with pytest.raises(ValueError, match="Invalid task parameters"):
        provider.execute({})
