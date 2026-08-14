"""Tests for C2 deploy provider."""
from __future__ import annotations

import pytest
from core.providers.c2_deploy import C2DeployProvider

pytestmark = pytest.mark.unit


def test_deploy_provider_validation():
    provider = C2DeployProvider()
    assert provider.validate_input({"target_os": "linux", "backend_name": "local"}) is True
    assert provider.validate_input({"target_os": "linux"}) is False


def test_deploy_provider_readiness():
    provider = C2DeployProvider()
    assert provider.check_readiness() is True


def test_deploy_provider_execute():
    provider = C2DeployProvider()
    res = provider.execute({
        "target_os": "linux",
        "backend_name": "local",
        "binary_path": "/tmp/agent_bin",
        "target_dir": "/tmp/agent_dir",
    })
    assert res["status"] == "deployed"
    assert res["attempt_id"].startswith("att_")
    assert res["deployment_result"]["backend"] == "local"


def test_deploy_provider_execute_invalid_raises():
    provider = C2DeployProvider()
    with pytest.raises(ValueError, match="Invalid deploy parameters"):
        provider.execute({})
