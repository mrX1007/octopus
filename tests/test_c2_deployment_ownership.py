"""Tests for deployment ownership and tracking."""
from __future__ import annotations

import pytest
from core.c2.deployment import C2DeploymentService
from core.c2.deployment_backends import LocalProcessDeploymentBackend, SSHDeploymentBackend

pytestmark = pytest.mark.unit


def test_deployment_service_register_and_get_backend():
    service = C2DeploymentService()
    local_backend = service.get_backend("local")
    assert isinstance(local_backend, LocalProcessDeploymentBackend)

    ssh_backend = service.get_backend("ssh")
    assert isinstance(ssh_backend, SSHDeploymentBackend)

    with pytest.raises(KeyError, match="not registered"):
        service.get_backend("unknown_backend")


def test_deployment_ownership_lifecycle():
    service = C2DeploymentService()
    res = service.deploy(
        attempt_id="att_own_1",
        backend_name="local",
        binary_path="/tmp/agent",
        target_dir="/tmp/agent_dir",
    )
    assert res["status"] == "running"

    # Probe deployment ownership
    assert service.probe("att_own_1") is True

    # Terminate deployment
    assert service.terminate("att_own_1") is True
    assert service.probe("att_own_1") is False


def test_deployment_multiple_attempts_ownership():
    service = C2DeploymentService()
    r1 = service.deploy("att_1", "local", "/tmp/a1", "/tmp/d1")
    r2 = service.deploy("att_2", "ssh", "/tmp/a2", "/tmp/d2")

    assert r1["target_identifier"] != r2["target_identifier"]
    assert service.probe("att_1") is True
    assert service.probe("att_2") is True
