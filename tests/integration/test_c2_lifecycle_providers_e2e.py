"""E2E tests for C2 lifecycle providers."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.client import DefaultC2ControlClient
from core.c2.control_signing import ControlSignerV2
from core.providers.c2_cleanup import C2CleanupProvider
from core.providers.c2_deploy import C2DeployProvider
from core.providers.c2_enroll import C2EnrollProvider
from core.providers.c2_task import C2TaskProvider

pytestmark = pytest.mark.unit


def test_c2_lifecycle_e2e_full_flow():
    # 1. Enroll
    enroll_provider = C2EnrollProvider()
    enroll_res = enroll_provider.execute({"mission_id": "e2e_mission", "agent_ref": "agent_e2e_1"})
    assert enroll_res["status"] == "enrolled"
    agent_ref = enroll_res["agent_ref"]

    # 2. Deploy
    deploy_provider = C2DeployProvider()
    deploy_res = deploy_provider.execute(
        {
            "target_os": "linux",
            "backend_name": "local",
            "binary_path": "/tmp/agent_bin",
            "target_dir": "/tmp/agent_dir",
        }
    )
    assert deploy_res["status"] == "deployed"

    # 3. Task
    task_provider = C2TaskProvider()
    task_res = task_provider.execute({"agent_ref": agent_ref, "operation_id": "exec"})
    assert task_res["status"] == "dispatched"
    assert task_res["agent_ref"] == agent_ref

    # 4. Cleanup
    cleanup_provider = C2CleanupProvider()
    cleanup_res = cleanup_provider.execute({"mission_id": "e2e_mission"})
    assert cleanup_res["status"] == "cleaned"


from tests.helpers.c2_loopback import create_mock_loopback_transport


def test_c2_lifecycle_client_integration():
    priv = ed25519.Ed25519PrivateKey.generate()
    signer = ControlSignerV2("key_e2e", priv)
    mock_transport, verifier, service_id = create_mock_loopback_transport()
    client = DefaultC2ControlClient(
        signer=signer,
        transport_handler=mock_transport,
        daemon_verifier=verifier,
        expected_service_id=service_id,
    )

    ping_res = client.ping(mission_id="m_e2e", subject_id="sub_e2e")
    assert ping_res.action.value == "ping"

    readiness_res = client.execute_action(
        action="readiness",
        payload={"check": "e2e"},
        mission_id="m_e2e",
        subject_id="sub_e2e",
        transaction_id="tx_e2e_1",
        participant_id="part_e2e_1",
    )
    assert readiness_res.transaction_id == "tx_e2e_1"


def test_c2_lifecycle_multi_agent_flow():
    enroll_provider = C2EnrollProvider()
    task_provider = C2TaskProvider()

    agents = ["agent_alpha", "agent_beta", "agent_gamma"]
    for ag in agents:
        e_res = enroll_provider.execute({"mission_id": "m_multi", "agent_ref": ag})
        assert e_res["status"] == "enrolled"

        t_res = task_provider.execute({"agent_ref": ag, "operation_id": "system_info"})
        assert t_res["status"] == "dispatched"
