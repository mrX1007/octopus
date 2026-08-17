"""Tests for C2 control client."""

from __future__ import annotations

import pytest

from core.c2.client import (
    C2ControlClient,
    C2DaemonUnavailable,
    DefaultC2ControlClient,
)
from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlReceiptV2,
)
from core.c2.control_signing import ControlSignerV2

pytestmark = pytest.mark.unit

TEST_KEY_32 = b"01234567890123456789012345678901"
TEST_DAEMON_KEY_32 = b"daemon_pubkey_012345678901234567"


def test_control_client_init_and_context_manager():
    signer = ControlSignerV2("key_test", TEST_KEY_32)
    client = DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv_test",
        trusted_daemon_keys={"mock_daemon_key": TEST_DAEMON_KEY_32},
    )
    assert client.signer.key_id == "key_test"

    with client as c:
        assert isinstance(c, C2ControlClient)
    assert client._is_closed is True


def test_control_client_ping_with_mock_transport():
    signer = ControlSignerV2("key_test", TEST_KEY_32)
    client = DefaultC2ControlClient(
        signer=signer,
        transport_handler=DefaultC2ControlClient.create_mock_loopback_transport(),
    )

    receipt = client.ping(mission_id="mission_alpha", subject_id="op_1")
    assert isinstance(receipt, ParticipantControlReceiptV2)
    assert receipt.action == C2ControlAction.PING
    assert receipt.daemon_instance_id == "daemon_inst_0"


def test_control_client_execute_action_with_mock_transport():
    signer = ControlSignerV2("key_test", TEST_KEY_32)
    client = DefaultC2ControlClient(
        signer=signer,
        transport_handler=DefaultC2ControlClient.create_mock_loopback_transport(),
    )

    res = client.execute_action(
        action=C2ControlAction.READINESS,
        payload={"check": "system"},
        mission_id="m1",
        subject_id="sub1",
        transaction_id="tx1",
        participant_id="part1",
    )
    assert isinstance(res, ParticipantControlReceiptV2)
    assert res.transaction_id == "tx1"
    assert res.participant_id == "part1"


def test_control_client_closed_error():
    signer = ControlSignerV2("key_test", TEST_KEY_32)
    client = DefaultC2ControlClient(
        signer=signer,
        transport_handler=DefaultC2ControlClient.create_mock_loopback_transport(),
    )
    client.close()

    with pytest.raises(RuntimeError, match="Client is closed"):
        client.ping(mission_id="m1", subject_id="s1")


def test_control_client_fails_closed_when_socket_unavailable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OCTOPUS_C2_SOCKET", "/tmp/nonexistent_octopus_test.sock")
    signer = ControlSignerV2("key_test", TEST_KEY_32)
    client = DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv_test",
        trusted_daemon_keys={"mock_daemon_key": TEST_DAEMON_KEY_32},
    )

    with pytest.raises(C2DaemonUnavailable):
        client.ping(mission_id="m1", subject_id="s1")
