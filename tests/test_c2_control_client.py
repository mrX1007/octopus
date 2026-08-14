"""Tests for C2 control client."""

from __future__ import annotations

import pytest

from core.c2.client import C2ControlClient, DefaultC2ControlClient
from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlReceiptV1,
)
from core.c2.control_signing import ControlSignerV1

pytestmark = pytest.mark.unit


def test_control_client_init_and_context_manager():
    signer = ControlSignerV1("key_test", b"secret_key_12345678901234567890")
    client = DefaultC2ControlClient(signer=signer)
    assert client.signer.key_id == "key_test"

    with client as c:
        assert isinstance(c, C2ControlClient)
    assert client._is_closed is True


def test_control_client_ping():
    signer = ControlSignerV1("key_test", b"secret_key_12345678901234567890")
    client = DefaultC2ControlClient(signer=signer)

    receipt = client.ping(mission_id="mission_alpha", subject_id="op_1")
    assert isinstance(receipt, ParticipantControlReceiptV1)
    assert receipt.action == C2ControlActionV1.PING
    assert receipt.daemon_instance_id == "daemon_inst_0"


def test_control_client_execute_action():
    signer = ControlSignerV1("key_test", b"secret_key_12345678901234567890")
    client = DefaultC2ControlClient(signer=signer)

    res = client.execute_action(
        action=C2ControlActionV1.READINESS,
        payload={"check": "system"},
        mission_id="m1",
        subject_id="sub1",
        transaction_id="tx1",
        participant_id="part1",
    )
    assert isinstance(res, ParticipantControlReceiptV1)
    assert res.transaction_id == "tx1"
    assert res.participant_id == "part1"


def test_control_client_closed_error():
    signer = ControlSignerV1("key_test", b"secret_key_12345678901234567890")
    client = DefaultC2ControlClient(signer=signer)
    client.close()

    with pytest.raises(RuntimeError, match="Client is closed"):
        client.ping(mission_id="m1", subject_id="s1")
