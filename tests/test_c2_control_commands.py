"""Tests for C2 control command structures."""

from __future__ import annotations

import pytest

from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlPhaseV1,
    ParticipantControlReceiptV1,
)

pytestmark = pytest.mark.unit


def test_control_action_enum_values():
    assert C2ControlActionV1.PING.value == "ping"
    assert C2ControlActionV1.VERSION.value == "version"
    assert C2ControlActionV1.READINESS.value == "readiness"
    assert C2ControlActionV1.LIST_AGENTS.value == "list_agents"


def test_participant_control_authorization_creation():
    auth = ParticipantControlAuthorizationV1(
        key_id="k1",
        transaction_id="tx1",
        participant_id="p1",
        mission_id="m1",
        subject_id="s1",
        action_id="ping",
        coordinator_revision=1,
        request_digest="a" * 64,
        expires_at=100.0,
        nonce="nonce_12345678901234",
        signature="c" * 64,
    )
    assert auth.key_id == "k1"
    assert auth.transaction_id == "tx1"
    assert auth.signature == "c" * 64


def test_participant_control_receipt_and_error():
    rcpt = ParticipantControlReceiptV1(
        transaction_id="tx1",
        participant_id="p1",
        action=C2ControlActionV1.PING,
        resource_ref="res1",
        resource_revision=1,
        receipt_ref="r1",
        receipt_digest="b" * 64,
        daemon_instance_id="d1",
        result_payload_schema_id=None,
        result_payload_digest=None,
        result_payload_b64u=None,
    )
    assert rcpt.transaction_id == "tx1"
    assert rcpt.action == C2ControlActionV1.PING

    err = BoundedControlErrorV1(
        reason_code=C2ControlErrorCodeV1.NOT_AUTHORIZED,
        retryable=False,
        detail_ref="unauthorized",
    )
    assert err.reason_code == C2ControlErrorCodeV1.NOT_AUTHORIZED
    assert err.retryable is False


def test_participant_control_phase_enum():
    assert ParticipantControlPhaseV1.PENDING.value == "pending"
    assert ParticipantControlPhaseV1.COMMITTED_HIDDEN.value == "committed_hidden"
    assert ParticipantControlPhaseV1.FINALIZED_VISIBLE.value == "finalized_visible"
    assert ParticipantControlPhaseV1.ABORTED.value == "aborted"
