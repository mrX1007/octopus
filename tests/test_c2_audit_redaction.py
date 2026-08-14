"""Tests for C2 audit log and secret redaction (§14.9)."""

from __future__ import annotations

import pytest
from core.c2.control_audit import (
    ControlAuditLoggerV1,
    redact_sensitive_dict,
    redact_sensitive_text,
)

pytestmark = pytest.mark.unit


def test_redact_sensitive_dict():
    raw = {
        "operator_id": "op-1",
        "action": "c2_deploy",
        "api_key": "supersecretkey123",
        "password": "Password123!",
        "token": "tok-abcdef",
        "enrollment_token": "enr-xyz",
        "nested": {
            "secret_key": "sec-456",
            "normal_field": "visible_value",
        },
    }
    cleaned = redact_sensitive_dict(raw)
    assert cleaned["operator_id"] == "op-1"
    assert cleaned["action"] == "c2_deploy"
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["token"] == "[REDACTED]"
    assert cleaned["enrollment_token"] == "[REDACTED]"
    assert cleaned["nested"]["secret_key"] == "[REDACTED]"
    assert cleaned["nested"]["normal_field"] == "visible_value"


def test_redact_sensitive_text():
    text = "Error authenticating with api_key=secret123 and token=tok456"
    cleaned = redact_sensitive_text(text)
    assert "secret123" not in cleaned
    assert "tok456" not in cleaned


def test_audit_logger_records_and_filters():
    logger = ControlAuditLoggerV1()
    ev1 = logger.record_event(
        operator_id="op-1",
        subject_id="sub-1",
        peer_pid=1001,
        peer_uid=1000,
        peer_gid=1000,
        mission_id="m-1",
        action="list_agents",
        request_id="req-1",
        request_digest="sha256:1",
        result_code="ok",
        duration_ms=5.2,
    )
    ev2 = logger.record_event(
        operator_id="op-2",
        subject_id="sub-2",
        peer_pid=1002,
        peer_uid=1000,
        peer_gid=1000,
        mission_id="m-2",
        action="list_results",
        request_id="req-2",
        request_digest="sha256:2",
        result_code="ok",
        duration_ms=3.1,
    )

    all_events = logger.list_events()
    assert len(all_events) == 2
    m1_events = logger.list_events(mission_id="m-1")
    assert len(m1_events) == 1
    assert m1_events[0].event_id == ev1.event_id
