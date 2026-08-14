"""Tests for deployment exactly-once semantics and idempotency."""

from __future__ import annotations

import time

import pytest

from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
)
from core.c2.deployment import C2DeploymentService
from core.c2.resource_participant import C2DaemonResourceParticipant

pytestmark = pytest.mark.unit


def test_deployment_service_idempotent_deploy():
    service = C2DeploymentService()
    res1 = service.deploy("att_idempotent_1", "local", "/tmp/bin", "/tmp/target")
    res2 = service.deploy("att_idempotent_1", "local", "/tmp/bin", "/tmp/target")

    assert res1["status"] == "running"
    assert res2["status"] == "running"
    assert res1["target_identifier"] == res2["target_identifier"]


def test_resource_participant_idempotent_commit():
    participant = C2DaemonResourceParticipant("deploy_part")
    auth = ParticipantControlAuthorizationV1(
        key_id="k1",
        transaction_id="tx_exact_1",
        participant_id="deploy_part",
        mission_id="m1",
        subject_id="s1",
        action_id="commit_enrollment_deployment",
        coordinator_revision=1,
        request_digest="0" * 64,
        expires_at=time.time() + 300,
        nonce="nonce_exact_12345678",
        signature="0" * 64,
    )
    req = ParticipantControlRequestV1(
        action=C2ControlActionV1.COMMIT_ENROLLMENT_DEPLOYMENT,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )

    # First prepare & commit
    participant.prepare(req)
    c1 = participant.commit(req)
    assert isinstance(c1, ParticipantControlReceiptV1)

    # Duplicate commit returns same receipt idempotently
    c2 = participant.commit(req)
    assert isinstance(c2, ParticipantControlReceiptV1)
    assert c1.receipt_digest == c2.receipt_digest
