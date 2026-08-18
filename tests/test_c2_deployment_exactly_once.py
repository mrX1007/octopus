"""Tests for deployment exactly-once semantics and idempotency."""

from __future__ import annotations

import os
import sqlite3
import time

import pytest

from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.deployment import C2DeploymentService
from core.c2.resource_participant import C2DaemonResourceParticipant
from tests.helpers.c2_authority import provision_test_authority

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"P" * 32


def test_deployment_service_idempotent_deploy():
    service = C2DeploymentService()
    res1 = service.deploy("att_idempotent_1", "local", "/tmp/bin", "/tmp/target")
    res2 = service.deploy("att_idempotent_1", "local", "/tmp/bin", "/tmp/target")

    assert res1["status"] == "running"
    assert res2["status"] == "running"
    assert res1["target_identifier"] == res2["target_identifier"]


def test_resource_participant_idempotent_commit():
    participant = C2DaemonResourceParticipant("deploy_part")
    with sqlite3.connect(participant._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_deploy",
            subject_id="s1",
            key_id="k1",
            public_key=TEST_ED_PUB,
            mission_id="m1",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )

    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id="tx_exact_1",
        participant_id="deploy_part",
        mission_id="m1",
        subject_id="s1",
        action_id=C2ControlAction.PREPARE_ENROLLMENT_DEPLOYMENT.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_exact_12345678",
        signature="0" * 86,
    )
    prep_req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_ENROLLMENT_DEPLOYMENT,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    prep_mut_auth = VerifiedMutationAuthority(
        operator_id="op_deploy",
        subject_id="s1",
        mission_id="m1",
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id="k1",
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest="0" * 64,
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="tx_exact_1",
        participant_id="deploy_part",
        action_id=C2ControlAction.PREPARE_ENROLLMENT_DEPLOYMENT.value,
    )

    # First prepare & commit
    prep = participant.prepare(prep_req, authority=prep_mut_auth)
    assert isinstance(prep, ParticipantControlReceiptV2)

    commit_auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k1",
        transaction_id="tx_exact_1",
        participant_id="deploy_part",
        mission_id="m1",
        subject_id="s1",
        action_id=C2ControlAction.COMMIT_ENROLLMENT_DEPLOYMENT.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce_exact_commit_12345",
        signature="0" * 86,
    )
    commit_req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_ENROLLMENT_DEPLOYMENT,
        authorization=commit_auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    commit_mut_auth = VerifiedMutationAuthority(
        operator_id="op_deploy",
        subject_id="s1",
        mission_id="m1",
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id="k1",
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest="0" * 64,
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="tx_exact_1",
        participant_id="deploy_part",
        action_id=C2ControlAction.COMMIT_ENROLLMENT_DEPLOYMENT.value,
    )
    c1 = participant.commit(commit_req, authority=commit_mut_auth)
    assert isinstance(c1, ParticipantControlReceiptV2)

    # Duplicate commit returns same receipt idempotently
    c2 = participant.commit(commit_req, authority=commit_mut_auth)
    assert isinstance(c2, ParticipantControlReceiptV2)
    assert c1.receipt_digest == c2.receipt_digest
