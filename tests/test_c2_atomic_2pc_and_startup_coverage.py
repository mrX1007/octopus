"""Unit test coverage for atomic 2PC recovery, participant rollback, and fail-closed startup in C2."""

from __future__ import annotations

import dataclasses
import os
import time
from unittest.mock import MagicMock

import pytest

from core.actions.provider_mounts import DefaultProviderMountRegistry
from core.c2 import daemon
from core.c2.control_auth import VerifiedMutationAuthority
from core.c2.control_commands import (
    BoundedControlErrorV1,
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV1,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.control_transactions import ControlTransactionCoordinator

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"A" * 32
TEST_SIG = "A" * 86


def _make_auth_v2(
    tx_id: str = "tx_2pc_test",
    action_id: str = "act_2pc",
    nonce: str = "nonce_2pc_12345678",
    request_digest: str = "0" * 64,
) -> ParticipantControlAuthorizationV2:
    now_ms = int(time.time() * 1000)
    return ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="k_test",
        transaction_id=tx_id,
        participant_id="part_c2_test",
        mission_id="m_test",
        subject_id="s_test",
        action_id=action_id,
        coordinator_revision=1,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 60000,
        nonce=nonce,
        request_digest=request_digest,
        signature=TEST_SIG,
    )


def test_control_transaction_coordinator_lifecycle():
    """Verify 2PC coordinator handles prepare -> commit -> finalize visibility pipeline."""
    coord = ControlTransactionCoordinator()

    # 1. Unregistered participant returns bounded error UNAVAILABLE
    auth = _make_auth_v2()
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    mut_auth = VerifiedMutationAuthority(
        operator_id="op_test",
        subject_id=auth.subject_id,
        mission_id=auth.mission_id,
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id=auth.key_id,
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest=auth.request_digest,
        authorization_issued_at_ms=auth.issued_at_ms,
        authorization_expires_at_ms=auth.expires_at_ms,
        transaction_id=auth.transaction_id,
        participant_id=auth.participant_id,
        action_id=auth.action_id,
    )
    err = coord.execute_transaction(req, authority=mut_auth)
    assert isinstance(err, (BoundedControlErrorV1, BoundedControlErrorV2))
    assert err.reason_code in (C2ControlErrorCodeV1.UNAVAILABLE, C2ControlErrorCodeV2.UNAVAILABLE)
    assert "unregistered_participant" in str(err.detail_ref)

    # 2. Registered mock participant: full success flow
    mock_participant = MagicMock()
    prep_receipt = ParticipantControlReceiptV2(
        transaction_id="tx_2pc_test",
        participant_id="part_c2_test",
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        resource_ref=None,
        resource_revision=None,
        receipt_ref="rcpt:prep:1",
        receipt_digest="0" * 64,
        daemon_instance_id="inst-1",
        result_payload_schema_id=None,
        result_payload_digest=None,
    )
    commit_receipt = ParticipantControlReceiptV2(
        transaction_id="tx_2pc_test",
        participant_id="part_c2_test",
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        resource_ref="c2:res:1",
        resource_revision=1,
        receipt_ref="rcpt:commit:1",
        receipt_digest="0" * 64,
        daemon_instance_id="inst-1",
        result_payload_schema_id=None,
        result_payload_digest=None,
    )
    final_receipt = ParticipantControlReceiptV2(
        transaction_id="tx_2pc_test",
        participant_id="part_c2_test",
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        resource_ref="c2:res:1",
        resource_revision=1,
        receipt_ref="rcpt:final:1",
        receipt_digest="0" * 64,
        daemon_instance_id="inst-1",
        result_payload_schema_id=None,
        result_payload_digest=None,
    )
    mock_participant.prepare.return_value = prep_receipt
    mock_participant.commit.return_value = commit_receipt
    mock_participant.finalize_visibility.return_value = final_receipt

    coord.register_participant("part_c2_test", mock_participant)
    result = coord.execute_transaction(req, authority=mut_auth)
    assert result == final_receipt
    assert mock_participant.prepare.called
    assert mock_participant.commit.called
    assert mock_participant.finalize_visibility.called

    # 3. Prepare failure aborts flow immediately
    mock_participant.reset_mock()
    prep_err = BoundedControlErrorV1(
        reason_code=C2ControlErrorCodeV2.MALFORMED, retryable=False, detail_ref="prep_failed"
    )
    mock_participant.prepare.return_value = prep_err
    res_err = coord.execute_transaction(req, authority=mut_auth)
    assert res_err == prep_err
    assert not mock_participant.commit.called
    assert not mock_participant.finalize_visibility.called

    # 4. Commit failure triggers rollback on prepare receipt
    mock_participant.reset_mock()
    mock_participant.prepare.return_value = prep_receipt
    commit_err = BoundedControlErrorV1(
        reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT, retryable=False, detail_ref="commit_failed"
    )
    mock_participant.commit.return_value = commit_err
    res_commit_err = coord.execute_transaction(req, authority=mut_auth)
    assert res_commit_err == commit_err
    expected_abort_auth = dataclasses.replace(mut_auth, action_id="abort_c2_resource")
    mock_participant.rollback.assert_called_once_with(prep_receipt, authority=expected_abort_auth)
    assert not mock_participant.finalize_visibility.called


def test_daemon_startup_fails_closed_on_invalid_socket(monkeypatch):
    """Verify daemon startup rejects socket paths with missing parent directories."""
    with pytest.raises(RuntimeError, match=r"cannot.*socket|directory|failed"):
        daemon.run_socket_server(socket_override="/nonexistent_c2_dir_9999/c2.sock")

    # Systemd socket mismatch
    monkeypatch.setenv("LISTEN_FDS", "1")
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    with pytest.raises(RuntimeError):
        daemon.run_socket_server(socket_override="/nonexistent/mismatch.sock")


def test_v2_execution_containment_invariants():
    """Verify 4 leaf V2 providers are mounted and remaining 16 remain mounted=False."""
    registry = DefaultProviderMountRegistry()
    assert len(registry.snapshots()) == 20
    mounted = {snap.spec.action_id for snap in registry.snapshots() if snap.spec.mounted}
    assert mounted == {"c2:c2_enroll", "c2:c2_deploy", "c2:c2_task", "c2:c2_cleanup"}
