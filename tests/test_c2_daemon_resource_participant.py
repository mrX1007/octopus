"""Tests for C2 daemon resource participant 2PC transaction contracts (§14.6A)."""

from __future__ import annotations

import time

import pytest

from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlAuthorizationV2,
    ParticipantControlPhaseV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.resource_participant import C2DaemonResourceParticipant

pytestmark = pytest.mark.unit


def _make_req(
    action: C2ControlAction,
    tx_id: str,
    part_id: str = "part-1",
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
) -> ParticipantControlRequestV2:
    now_ms = int(time.time() * 1000)
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id="key-1",
        transaction_id=tx_id,
        participant_id=part_id,
        mission_id="m-1",
        subject_id="sub-1",
        action_id=action.value,
        coordinator_revision=1,
        request_digest="0" * 64,
        issued_at_ms=now_ms,
        expires_at_ms=now_ms + 100000,
        nonce="nonce-1-1234567890",
        signature="0" * 86,
    )
    return ParticipantControlRequestV2(
        action=action,
        authorization=auth,
        payload_schema_id="schema:enrollment",
        payload_digest="0" * 64,
        canonical_payload_b64u="ey...",
        prior_receipt_ref=prior_receipt_ref,
        prior_receipt_digest=prior_receipt_digest,
    )


def test_daemon_resource_participant_2pc_lifecycle():
    part = C2DaemonResourceParticipant(participant_id="part-1", daemon_instance_id="inst-1")

    # 1. Prepare
    prep_req = _make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-100")
    prep_res = part.prepare(prep_req)
    assert isinstance(prep_res, ParticipantControlReceiptV2)
    assert prep_res.transaction_id == "tx-100"
    assert prep_res.resource_ref is not None

    # 2. Commit
    commit_req = _make_req(
        C2ControlAction.COMMIT_C2_RESOURCE,
        "tx-100",
        prior_receipt_ref=prep_res.receipt_ref,
        prior_receipt_digest=prep_res.receipt_digest,
    )
    commit_res = part.commit(commit_req)
    assert isinstance(commit_res, ParticipantControlReceiptV2)
    assert commit_res.resource_revision == 1

    # 3. Finalize visibility
    fin_res = part.finalize_visibility(prep_res, commit_res)
    assert fin_res.transaction_id == "tx-100"
    assert part._committed_resources["tx-100"]["phase"] == ParticipantControlPhaseV2.FINALIZED_VISIBLE


def test_daemon_resource_participant_rollback():
    part = C2DaemonResourceParticipant(participant_id="part-1", daemon_instance_id="inst-1")
    prep_req = _make_req(C2ControlAction.PREPARE_C2_RESOURCE, "tx-200")
    prep_res = part.prepare(prep_req)
    assert isinstance(prep_res, ParticipantControlReceiptV2)

    rollback_res = part.rollback(prep_res)
    assert rollback_res.transaction_id == "tx-200"
    assert "tx-200" not in part._pending_transactions
