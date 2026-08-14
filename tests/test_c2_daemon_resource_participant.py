"""Tests for C2 daemon resource participant 2PC transaction contracts (§14.6A)."""

from __future__ import annotations

import pytest

from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlPhaseV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
)
from core.c2.resource_participant import C2DaemonResourceParticipant

pytestmark = pytest.mark.unit


def _make_req(action: C2ControlActionV1, tx_id: str, part_id: str = "part-1") -> ParticipantControlRequestV1:
    auth = ParticipantControlAuthorizationV1(
        key_id="key-1",
        transaction_id=tx_id,
        participant_id=part_id,
        mission_id="m-1",
        subject_id="sub-1",
        action_id="c2:c2_enroll",
        coordinator_revision=1,
        request_digest="sha256:req",
        expires_at=9999999999.0,
        nonce="nonce-1",
        signature="sig-ok",
    )
    return ParticipantControlRequestV1(
        action=action,
        authorization=auth,
        payload_schema_id="schema:enrollment",
        payload_digest="sha256:payload",
        canonical_payload_b64u="ey...",
    )


def test_daemon_resource_participant_2pc_lifecycle():
    part = C2DaemonResourceParticipant(participant_id="part-1", daemon_instance_id="inst-1")

    # 1. Prepare
    prep_req = _make_req(C2ControlActionV1.PREPARE_C2_RESOURCE, "tx-100")
    prep_res = part.prepare(prep_req)
    assert isinstance(prep_res, ParticipantControlReceiptV1)
    assert prep_res.transaction_id == "tx-100"
    assert prep_res.resource_ref is not None

    # 2. Commit
    commit_req = _make_req(C2ControlActionV1.COMMIT_C2_RESOURCE, "tx-100")
    commit_res = part.commit(commit_req)
    assert isinstance(commit_res, ParticipantControlReceiptV1)
    assert commit_res.resource_revision == 1

    # 3. Finalize visibility
    fin_res = part.finalize_visibility(prep_res, commit_res)
    assert fin_res.transaction_id == "tx-100"
    assert part._committed_resources["tx-100"]["phase"] == ParticipantControlPhaseV1.FINALIZED_VISIBLE


def test_daemon_resource_participant_rollback():
    part = C2DaemonResourceParticipant(participant_id="part-1", daemon_instance_id="inst-1")
    prep_req = _make_req(C2ControlActionV1.PREPARE_C2_RESOURCE, "tx-200")
    prep_res = part.prepare(prep_req)
    assert isinstance(prep_res, ParticipantControlReceiptV1)

    rollback_res = part.rollback(prep_res)
    assert rollback_res.transaction_id == "tx-200"
    assert "tx-200" not in part._pending_transactions
