"""Tests for C2 resource visibility fence and hidden commit state (§14.6A)."""

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


def _make_req(action: C2ControlActionV1, tx_id: str) -> ParticipantControlRequestV1:
    auth = ParticipantControlAuthorizationV1(
        key_id="key-1",
        transaction_id=tx_id,
        participant_id="part-vis-1",
        mission_id="m-vis",
        subject_id="sub-vis",
        action_id="c2:dns_c2_channel",
        coordinator_revision=1,
        request_digest="sha256:req",
        expires_at=9999999999.0,
        nonce="nonce-vis",
        signature="sig-vis",
    )
    return ParticipantControlRequestV1(
        action=action,
        authorization=auth,
        payload_schema_id="schema:dns_channel",
        payload_digest="sha256:dns_payload",
        canonical_payload_b64u="ey...",
    )


def test_resource_hidden_until_finalization():
    part = C2DaemonResourceParticipant(participant_id="part-vis-1")
    prep = part.prepare(_make_req(C2ControlActionV1.PREPARE_C2_RESOURCE, "tx-vis-1"))
    assert isinstance(prep, ParticipantControlReceiptV1)

    # Commit keeps resource COMMITTED_HIDDEN
    commit = part.commit(_make_req(C2ControlActionV1.COMMIT_C2_RESOURCE, "tx-vis-1"))
    assert isinstance(commit, ParticipantControlReceiptV1)
    assert part._committed_resources["tx-vis-1"]["phase"] == ParticipantControlPhaseV1.COMMITTED_HIDDEN

    # Finalize visibility transitions to FINALIZED_VISIBLE
    part.finalize_visibility(prep, commit)
    assert part._committed_resources["tx-vis-1"]["phase"] == ParticipantControlPhaseV1.FINALIZED_VISIBLE


def test_aborted_resource_never_becomes_visible():
    part = C2DaemonResourceParticipant(participant_id="part-vis-2")
    prep = part.prepare(_make_req(C2ControlActionV1.PREPARE_C2_RESOURCE, "tx-vis-2"))
    assert isinstance(prep, ParticipantControlReceiptV1)

    part.rollback(prep)
    # Check that transaction is removed from pending
    assert "tx-vis-2" not in part._pending_transactions
