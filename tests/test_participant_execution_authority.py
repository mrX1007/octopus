"""Tests for participant execution authority."""
import pytest
from core.actions.participant_authority import (
    ParticipantExecutionAuthorityBindingV2,
    canonical_participant_authority_digest,
)

@pytest.mark.unit
def test_participant_authority():
    auth = ParticipantExecutionAuthorityBindingV2(
        authority_id="auth-1",
        transaction_id="tx-1",
        creation_ref="c1",
        intent_ref="i1",
        checkout_ref="ck1",
        coordinator_ref="co1",
        authority_digest="sha256:auth",
    )
    digest = canonical_participant_authority_digest(auth)
    assert digest.startswith("sha256:")
