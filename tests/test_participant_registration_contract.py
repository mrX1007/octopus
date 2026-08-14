"""Tests for ProviderParticipantRegistrationFacade."""

import pytest

from core.actions.provider_participants import ProviderParticipantRegistrationFacade
from tests.test_execution_commit_participant_protocol import SampleParticipant


@pytest.mark.unit
def test_registration_facade():
    facade = ProviderParticipantRegistrationFacade("tx-1")
    ref = facade.register_participant(SampleParticipant())
    assert ref.participant_id == "part-1"
    parts = facade.seal()
    assert len(parts) == 1
