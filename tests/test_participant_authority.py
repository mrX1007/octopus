"""Unit tests for core/actions/participant_authority.py."""

from __future__ import annotations

import pytest

from core.actions.participant_authority import (
    DefaultParticipantExecutionAuthorityFactoryV2,
    ParticipantExecutionAuthorityBindingV2,
    ParticipantExecutionAuthorityFactoryV2,
    canonical_participant_authority_digest,
)

pytestmark = pytest.mark.unit


def test_participant_authority_issuance() -> None:
    factory = DefaultParticipantExecutionAuthorityFactoryV2()
    binding = factory.issue(
        creation_ref="creation_123",
        transaction_id="tx_999",
        intent_ref="intent_456",
        checkout_ref="chk_789",
        coordinator_ref="coord_101",
    )

    assert isinstance(binding, ParticipantExecutionAuthorityBindingV2)
    assert binding.transaction_id == "tx_999"
    assert binding.creation_ref == "creation_123"
    assert binding.intent_ref == "intent_456"
    assert binding.checkout_ref == "chk_789"
    assert binding.coordinator_ref == "coord_101"
    assert binding.authority_id.startswith("auth:tx_999:")
    assert binding.authority_digest.startswith("sha256:")


def test_canonical_participant_authority_digest_deterministic() -> None:
    binding1 = ParticipantExecutionAuthorityBindingV2(
        authority_id="auth:tx_001:abcd1234",
        transaction_id="tx_001",
        creation_ref="creation_ref_1",
        intent_ref="intent_ref_1",
        checkout_ref="checkout_ref_1",
        coordinator_ref="coordinator_ref_1",
        authority_digest="",
    )
    binding2 = ParticipantExecutionAuthorityBindingV2(
        authority_id="auth:tx_001:abcd1234",
        transaction_id="tx_001",
        creation_ref="creation_ref_1",
        intent_ref="intent_ref_1",
        checkout_ref="checkout_ref_1",
        coordinator_ref="coordinator_ref_1",
        authority_digest="",
    )

    digest1 = canonical_participant_authority_digest(binding1)
    digest2 = canonical_participant_authority_digest(binding2)

    assert digest1 == digest2
    assert digest1.startswith("sha256:")


def test_participant_authority_digest_sensitivity() -> None:
    base_binding = ParticipantExecutionAuthorityBindingV2(
        authority_id="auth:tx_001:abcd1234",
        transaction_id="tx_001",
        creation_ref="creation_ref_1",
        intent_ref="intent_ref_1",
        checkout_ref="checkout_ref_1",
        coordinator_ref="coordinator_ref_1",
        authority_digest="",
    )
    base_digest = canonical_participant_authority_digest(base_binding)

    modified_binding = ParticipantExecutionAuthorityBindingV2(
        authority_id="auth:tx_001:abcd1234",
        transaction_id="tx_001_diff",
        creation_ref="creation_ref_1",
        intent_ref="intent_ref_1",
        checkout_ref="checkout_ref_1",
        coordinator_ref="coordinator_ref_1",
        authority_digest="",
    )
    modified_digest = canonical_participant_authority_digest(modified_binding)

    assert base_digest != modified_digest


def test_participant_authority_factory_protocol() -> None:
    factory = DefaultParticipantExecutionAuthorityFactoryV2()
    assert isinstance(factory, ParticipantExecutionAuthorityFactoryV2)
