"""Exact trusted-fact precondition registry tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from core.actions.action_preconditions import get_action_precondition_registry_v2
from core.actions.trusted_facts import (
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
    TrustedFactSnapshot,
    TrustedFactTrustLevelV2,
    TrustedFactType,
)

pytestmark = pytest.mark.unit


def _fact(fact_ref: str, fact_type: TrustedFactType) -> TrustedFactSnapshot:
    return TrustedFactSnapshot(
        schema_version="2.0",
        fact_ref=fact_ref,
        revision=1,
        payload_digest="sha256:fixture",
        mission_id="mission-1",
        target="target.example",
        fact_type=fact_type,
        assessment_status=AssessmentStatus.VERIFIED,
        trust_level=TrustedFactTrustLevelV2.TRUSTED,
        freshness_status=FactFreshnessStatus.FRESH,
        coverage_status=EvidenceCoverageStatus.COMPLETE,
        source_execution_ids=("execution-1",),
        expires_at=None,
    )


def test_action_precondition_evaluation() -> None:
    registry = get_action_precondition_registry_v2()
    facts = (
        _fact("fact://windows", TrustedFactType.CONFIRMED_WINDOWS_ACCESS),
        _fact("fact://ad", TrustedFactType.AD_ENVIRONMENT_DETECTED),
    )
    decision = registry.evaluate_preconditions("killchain:kerberos_extract_tickets", facts)
    assert decision.satisfied
    assert decision.matched_fact_refs == ("fact://windows", "fact://ad")

    incomplete = registry.evaluate_preconditions(
        "killchain:kerberos_extract_tickets",
        facts[:1],
    )
    assert not incomplete.satisfied
    assert "missing_required_fact:ad_environment_detected" in incomplete.reason_codes


def test_trusted_fact_unknown_trust_fails_closed() -> None:
    facts = (
        replace(
            _fact("fact://windows", TrustedFactType.CONFIRMED_WINDOWS_ACCESS),
            trust_level=TrustedFactTrustLevelV2.UNKNOWN,
        ),
        _fact("fact://ad", TrustedFactType.AD_ENVIRONMENT_DETECTED),
    )
    assert (
        not get_action_precondition_registry_v2()
        .evaluate_preconditions(
            "killchain:kerberos_extract_tickets",
            facts,
        )
        .satisfied
    )


def test_semantic_matrix_required_fact_ids_resolve_exactly_once() -> None:
    registry = get_action_precondition_registry_v2()
    bindings = registry.bindings()
    assert len(bindings) == len(TrustedFactType) == 12
    assert {binding.required_fact_type_id for binding in bindings} == {fact_type.value for fact_type in TrustedFactType}
    with pytest.raises(KeyError):
        registry.require_binding("resource_exists")
