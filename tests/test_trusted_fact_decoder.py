"""Closed trusted fact decoding and integrity tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from core.actions.trusted_facts import (
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
    StoredFactRecord,
    TrustedFactDecoder,
    TrustedFactTrustLevelV2,
    TrustedFactType,
    canonical_stored_fact_payload_digest,
)

pytestmark = pytest.mark.unit


def _stored(**changes: object) -> StoredFactRecord:
    record = StoredFactRecord(
        schema_version="2.0",
        fact_ref="fact://one",
        revision=2,
        mission_id="mission-1",
        target="target.example",
        fact_type=TrustedFactType.CONFIRMED_TARGET_ACCESS.value,
        assessment_status=AssessmentStatus.VERIFIED.value,
        trust_level=TrustedFactTrustLevelV2.TRUSTED.value,
        freshness_status=FactFreshnessStatus.FRESH.value,
        coverage_status=EvidenceCoverageStatus.COMPLETE.value,
        source_execution_ids=("execution-1",),
        payload_digest="",
        expires_at=100.0,
    )
    record = replace(record, payload_digest=canonical_stored_fact_payload_digest(record))
    return replace(record, **changes)


def test_trusted_fact_decoder_exact_snapshot() -> None:
    snapshot = TrustedFactDecoder().decode(_stored(), "fact://one")
    assert snapshot.fact_type is TrustedFactType.CONFIRMED_TARGET_ACCESS
    assert snapshot.assessment_status is AssessmentStatus.VERIFIED
    assert snapshot.satisfies_positive_precondition


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("trust_level", TrustedFactTrustLevelV2.UNKNOWN.value),
        ("freshness_status", FactFreshnessStatus.UNKNOWN.value),
        ("coverage_status", EvidenceCoverageStatus.UNKNOWN.value),
    ),
)
def test_trusted_fact_unknown_values_fail_closed(field: str, value: str) -> None:
    record = _stored()
    changed = replace(record, **{field: value}, payload_digest="")
    changed = replace(changed, payload_digest=canonical_stored_fact_payload_digest(changed))
    assert not TrustedFactDecoder().decode(changed, "fact://one").satisfies_positive_precondition


def test_trusted_fact_payload_substitution_denied() -> None:
    with pytest.raises(ValueError, match="digest"):
        TrustedFactDecoder().decode(_stored(target="other.example"), "fact://one")


def test_trusted_fact_unknown_enum_denied() -> None:
    changed = replace(_stored(), fact_type="caller-defined", payload_digest="")
    changed = replace(changed, payload_digest=canonical_stored_fact_payload_digest(changed))
    with pytest.raises(ValueError, match="unknown enum"):
        TrustedFactDecoder().decode(changed, "fact://one")
