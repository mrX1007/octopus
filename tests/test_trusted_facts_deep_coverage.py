"""Unit tests for trusted_facts.py validations and branch coverage."""

from __future__ import annotations

import pytest

from core.actions.trusted_facts import (
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
    StoredFactRecord,
    TrustedFactDecoder,
    TrustedFactSnapshot,
    TrustedFactTrustLevelV2,
    TrustedFactType,
    canonical_stored_fact_payload_digest,
)

pytestmark = pytest.mark.unit


def test_trusted_fact_snapshot_validations():
    # Unsupported schema
    with pytest.raises(ValueError, match="trusted fact schema version is unsupported"):
        TrustedFactSnapshot(
            schema_version="1.0",  # type: ignore
            fact_ref="fact://1",
            revision=1,
            payload_digest="sha256:d",
            mission_id="m-1",
            target="10.0.0.1",
            fact_type=TrustedFactType.CONFIRMED_WINDOWS_ACCESS,
            assessment_status=AssessmentStatus.VERIFIED,
            trust_level=TrustedFactTrustLevelV2.TRUSTED,
            freshness_status=FactFreshnessStatus.FRESH,
            coverage_status=EvidenceCoverageStatus.COMPLETE,
            source_execution_ids=("exec-1",),
            expires_at=2000.0,
        )

    # Revision invalid
    with pytest.raises(ValueError, match="trusted fact revision must be positive"):
        TrustedFactSnapshot(
            schema_version="2.0",
            fact_ref="fact://1",
            revision=0,
            payload_digest="sha256:d",
            mission_id="m-1",
            target="10.0.0.1",
            fact_type=TrustedFactType.CONFIRMED_WINDOWS_ACCESS,
            assessment_status=AssessmentStatus.VERIFIED,
            trust_level=TrustedFactTrustLevelV2.TRUSTED,
            freshness_status=FactFreshnessStatus.FRESH,
            coverage_status=EvidenceCoverageStatus.COMPLETE,
            source_execution_ids=("exec-1",),
            expires_at=2000.0,
        )

    # Enums invalid
    with pytest.raises(ValueError, match="trusted fact enums must be canonical"):
        TrustedFactSnapshot(
            schema_version="2.0",
            fact_ref="fact://1",
            revision=1,
            payload_digest="sha256:d",
            mission_id="m-1",
            target="10.0.0.1",
            fact_type="not_a_type",  # type: ignore
            assessment_status=AssessmentStatus.VERIFIED,
            trust_level=TrustedFactTrustLevelV2.TRUSTED,
            freshness_status=FactFreshnessStatus.FRESH,
            coverage_status=EvidenceCoverageStatus.COMPLETE,
            source_execution_ids=("exec-1",),
            expires_at=2000.0,
        )

    # Source execution IDs duplicate
    with pytest.raises(ValueError, match="source execution IDs contain duplicates"):
        TrustedFactSnapshot(
            schema_version="2.0",
            fact_ref="fact://1",
            revision=1,
            payload_digest="sha256:d",
            mission_id="m-1",
            target="10.0.0.1",
            fact_type=TrustedFactType.CONFIRMED_WINDOWS_ACCESS,
            assessment_status=AssessmentStatus.VERIFIED,
            trust_level=TrustedFactTrustLevelV2.TRUSTED,
            freshness_status=FactFreshnessStatus.FRESH,
            coverage_status=EvidenceCoverageStatus.COMPLETE,
            source_execution_ids=("exec-1", "exec-1"),
            expires_at=2000.0,
        )

    # Expiry not finite
    with pytest.raises(ValueError, match="trusted fact expiry must be finite"):
        TrustedFactSnapshot(
            schema_version="2.0",
            fact_ref="fact://1",
            revision=1,
            payload_digest="sha256:d",
            mission_id="m-1",
            target="10.0.0.1",
            fact_type=TrustedFactType.CONFIRMED_WINDOWS_ACCESS,
            assessment_status=AssessmentStatus.VERIFIED,
            trust_level=TrustedFactTrustLevelV2.TRUSTED,
            freshness_status=FactFreshnessStatus.FRESH,
            coverage_status=EvidenceCoverageStatus.COMPLETE,
            source_execution_ids=("exec-1",),
            expires_at=float("nan"),
        )


def test_trusted_fact_decoder_errors():
    with pytest.raises(TypeError, match="stored fact must be an exact StoredFactRecord"):
        canonical_stored_fact_payload_digest("not_a_record")  # type: ignore

    decoder = TrustedFactDecoder()
    with pytest.raises(TypeError, match="stored fact must be an exact StoredFactRecord"):
        decoder.decode("not_a_record", "fact://1")  # type: ignore
