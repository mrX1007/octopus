"""Closed trusted-fact snapshots and the sole stored-record decoder."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Literal

from core.ai.fact_assessment import AssessmentStatus, EvidenceCoverageStatus, FactFreshnessStatus


class TrustedFactType(str, Enum):
    CONFIRMED_WINDOWS_ACCESS = "confirmed_windows_access"
    AD_ENVIRONMENT_DETECTED = "ad_environment_detected"
    CONFIRMED_AD_ACCESS = "confirmed_ad_access"
    SMB_SERVICE_AVAILABLE = "smb_service_available"
    WINRM_SERVICE_AVAILABLE = "winrm_service_available"
    DCOM_SERVICE_AVAILABLE = "dcom_service_available"
    CONFIRMED_SSH_ACCESS = "confirmed_ssh_access"
    CONFIRMED_PIVOT = "confirmed_pivot"
    APPROVED_C2_SCOPE = "approved_c2_scope"
    CONFIRMED_TARGET_ACCESS = "confirmed_target_access"
    C2_CHANNEL_AUTHORIZED = "c2_channel_authorized"
    C2_AGENT_ENROLLED = "c2_agent_enrolled"


class TrustedFactTrustLevelV2(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StoredFactRecord:
    schema_version: str
    fact_ref: str
    revision: int
    mission_id: str
    target: str
    fact_type: str
    assessment_status: str
    trust_level: str
    freshness_status: str
    coverage_status: str
    source_execution_ids: tuple[str, ...]
    payload_digest: str
    expires_at: float | None


@dataclass(frozen=True)
class TrustedFactSnapshot:
    schema_version: Literal["2.0"]
    fact_ref: str
    revision: int
    payload_digest: str
    mission_id: str
    target: str
    fact_type: TrustedFactType
    assessment_status: AssessmentStatus
    trust_level: TrustedFactTrustLevelV2
    freshness_status: FactFreshnessStatus
    coverage_status: EvidenceCoverageStatus
    source_execution_ids: tuple[str, ...]
    expires_at: float | None

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("trusted fact schema version is unsupported")
        for name in ("fact_ref", "payload_digest", "mission_id", "target"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("trusted fact revision must be positive")
        if (
            type(self.fact_type) is not TrustedFactType
            or type(self.assessment_status) is not AssessmentStatus
            or type(self.trust_level) is not TrustedFactTrustLevelV2
            or type(self.freshness_status) is not FactFreshnessStatus
            or type(self.coverage_status) is not EvidenceCoverageStatus
        ):
            raise ValueError("trusted fact enums must be canonical")
        if type(self.source_execution_ids) is not tuple or any(
            type(value) is not str or not value for value in self.source_execution_ids
        ):
            raise ValueError("source execution IDs must be non-empty strings")
        if len(self.source_execution_ids) != len(set(self.source_execution_ids)):
            raise ValueError("source execution IDs contain duplicates")
        if self.expires_at is not None and not math.isfinite(self.expires_at):
            raise ValueError("trusted fact expiry must be finite")

    @property
    def satisfies_positive_precondition(self) -> bool:
        return (
            self.assessment_status is AssessmentStatus.VERIFIED
            and self.trust_level is TrustedFactTrustLevelV2.TRUSTED
            and self.freshness_status is FactFreshnessStatus.FRESH
            and self.coverage_status is EvidenceCoverageStatus.COMPLETE
        )


def canonical_stored_fact_payload_digest(record: StoredFactRecord) -> str:
    """Digest all exact stored fields except payload_digest."""

    if type(record) is not StoredFactRecord:
        raise TypeError("stored fact must be an exact StoredFactRecord")
    payload = {
        "schema_version": record.schema_version,
        "fact_ref": record.fact_ref,
        "revision": record.revision,
        "mission_id": record.mission_id,
        "target": record.target,
        "fact_type": record.fact_type,
        "assessment_status": record.assessment_status,
        "trust_level": record.trust_level,
        "freshness_status": record.freshness_status,
        "coverage_status": record.coverage_status,
        "source_execution_ids": list(record.source_execution_ids),
        "expires_at": record.expires_at,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    tagged = b"octopus-trusted-fact/2.0\x00" + canonical
    return "sha256:" + hashlib.sha256(tagged).hexdigest()


class TrustedFactDecoder:
    """Convert only canonical stored strings into the closed trusted snapshot."""

    def decode(self, stored_fact: StoredFactRecord, expected_ref: str) -> TrustedFactSnapshot:
        if type(stored_fact) is not StoredFactRecord:
            raise TypeError("stored fact must be an exact StoredFactRecord")
        if type(expected_ref) is not str or not expected_ref:
            raise ValueError("expected fact reference must be non-empty")
        if stored_fact.schema_version != "2.0":
            raise ValueError("trusted fact schema version is unsupported")
        if stored_fact.fact_ref != expected_ref:
            raise ValueError("trusted fact reference mismatch")
        if type(stored_fact.revision) is not int or stored_fact.revision < 1:
            raise ValueError("trusted fact revision is invalid")
        if type(stored_fact.source_execution_ids) is not tuple or any(
            type(value) is not str or not value for value in stored_fact.source_execution_ids
        ):
            raise ValueError("trusted fact source executions are invalid")
        if len(stored_fact.source_execution_ids) != len(set(stored_fact.source_execution_ids)):
            raise ValueError("trusted fact source executions contain duplicates")
        if stored_fact.expires_at is not None and not math.isfinite(stored_fact.expires_at):
            raise ValueError("trusted fact expiry is invalid")
        expected_digest = canonical_stored_fact_payload_digest(stored_fact)
        if not hmac.compare_digest(stored_fact.payload_digest, expected_digest):
            raise ValueError("trusted fact payload digest mismatch")
        try:
            fact_type = TrustedFactType(stored_fact.fact_type)
            assessment = AssessmentStatus(stored_fact.assessment_status)
            trust = TrustedFactTrustLevelV2(stored_fact.trust_level)
            freshness = FactFreshnessStatus(stored_fact.freshness_status)
            coverage = EvidenceCoverageStatus(stored_fact.coverage_status)
        except ValueError as exc:
            raise ValueError("trusted fact contains an unknown enum value") from exc
        return TrustedFactSnapshot(
            schema_version="2.0",
            fact_ref=stored_fact.fact_ref,
            revision=stored_fact.revision,
            payload_digest=stored_fact.payload_digest,
            mission_id=stored_fact.mission_id,
            target=stored_fact.target,
            fact_type=fact_type,
            assessment_status=assessment,
            trust_level=trust,
            freshness_status=freshness,
            coverage_status=coverage,
            source_execution_ids=stored_fact.source_execution_ids,
            expires_at=stored_fact.expires_at,
        )


__all__ = [
    "AssessmentStatus",
    "EvidenceCoverageStatus",
    "FactFreshnessStatus",
    "StoredFactRecord",
    "TrustedFactDecoder",
    "TrustedFactSnapshot",
    "TrustedFactTrustLevelV2",
    "TrustedFactType",
    "canonical_stored_fact_payload_digest",
]
