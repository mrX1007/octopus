"""PR-5 Module: Execution draft references and staging registries (§8.2, §8.3)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


class DraftReferenceKindV2(str, Enum):
    ARTIFACT = "artifact_draft"
    SENSITIVE_BATCH = "sensitive_batch_draft"
    MANAGED_RESOURCE = "managed_resource_draft"
    OBSERVATION = "observation_draft"
    FACT = "fact_draft"
    AUDIT_OUTBOX = "audit_outbox_draft"
    DECISION_TRACE = "decision_trace_draft"
    EXTERNAL_EFFECT_OUTPUT = "external_effect_output_draft"


@dataclass(frozen=True)
class ArtifactDraftRefV2:
    transaction_id: str
    draft_id: str
    artifact_schema_id: str
    payload_digest: str


@dataclass(frozen=True)
class ObservationDraftRefV2:
    transaction_id: str
    draft_id: str
    observation_schema_id: str
    payload_digest: str


@dataclass(frozen=True)
class SensitiveBatchDraftRefV2:
    transaction_id: str
    draft_id: str
    batch_digest: str


@dataclass(frozen=True)
class ManagedResourceDraftRefV2:
    transaction_id: str
    draft_id: str
    resource_kind: str
    resource_digest: str


@dataclass(frozen=True)
class AuditOutboxDraftRefV2:
    transaction_id: str
    draft_id: str
    event_schema_id: str
    event_digest: str


@dataclass(frozen=True)
class DecisionTraceDraftRefV2:
    transaction_id: str
    draft_id: str
    trace_schema_id: Literal["decision-trace/2.0"]
    trace_digest: str


__all__ = [
    "ArtifactDraftRefV2",
    "AuditOutboxDraftRefV2",
    "DecisionTraceDraftRefV2",
    "DraftReferenceKindV2",
    "ManagedResourceDraftRefV2",
    "ObservationDraftRefV2",
    "SensitiveBatchDraftRefV2",
]
