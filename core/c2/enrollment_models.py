"""Compatibility import surface for canonical PR-15 agent-wire DTOs.

The definitions live only in :mod:`core.c2.agent_task_models`. This module
retains the historical import path without creating a second model owner.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
    AgentTaskDeliveryAckV12,
    AgentTaskEnvelopeV12,
    AgentTaskPayloadV12,
)


class EnrollmentParticipantState(str, Enum):
    REGISTERED = "registered"
    PREPARED = "prepared"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED = "finalized"
    ABORTED = "aborted"


@dataclass(frozen=True)
class EnrollmentEmbeddedReceipt:
    receipt_id: str
    enrollment_ref: str
    enrollment_revision: int
    build_reservation_id: str
    artifact_draft_ref: str
    artifact_sealed_record_digest: str
    artifact_integrity_tag: Any
    artifact_binding_digest: str
    deployment_ref: str
    mission_id: str
    subject_id: str


@dataclass(frozen=True)
class EnrollmentPrepareReceipt:
    receipt_id: str
    transaction_id: str
    embedded: EnrollmentEmbeddedReceipt
    deployment_request_digest: str
    participant_revision: int
    state: EnrollmentParticipantState


__all__ = [
    "AgentHostInventoryTaskPayloadV12",
    "AgentIdentityTaskPayloadV12",
    "AgentNetworkInventoryTaskPayloadV12",
    "AgentServiceInventoryTaskPayloadV12",
    "AgentTaskDeliveryAckV12",
    "AgentTaskEnvelopeV12",
    "AgentTaskPayloadV12",
    "EnrollmentEmbeddedReceipt",
    "EnrollmentParticipantState",
    "EnrollmentPrepareReceipt",
]
