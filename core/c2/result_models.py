"""Closed control-plane DTOs for mission-scoped C2 result access.

These models deliberately contain summaries only. Agent wire payloads and task
delivery acknowledgements are owned by PR-15 and must not cross this boundary.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import cast

from core.c2.deployment_profiles import C2TargetArch, C2TargetOS

_MAX_REFERENCE_LENGTH = 512
_MAX_ACK_SELECTIONS = 100


def _require_reference(value: object, field_name: str) -> None:
    if type(value) is not str or not value or len(value) > _MAX_REFERENCE_LENGTH:
        raise ValueError(f"{field_name} must be a non-empty bounded string")


def _require_positive_revision(value: object, field_name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")


def _require_finite_timestamp(value: object, field_name: str) -> None:
    if type(value) not in (int, float):
        raise ValueError(f"{field_name} must be a finite non-negative timestamp")
    numeric_value = float(cast("int | float", value))
    if not math.isfinite(numeric_value) or numeric_value < 0:
        raise ValueError(f"{field_name} must be a finite non-negative timestamp")


class ResultRecordStatusV1(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    INVALID_PAYLOAD = "invalid_payload"
    LEGACY_UNASSIGNED = "legacy_unassigned"


@dataclass(frozen=True)
class AgentSummaryV1:
    agent_ref: str
    mission_id: str
    revision: int
    state: str
    hostname: str
    os: C2TargetOS | None
    arch: C2TargetArch | None
    last_seen: float | None

    def __post_init__(self) -> None:
        _require_reference(self.agent_ref, "agent_ref")
        _require_reference(self.mission_id, "mission_id")
        _require_positive_revision(self.revision, "revision")
        _require_reference(self.state, "state")
        _require_reference(self.hostname, "hostname")
        if self.os is not None and type(self.os) is not C2TargetOS:
            raise ValueError("os must be a C2TargetOS or None")
        if self.arch is not None and type(self.arch) is not C2TargetArch:
            raise ValueError("arch must be a C2TargetArch or None")
        if self.last_seen is not None:
            _require_finite_timestamp(self.last_seen, "last_seen")


@dataclass(frozen=True)
class AgentPageV1:
    items: tuple[AgentSummaryV1, ...]
    next_cursor: str | None

    def __post_init__(self) -> None:
        if type(self.items) is not tuple or any(type(item) is not AgentSummaryV1 for item in self.items):
            raise ValueError("items must contain only AgentSummaryV1 values")
        if self.next_cursor is not None:
            _require_reference(self.next_cursor, "next_cursor")


@dataclass(frozen=True)
class ResultSummaryV1:
    result_ref: str
    task_ref: str
    agent_ref: str
    mission_id: str
    revision: int
    status: ResultRecordStatusV1
    result_schema_id: str
    completed_at: float
    acknowledged: bool

    def __post_init__(self) -> None:
        _require_reference(self.result_ref, "result_ref")
        _require_reference(self.task_ref, "task_ref")
        _require_reference(self.agent_ref, "agent_ref")
        _require_reference(self.mission_id, "mission_id")
        _require_positive_revision(self.revision, "revision")
        if type(self.status) is not ResultRecordStatusV1:
            raise ValueError("status must be a ResultRecordStatusV1")
        _require_reference(self.result_schema_id, "result_schema_id")
        _require_finite_timestamp(self.completed_at, "completed_at")
        if type(self.acknowledged) is not bool:
            raise ValueError("acknowledged must be a bool")


@dataclass(frozen=True)
class ResultPageV1:
    items: tuple[ResultSummaryV1, ...]
    next_cursor: str | None

    def __post_init__(self) -> None:
        if type(self.items) is not tuple or any(type(item) is not ResultSummaryV1 for item in self.items):
            raise ValueError("items must contain only ResultSummaryV1 values")
        if self.next_cursor is not None:
            _require_reference(self.next_cursor, "next_cursor")


@dataclass(frozen=True)
class ResultAckSelectionV1:
    result_ref: str
    expected_revision: int

    def __post_init__(self) -> None:
        _require_reference(self.result_ref, "result_ref")
        _require_positive_revision(self.expected_revision, "expected_revision")


@dataclass(frozen=True)
class ResultAckRequestV1:
    mission_id: str
    agent_ref: str
    selections: tuple[ResultAckSelectionV1, ...]

    def __post_init__(self) -> None:
        _require_reference(self.mission_id, "mission_id")
        _require_reference(self.agent_ref, "agent_ref")
        if type(self.selections) is not tuple or any(
            type(selection) is not ResultAckSelectionV1 for selection in self.selections
        ):
            raise ValueError("selections must contain only ResultAckSelectionV1 values")
        if len(self.selections) > _MAX_ACK_SELECTIONS:
            raise ValueError("selections exceeds the bounded batch size")


@dataclass(frozen=True)
class ResultAcknowledgementRecordV1:
    result_ref: str
    result_revision: int
    acknowledged_by_subject_id: str
    acknowledged_at: float
    acknowledgement_revision: int

    def __post_init__(self) -> None:
        _require_reference(self.result_ref, "result_ref")
        _require_positive_revision(self.result_revision, "result_revision")
        _require_reference(self.acknowledged_by_subject_id, "acknowledged_by_subject_id")
        _require_finite_timestamp(self.acknowledged_at, "acknowledged_at")
        _require_positive_revision(self.acknowledgement_revision, "acknowledgement_revision")


@dataclass(frozen=True)
class ResultAckBatchV1:
    acknowledgements: tuple[ResultAcknowledgementRecordV1, ...]
    rejected_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.acknowledgements) is not tuple or any(
            type(record) is not ResultAcknowledgementRecordV1 for record in self.acknowledgements
        ):
            raise ValueError("acknowledgements must contain only ResultAcknowledgementRecordV1 values")
        if type(self.rejected_refs) is not tuple:
            raise ValueError("rejected_refs must be a tuple")
        for result_ref in self.rejected_refs:
            _require_reference(result_ref, "rejected_refs item")


@dataclass(frozen=True)
class PurgeResultV1:
    purged_count: int
    next_cursor: str | None

    def __post_init__(self) -> None:
        if type(self.purged_count) is not int or self.purged_count < 0:
            raise ValueError("purged_count must be a non-negative integer")
        if self.next_cursor is not None:
            _require_reference(self.next_cursor, "next_cursor")


__all__ = [
    "AgentPageV1",
    "AgentSummaryV1",
    "PurgeResultV1",
    "ResultAckBatchV1",
    "ResultAckRequestV1",
    "ResultAckSelectionV1",
    "ResultAcknowledgementRecordV1",
    "ResultPageV1",
    "ResultRecordStatusV1",
    "ResultSummaryV1",
]
