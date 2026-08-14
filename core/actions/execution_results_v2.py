"""Execution result V2 foundation models for PR-2 (§4.0).

This module owns all stable V2 execution result, finalization, report,
progress, retry, and ownership types. It intentionally does NOT import
provider-result or input DTO classes from later PRs.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol, Union, runtime_checkable

from typing_extensions import TypeAlias


def _require_non_empty_strings(**values: object) -> None:
    for name, value in values.items():
        if type(value) is not str or not value:
            raise ValueError(f"{name} must be a non-empty string")


def _require_unique_string_tuple(name: str, values: object) -> None:
    if type(values) is not tuple or any(type(value) is not str or not value for value in values):
        raise ValueError(f"{name} must be a tuple of non-empty strings")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} contains duplicates")


# ── Execution status enums ──────────────────────────────────────────────


class ExecutionStatusV2(str, Enum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INTERNAL_FAILURE = "internal_failure"


class CleanupStatusV2(str, Enum):
    NOT_REQUIRED = "not_required"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class CleanupErrorSummaryV2:
    phase: str
    reason_code: str

    def __post_init__(self) -> None:
        if type(self.phase) is not str or not self.phase:
            raise ValueError("cleanup phase must be non-empty")
        if type(self.reason_code) is not str or not self.reason_code:
            raise ValueError("cleanup reason code must be non-empty")


@dataclass(frozen=True)
class CleanupSummaryV2:
    status: CleanupStatusV2
    errors: tuple[CleanupErrorSummaryV2, ...] = ()

    def __post_init__(self) -> None:
        if type(self.status) is not CleanupStatusV2:
            raise ValueError("cleanup status must be canonical")
        if type(self.errors) is not tuple or any(type(error) is not CleanupErrorSummaryV2 for error in self.errors):
            raise ValueError("cleanup errors must be exact summaries")
        if self.status in (CleanupStatusV2.NOT_REQUIRED, CleanupStatusV2.SUCCEEDED):
            if self.errors:
                raise ValueError("cleanup_success_has_errors")
        elif not self.errors:
            raise ValueError("cleanup_failure_requires_error")


# ── Status precedence ───────────────────────────────────────────────────


def derive_effective_status_and_reasons(
    transaction_status: ExecutionStatusV2,
    cleanup: CleanupSummaryV2,
    reason_codes: tuple[str, ...],
) -> tuple[ExecutionStatusV2, tuple[str, ...]]:
    """Apply §8.8 status precedence table."""
    if type(transaction_status) is not ExecutionStatusV2:
        raise TypeError("transaction status must be canonical")
    if type(cleanup) is not CleanupSummaryV2:
        raise TypeError("cleanup summary must be exact")
    if type(reason_codes) is not tuple or any(type(reason) is not str or not reason for reason in reason_codes):
        raise ValueError("reason codes must be non-empty strings")
    if len(reason_codes) != len(set(reason_codes)):
        raise ValueError("reason codes contain duplicates")
    if transaction_status not in (ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL):
        return transaction_status, reason_codes
    if cleanup.status == CleanupStatusV2.FAILED:
        extra = "invocation_cleanup_failed"
        if extra not in reason_codes:
            return ExecutionStatusV2.PARTIAL, (*reason_codes, extra)
        return ExecutionStatusV2.PARTIAL, reason_codes
    return transaction_status, reason_codes


# ── Execution result refs ───────────────────────────────────────────────


@dataclass(frozen=True)
class ExecutionResultRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    result_digest: str

    def __post_init__(self) -> None:
        _require_non_empty_strings(
            reference=self.reference,
            execution_id=self.execution_id,
            action_id=self.action_id,
            result_digest=self.result_digest,
        )
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("execution result reference revision must be positive")


@dataclass(frozen=True)
class ExecutionResultDraftRefV2:
    transaction_id: str
    draft_id: str
    execution_id: str
    action_id: str
    normalized_draft_digest: str

    def __post_init__(self) -> None:
        _require_non_empty_strings(
            transaction_id=self.transaction_id,
            draft_id=self.draft_id,
            execution_id=self.execution_id,
            action_id=self.action_id,
            normalized_draft_digest=self.normalized_draft_digest,
        )


# ── Execution result ────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExecutionResultV2:
    schema_version: Literal["2.0"]
    execution_id: str
    action_id: str
    status: Literal[ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL]
    reason_codes: tuple[str, ...]
    artifact_refs: tuple[str, ...]
    credential_refs: tuple[str, ...]
    session_refs: tuple[str, ...]
    route_refs: tuple[str, ...]
    c2_refs: tuple[str, ...]
    fact_refs: tuple[str, ...]
    audit_ref: str
    decision_trace_ref: str
    linked_result_refs: tuple[ExecutionResultRefV2, ...]
    provenance_chain: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("execution result schema version is unsupported")
        _require_non_empty_strings(
            execution_id=self.execution_id,
            action_id=self.action_id,
            audit_ref=self.audit_ref,
            decision_trace_ref=self.decision_trace_ref,
        )
        if self.status not in (ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL):
            raise ValueError("execution result must be a committed success or partial result")
        for name in (
            "reason_codes",
            "artifact_refs",
            "credential_refs",
            "session_refs",
            "route_refs",
            "c2_refs",
            "fact_refs",
            "provenance_chain",
        ):
            _require_unique_string_tuple(name, getattr(self, name))
        if type(self.linked_result_refs) is not tuple or any(
            type(reference) is not ExecutionResultRefV2 for reference in self.linked_result_refs
        ):
            raise ValueError("linked result references must be exact")
        linked_identities = tuple(reference.reference for reference in self.linked_result_refs)
        if len(linked_identities) != len(set(linked_identities)):
            raise ValueError("linked result references contain duplicates")


def canonical_execution_result_digest(result: ExecutionResultV2) -> str:
    """SHA-256 over canonical JSON schema execution-result/2.0."""
    payload = {
        "schema": "execution-result/2.0",
        "schema_version": result.schema_version,
        "execution_id": result.execution_id,
        "action_id": result.action_id,
        "status": result.status.value if hasattr(result.status, "value") else str(result.status),
        "reason_codes": list(result.reason_codes),
        "artifact_refs": list(result.artifact_refs),
        "credential_refs": list(result.credential_refs),
        "session_refs": list(result.session_refs),
        "route_refs": list(result.route_refs),
        "c2_refs": list(result.c2_refs),
        "fact_refs": list(result.fact_refs),
        "audit_ref": result.audit_ref,
        "decision_trace_ref": result.decision_trace_ref,
        "linked_result_refs": [
            {
                "reference": r.reference,
                "revision": r.revision,
                "execution_id": r.execution_id,
                "action_id": r.action_id,
                "result_digest": r.result_digest,
            }
            for r in result.linked_result_refs
        ],
        "provenance_chain": list(result.provenance_chain),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


# ── Committed result binding (sentinel-guarded) ─────────────────────────


class _CommittedBindingConstructionTokenV2:
    pass


@dataclass(frozen=True, init=False)
class CommittedExecutionResultBindingV2:
    """Store-issued only after the coordinator reaches global COMMITTED."""

    transaction_id: str
    coordinator_revision: int
    commit_state: Literal["committed"]
    execution_result_ref: ExecutionResultRefV2
    canonical_result_digest: str
    committed_marker_ref: str
    committed_marker_digest: str

    @classmethod
    def _from_committed_marker(
        cls,
        *,
        token: _CommittedBindingConstructionTokenV2,
        transaction_id: str,
        coordinator_revision: int,
        execution_result_ref: ExecutionResultRefV2,
        canonical_result_digest: str,
        committed_marker_ref: str,
        committed_marker_digest: str,
    ) -> CommittedExecutionResultBindingV2:
        if not isinstance(token, _CommittedBindingConstructionTokenV2):
            raise TypeError("committed_binding_construction_denied")
        obj = object.__new__(cls)
        object.__setattr__(obj, "transaction_id", transaction_id)
        object.__setattr__(obj, "coordinator_revision", coordinator_revision)
        object.__setattr__(obj, "commit_state", "committed")
        object.__setattr__(obj, "execution_result_ref", execution_result_ref)
        object.__setattr__(obj, "canonical_result_digest", canonical_result_digest)
        object.__setattr__(obj, "committed_marker_ref", committed_marker_ref)
        object.__setattr__(obj, "committed_marker_digest", committed_marker_digest)
        return obj


# ── Invocation finalization ─────────────────────────────────────────────


class _FinalizationConstructionTokenV2:
    pass


@dataclass(frozen=True)
class InvocationFinalizationRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    transaction_id: str
    finalization_digest: str

    def __post_init__(self) -> None:
        _require_non_empty_strings(
            reference=self.reference,
            execution_id=self.execution_id,
            action_id=self.action_id,
            transaction_id=self.transaction_id,
            finalization_digest=self.finalization_digest,
        )
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("finalization reference revision must be positive")


@dataclass(frozen=True)
class InvocationFinalizationRetryRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    transaction_id: str
    finalization_digest: str

    def __post_init__(self) -> None:
        _require_non_empty_strings(
            reference=self.reference,
            execution_id=self.execution_id,
            action_id=self.action_id,
            transaction_id=self.transaction_id,
            finalization_digest=self.finalization_digest,
        )
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("finalization retry reference revision must be positive")


@dataclass(frozen=True, init=False)
class InvocationFinalizationRecordV2:
    schema_version: Literal["1.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    transaction_status: ExecutionStatusV2
    effective_status: ExecutionStatusV2
    cleanup: CleanupSummaryV2
    transaction_reason_codes: tuple[str, ...]
    effective_reason_codes: tuple[str, ...]
    finalized_at: float

    @classmethod
    def _from_factory(
        cls,
        *,
        _token: _FinalizationConstructionTokenV2,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        transaction_status: ExecutionStatusV2,
        effective_status: ExecutionStatusV2,
        cleanup: CleanupSummaryV2,
        transaction_reason_codes: tuple[str, ...],
        effective_reason_codes: tuple[str, ...],
        finalized_at: float,
    ) -> InvocationFinalizationRecordV2:
        if not isinstance(_token, _FinalizationConstructionTokenV2):
            raise TypeError("finalization_construction_denied")
        obj = object.__new__(cls)
        object.__setattr__(obj, "schema_version", "1.0")
        object.__setattr__(obj, "execution_id", execution_id)
        object.__setattr__(obj, "action_id", action_id)
        object.__setattr__(obj, "transaction_id", transaction_id)
        object.__setattr__(obj, "transaction_status", transaction_status)
        object.__setattr__(obj, "effective_status", effective_status)
        object.__setattr__(obj, "cleanup", cleanup)
        object.__setattr__(obj, "transaction_reason_codes", transaction_reason_codes)
        object.__setattr__(obj, "effective_reason_codes", effective_reason_codes)
        object.__setattr__(obj, "finalized_at", finalized_at)
        return obj


def canonical_invocation_finalization_digest(
    record: InvocationFinalizationRecordV2,
) -> str:
    """RFC-8785 digest tagged invocation-finalization/1.0."""
    payload = {
        "schema": "invocation-finalization/1.0",
        "schema_version": record.schema_version,
        "execution_id": record.execution_id,
        "action_id": record.action_id,
        "transaction_id": record.transaction_id,
        "transaction_status": record.transaction_status.value,
        "effective_status": record.effective_status.value,
        "cleanup_status": record.cleanup.status.value,
        "cleanup_errors": [{"phase": e.phase, "reason_code": e.reason_code} for e in record.cleanup.errors],
        "transaction_reason_codes": list(record.transaction_reason_codes),
        "effective_reason_codes": list(record.effective_reason_codes),
        "finalized_at": record.finalized_at,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


class InvocationFinalizationFactoryV2:
    """Sole constructor of InvocationFinalizationRecordV2."""

    def __init__(self) -> None:
        self._construction_token = _FinalizationConstructionTokenV2()

    def create(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        transaction_status: ExecutionStatusV2,
        cleanup: CleanupSummaryV2,
        transaction_reason_codes: tuple[str, ...],
        finalized_at: float,
    ) -> InvocationFinalizationRecordV2:
        _require_non_empty_strings(
            execution_id=execution_id,
            action_id=action_id,
            transaction_id=transaction_id,
        )
        if type(transaction_status) is not ExecutionStatusV2:
            raise TypeError("transaction status must be canonical")
        if type(cleanup) is not CleanupSummaryV2:
            raise TypeError("cleanup summary must be exact")
        _require_unique_string_tuple("transaction_reason_codes", transaction_reason_codes)
        if type(finalized_at) not in (int, float) or not math.isfinite(finalized_at) or finalized_at < 0:
            raise ValueError("finalized_at must be a finite non-negative timestamp")
        effective_status, effective_reason_codes = derive_effective_status_and_reasons(
            transaction_status,
            cleanup,
            transaction_reason_codes,
        )
        return InvocationFinalizationRecordV2._from_factory(
            _token=self._construction_token,
            execution_id=execution_id,
            action_id=action_id,
            transaction_id=transaction_id,
            transaction_status=transaction_status,
            effective_status=effective_status,
            cleanup=cleanup,
            transaction_reason_codes=transaction_reason_codes,
            effective_reason_codes=effective_reason_codes,
            finalized_at=finalized_at,
        )


# ── Child execution helper ──────────────────────────────────────────────


class ChildExecutionHasNoCommittedResult(RuntimeError):
    """The child has no successful globally committed result reference."""


# ── Progress reports ────────────────────────────────────────────────────


class ExecutionProgressStatusV2(str, Enum):
    TERMINATION_PENDING = "termination_pending"
    RECONCILIATION_PENDING = "reconciliation_pending"
    FINALIZATION_PENDING = "finalization_pending"


@dataclass(frozen=True)
class ExecutionProgressReportV2:
    schema_version: Literal["1.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    status: ExecutionProgressStatusV2
    reason_codes: tuple[str, ...]
    progress_revision: int
    progress_ref: str
    progress_digest: str


@dataclass(frozen=True)
class ExecutionProgressDraftV2:
    schema_version: Literal["1.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    status: ExecutionProgressStatusV2
    reason_codes: tuple[str, ...]


# ── Report ownership ────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExecutionReportOwnershipBindingV2:
    execution_id: str
    action_id: str
    mission_ref: str
    mission_revision: int
    owner_subject_id: str
    owner_principal_ref: str
    owner_principal_revision: int
    binding_digest: str


@dataclass(frozen=True)
class ExecutionReportOwnershipRefV2:
    reference: str
    revision: int
    execution_id: str
    binding_digest: str


@runtime_checkable
class ExecutionReportOwnershipStoreV2(Protocol):
    def require_by_execution_id(
        self,
        execution_id: str,
    ) -> tuple[ExecutionReportOwnershipRefV2, ExecutionReportOwnershipBindingV2]: ...


# ── Full action execution report ────────────────────────────────────────


@dataclass(frozen=True)
class ActionExecutionReportV2:
    schema_version: Literal["2.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    execution_result: ExecutionResultV2 | None
    execution_result_ref: ExecutionResultRefV2 | None
    committed_result_binding: CommittedExecutionResultBindingV2 | None
    finalization: InvocationFinalizationRecordV2
    finalization_ref: InvocationFinalizationRefV2 | None
    finalization_retry_ref: InvocationFinalizationRetryRefV2 | None
    finalization_persistence_pending: bool

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("action execution report schema version is unsupported")
        _require_non_empty_strings(
            execution_id=self.execution_id,
            action_id=self.action_id,
            transaction_id=self.transaction_id,
        )
        if type(self.finalization) is not InvocationFinalizationRecordV2:
            raise TypeError("report finalization must be factory-issued")
        if type(self.finalization_persistence_pending) is not bool:
            raise TypeError("finalization persistence state must be a bool")
        committed_parts = (
            self.execution_result,
            self.execution_result_ref,
            self.committed_result_binding,
        )
        if any(part is None for part in committed_parts) and any(part is not None for part in committed_parts):
            raise ValueError("committed_result_all_or_none")
        commit_status = self.finalization.transaction_status in (
            ExecutionStatusV2.SUCCEEDED,
            ExecutionStatusV2.PARTIAL,
        )
        if commit_status != all(part is not None for part in committed_parts):
            raise ValueError("publication_table_mismatch")
        if self.finalization_persistence_pending:
            if self.finalization_ref is not None or self.finalization_retry_ref is None:
                raise ValueError("finalization_pending_xor")
        elif self.finalization_ref is None or self.finalization_retry_ref is not None:
            raise ValueError("finalization_persisted_xor")
        if (
            self.finalization.execution_id != self.execution_id
            or self.finalization.action_id != self.action_id
            or self.finalization.transaction_id != self.transaction_id
        ):
            raise ValueError("finalization_identity")
        if self.execution_result is not None and (self.finalization.transaction_status != self.execution_result.status):
            raise ValueError("transaction_status_mismatch")
        if self.execution_result is not None:
            assert self.execution_result_ref is not None
            assert self.committed_result_binding is not None
            result_digest = canonical_execution_result_digest(self.execution_result)
            if (
                self.execution_result.execution_id != self.execution_id
                or self.execution_result.action_id != self.action_id
                or self.execution_result_ref.execution_id != self.execution_id
                or self.execution_result_ref.action_id != self.action_id
                or self.execution_result_ref.result_digest != result_digest
                or self.committed_result_binding.transaction_id != self.transaction_id
                or self.committed_result_binding.commit_state != "committed"
                or self.committed_result_binding.execution_result_ref != self.execution_result_ref
                or self.committed_result_binding.canonical_result_digest != result_digest
            ):
                raise ValueError("committed_result_binding_mismatch")
        expected_effective, expected_reasons = derive_effective_status_and_reasons(
            self.finalization.transaction_status,
            self.finalization.cleanup,
            self.finalization.transaction_reason_codes,
        )
        if (
            self.finalization.effective_status != expected_effective
            or self.finalization.effective_reason_codes != expected_reasons
        ):
            raise ValueError("finalization_precedence_mismatch")
        if self.finalization_ref is not None and (
            self.finalization_ref.execution_id != self.execution_id
            or self.finalization_ref.action_id != self.action_id
            or self.finalization_ref.transaction_id != self.transaction_id
            or self.finalization_ref.finalization_digest != canonical_invocation_finalization_digest(self.finalization)
        ):
            raise ValueError("finalization_ref_mismatch")
        if self.finalization_retry_ref is not None and (
            self.finalization_retry_ref.execution_id != self.execution_id
            or self.finalization_retry_ref.action_id != self.action_id
            or self.finalization_retry_ref.transaction_id != self.transaction_id
            or self.finalization_retry_ref.finalization_digest
            != canonical_invocation_finalization_digest(self.finalization)
        ):
            raise ValueError("finalization_retry_ref_mismatch")

    def require_successful_committed_result_ref(self) -> ExecutionResultRefV2:
        if (
            self.execution_result_ref is None
            or self.execution_result is None
            or self.committed_result_binding is None
            or self.execution_result.status not in (ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL)
            or self.finalization.effective_status not in (ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL)
        ):
            raise ChildExecutionHasNoCommittedResult(self.execution_id)
        result_digest = canonical_execution_result_digest(self.execution_result)
        binding = self.committed_result_binding
        if (
            self.execution_result.execution_id != self.execution_id
            or self.execution_result.action_id != self.action_id
            or self.execution_result_ref.execution_id != self.execution_id
            or self.execution_result_ref.action_id != self.action_id
            or binding.transaction_id != self.transaction_id
            or binding.commit_state != "committed"
            or binding.execution_result_ref != self.execution_result_ref
            or binding.canonical_result_digest != result_digest
            or self.execution_result_ref.result_digest != result_digest
            or self.finalization.execution_id != self.execution_id
            or self.finalization.action_id != self.action_id
            or self.finalization.transaction_id != self.transaction_id
        ):
            raise ChildExecutionHasNoCommittedResult(self.execution_id)
        return self.execution_result_ref


# ── Report envelope ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class ActionExecutionReportEnvelopeV2:
    report: ActionExecutionReportV2
    report_revision: int
    report_ref: str
    report_digest: str

    def __post_init__(self) -> None:
        if type(self.report) is not ActionExecutionReportV2:
            raise TypeError("report envelope requires an exact terminal report")
        if type(self.report_revision) is not int or self.report_revision < 1:
            raise ValueError("report revision must be positive")
        _require_non_empty_strings(
            report_ref=self.report_ref,
            report_digest=self.report_digest,
        )


ExecutionReportViewV2: TypeAlias = Union[
    ExecutionProgressReportV2,
    ActionExecutionReportEnvelopeV2,
]
InvocationExecutionOutcomeV2: TypeAlias = Union[
    ExecutionProgressReportV2,
    ActionExecutionReportEnvelopeV2,
]


# ── Finalization persistence ────────────────────────────────────────────


@dataclass(frozen=True)
class FinalizationPersistedV2:
    finalization_ref: InvocationFinalizationRefV2

    def __post_init__(self) -> None:
        if type(self.finalization_ref) is not InvocationFinalizationRefV2:
            raise TypeError("persisted finalization requires an exact durable reference")


@dataclass(frozen=True)
class FinalizationRetryEnqueuedV2:
    retry_ref: InvocationFinalizationRetryRefV2

    def __post_init__(self) -> None:
        if type(self.retry_ref) is not InvocationFinalizationRetryRefV2:
            raise TypeError("retry enqueue requires an exact durable retry reference")


FinalizationPersistenceOutcomeV2: TypeAlias = Union[
    FinalizationPersistedV2,
    FinalizationRetryEnqueuedV2,
]


def canonical_finalization_persistence_outcome_digest(
    outcome: FinalizationPersistenceOutcomeV2,
) -> str:
    """RFC-8785 finalization-persistence-outcome/1.0 tagged union + exact ref."""
    if isinstance(outcome, FinalizationPersistedV2):
        finalization_ref = outcome.finalization_ref
        payload = {
            "schema": "finalization-persistence-outcome/1.0",
            "type": "persisted",
            "reference": finalization_ref.reference,
            "revision": finalization_ref.revision,
            "finalization_digest": finalization_ref.finalization_digest,
        }
    elif isinstance(outcome, FinalizationRetryEnqueuedV2):
        retry_ref = outcome.retry_ref
        payload = {
            "schema": "finalization-persistence-outcome/1.0",
            "type": "retry_enqueued",
            "reference": retry_ref.reference,
            "revision": retry_ref.revision,
            "finalization_digest": retry_ref.finalization_digest,
        }
    else:
        raise TypeError(f"Unknown outcome type: {type(outcome)}")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


# ── Finalization retry ──────────────────────────────────────────────────


@dataclass(frozen=True)
class FinalizationRetryClaimV2:
    retry_ref: InvocationFinalizationRetryRefV2
    expected_revision: int
    claim_id: str
    fencing_token: int
    claim_expires_at_utc: float
    claimer_instance_id: str
    claimer_boot_id: str


class FinalizationRetryStateV2(str, Enum):
    UNBOUND = "unbound"
    PENDING = "pending"
    CLAIMED = "claimed"
    COMPLETED = "completed"


@dataclass(frozen=True)
class FinalizationRetryCompletionReceiptV2:
    retry_ref: InvocationFinalizationRetryRefV2
    persisted_finalization_ref: InvocationFinalizationRefV2
    superseding_report_ref: str
    superseding_report_digest: str
    completion_digest: str


@dataclass(frozen=True)
class FinalizationRetryRecordV2:
    retry_ref: InvocationFinalizationRetryRefV2
    finalization: InvocationFinalizationRecordV2
    finalization_digest: str
    state: FinalizationRetryStateV2
    claim_id: str | None
    fencing_token: int
    claim_expires_at_utc: float | None
    claimer_instance_id: str | None
    claimer_boot_id: str | None
    completion_receipt: FinalizationRetryCompletionReceiptV2 | None
    record_digest: str


def canonical_finalization_retry_record_digest(
    record: FinalizationRetryRecordV2,
) -> str:
    """RFC-8785 finalization-retry/1.0; excludes record_digest itself."""
    payload = {
        "schema": "finalization-retry/1.0",
        "retry_ref": record.retry_ref.reference,
        "finalization_digest": record.finalization_digest,
        "state": record.state.value,
        "claim_id": record.claim_id,
        "fencing_token": record.fencing_token,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def canonical_finalization_retry_claim_digest(
    claim: FinalizationRetryClaimV2,
) -> str:
    """RFC-8785 finalization-retry-claim/1.0; covers all claim fields."""
    payload = {
        "schema": "finalization-retry-claim/1.0",
        "retry_ref": claim.retry_ref.reference,
        "expected_revision": claim.expected_revision,
        "claim_id": claim.claim_id,
        "fencing_token": claim.fencing_token,
        "claim_expires_at_utc": claim.claim_expires_at_utc,
        "claimer_instance_id": claim.claimer_instance_id,
        "claimer_boot_id": claim.claimer_boot_id,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def canonical_finalization_retry_completion_digest(
    receipt: FinalizationRetryCompletionReceiptV2,
) -> str:
    """RFC-8785 finalization-retry-completion/1.0; excludes its digest."""
    payload = {
        "schema": "finalization-retry-completion/1.0",
        "retry_ref": receipt.retry_ref.reference,
        "persisted_ref": receipt.persisted_finalization_ref.reference,
        "superseding_report_ref": receipt.superseding_report_ref,
        "superseding_report_digest": receipt.superseding_report_digest,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


# ── Retry store and reconciler protocols ────────────────────────────────


@runtime_checkable
class FinalizationRetryStoreV2(Protocol):
    def list_pending(self) -> tuple[InvocationFinalizationRetryRefV2, ...]: ...
    def list_claimable(
        self,
        now_utc: float,
    ) -> tuple[InvocationFinalizationRetryRefV2, ...]: ...
    def claim(
        self,
        reference: InvocationFinalizationRetryRefV2,
        *,
        expected_revision: int,
        claim_id: str,
        claim_expires_at_utc: float,
        claimer_instance_id: str,
        claimer_boot_id: str,
    ) -> tuple[FinalizationRetryClaimV2, FinalizationRetryRecordV2]: ...
    def require(
        self,
        reference: InvocationFinalizationRetryRefV2,
    ) -> FinalizationRetryRecordV2: ...
    def complete(
        self,
        claim: FinalizationRetryClaimV2,
        persisted: InvocationFinalizationRefV2,
        superseding_report: ActionExecutionReportEnvelopeV2,
    ) -> FinalizationRetryCompletionReceiptV2: ...


class FinalizationRetryReconcilerV2:
    def reconcile_once(
        self,
        reference: InvocationFinalizationRetryRefV2,
    ) -> ActionExecutionReportEnvelopeV2:
        raise NotImplementedError("reconcile_once")


# ── __all__ ─────────────────────────────────────────────────────────────

__all__ = [
    "ActionExecutionReportEnvelopeV2",
    "ActionExecutionReportV2",
    "ChildExecutionHasNoCommittedResult",
    "CleanupErrorSummaryV2",
    "CleanupStatusV2",
    "CleanupSummaryV2",
    "CommittedExecutionResultBindingV2",
    "ExecutionProgressDraftV2",
    "ExecutionProgressReportV2",
    "ExecutionProgressStatusV2",
    "ExecutionReportOwnershipBindingV2",
    "ExecutionReportOwnershipRefV2",
    "ExecutionReportOwnershipStoreV2",
    "ExecutionReportViewV2",
    "ExecutionResultDraftRefV2",
    "ExecutionResultRefV2",
    "ExecutionResultV2",
    "ExecutionStatusV2",
    "FinalizationPersistedV2",
    "FinalizationPersistenceOutcomeV2",
    "FinalizationRetryClaimV2",
    "FinalizationRetryCompletionReceiptV2",
    "FinalizationRetryEnqueuedV2",
    "FinalizationRetryReconcilerV2",
    "FinalizationRetryRecordV2",
    "FinalizationRetryStateV2",
    "FinalizationRetryStoreV2",
    "InvocationExecutionOutcomeV2",
    "InvocationFinalizationFactoryV2",
    "InvocationFinalizationRecordV2",
    "InvocationFinalizationRefV2",
    "InvocationFinalizationRetryRefV2",
    "canonical_execution_result_digest",
    "canonical_finalization_persistence_outcome_digest",
    "canonical_finalization_retry_claim_digest",
    "canonical_finalization_retry_completion_digest",
    "canonical_finalization_retry_record_digest",
    "canonical_invocation_finalization_digest",
    "derive_effective_status_and_reasons",
]
