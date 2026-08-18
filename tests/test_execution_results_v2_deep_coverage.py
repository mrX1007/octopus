"""Comprehensive unit tests for execution_results_v2.py models and validation branches."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.actions.execution_results_v2 import (
    ActionExecutionReportEnvelopeV2,
    ActionExecutionReportV2,
    ChildExecutionHasNoCommittedResult,
    CleanupErrorSummaryV2,
    CleanupStatusV2,
    CleanupSummaryV2,
    CommittedExecutionResultBindingV2,
    ExecutionResultDraftRefV2,
    ExecutionResultRefV2,
    ExecutionResultV2,
    ExecutionStatusV2,
    InvocationFinalizationFactoryV2,
    InvocationFinalizationRecordV2,
    InvocationFinalizationRefV2,
    InvocationFinalizationRetryRefV2,
    _require_non_empty_strings,
    _require_unique_string_tuple,
    canonical_invocation_finalization_digest,
    derive_effective_status_and_reasons,
)

pytestmark = pytest.mark.unit


def test_helper_and_cleanup_errors():
    with pytest.raises(ValueError, match="name must be a non-empty string"):
        _require_non_empty_strings(name="")

    with pytest.raises(ValueError, match="name must be a tuple of non-empty strings"):
        _require_unique_string_tuple("name", ["not_a_tuple"])

    with pytest.raises(ValueError, match="name must be a tuple of non-empty strings"):
        _require_unique_string_tuple("name", ("",))

    with pytest.raises(ValueError, match="name contains duplicates"):
        _require_unique_string_tuple("name", ("a", "a"))

    with pytest.raises(ValueError, match="cleanup phase must be non-empty"):
        CleanupErrorSummaryV2(phase="", reason_code="r1")

    with pytest.raises(ValueError, match="cleanup reason code must be non-empty"):
        CleanupErrorSummaryV2(phase="p1", reason_code="")

    with pytest.raises(ValueError, match="cleanup status must be canonical"):
        CleanupSummaryV2(status="not_a_status")  # type: ignore

    with pytest.raises(ValueError, match="cleanup errors must be exact summaries"):
        CleanupSummaryV2(status=CleanupStatusV2.FAILED, errors=("not_a_summary",))  # type: ignore

    with pytest.raises(ValueError, match="cleanup_success_has_errors"):
        err = CleanupErrorSummaryV2(phase="p", reason_code="r")
        CleanupSummaryV2(status=CleanupStatusV2.SUCCEEDED, errors=(err,))

    with pytest.raises(ValueError, match="cleanup_failure_requires_error"):
        CleanupSummaryV2(status=CleanupStatusV2.FAILED, errors=())


def test_derive_effective_status_and_reasons_errors():
    with pytest.raises(TypeError, match="transaction status must be canonical"):
        derive_effective_status_and_reasons("bad_status", MagicMock(), ())  # type: ignore

    with pytest.raises(TypeError, match="cleanup summary must be exact"):
        derive_effective_status_and_reasons(ExecutionStatusV2.SUCCEEDED, "bad_cleanup", ())  # type: ignore

    with pytest.raises(ValueError, match="reason codes must be non-empty strings"):
        cleanup = CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED)
        derive_effective_status_and_reasons(ExecutionStatusV2.SUCCEEDED, cleanup, ["not_a_tuple"])  # type: ignore

    with pytest.raises(ValueError, match="reason codes contain duplicates"):
        cleanup = CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED)
        derive_effective_status_and_reasons(ExecutionStatusV2.SUCCEEDED, cleanup, ("r1", "r1"))

    # Cleanup failed when extra already in reason_codes
    cleanup_fail = CleanupSummaryV2(
        status=CleanupStatusV2.FAILED,
        errors=(CleanupErrorSummaryV2(phase="p", reason_code="r"),),
    )
    status, reasons = derive_effective_status_and_reasons(
        ExecutionStatusV2.SUCCEEDED,
        cleanup_fail,
        ("invocation_cleanup_failed",),
    )
    assert status == ExecutionStatusV2.PARTIAL
    assert reasons == ("invocation_cleanup_failed",)


def test_execution_result_and_refs_errors():
    with pytest.raises(ValueError, match="execution result reference revision must be positive"):
        ExecutionResultRefV2(
            reference="ref://1",
            revision=0,
            execution_id="e1",
            action_id="a1",
            result_digest="sha256:d",
        )

    with pytest.raises(ValueError, match="transaction_id must be a non-empty string"):
        ExecutionResultDraftRefV2(
            transaction_id="",
            draft_id="d1",
            execution_id="e1",
            action_id="a1",
            normalized_draft_digest="sha256:d",
        )

    valid_ref = ExecutionResultRefV2(
        reference="ref://1",
        revision=1,
        execution_id="e1",
        action_id="a1",
        result_digest="sha256:d",
    )

    with pytest.raises(ValueError, match="execution result schema version is unsupported"):
        ExecutionResultV2(
            schema_version="1.0",  # type: ignore
            execution_id="e1",
            action_id="a1",
            status=ExecutionStatusV2.SUCCEEDED,
            reason_codes=(),
            artifact_refs=(),
            credential_refs=(),
            session_refs=(),
            route_refs=(),
            c2_refs=(),
            fact_refs=(),
            audit_ref="aud://1",
            decision_trace_ref="trace://1",
            linked_result_refs=(),
            provenance_chain=(),
        )

    with pytest.raises(ValueError, match="execution result must be a committed success or partial result"):
        ExecutionResultV2(
            schema_version="2.0",
            execution_id="e1",
            action_id="a1",
            status=ExecutionStatusV2.FAILED,  # type: ignore
            reason_codes=(),
            artifact_refs=(),
            credential_refs=(),
            session_refs=(),
            route_refs=(),
            c2_refs=(),
            fact_refs=(),
            audit_ref="aud://1",
            decision_trace_ref="trace://1",
            linked_result_refs=(),
            provenance_chain=(),
        )

    with pytest.raises(ValueError, match="linked result references must be exact"):
        ExecutionResultV2(
            schema_version="2.0",
            execution_id="e1",
            action_id="a1",
            status=ExecutionStatusV2.SUCCEEDED,
            reason_codes=(),
            artifact_refs=(),
            credential_refs=(),
            session_refs=(),
            route_refs=(),
            c2_refs=(),
            fact_refs=(),
            audit_ref="aud://1",
            decision_trace_ref="trace://1",
            linked_result_refs=("not_a_ref",),  # type: ignore
            provenance_chain=(),
        )

    with pytest.raises(ValueError, match="linked result references contain duplicates"):
        ExecutionResultV2(
            schema_version="2.0",
            execution_id="e1",
            action_id="a1",
            status=ExecutionStatusV2.SUCCEEDED,
            reason_codes=(),
            artifact_refs=(),
            credential_refs=(),
            session_refs=(),
            route_refs=(),
            c2_refs=(),
            fact_refs=(),
            audit_ref="aud://1",
            decision_trace_ref="trace://1",
            linked_result_refs=(valid_ref, valid_ref),
            provenance_chain=(),
        )


def test_action_execution_report_errors():
    factory = InvocationFinalizationFactoryV2()
    cleanup = CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED)
    final_success = factory.create(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        transaction_status=ExecutionStatusV2.SUCCEEDED,
        cleanup=cleanup,
        transaction_reason_codes=(),
        finalized_at=100.0,
    )
    final_unavail = factory.create(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        transaction_status=ExecutionStatusV2.UNAVAILABLE,
        cleanup=cleanup,
        transaction_reason_codes=(),
        finalized_at=100.0,
    )
    final_ref = InvocationFinalizationRefV2(
        reference="fin://1",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        finalization_digest=canonical_invocation_finalization_digest(final_unavail),
    )
    retry_ref = InvocationFinalizationRetryRefV2(
        reference="ret://1",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        finalization_digest=canonical_invocation_finalization_digest(final_unavail),
    )

    with pytest.raises(ValueError, match="action execution report schema version is unsupported"):
        ActionExecutionReportV2(
            schema_version="1.0",  # type: ignore
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=final_unavail,
            finalization_ref=final_ref,
            finalization_retry_ref=None,
            finalization_persistence_pending=False,
        )

    with pytest.raises(TypeError, match="report finalization must be factory-issued"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization="not_a_finalization",  # type: ignore
            finalization_ref=final_ref,
            finalization_retry_ref=None,
            finalization_persistence_pending=False,
        )

    with pytest.raises(TypeError, match="finalization persistence state must be a bool"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=final_unavail,
            finalization_ref=final_ref,
            finalization_retry_ref=None,
            finalization_persistence_pending="not_a_bool",  # type: ignore
        )

    # publication_table_mismatch
    with pytest.raises(ValueError, match="publication_table_mismatch"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=final_success,  # success requires committed parts
            finalization_ref=final_ref,
            finalization_retry_ref=None,
            finalization_persistence_pending=False,
        )

    # finalization_pending_xor
    with pytest.raises(ValueError, match="finalization_pending_xor"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=final_unavail,
            finalization_ref=final_ref,  # pending requires finalization_ref=None
            finalization_retry_ref=retry_ref,
            finalization_persistence_pending=True,
        )

    # finalization_persisted_xor
    with pytest.raises(ValueError, match="finalization_persisted_xor"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=final_unavail,
            finalization_ref=None,  # non-pending requires finalization_ref
            finalization_retry_ref=None,
            finalization_persistence_pending=False,
        )

    # finalization_identity mismatch
    diff_final = factory.create(
        execution_id="exec-DIFF",
        action_id="act-1",
        transaction_id="tx-1",
        transaction_status=ExecutionStatusV2.UNAVAILABLE,
        cleanup=cleanup,
        transaction_reason_codes=(),
        finalized_at=100.0,
    )
    with pytest.raises(ValueError, match="finalization_identity"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=diff_final,
            finalization_ref=final_ref,
            finalization_retry_ref=None,
            finalization_persistence_pending=False,
        )

    # Envelope revision error
    valid_report = ActionExecutionReportV2(
        schema_version="2.0",
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        execution_result=None,
        execution_result_ref=None,
        committed_result_binding=None,
        finalization=final_unavail,
        finalization_ref=final_ref,
        finalization_retry_ref=None,
        finalization_persistence_pending=False,
    )
    with pytest.raises(ValueError, match="report revision must be positive"):
        ActionExecutionReportEnvelopeV2(
            report=valid_report,
            report_revision=0,
            report_ref="rep://1",
            report_digest="sha256:d",
        )

    # require_successful_committed_result_ref error
    with pytest.raises(ChildExecutionHasNoCommittedResult):
        valid_report.require_successful_committed_result_ref()

    # Factory create validations
    with pytest.raises(TypeError, match="transaction status must be canonical"):
        factory.create(
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            transaction_status="not_a_status",  # type: ignore
            cleanup=cleanup,
            transaction_reason_codes=(),
            finalized_at=100.0,
        )

    with pytest.raises(TypeError, match="cleanup summary must be exact"):
        factory.create(
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            transaction_status=ExecutionStatusV2.SUCCEEDED,
            cleanup="not_cleanup",  # type: ignore
            transaction_reason_codes=(),
            finalized_at=100.0,
        )

    with pytest.raises(ValueError, match="finalized_at must be a finite non-negative timestamp"):
        factory.create(
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            transaction_status=ExecutionStatusV2.SUCCEEDED,
            cleanup=cleanup,
            transaction_reason_codes=(),
            finalized_at=float("nan"),
        )

    # Report committed_result_all_or_none
    with pytest.raises(ValueError, match="committed_result_all_or_none"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            execution_result=MagicMock(),
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=final_unavail,
            finalization_ref=final_ref,
            finalization_retry_ref=None,
            finalization_persistence_pending=False,
        )

    # Token and revision errors
    with pytest.raises(TypeError, match="committed_binding_construction_denied"):
        CommittedExecutionResultBindingV2._from_committed_marker(
            token="bad",  # type: ignore
            transaction_id="tx-1",
            coordinator_revision=1,
            execution_result_ref=MagicMock(),
            canonical_result_digest="sha256:d",
            committed_marker_ref="mark://1",
            committed_marker_digest="sha256:m",
        )

    with pytest.raises(ValueError, match="finalization reference revision must be positive"):
        InvocationFinalizationRefV2(
            reference="ref://1",
            revision=0,
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            finalization_digest="sha256:d",
        )

    with pytest.raises(ValueError, match="finalization retry reference revision must be positive"):
        InvocationFinalizationRetryRefV2(
            reference="ref://1",
            revision=0,
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            finalization_digest="sha256:d",
        )

    with pytest.raises(TypeError, match="finalization_construction_denied"):
        InvocationFinalizationRecordV2._from_factory(
            _token="bad",  # type: ignore
            execution_id="exec-1",
            action_id="act-1",
            transaction_id="tx-1",
            transaction_status=ExecutionStatusV2.SUCCEEDED,
            effective_status=ExecutionStatusV2.SUCCEEDED,
            cleanup=cleanup,
            transaction_reason_codes=(),
            effective_reason_codes=(),
            finalized_at=100.0,
        )
