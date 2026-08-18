"""Comprehensive unit tests for execution results v2, status precedence, progress reports, retry records."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.actions.execution_results_v2 import (
    ActionExecutionReportEnvelopeV2,
    ActionExecutionReportV2,
    CleanupErrorSummaryV2,
    CleanupStatusV2,
    CleanupSummaryV2,
    CommittedExecutionResultBindingV2,
    ExecutionProgressReportV2,
    ExecutionResultRefV2,
    ExecutionResultV2,
    ExecutionStatusV2,
    FinalizationPersistedV2,
    FinalizationRetryClaimV2,
    FinalizationRetryCompletionReceiptV2,
    FinalizationRetryEnqueuedV2,
    InvocationFinalizationFactoryV2,
    InvocationFinalizationRefV2,
    InvocationFinalizationRetryRefV2,
    _CommittedBindingConstructionTokenV2,
    canonical_execution_result_digest,
    canonical_finalization_persistence_outcome_digest,
    canonical_finalization_retry_claim_digest,
    canonical_finalization_retry_completion_digest,
    canonical_invocation_finalization_digest,
    derive_effective_status_and_reasons,
)

pytestmark = pytest.mark.unit


def test_cleanup_summary_and_status_precedence():
    err = CleanupErrorSummaryV2(phase="execution", reason_code="cleanup_err")
    assert err.phase == "execution"
    assert err.reason_code == "cleanup_err"

    # CleanupSummary failure requires errors
    with pytest.raises(ValueError, match="cleanup_failure_requires_error"):
        CleanupSummaryV2(status=CleanupStatusV2.FAILED, errors=())

    summary_failed = CleanupSummaryV2(status=CleanupStatusV2.FAILED, errors=(err,))
    assert summary_failed.status == CleanupStatusV2.FAILED

    # Derive effective status: success + cleanup failure -> partial
    eff_status, reasons = derive_effective_status_and_reasons(
        ExecutionStatusV2.SUCCEEDED,
        summary_failed,
        ("op_ok",),
    )
    assert eff_status == ExecutionStatusV2.PARTIAL
    assert "invocation_cleanup_failed" in reasons

    # Derive effective status: failed transaction remains failed
    summary_ok = CleanupSummaryV2(status=CleanupStatusV2.SUCCEEDED, errors=())
    eff_fail, _ = derive_effective_status_and_reasons(
        ExecutionStatusV2.FAILED,
        summary_ok,
        ("op_fail",),
    )
    assert eff_fail == ExecutionStatusV2.FAILED


def test_execution_progress_report():
    from core.actions.execution_results_v2 import ExecutionProgressStatusV2

    report = ExecutionProgressReportV2(
        schema_version="1.0",
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        status=ExecutionProgressStatusV2.TERMINATION_PENDING,
        reason_codes=(),
        progress_revision=1,
        progress_ref="prog://1",
        progress_digest="sha256:d",
    )
    assert report.execution_id == "exec-1"
    assert report.progress_revision == 1


def test_finalization_persistence_outcomes_and_digests():
    factory = InvocationFinalizationFactoryV2()
    finalization = factory.create(
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        transaction_status=ExecutionStatusV2.UNAVAILABLE,
        cleanup=CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED),
        transaction_reason_codes=(),
        finalized_at=123.0,
    )
    fin_digest = canonical_invocation_finalization_digest(finalization)
    fin_ref = InvocationFinalizationRefV2(
        reference="finalization://1",
        revision=1,
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        finalization_digest=fin_digest,
    )

    persisted = FinalizationPersistedV2(finalization_ref=fin_ref)
    p_digest = canonical_finalization_persistence_outcome_digest(persisted)
    assert p_digest.startswith("sha256:")

    retry_ref = InvocationFinalizationRetryRefV2(
        reference="retry://1",
        revision=1,
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        finalization_digest=fin_digest,
    )
    enqueued = FinalizationRetryEnqueuedV2(retry_ref=retry_ref)
    e_digest = canonical_finalization_persistence_outcome_digest(enqueued)
    assert e_digest.startswith("sha256:")


def test_finalization_retry_claim_record_completion_digests():
    retry_ref = InvocationFinalizationRetryRefV2(
        reference="retry://1",
        revision=1,
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        finalization_digest="sha256:d",
    )
    claim = FinalizationRetryClaimV2(
        retry_ref=retry_ref,
        expected_revision=1,
        claim_id="claim-1",
        fencing_token=10,
        claim_expires_at_utc=2000.0,
        claimer_instance_id="inst-1",
        claimer_boot_id="boot-1",
    )
    c_digest = canonical_finalization_retry_claim_digest(claim)
    assert c_digest.startswith("sha256:")

    fin_ref = InvocationFinalizationRefV2(
        reference="finalization://1",
        revision=1,
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        finalization_digest="sha256:d",
    )
    receipt = FinalizationRetryCompletionReceiptV2(
        retry_ref=retry_ref,
        persisted_finalization_ref=fin_ref,
        superseding_report_ref="rep://1",
        superseding_report_digest="sha256:rep",
        completion_digest="sha256:c",
    )
    rc_digest = canonical_finalization_retry_completion_digest(receipt)
    assert rc_digest.startswith("sha256:")


def test_committed_execution_result_binding_and_envelope():
    factory = InvocationFinalizationFactoryV2()
    finalization = factory.create(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        transaction_status=ExecutionStatusV2.SUCCEEDED,
        cleanup=CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED),
        transaction_reason_codes=(),
        finalized_at=123.0,
    )
    fin_digest = canonical_invocation_finalization_digest(finalization)
    fin_ref = InvocationFinalizationRefV2(
        reference="finalization://1",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        finalization_digest=fin_digest,
    )

    res = ExecutionResultV2(
        schema_version="2.0",
        execution_id="exec-1",
        action_id="act-1",
        status=ExecutionStatusV2.SUCCEEDED,
        reason_codes=(),
        artifact_refs=(),
        credential_refs=(),
        session_refs=(),
        route_refs=(),
        c2_refs=(),
        fact_refs=(),
        audit_ref="audit://1",
        decision_trace_ref="trace://1",
        linked_result_refs=(),
        provenance_chain=("p1",),
    )
    r_digest = canonical_execution_result_digest(res)

    res_ref = ExecutionResultRefV2(
        reference="result://1",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        result_digest=r_digest,
    )

    binding = CommittedExecutionResultBindingV2._from_committed_marker(
        token=_CommittedBindingConstructionTokenV2(),
        transaction_id="tx-1",
        coordinator_revision=1,
        execution_result_ref=res_ref,
        canonical_result_digest=r_digest,
        committed_marker_ref="marker://1",
        committed_marker_digest="sha256:mark",
    )
    assert binding.transaction_id == "tx-1"

    report = ActionExecutionReportV2(
        schema_version="2.0",
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        execution_result=res,
        execution_result_ref=res_ref,
        committed_result_binding=binding,
        finalization=finalization,
        finalization_ref=fin_ref,
        finalization_retry_ref=None,
        finalization_persistence_pending=False,
    )
    envelope = ActionExecutionReportEnvelopeV2(
        report=report,
        report_revision=1,
        report_ref="rep://1",
        report_digest="sha256:d",
    )
    assert envelope.report_ref == "rep://1"

    # require_successful_committed_result_ref
    assert report.require_successful_committed_result_ref() == res_ref

    # FinalizationRetryReconcilerV2 raises NotImplementedError
    from core.actions.execution_results_v2 import FinalizationRetryReconcilerV2

    reconciler = FinalizationRetryReconcilerV2()
    with pytest.raises(NotImplementedError, match="reconcile_once"):
        reconciler.reconcile_once(MagicMock())
