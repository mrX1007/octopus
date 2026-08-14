"""Tests for ExecutionResultV2 and ActionExecutionReportV2 foundation types."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.actions.execution_results_v2 import (
    ActionExecutionReportV2,
    CleanupStatusV2,
    CleanupSummaryV2,
    ExecutionResultV2,
    ExecutionStatusV2,
    InvocationFinalizationFactoryV2,
    InvocationFinalizationRefV2,
    InvocationFinalizationRetryRefV2,
    canonical_invocation_finalization_digest,
)

pytestmark = pytest.mark.unit


def test_execution_result_v2_foundation_exact_fields() -> None:
    assert tuple(field.name for field in fields(ExecutionResultV2)) == (
        "schema_version",
        "execution_id",
        "action_id",
        "status",
        "reason_codes",
        "artifact_refs",
        "credential_refs",
        "session_refs",
        "route_refs",
        "c2_refs",
        "fact_refs",
        "audit_ref",
        "decision_trace_ref",
        "linked_result_refs",
        "provenance_chain",
    )


def test_action_execution_report_v2_foundation_exact_fields() -> None:
    assert tuple(field.name for field in fields(ActionExecutionReportV2)) == (
        "schema_version",
        "execution_id",
        "action_id",
        "transaction_id",
        "execution_result",
        "execution_result_ref",
        "committed_result_binding",
        "finalization",
        "finalization_ref",
        "finalization_retry_ref",
        "finalization_persistence_pending",
    )


def test_action_execution_report_v2_has_finalization_persistence_pending() -> None:
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
    report_pending = ActionExecutionReportV2(
        schema_version="2.0",
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        execution_result=None,
        execution_result_ref=None,
        committed_result_binding=None,
        finalization=finalization,
        finalization_ref=None,
        finalization_retry_ref=InvocationFinalizationRetryRefV2(
            reference="retry://1",
            revision=1,
            execution_id="exec-1",
            action_id="plugin:payload_keying",
            transaction_id="tx-1",
            finalization_digest=canonical_invocation_finalization_digest(finalization),
        ),
        finalization_persistence_pending=True,
    )
    assert report_pending.finalization_persistence_pending is True


def test_finalization_pending_requires_none_ref_and_durable_retry() -> None:
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
    ref = InvocationFinalizationRefV2(
        reference="result://1",
        revision=1,
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        finalization_digest=canonical_invocation_finalization_digest(finalization),
    )
    with pytest.raises(ValueError, match="finalization_pending_xor"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="plugin:payload_keying",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=finalization,
            finalization_ref=ref,
            finalization_retry_ref=None,
            finalization_persistence_pending=True,
        )

    with pytest.raises(ValueError, match="finalization_pending_xor"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="plugin:payload_keying",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=finalization,
            finalization_ref=None,
            finalization_retry_ref=None,
            finalization_persistence_pending=True,
        )


def test_finalization_not_pending_requires_durable_ref() -> None:
    finalization = InvocationFinalizationFactoryV2().create(
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        transaction_status=ExecutionStatusV2.UNAVAILABLE,
        cleanup=CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED),
        transaction_reason_codes=(),
        finalized_at=123.0,
    )
    retry_ref = InvocationFinalizationRetryRefV2(
        reference="retry://1",
        revision=1,
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        finalization_digest=canonical_invocation_finalization_digest(finalization),
    )

    with pytest.raises(ValueError, match="finalization_persisted_xor"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="plugin:payload_keying",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=finalization,
            finalization_ref=None,
            finalization_retry_ref=None,
            finalization_persistence_pending=False,
        )

    with pytest.raises(ValueError, match="finalization_persisted_xor"):
        ActionExecutionReportV2(
            schema_version="2.0",
            execution_id="exec-1",
            action_id="plugin:payload_keying",
            transaction_id="tx-1",
            execution_result=None,
            execution_result_ref=None,
            committed_result_binding=None,
            finalization=finalization,
            finalization_ref=None,
            finalization_retry_ref=retry_ref,
            finalization_persistence_pending=False,
        )
