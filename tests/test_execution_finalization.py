"""Unit tests for core/actions/execution_finalization.py."""

from __future__ import annotations

import pytest

from core.actions.execution_finalization import (
    ActionExecutionReportEnvelopeV2,
    DefaultInvocationFinalizationIntentStoreV2,
    FinalizationPersistedV2,
    InvocationFinalizationIntentBodyV2,
    InvocationFinalizationIntentCheckpointV2,
    InvocationFinalizationIntentPhaseV2,
    InvocationFinalizationIntentRecordV2,
    InvocationFinalizationIntentRefV2,
    InvocationFinalizationIntentStoreV2,
)
from core.actions.execution_results_v2 import (
    ActionExecutionReportV2,
    CleanupStatusV2,
    CleanupSummaryV2,
    ExecutionStatusV2,
    InvocationFinalizationFactoryV2,
    InvocationFinalizationRefV2,
    canonical_invocation_finalization_digest,
)

pytestmark = pytest.mark.unit


def _make_initial_intent(
    ref_name: str = "intent_ref_001",
    exec_id: str = "exec_001",
    action_id: str = "act_001",
    tx_id: str = "tx_001",
) -> InvocationFinalizationIntentRecordV2:
    intent_ref = InvocationFinalizationIntentRefV2(
        reference=ref_name,
        revision=1,
        execution_id=exec_id,
        action_id=action_id,
        transaction_id=tx_id,
        intent_digest="sha256:initial_digest",
    )
    body = InvocationFinalizationIntentBodyV2(
        execution_id=exec_id,
        action_id=action_id,
        transaction_id=tx_id,
        phase=InvocationFinalizationIntentPhaseV2.CREATED,
    )
    return InvocationFinalizationIntentRecordV2(intent_ref=intent_ref, body=body)


def _make_persisted_report(
    *,
    execution_id: str,
    action_id: str,
    transaction_id: str,
    finalization_ref: str,
    report_ref: str,
) -> tuple[FinalizationPersistedV2, ActionExecutionReportEnvelopeV2]:
    finalization = InvocationFinalizationFactoryV2().create(
        execution_id=execution_id,
        action_id=action_id,
        transaction_id=transaction_id,
        transaction_status=ExecutionStatusV2.UNAVAILABLE,
        cleanup=CleanupSummaryV2(CleanupStatusV2.NOT_REQUIRED),
        transaction_reason_codes=("provider_unavailable",),
        finalized_at=123.0,
    )
    durable_ref = InvocationFinalizationRefV2(
        reference=finalization_ref,
        revision=1,
        execution_id=execution_id,
        action_id=action_id,
        transaction_id=transaction_id,
        finalization_digest=canonical_invocation_finalization_digest(finalization),
    )
    terminal = ActionExecutionReportV2(
        schema_version="2.0",
        execution_id=execution_id,
        action_id=action_id,
        transaction_id=transaction_id,
        execution_result=None,
        execution_result_ref=None,
        committed_result_binding=None,
        finalization=finalization,
        finalization_ref=durable_ref,
        finalization_retry_ref=None,
        finalization_persistence_pending=False,
    )
    return (
        FinalizationPersistedV2(durable_ref),
        ActionExecutionReportEnvelopeV2(
            report=terminal,
            report_revision=1,
            report_ref=report_ref,
            report_digest="sha256:report",
        ),
    )


def test_checkpoint_and_require_current() -> None:
    store = DefaultInvocationFinalizationIntentStoreV2()
    assert isinstance(store, InvocationFinalizationIntentStoreV2)

    initial_record = _make_initial_intent()

    checkpoint_update = InvocationFinalizationIntentCheckpointV2(
        expected_revision=1,
        phase=InvocationFinalizationIntentPhaseV2.OWNERS_FENCED,
    )

    updated_record = store.checkpoint(initial_record, checkpoint_update)

    assert updated_record.intent_ref.reference == "intent_ref_001"
    assert updated_record.intent_ref.revision == 2
    assert updated_record.body.phase == InvocationFinalizationIntentPhaseV2.OWNERS_FENCED
    assert updated_record.intent_ref.intent_digest.startswith("sha256:")

    current = store.require_current("intent_ref_001")
    assert current == updated_record

    required = store.require(updated_record.intent_ref)
    assert required == updated_record


def test_checkpoint_revision_mismatch() -> None:
    store = DefaultInvocationFinalizationIntentStoreV2()
    initial_record = _make_initial_intent()

    checkpoint_1 = InvocationFinalizationIntentCheckpointV2(
        expected_revision=1,
        phase=InvocationFinalizationIntentPhaseV2.OWNERS_FENCED,
    )
    store.checkpoint(initial_record, checkpoint_1)

    # Secondary checkpoint with wrong expected_revision
    checkpoint_wrong = InvocationFinalizationIntentCheckpointV2(
        expected_revision=1,  # Record is now at revision 2
        phase=InvocationFinalizationIntentPhaseV2.EFFECT_FENCED,
    )

    with pytest.raises(ValueError, match="Revision mismatch"):
        store.checkpoint(initial_record, checkpoint_wrong)


def test_complete_and_require_completion() -> None:
    store = DefaultInvocationFinalizationIntentStoreV2()
    initial_record = _make_initial_intent("intent_ref_002", "exec_002", "act_002", "tx_002")

    checkpoint_update = InvocationFinalizationIntentCheckpointV2(
        expected_revision=1,
        phase=InvocationFinalizationIntentPhaseV2.RESULT_COMMITTED,
    )
    updated_record = store.checkpoint(initial_record, checkpoint_update)

    outcome, report = _make_persisted_report(
        execution_id="exec_002",
        action_id="act_002",
        transaction_id="tx_002",
        finalization_ref="persisted_002",
        report_ref="report_002",
    )

    receipt = store.complete(updated_record.intent_ref, outcome, report)

    assert receipt.intent_ref == updated_record.intent_ref
    assert receipt.report_ref == "report_002"
    assert receipt.completion_digest.startswith("sha256:")

    retrieved = store.require_completion(updated_record.intent_ref)
    assert retrieved == receipt


def test_list_pending() -> None:
    store = DefaultInvocationFinalizationIntentStoreV2()

    rec1 = _make_initial_intent("intent_1", "e1", "a1", "t1")
    rec2 = _make_initial_intent("intent_2", "e2", "a2", "t2")

    chk1 = store.checkpoint(
        rec1,
        InvocationFinalizationIntentCheckpointV2(
            expected_revision=1, phase=InvocationFinalizationIntentPhaseV2.CREATED
        ),
    )
    store.checkpoint(
        rec2,
        InvocationFinalizationIntentCheckpointV2(
            expected_revision=1, phase=InvocationFinalizationIntentPhaseV2.CREATED
        ),
    )

    pending = store.list_pending()
    assert len(pending) == 2

    # Complete intent_1
    outcome, report = _make_persisted_report(
        execution_id="e1",
        action_id="a1",
        transaction_id="t1",
        finalization_ref="p1",
        report_ref="r1",
    )
    store.complete(chk1.intent_ref, outcome, report)

    pending_after = store.list_pending()
    assert len(pending_after) == 1
    assert pending_after[0].intent_ref.reference == "intent_2"


def test_require_unregistered_raises_key_error() -> None:
    store = DefaultInvocationFinalizationIntentStoreV2()

    missing_ref = InvocationFinalizationIntentRefV2(
        reference="intent_missing",
        revision=1,
        execution_id="e_missing",
        action_id="a_missing",
        transaction_id="t_missing",
        intent_digest="sha256:missing",
    )

    with pytest.raises(KeyError, match="No finalization intent record found"):
        store.require(missing_ref)

    with pytest.raises(KeyError, match="No finalization intent record found"):
        store.require_current("intent_missing")

    with pytest.raises(KeyError, match="No completion receipt found"):
        store.require_completion(missing_ref)
