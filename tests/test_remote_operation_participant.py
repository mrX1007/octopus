from __future__ import annotations

import pytest

from core.execution.remote_operation_models import (
    HostRemoteOperationOutputV1,
    RemoteOperationBackendRequestV1,
    RemoteOperationEffectDispositionV1,
    RemoteOperationEffectProbeV1,
    RemoteOperationEffectReceiptV1,
    RemoteOperationOutputReservationRefV1,
    RemoteOperationPlanV1,
    RemoteOperationServiceV1,
)
from core.execution.remote_operation_participant import (
    ExecutionFinalizationFenceV2,
    ParticipantCommitReceiptV2,
    ParticipantCommitRequestV2,
    ParticipantOperationContextV2,
    ParticipantPrepareReceiptV2,
    ParticipantPrepareRequestV2,
    RemoteOperationExternalEffectParticipant,
)

pytestmark = pytest.mark.unit


class MockRemoteOperationBackend:
    def __init__(self, fail_dispatch: bool = False, fail_probe: bool = False, unknown_disposition: bool = False):
        self.fail_dispatch = fail_dispatch
        self.fail_probe = fail_probe
        self.unknown_disposition = unknown_disposition
        self.dispatched_requests: list[RemoteOperationBackendRequestV1] = []
        self.probed_requests: list[RemoteOperationBackendRequestV1] = []

    def dispatch(self, request: RemoteOperationBackendRequestV1) -> RemoteOperationEffectReceiptV1:
        self.dispatched_requests.append(request)
        if self.fail_dispatch:
            raise RuntimeError("Backend connection timed out")
        return RemoteOperationEffectReceiptV1(
            transaction_id="tx-100",
            participant_id="part-100",
            attempt_id=request.attempt_id,
            plan_digest=request.plan_digest,
            disposition=RemoteOperationEffectDispositionV1.CONFIRMED,
            backend_receipt_ref="receipt-001",
            output=HostRemoteOperationOutputV1(
                hostname="server01",
                os_name="Linux",
                os_version="5.15",
                architecture="x86_64",
            ),
            output_digest="out-digest-123",
            probe_token="probe-token-abc",
            attempt_revision=1,
            receipt_digest="receipt-digest-xyz",
        )

    def probe(self, request: RemoteOperationBackendRequestV1) -> RemoteOperationEffectProbeV1:
        self.probed_requests.append(request)
        if self.fail_probe:
            raise RuntimeError("Probe network error")
        disposition = (
            RemoteOperationEffectDispositionV1.UNKNOWN
            if self.unknown_disposition
            else RemoteOperationEffectDispositionV1.CONFIRMED
        )
        return RemoteOperationEffectProbeV1(
            transaction_id="tx-100",
            participant_id="part-100",
            attempt_id=request.attempt_id,
            disposition=disposition,
            backend_receipt_ref="receipt-001",
            output=None,
            output_digest=None,
            attempt_revision=1,
            probe_digest="probe-digest-123",
        )


def _make_sample_plan() -> RemoteOperationPlanV1:
    res_ref = RemoteOperationOutputReservationRefV1(
        reference="res-1",
        transaction_id="tx-100",
        operation_id="op-1",
        output_schema_id="host_info",
        reservation_revision=1,
        reservation_digest="res-digest",
    )
    return RemoteOperationPlanV1(
        transaction_id="tx-100",
        action_id="act-1",
        target="192.168.1.10",
        service=RemoteOperationServiceV1.WINRM,
        operation_id="op-1",
        operation_payload_schema_id="schema-1",
        operation_payload_ref="ref-1",
        output_reservation_ref=res_ref,
        credential_ref="cred-100",
        credential_revision=1,
        attempt_id="att-1",
        idempotency_key="idem-key-1",
        plan_digest="plan-digest-abc12345",
    )


def test_participant_prepare_outcomes() -> None:
    plan = _make_sample_plan()
    backend = MockRemoteOperationBackend()
    participant = RemoteOperationExternalEffectParticipant(
        participant_id="part-100",
        transaction_id="tx-100",
        backend=backend,
        plan=plan,
    )
    ctx = ParticipantOperationContextV2(operation_attempt_id="att-1")

    # Success prepare
    prep_req = ParticipantPrepareRequestV2(
        transaction_id="tx-100",
        participant_id="part-100",
        operation=ctx,
    )
    outcome = participant.prepare(prep_req)
    assert outcome.is_ready is True
    assert outcome.prepare_receipt is not None
    assert outcome.prepare_receipt.plan_digest == plan.plan_digest
    assert outcome.error is None

    # Mismatched transaction
    bad_tx_req = ParticipantPrepareRequestV2(
        transaction_id="tx-999",
        participant_id="part-100",
        operation=ctx,
    )
    bad_tx_outcome = participant.prepare(bad_tx_req)
    assert bad_tx_outcome.is_ready is False
    assert "Transaction ID mismatch" in bad_tx_outcome.error

    # Mismatched participant
    bad_part_req = ParticipantPrepareRequestV2(
        transaction_id="tx-100",
        participant_id="part-999",
        operation=ctx,
    )
    bad_part_outcome = participant.prepare(bad_part_req)
    assert bad_part_outcome.is_ready is False
    assert "Participant ID mismatch" in bad_part_outcome.error


def test_participant_commit_success() -> None:
    plan = _make_sample_plan()
    backend = MockRemoteOperationBackend()
    participant = RemoteOperationExternalEffectParticipant(
        participant_id="part-100",
        transaction_id="tx-100",
        backend=backend,
        plan=plan,
    )
    ctx = ParticipantOperationContextV2(operation_attempt_id="att-1")
    prep_receipt = ParticipantPrepareReceiptV2(
        participant_id="part-100",
        plan_digest=plan.plan_digest,
    )
    commit_req = ParticipantCommitRequestV2(
        transaction_id="tx-100",
        participant_id="part-100",
        prepare_receipt=prep_receipt,
        operation=ctx,
    )

    commit_receipt = participant.commit(commit_req)
    assert commit_receipt.success is True
    assert commit_receipt.error is None
    assert commit_receipt.effect_receipt is not None
    assert commit_receipt.effect_receipt.disposition == RemoteOperationEffectDispositionV1.CONFIRMED
    assert len(backend.dispatched_requests) == 1


def test_participant_commit_failures() -> None:
    plan = _make_sample_plan()
    backend = MockRemoteOperationBackend(fail_dispatch=True)
    participant = RemoteOperationExternalEffectParticipant(
        participant_id="part-100",
        transaction_id="tx-100",
        backend=backend,
        plan=plan,
    )
    ctx = ParticipantOperationContextV2(operation_attempt_id="att-1")

    # Mismatched digest
    bad_digest_receipt = ParticipantPrepareReceiptV2(
        participant_id="part-100",
        plan_digest="wrong-digest",
    )
    bad_commit_req = ParticipantCommitRequestV2(
        transaction_id="tx-100",
        participant_id="part-100",
        prepare_receipt=bad_digest_receipt,
        operation=ctx,
    )
    res_bad_digest = participant.commit(bad_commit_req)
    assert res_bad_digest.success is False
    assert "digest mismatch" in res_bad_digest.error.lower()

    # Backend exception
    valid_receipt = ParticipantPrepareReceiptV2(
        participant_id="part-100",
        plan_digest=plan.plan_digest,
    )
    commit_req = ParticipantCommitRequestV2(
        transaction_id="tx-100",
        participant_id="part-100",
        prepare_receipt=valid_receipt,
        operation=ctx,
    )
    res_backend_err = participant.commit(commit_req)
    assert res_backend_err.success is False
    assert "Backend connection timed out" in res_backend_err.error


def test_participant_reconcile() -> None:
    plan = _make_sample_plan()

    # Confirmed probe
    backend_ok = MockRemoteOperationBackend()
    participant_ok = RemoteOperationExternalEffectParticipant(
        participant_id="part-100",
        transaction_id="tx-100",
        backend=backend_ok,
        plan=plan,
    )
    ctx = ParticipantOperationContextV2(operation_attempt_id="att-1")
    fence = ExecutionFinalizationFenceV2(
        intent_ref=None,  # type: ignore
        coordinator_recovery_ref=None,  # type: ignore
        operation=None,  # type: ignore
        fence_digest="fence-1",
    )

    rec_ok = participant_ok.reconcile(ctx, fence)
    assert rec_ok.reconciled is True

    # Unknown probe disposition
    backend_unk = MockRemoteOperationBackend(unknown_disposition=True)
    participant_unk = RemoteOperationExternalEffectParticipant(
        participant_id="part-100",
        transaction_id="tx-100",
        backend=backend_unk,
        plan=plan,
    )
    rec_unk = participant_unk.reconcile(ctx, fence)
    assert rec_unk.reconciled is False

    # Probe exception
    backend_fail = MockRemoteOperationBackend(fail_probe=True)
    participant_fail = RemoteOperationExternalEffectParticipant(
        participant_id="part-100",
        transaction_id="tx-100",
        backend=backend_fail,
        plan=plan,
    )
    rec_fail = participant_fail.reconcile(ctx, fence)
    assert rec_fail.reconciled is False


def test_participant_finalize_and_rollback() -> None:
    plan = _make_sample_plan()
    backend = MockRemoteOperationBackend()
    participant = RemoteOperationExternalEffectParticipant(
        participant_id="part-100",
        transaction_id="tx-100",
        backend=backend,
        plan=plan,
    )
    ctx = ParticipantOperationContextV2(operation_attempt_id="att-1")
    fence = ExecutionFinalizationFenceV2(
        intent_ref=None,  # type: ignore
        coordinator_recovery_ref=None,  # type: ignore
        operation=None,  # type: ignore
        fence_digest="fence-1",
    )
    prep_receipt = ParticipantPrepareReceiptV2(
        participant_id="part-100",
        plan_digest=plan.plan_digest,
    )
    commit_receipt = ParticipantCommitReceiptV2(
        participant_id="part-100",
        success=True,
    )

    finalize_res = participant.finalize_visibility(prep_receipt, commit_receipt, ctx, fence)
    assert finalize_res.finalized is True

    rollback_res = participant.rollback(prep_receipt, ctx)
    assert rollback_res.rolled_back is True
