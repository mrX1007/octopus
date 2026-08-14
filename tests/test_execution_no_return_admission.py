"""Unit tests for core/actions/execution_no_return_admission.py."""

from __future__ import annotations

import pytest

from core.actions.execution_no_return_admission import (
    DefaultExecutionNoReturnAdmissionStoreV2,
    ExecutionNoReturnAdmissionStoreV2,
)
from core.actions.execution_recovery_types import (
    CancellationRecoveryRecordV2,
    CancellationRecoveryRefV2,
    ExecutionNoReturnAdmissionBodyV2,
    ExecutionNoReturnAdmissionReceiptV2,
    ExecutionNoReturnAdmissionRefV2,
    canonical_execution_no_return_admission_digest,
)

pytestmark = pytest.mark.unit


def _make_cancellation_record(
    root_id: str = "root_exec_1",
    graph_id: str = "graph_1",
    revision: int = 1,
) -> CancellationRecoveryRecordV2:
    ref = CancellationRecoveryRefV2(
        reference="canc_ref_1",
        revision=revision,
        root_execution_id=root_id,
        execution_graph_id=graph_id,
        token_id="tok_1",
        state="cancelled",
        cancellation_digest="sha256:canc_digest",
    )
    return CancellationRecoveryRecordV2(
        cancellation_ref=ref,
        requested_reason_code="USER_CANCEL",
        requested_at_utc=1700000000.0,
    )


def test_admit_and_require_for_transaction() -> None:
    store = DefaultExecutionNoReturnAdmissionStoreV2()
    assert isinstance(store, ExecutionNoReturnAdmissionStoreV2)

    cancellation = _make_cancellation_record()

    assert store.require_for_transaction("tx_100") is None

    receipt = store.admit(
        cancellation=cancellation,
        transaction_id="tx_100",
        decision_identity_digest="sha256:dec_digest",
        external_effect_participant_id="part_1",
        external_effect_registration_digest="sha256:reg_digest",
    )

    assert isinstance(receipt, ExecutionNoReturnAdmissionReceiptV2)
    assert receipt.body.transaction_id == "tx_100"
    assert receipt.body.root_execution_id == "root_exec_1"
    assert receipt.body.decision_identity_digest == "sha256:dec_digest"

    receipt2 = store.require_for_transaction("tx_100")
    assert receipt2 == receipt

    # Test idempotency
    receipt3 = store.admit(
        cancellation=cancellation,
        transaction_id="tx_100",
        decision_identity_digest="sha256:dec_digest",
    )
    assert receipt3 == receipt


def test_require_existing_admission_ref() -> None:
    store = DefaultExecutionNoReturnAdmissionStoreV2()
    cancellation = _make_cancellation_record()

    receipt = store.admit(
        cancellation=cancellation,
        transaction_id="tx_200",
        decision_identity_digest="sha256:dec_digest_200",
    )

    retrieved = store.require(receipt.admission_ref)
    assert retrieved == receipt

    missing_ref = ExecutionNoReturnAdmissionRefV2(
        reference="adm:missing",
        revision=1,
        transaction_id="missing",
        admission_digest="sha256:fake",
    )
    with pytest.raises(KeyError, match="No admission receipt found"):
        store.require(missing_ref)


def test_require_mismatch_raises() -> None:
    store = DefaultExecutionNoReturnAdmissionStoreV2()
    cancellation = _make_cancellation_record()

    store.admit(
        cancellation=cancellation,
        transaction_id="tx_300",
        decision_identity_digest="sha256:dec_digest_300",
    )

    mismatched_ref = ExecutionNoReturnAdmissionRefV2(
        reference="adm:tx_300",
        revision=99,  # Mismatched revision
        transaction_id="tx_300",
        admission_digest="sha256:wrong_digest",
    )

    with pytest.raises(ValueError, match="Admission ref mismatch"):
        store.require(mismatched_ref)


def test_canonical_execution_no_return_admission_digest_validation() -> None:
    body = ExecutionNoReturnAdmissionBodyV2(
        root_execution_id="root_1",
        execution_graph_id="graph_1",
        transaction_id="tx_400",
        cancellation_revision=1,
        decision_identity_digest="sha256:dec_400",
        external_effect_participant_id=None,
        external_effect_registration_digest=None,
    )
    digest = canonical_execution_no_return_admission_digest(body)
    assert digest.startswith("sha256:")

    ref = ExecutionNoReturnAdmissionRefV2(
        reference="adm:tx_400",
        revision=1,
        transaction_id="tx_400",
        admission_digest=digest,
    )
    receipt = ExecutionNoReturnAdmissionReceiptV2(admission_ref=ref, body=body)
    assert receipt.admission_ref.admission_digest == digest

    # Transaction mismatch in post_init
    wrong_tx_ref = ExecutionNoReturnAdmissionRefV2(
        reference="adm:tx_wrong",
        revision=1,
        transaction_id="tx_wrong",
        admission_digest=digest,
    )
    with pytest.raises(ValueError, match="admission_transaction_mismatch"):
        ExecutionNoReturnAdmissionReceiptV2(admission_ref=wrong_tx_ref, body=body)
