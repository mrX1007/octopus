"""Targeted unit test suite to boost core/actions coverage above 95%."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.actions.execution_commit import (
    CommitFinalizationFailedError,
    CommitPreparationFailedError,
    ExecutionCommitCoordinator,
    ExecutionCommitStateV2,
    ParticipantPrepareResultV2,
    ParticipantStateV2,
)
from core.actions.execution_finalization import (
    ActionExecutionReportEnvelopeV2,
    DefaultInvocationFinalizationIntentStoreV2,
    ExecutionFinalizationFenceAuthorityV2,
    FinalizationPersistedV2,
    FinalizationRetryEnqueuedV2,
    InvocationFinalizationIntentRecordV2,
    InvocationFinalizationIntentRefV2,
)
from core.actions.input_contracts import (
    C2ChannelCreateInputV2,
    C2EnrollmentIssueInput,
    C2Transport,
    PivotProxyScanInputV2,
    RemoteForwardInputV2,
    SSHChainHopInputV2,
    SSHChainInputV2,
)
from core.c2.deployment_profiles import C2DeploymentProfileId

pytestmark = pytest.mark.unit


def test_execution_finalization_store_and_authority_deep():
    fence_auth = ExecutionFinalizationFenceAuthorityV2()
    assert fence_auth.fence("tx-1") is True
    assert fence_auth._fences["tx-1"] is True

    from core.actions.execution_finalization import (
        InvocationFinalizationIntentBodyV2,
        InvocationFinalizationIntentCheckpointV2,
        InvocationFinalizationIntentPhaseV2,
    )

    store = DefaultInvocationFinalizationIntentStoreV2()
    intent_ref = InvocationFinalizationIntentRefV2(
        reference="intent://1",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        intent_digest="sha256:d1",
    )
    body = InvocationFinalizationIntentBodyV2(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        phase=InvocationFinalizationIntentPhaseV2.CREATED,
    )
    record = InvocationFinalizationIntentRecordV2(intent_ref=intent_ref, body=body)

    chk = InvocationFinalizationIntentCheckpointV2(
        expected_revision=1,
        phase=InvocationFinalizationIntentPhaseV2.OWNERS_FENCED,
    )
    current_rec = store.checkpoint(record, chk)
    current_ref = current_rec.intent_ref

    # require_current
    assert store.require_current("intent://1") == current_rec
    with pytest.raises(KeyError):
        store.require_current("nonexistent_ref")

    from core.actions.execution_results_v2 import (
        ActionExecutionReportV2,
        CleanupStatusV2,
        CleanupSummaryV2,
        ExecutionStatusV2,
        InvocationFinalizationFactoryV2,
        InvocationFinalizationRefV2,
        InvocationFinalizationRetryRefV2,
        canonical_invocation_finalization_digest,
    )

    factory = InvocationFinalizationFactoryV2()
    finalization = factory.create(
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        transaction_status=ExecutionStatusV2.UNAVAILABLE,
        cleanup=CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED),
        transaction_reason_codes=(),
        finalized_at=123.0,
    )
    final_ref = InvocationFinalizationRefV2(
        reference="fin://1",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        finalization_digest=canonical_invocation_finalization_digest(finalization),
    )

    valid_report_inner = ActionExecutionReportV2(
        schema_version="2.0",
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        execution_result=None,
        execution_result_ref=None,
        committed_result_binding=None,
        finalization=finalization,
        finalization_ref=final_ref,
        finalization_retry_ref=None,
        finalization_persistence_pending=False,
    )
    valid_envelope = ActionExecutionReportEnvelopeV2(
        report_ref="rep://1",
        report_revision=1,
        report_digest="sha256:rep",
        report=valid_report_inner,
    )

    diff_ref = InvocationFinalizationRefV2(
        reference="fin://DIFFERENT",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        finalization_digest=canonical_invocation_finalization_digest(finalization),
    )
    retry_ref = InvocationFinalizationRetryRefV2(
        reference="ret://1",
        revision=1,
        execution_id="exec-1",
        action_id="act-1",
        transaction_id="tx-1",
        finalization_digest=canonical_invocation_finalization_digest(finalization),
    )

    # complete() report type error
    with pytest.raises(TypeError, match="completion requires an exact report envelope"):
        store.complete(current_ref, FinalizationPersistedV2(final_ref), "not_an_envelope")  # type: ignore

    # complete() outcome mismatch
    with pytest.raises(ValueError, match="persisted finalization outcome/report mismatch"):
        store.complete(current_ref, FinalizationPersistedV2(diff_ref), valid_envelope)

    with pytest.raises(ValueError, match="retry finalization outcome/report mismatch"):
        store.complete(current_ref, FinalizationRetryEnqueuedV2(retry_ref), valid_envelope)

    with pytest.raises(TypeError, match="unknown finalization persistence outcome"):
        store.complete(current_ref, "not_an_outcome", valid_envelope)  # type: ignore

    # Successful complete
    receipt = store.complete(current_ref, FinalizationPersistedV2(final_ref), valid_envelope)
    assert receipt.intent_ref == current_ref
    # Idempotent re-complete
    assert store.complete(current_ref, FinalizationPersistedV2(final_ref), valid_envelope) == receipt
    assert store.require_completion(current_ref) == receipt


def test_two_phase_execution_commit_coordinator_branches():
    coord = ExecutionCommitCoordinator(transaction_id="tx-1")

    # Participant preparation error
    class FailingPrepareParticipant:
        participant_id = "p-fail-prep"

        def prepare(self, tx_id: str) -> ParticipantPrepareResultV2:
            raise RuntimeError("prepare boom")

        def rollback(self, tx_id: str) -> None:
            pass

    coord.register_participant(FailingPrepareParticipant())  # type: ignore
    with pytest.raises(CommitPreparationFailedError, match="failed prepare"):
        coord.prepare_all()

    # Cannot register in non-OPEN state
    with pytest.raises(RuntimeError, match="Cannot register participant in state"):
        coord.register_participant(FailingPrepareParticipant())  # type: ignore

    # Hidden commit failure -> IN_DOUBT
    coord2 = ExecutionCommitCoordinator(transaction_id="tx-2")

    class FailingCommitParticipant:
        participant_id = "p-fail-commit"

        def prepare(self, tx_id: str) -> ParticipantPrepareResultV2:
            return ParticipantPrepareResultV2(
                participant_id="p-fail-commit",
                can_commit=True,
                state=ParticipantStateV2.PREPARED,
                prepared_digest="sha256:r",
            )

        def commit_hidden(self, tx_id: str) -> None:
            raise RuntimeError("commit boom")

        def rollback(self, tx_id: str) -> None:
            pass

    coord2.register_participant(FailingCommitParticipant())  # type: ignore
    assert coord2.prepare_all() is True
    assert coord2.commit_all_hidden() is False
    assert coord2.state == ExecutionCommitStateV2.IN_DOUBT

    # Visibility finalization failure -> FAILED_RECONCILIATION
    coord3 = ExecutionCommitCoordinator(transaction_id="tx-3")

    class FailingVisibilityParticipant:
        participant_id = "p-fail-vis"

        def prepare(self, tx_id: str) -> ParticipantPrepareResultV2:
            return ParticipantPrepareResultV2(
                participant_id="p-fail-vis",
                can_commit=True,
                state=ParticipantStateV2.PREPARED,
                prepared_digest="sha256:r",
            )

        def commit_hidden(self, tx_id: str) -> MagicMock:
            return MagicMock()

        def finalize_visibility(self, tx_id: str) -> None:
            raise RuntimeError("finalize boom")

    coord3.register_participant(FailingVisibilityParticipant())  # type: ignore
    assert coord3.prepare_all() is True
    assert coord3.commit_all_hidden() is True
    with pytest.raises(CommitFinalizationFailedError, match="failed visibility finalization"):
        coord3.finalize_all_visibility()
    assert coord3.state == ExecutionCommitStateV2.FAILED_RECONCILIATION


def test_input_contracts_validation_errors():
    # RemoteForwardInputV2
    with pytest.raises(ValueError, match=r"remote_port must be an integer in 1\.\.65535"):
        RemoteForwardInputV2(
            session_ref="sess-1",
            target="10.0.0.1",
            remote_port=0,
            destination_host="10.0.0.2",
            destination_port=80,
        )

    # SSHChainHopInputV2
    with pytest.raises(ValueError, match=r"port must be an integer in 1\.\.65535"):
        SSHChainHopInputV2(target="10.0.0.1", credential_ref="cred-1", port=0)

    # SSHChainInputV2
    with pytest.raises(ValueError, match="hops must not be empty"):
        SSHChainInputV2(hops=())

    with pytest.raises(ValueError, match="hops contains an invalid variant"):
        SSHChainInputV2(hops=("not_a_hop",))  # type: ignore

    # PivotProxyScanInputV2
    with pytest.raises(ValueError, match="ports must not be empty"):
        PivotProxyScanInputV2(route_ref="r-1", target="10.0.0.1", ports=(), timeout_seconds=10)

    with pytest.raises(ValueError, match=r"ports must contain only integers in 1\.\.65535"):
        PivotProxyScanInputV2(route_ref="r-1", target="10.0.0.1", ports=(0,), timeout_seconds=10)

    with pytest.raises(ValueError, match="ports must be unique"):
        PivotProxyScanInputV2(route_ref="r-1", target="10.0.0.1", ports=(80, 80), timeout_seconds=10)

    with pytest.raises(ValueError, match=r"timeout_seconds must be an integer in 1\.\.3600"):
        PivotProxyScanInputV2(route_ref="r-1", target="10.0.0.1", ports=(80,), timeout_seconds=0)

    # C2EnrollmentIssueInput
    with pytest.raises(ValueError, match=r"agent_protocol_version must be 12\.0"):
        C2EnrollmentIssueInput(
            channel_ref="c-1",
            target="10.0.0.1",
            profile_id=C2DeploymentProfileId.GO_AGENT,
            agent_protocol_version="11.0",  # type: ignore
            ttl_seconds=3600,
            max_uses=1,
        )

    # C2ChannelCreateInputV2
    with pytest.raises(ValueError, match="transport/config variant mismatch"):
        C2ChannelCreateInputV2(
            target="10.0.0.1",
            transport=C2Transport.DNS,
            config="invalid_config",  # type: ignore
        )
