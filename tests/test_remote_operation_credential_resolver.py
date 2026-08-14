from __future__ import annotations

import pytest

from core.execution.remote_operation_models import (
    RemoteOperationOutputReservationRefV1,
    RemoteOperationPlanV1,
    RemoteOperationServiceV1,
)
from core.execution.remote_operation_participant import (
    CheckoutRecoveryRefV2,
    DefaultRemoteOperationCredentialLeaseV1,
    DefaultRemoteOperationCredentialResolverV1,
    ExecutionFinalizationFenceV2,
    ParticipantOperationContextV2,
)

pytestmark = pytest.mark.unit


def _make_plan(target: str = "192.168.1.100", credential_ref: str = "cred-domain-admin") -> RemoteOperationPlanV1:
    res_ref = RemoteOperationOutputReservationRefV1(
        reference="res-1",
        transaction_id="tx-200",
        operation_id="op-1",
        output_schema_id="host_info",
        reservation_revision=1,
        reservation_digest="digest-res",
    )
    return RemoteOperationPlanV1(
        transaction_id="tx-200",
        action_id="act-1",
        target=target,
        service=RemoteOperationServiceV1.SMBEXEC,
        operation_id="op-1",
        operation_payload_schema_id="schema-1",
        operation_payload_ref="ref-1",
        output_reservation_ref=res_ref,
        credential_ref=credential_ref,
        credential_revision=2,
        attempt_id="att-1",
        idempotency_key="idem-key-1",
        plan_digest="plan-digest-12345",
    )


def test_credential_resolver_acquire_success() -> None:
    resolver = DefaultRemoteOperationCredentialResolverV1()
    plan = _make_plan()
    checkout_ref = CheckoutRecoveryRefV2(
        checkout_id="chk-1",
        fence_generation=1,
        journal_ref="j-1",
        journal_digest="j-digest",
    )
    ctx = ParticipantOperationContextV2(operation_attempt_id="att-1")
    fence = ExecutionFinalizationFenceV2(
        intent_ref=None,  # type: ignore
        coordinator_recovery_ref=None,  # type: ignore
        operation=None,  # type: ignore
        fence_digest="fence-digest-1",
    )

    lease = resolver.acquire(
        plan=plan,
        checkout_recovery_ref=checkout_ref,
        mission_id="mission-alpha",
        subject_id="subject-beta",
        target="192.168.1.100",
        operation=ctx,
        fence=fence,
    )

    assert isinstance(lease, DefaultRemoteOperationCredentialLeaseV1)
    assert lease.is_closed is False
    assert "cred-domain-admin" in lease.lease_id
    assert "2" in lease.lease_id
    assert "mission-alpha" in lease.lease_id
    assert "subject-beta" in lease.lease_id


def test_credential_lease_transfer_and_zeroize() -> None:
    lease = DefaultRemoteOperationCredentialLeaseV1(_lease_id="lease-test-123")
    assert lease.is_closed is False

    channel_token = lease.transfer_to_protected_worker_channel(backend_request_digest="digest-backend-req-456")
    assert channel_token == "protected-channel-lease-test-123-digest-backend-req-456"

    lease.close_and_zeroize()
    assert lease.is_closed is True

    with pytest.raises(RuntimeError, match="Lease is closed"):
        lease.transfer_to_protected_worker_channel(backend_request_digest="digest-backend-req-456")


def test_credential_resolver_empty_credential_ref() -> None:
    resolver = DefaultRemoteOperationCredentialResolverV1()
    plan = _make_plan(credential_ref="")
    checkout_ref = CheckoutRecoveryRefV2("chk-1", 1, "j-1", "j-digest")
    ctx = ParticipantOperationContextV2()
    fence = ExecutionFinalizationFenceV2(None, None, None, "fence-1")  # type: ignore

    with pytest.raises(ValueError, match="credential reference cannot be empty"):
        resolver.acquire(
            plan=plan,
            checkout_recovery_ref=checkout_ref,
            mission_id="m1",
            subject_id="s1",
            target="192.168.1.100",
            operation=ctx,
            fence=fence,
        )


def test_credential_resolver_target_mismatch() -> None:
    resolver = DefaultRemoteOperationCredentialResolverV1()
    plan = _make_plan(target="192.168.1.100")
    checkout_ref = CheckoutRecoveryRefV2("chk-1", 1, "j-1", "j-digest")
    ctx = ParticipantOperationContextV2()
    fence = ExecutionFinalizationFenceV2(None, None, None, "fence-1")  # type: ignore

    with pytest.raises(ValueError, match="Target mismatch"):
        resolver.acquire(
            plan=plan,
            checkout_recovery_ref=checkout_ref,
            mission_id="m1",
            subject_id="s1",
            target="10.0.0.1",
            operation=ctx,
            fence=fence,
        )
