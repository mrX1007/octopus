"""Unit tests for core/actions/provider_invocation.py."""

from __future__ import annotations

import pytest

from core.actions.provider_invocation import (
    BackendOwnedTransientReceiptV2,
    CleanupDescriptorKindV2,
    DefaultProviderInvocationScopeV2,
    PhaseBoundTransientRefV2,
    ProviderExecutePhaseLeaseV2,
    ProviderPhaseLeaseStateV2,
    ProviderTransientKindV2,
    ProviderTransientRegistrationV2,
    RecoverableCleanupDescriptorV2,
)

pytestmark = pytest.mark.unit


def test_provider_phase_lease_initialization_and_active_check() -> None:
    active_lease = ProviderExecutePhaseLeaseV2(ProviderPhaseLeaseStateV2.ACTIVE)
    assert active_lease.active is True
    assert active_lease.state == ProviderPhaseLeaseStateV2.ACTIVE
    active_lease.require_active()  # Should not raise

    revoked_lease = ProviderExecutePhaseLeaseV2(ProviderPhaseLeaseStateV2.REVOKED)
    assert revoked_lease.active is False
    assert revoked_lease.state == ProviderPhaseLeaseStateV2.REVOKED
    with pytest.raises(RuntimeError, match="ProviderExecutePhaseLease is not active"):
        revoked_lease.require_active()


def test_default_provider_invocation_scope_registration() -> None:
    phase_lease = ProviderExecutePhaseLeaseV2(ProviderPhaseLeaseStateV2.ACTIVE)
    scope = DefaultProviderInvocationScopeV2(phase_lease=phase_lease)

    assert scope.phase_lease is phase_lease

    descriptor = RecoverableCleanupDescriptorV2(
        cleanup_id="clean_001",
        kind=CleanupDescriptorKindV2.CLOSE_TRANSIENT,
        registry_id="reg_001",
        resource_ref="res_001",
        expected_revision=1,
        idempotency_key="idem_001",
        descriptor_digest="sha256:descriptor_digest",
    )
    receipt = BackendOwnedTransientReceiptV2(
        backend_registry_id="reg_001",
        backend_handle_ref="handle_001",
        transient_kind=ProviderTransientKindV2.ARTIFACT,
        cleanup_descriptor=descriptor,
        receipt_digest="sha256:receipt_digest",
    )
    registration = ProviderTransientRegistrationV2(creation_receipt=receipt)

    transient_ref = scope.register_transient(registration)

    assert isinstance(transient_ref, PhaseBoundTransientRefV2)
    assert transient_ref.transient_id == "handle_001"
    assert transient_ref.transient_kind == ProviderTransientKindV2.ARTIFACT
    assert transient_ref.phase_lease is phase_lease
    transient_ref.require_active()


def test_provider_invocation_scope_inactive_lease_raises() -> None:
    revoked_lease = ProviderExecutePhaseLeaseV2(ProviderPhaseLeaseStateV2.REVOKED)
    scope = DefaultProviderInvocationScopeV2(phase_lease=revoked_lease)

    descriptor = RecoverableCleanupDescriptorV2(
        cleanup_id="clean_002",
        kind=CleanupDescriptorKindV2.CLOSE_LOCAL_IPC,
        registry_id="reg_002",
        resource_ref="res_002",
        expected_revision=None,
        idempotency_key="idem_002",
        descriptor_digest="sha256:descriptor_digest_2",
    )
    receipt = BackendOwnedTransientReceiptV2(
        backend_registry_id="reg_002",
        backend_handle_ref="handle_002",
        transient_kind=ProviderTransientKindV2.PROCESS,
        cleanup_descriptor=descriptor,
        receipt_digest="sha256:receipt_digest_2",
    )
    registration = ProviderTransientRegistrationV2(creation_receipt=receipt)

    with pytest.raises(RuntimeError, match="ProviderExecutePhaseLease is not active"):
        scope.register_transient(registration)


def test_transient_kind_and_cleanup_enums() -> None:
    assert ProviderTransientKindV2.ARTIFACT.value == "artifact"
    assert ProviderTransientKindV2.REMOTE_FORWARD.value == "remote_forward"
    assert CleanupDescriptorKindV2.CLOSE_TRANSIENT.value == "close_transient"
    assert CleanupDescriptorKindV2.RELEASE_CHECKOUT.value == "release_checkout"
