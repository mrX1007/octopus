"""Unit tests for zeroizable buffers, sensitive integrity runtime, and provider results."""

from __future__ import annotations

import math
from unittest.mock import MagicMock
import pytest

from core.actions.checkout_models import ReferenceKind
from core.actions.execution_results_v2 import ExecutionResultRefV2, ExecutionStatusV2
from core.actions.provider_participants import ParticipantRegistrationRefV2
from core.actions.provider_results import (
    ArtifactProviderResult,
    C2ArtifactStageReceiptV1,
    C2ProviderResult,
    CompositeProviderResult,
    CredentialProviderResult,
    ExternalEffectRegistrationResultV2,
    ManagedResourceDraftRefV2,
    ManagedResourceKind,
    NonSensitiveArtifactDraftRefV2,
    ObservationDraftRefV2,
    OperationProviderResult,
    PartialCommitDispositionV2,
    PartialCommitPolicyRegistryV2,
    PartialCommitPolicySnapshotV2,
    PartialCommitPolicyV2,
    PartialCommitRuleV2,
    ParticipantPayloadDraftRefV2,
    ProviderOutcomeNormalizationV2,
    ProviderOutcomeNormalizerV2,
    ProviderOutcomeV2,
    ProviderProvenanceV2,
    ProviderResultHeaderV2,
    ProviderResultKind,
    RouteProviderResult,
    SensitiveArtifactDraftRefV2,
    SensitiveBatchDraftRefV2,
    SensitiveBatchHandleV2,
    SensitiveHandleStateV2,
    SensitiveProviderResult,
    SessionProviderResult,
    StagedArtifactV2,
    StagedObservationV2,
    canonical_partial_commit_policy_digest,
)
from core.actions.reference_types import ArtifactKind
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    OwnedHmacSensitiveIntegrityAuthenticatorV2,
    PersistentSensitiveIntegrityKeyringV2,
    SensitiveIntegrityError,
    SensitiveIntegrityKeyLeaseStateV2,
    SensitiveIntegrityStreamStateV2,
)
from core.actions.zeroizable_buffers import (
    OwnedZeroizableSensitiveBufferV2,
    ZeroizableBufferError,
    ZeroizableDestinationBufferV2,
    _OWNED_BUFFER_TOKEN,
)

pytestmark = pytest.mark.unit


def test_sensitive_integrity_runtime_and_keyring():
    key_bytes = bytearray(b"01234567890123456789012345678901")
    keys = {"k1": key_bytes}
    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="k1",
        keys=keys,
    )
    assert keyring.active_key_id() == "k1"

    factory = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2()
    auth = factory.create(keyring=keyring, provenance_id="prov1")
    assert auth.provenance_id == "prov1"

    # Compute and verify
    src_data = bytearray(b"sensitive_password_data")
    src_view = memoryview(src_data)
    tag = auth.compute(domain="test_domain", source=src_view)
    assert tag.key_id == "k1"
    assert tag.algorithm == "hmac-sha256-v2"
    assert tag.domain == "test_domain"

    # Verify matching
    assert auth.verify(expected=tag, source=src_view) is True

    # Verify error on tampered tag
    bad_tag = SensitiveIntegrityTagV2(
        key_id="k1",
        algorithm="hmac-sha256-v2",
        domain="test_domain",
        tag="0" * 64,
    )
    with pytest.raises(SensitiveIntegrityError, match="sensitive_integrity_mismatch"):
        auth.verify(expected=bad_tag, source=src_view)

    # Keyring close
    keyring.close_and_zeroize()
    with pytest.raises(SensitiveIntegrityError, match="keyring_closed"):
        keyring.active_key_id()


def test_zeroizable_buffers():
    dest = ZeroizableDestinationBufferV2.allocate(64)
    assert dest.capacity == 64
    assert dest.closed is False
    assert dest.zeroized is False

    with dest as d:
        with d.borrow_writable_view() as w:
            w[:4] = b"test"

    assert dest.closed is True
    assert dest.zeroized is True

    # Non-serializable
    with pytest.raises(TypeError, match="not_serializable"):
        dest.__reduce__()

    # OwnedZeroizableSensitiveBufferV2
    tag = SensitiveIntegrityTagV2(
        key_id="k1",
        algorithm="hmac-sha256-v2",
        domain="dom",
        tag="a" * 64,
    )
    storage = bytearray(b"secret_bytes")
    buf = OwnedZeroizableSensitiveBufferV2._from_owned_storage(
        storage=storage,
        integrity_tag=tag,
        _token=_OWNED_BUFFER_TOKEN,
    )
    assert buf.byte_length == len(b"secret_bytes")
    assert buf.zeroized is False

    # Single-use lease
    lease = buf.acquire_single_use(consumer_id="c1")
    assert lease.byte_length == buf.byte_length

    # Already leased error
    with pytest.raises(ZeroizableBufferError, match="already_leased"):
        buf.acquire_single_use(consumer_id="c2")

    # Read into destination
    read_dest = ZeroizableDestinationBufferV2.allocate(64)
    bytes_read = lease.read_into(read_dest)
    assert bytes_read == len(b"secret_bytes")

    # Read twice error
    with pytest.raises(ZeroizableBufferError, match="already_read"):
        lease.read_into(read_dest)

    lease.close_and_zeroize()
    assert buf.zeroized is True


def test_provider_results_models_and_normalization():
    prov = ProviderProvenanceV2(
        implementation_id="imp1",
        implementation_version="1.0",
        request_digest="sha256:req",
        started_at=100.0,
        completed_at=100.5,
    )
    header = ProviderResultHeaderV2(
        schema_version="2.0",
        provider_id="prov1",
        outcome=ProviderOutcomeV2.SUCCEEDED,
        reason_codes=("ok",),
        duration_ms=500,
        provenance=prov,
    )

    # Operation result
    op_res = OperationProviderResult(
        header=header,
        observations=(),
    )
    assert op_res.result_kind == ProviderResultKind.OPERATION

    # Artifact result
    art_res = ArtifactProviderResult(
        header=header,
        artifacts=(),
    )
    assert art_res.result_kind == ProviderResultKind.ARTIFACT

    # Managed resource drafts
    res_draft = ManagedResourceDraftRefV2(
        transaction_id="tx1",
        draft_id="d1",
        resource_kind=ManagedResourceKind.SESSION,
        target="10.0.0.1",
        lifecycle_owner="owner1",
        close_action_id=None,
        expires_at=None,
    )
    sess_res = SessionProviderResult(
        header=header,
        session=res_draft,
    )
    assert sess_res.result_kind == ProviderResultKind.SESSION

    route_draft = ManagedResourceDraftRefV2(
        transaction_id="tx1",
        draft_id="d1",
        resource_kind=ManagedResourceKind.PIVOT_ROUTE,
        target="10.0.0.1",
        lifecycle_owner="owner1",
        close_action_id=None,
        expires_at=None,
    )
    route_res = RouteProviderResult(
        header=header,
        route=route_draft,
    )
    assert route_res.result_kind == ProviderResultKind.ROUTE

    # C2 Provider Result
    c2_draft = ManagedResourceDraftRefV2(
        transaction_id="tx1",
        draft_id="d1",
        resource_kind=ManagedResourceKind.C2_CHANNEL,
        target="10.0.0.1",
        lifecycle_owner="owner1",
        close_action_id=None,
        expires_at=None,
    )
    c2_res = C2ProviderResult(
        header=header,
        resources=(c2_draft,),
    )
    assert c2_res.result_kind == ProviderResultKind.C2_RESOURCE

    # Composite Provider Result
    comp_res = CompositeProviderResult(
        header=header,
        child_action_id="child_act",
        child_execution_id="exec1",
        child_result_ref=ExecutionResultRefV2(
            reference="res://1",
            revision=1,
            execution_id="e1",
            action_id="a1",
            result_digest="sha256:d",
        ),
    )
    assert comp_res.result_kind == ProviderResultKind.COMPOSITE

    # Normalization policy & normalizer
    rule = PartialCommitRuleV2(
        action_id="act1",
        result_kind=ProviderResultKind.OPERATION,
        accepted_reason_codes=("partial_ok",),
    )
    dummy_digest = ""
    dummy_snap = PartialCommitPolicySnapshotV2(
        policy_id="pol1",
        revision=1,
        rules=(rule,),
        policy_digest=dummy_digest,
    )
    digest = canonical_partial_commit_policy_digest(dummy_snap)
    snap = PartialCommitPolicySnapshotV2(
        policy_id="pol1",
        revision=1,
        rules=(rule,),
        policy_digest=digest,
    )

    class DummyRegistry:
        def require_current(self, action_id: str) -> PartialCommitPolicySnapshotV2:
            return snap

        def assert_current(self, snapshot: PartialCommitPolicySnapshotV2) -> None:
            pass

    mock_policy = MagicMock(spec=PartialCommitPolicyV2)
    mock_policy.decide.return_value = PartialCommitDispositionV2.ACCEPT

    normalizer = ProviderOutcomeNormalizerV2(
        policy=mock_policy,
        registry=DummyRegistry(),
    )

    norm_succeeded = normalizer.normalize(
        action_id="act1",
        result_kind=ProviderResultKind.OPERATION,
        outcome=ProviderOutcomeV2.SUCCEEDED,
        reason_codes=("ok",),
        partial_policy=snap,
    )
    assert norm_succeeded.commit_eligible is True
    assert norm_succeeded.execution_status == ExecutionStatusV2.SUCCEEDED

    norm_failed = normalizer.normalize(
        action_id="act1",
        result_kind=ProviderResultKind.OPERATION,
        outcome=ProviderOutcomeV2.FAILED,
        reason_codes=("error",),
        partial_policy=snap,
    )
    assert norm_failed.commit_eligible is False
    assert norm_failed.execution_status == ExecutionStatusV2.FAILED
