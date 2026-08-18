"""Unit tests for C2 control protocol (legacy codec), cancellation recovery, materials, task catalog, principals, and approvals."""

from __future__ import annotations

import math
from unittest.mock import MagicMock
import pytest

from core.actions.cancellation import ExecutorCancellationController
from core.actions.cancellation_recovery import (
    CancelExecutionRequestV2,
    CancellationCompletionReceiptV2,
    CancellationRecoveryManager,
    DefaultCancellationRecoveryStoreV2,
    ExecutionCancellationReasonV2,
    ExecutionCancellationReceiptV2,
    canonical_execution_cancellation_receipt_digest,
)
from core.actions.checkout_models import ReferenceKind
from core.actions.execution_cancellation_service import (
    DefaultExecutionCancellationServiceV2,
    ExecutionCancellationService,
)
from core.actions.execution_recovery_types import (
    CancellationRecoveryRecordV2,
    CancellationRecoveryRefV2,
)
from core.actions.materials import (
    ExecutorCheckoutHandleV2,
    ExecutorOpenedMaterialBundleV2,
    ExecutorOpenedMaterialV2,
    _metadata_matches_kind,
    _require_non_empty,
)
from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_snapshots import (
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    SessionReferenceSnapshot,
)
from core.actions.reference_types import (
    ArtifactKind,
    C2ResourceKind,
    C2ResourceState,
    DeploymentState,
    RouteState,
    SessionState,
)
from core.actions.target_scope import (
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot
from core.auth.types import ApprovalStatus, SubjectType
from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV1,
    ParticipantControlPhaseV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
    SignedControlResponseV1,
)
from core.c2.control_protocol import LegacyControlProtocolCodecV1
from core.c2.task_catalog import (
    C2TaskOperationId,
    HostInventoryTaskPayload,
    IdentityTaskPayload,
    NetworkInventoryTaskPayload,
    ServiceInventoryTaskPayload,
    TaskOperationCatalog,
    operation_for_payload,
)
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def _make_auth(ref: str) -> ReferenceAuthorizationSnapshot:
    return ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference=ref,
        authorization_revision=1,
        mission_id="m1",
        owner_subject_id="s1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("s1",),
        permitted_action_ids=("a1",),
        permitted_capabilities=("c1",),
        authorization_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
        ),
        created_by_request_id="req1",
        delegated_by_subject_id=None,
        expires_at=None,
    )


class DummyCheckoutHandle:
    def __init__(self, checkout_id: str) -> None:
        self._checkout_id = checkout_id

    @property
    def checkout_id(self) -> str:
        return self._checkout_id

    def close_checkout(self) -> None:
        pass


def test_legacy_control_protocol_codec():
    codec = LegacyControlProtocolCodecV1()

    sig86 = "A" * 86
    nonce16 = "A" * 16
    hex64 = "0" * 64

    auth = ParticipantControlAuthorizationV1(
        key_id="k1",
        transaction_id="tx1",
        participant_id="part1",
        mission_id="m1",
        subject_id="sub1",
        action_id="act1",
        coordinator_revision=1,
        request_digest=hex64,
        expires_at=1000.0,
        nonce=nonce16,
        signature=sig86,
    )
    req = ParticipantControlRequestV1(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema1",
        payload_digest=hex64,
        canonical_payload_b64u="e30",
        expected_resource_revision=1,
    )

    # Encode and decode request
    raw_req = codec.encode_request(req)
    decoded_req = codec.decode_request(raw_req)
    assert decoded_req.action == C2ControlAction.PREPARE_C2_RESOURCE
    assert decoded_req.authorization.key_id == "k1"

    # Encode and decode signed envelope response
    signed_resp = SignedControlResponseV1(
        protocol_version="1.0",
        daemon_instance_id="d1",
        daemon_generation="g1",
        service_id="svc1",
        boot_instance_id="b1",
        request_digest=hex64,
        request_nonce=nonce16,
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest=hex64,
        issued_at_ms=1000,
        key_id="k1",
        signature=sig86,
    )
    raw_signed = codec.encode_response(signed_resp)
    dec_signed = codec.decode_response(raw_signed)
    assert isinstance(dec_signed, SignedControlResponseV1)
    assert dec_signed.daemon_instance_id == "d1"

    # Encode and decode receipt response
    receipt_resp = ParticipantControlReceiptV1(
        transaction_id="tx1",
        participant_id="part1",
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        resource_ref="res1",
        resource_revision=1,
        receipt_ref="rcpt1",
        receipt_digest=hex64,
        daemon_instance_id="d1",
        result_payload_schema_id="res_schema",
        result_payload_digest=hex64,
        result_payload_b64u="e30",
    )
    raw_rcpt = codec.encode_response(receipt_resp)
    dec_rcpt = codec.decode_response(raw_rcpt)
    assert isinstance(dec_rcpt, ParticipantControlReceiptV1)
    assert dec_rcpt.receipt_ref == "rcpt1"

    # Encode and decode snapshot response
    snap_resp = ParticipantControlQuerySnapshotV1(
        transaction_id="tx1",
        participant_id="part1",
        resource_ref="res1",
        resource_revision=1,
        phase=ParticipantControlPhaseV1.COMMITTED_HIDDEN,
        receipt_ref="rcpt1",
        receipt_digest=hex64,
        snapshot_digest=hex64,
        result_payload_schema_id="res_schema",
        result_payload_digest=hex64,
        result_payload_b64u="e30",
    )
    raw_snap = codec.encode_response(snap_resp)
    dec_snap = codec.decode_response(raw_snap)
    assert isinstance(dec_snap, ParticipantControlQuerySnapshotV1)
    assert dec_snap.snapshot_digest == hex64

    # Encode and decode error response
    err_resp = BoundedControlErrorV1(
        reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
        retryable=False,
        detail_ref="err_detail",
    )
    raw_err = codec.encode_response(err_resp)
    dec_err = codec.decode_response(raw_err)
    assert isinstance(dec_err, BoundedControlErrorV1)
    assert dec_err.reason_code == C2ControlErrorCodeV2.NOT_AUTHORIZED


def test_cancellation_recovery_and_service():
    req = CancelExecutionRequestV2(
        request_id="req1",
        execution_id="exec1",
        reason=ExecutionCancellationReasonV2.USER_REQUESTED,
    )
    assert req.reason == ExecutionCancellationReasonV2.USER_REQUESTED

    svc = DefaultExecutionCancellationServiceV2()
    rcpt = svc.request_cancel(req)
    assert rcpt.request_id == "req1"
    assert rcpt.disposition == "cancel_requested"
    assert rcpt.receipt_digest.startswith("sha256:")

    # Idempotent cancel request
    rcpt2 = svc.request_cancel(req)
    assert rcpt2 == rcpt

    # CancellationRecoveryStore
    store = DefaultCancellationRecoveryStoreV2()
    c_ref = CancellationRecoveryRefV2(
        reference="cancel://1",
        revision=1,
        root_execution_id="root1",
        execution_graph_id="graph1",
        token_id="tok1",
        state="active",
        cancellation_digest="sha256:digest",
    )
    c_rec = CancellationRecoveryRecordV2(
        cancellation_ref=c_ref,
        requested_reason_code="none",
        requested_at_utc=100.0,
    )
    store._records["cancel://1"] = c_rec

    assert store.require(c_ref) == c_rec
    assert store.require_current(c_ref) == c_rec
    assert (
        store.require_current_for_graph(root_execution_id="root1", execution_graph_id="graph1", token_id="tok1")
        == c_rec
    )

    # Missing graph
    with pytest.raises(KeyError, match="not found"):
        store.require_current_for_graph(root_execution_id="root1", execution_graph_id="missing", token_id="tok1")

    # Request cancel
    updated_rec = store.request_cancel(c_ref, expected_revision=1, reason_code="user_stop")
    assert updated_rec.cancellation_ref.state == "cancel_requested"

    # Bind live controller
    mock_ctrl = MagicMock(spec=ExecutorCancellationController)
    rec_bound, binding = store.bind_live_controller(c_ref, mock_ctrl)
    assert binding.reference == "cancel://1"

    # Unbind controller
    rec_unbound = store.unbind_live_controller(binding)
    assert rec_unbound.cancellation_ref.reference == "cancel://1"

    # Acknowledge cancelled
    ack_rec = store.acknowledge_cancelled(c_ref, expected_revision=2)
    assert ack_rec.cancellation_ref.state == "cancelled"

    # Complete graph
    comp_rcpt = store.complete_graph(c_ref, expected_revision=3)
    assert comp_rcpt.completion_digest.startswith("sha256:")
    assert store.require_completion(c_ref) == comp_rcpt

    # Require missing completion
    c_missing = CancellationRecoveryRefV2(
        reference="cancel://missing",
        revision=1,
        root_execution_id="root",
        execution_graph_id="graph",
        token_id="tok",
        state="active",
        cancellation_digest="sha256:d",
    )
    with pytest.raises(KeyError, match="not found"):
        store.require_completion(c_missing)


def test_materials():
    handle = DummyCheckoutHandle("chk1")

    cred_snap = CredentialReferenceSnapshot(
        reference="cred://1",
        revision=1,
        authorization=_make_auth("cred://1"),
        target="10.0.0.1",
        service="ssh",
        username="admin",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=None,
    )

    mat = ExecutorOpenedMaterialV2(
        reference="cred://1",
        reference_kind=ReferenceKind.CREDENTIAL,
        checkout_id="chk1",
        metadata=cred_snap,
        checkout_handle=handle,
    )
    assert mat.reference == "cred://1"
    assert mat.checkout_id == "chk1"

    # Non-serializable
    with pytest.raises(TypeError, match="non-serializable"):
        mat.__reduce__()

    # Bundle
    bundle = ExecutorOpenedMaterialBundleV2(
        checkout_id="chk1",
        materials=(mat,),
    )
    assert bundle.checkout_id == "chk1"
    with pytest.raises(TypeError, match="non-serializable"):
        bundle.__reduce__()

    # Validation errors
    with pytest.raises(ValueError, match="reference_identity_mismatch"):
        ExecutorOpenedMaterialV2(
            reference="cred://wrong",
            reference_kind=ReferenceKind.CREDENTIAL,
            checkout_id="chk1",
            metadata=cred_snap,
            checkout_handle=handle,
        )

    with pytest.raises(ValueError, match="kind_mismatch"):
        ExecutorOpenedMaterialV2(
            reference="cred://1",
            reference_kind=ReferenceKind.SESSION,
            checkout_id="chk1",
            metadata=cred_snap,
            checkout_handle=handle,
        )

    with pytest.raises(ValueError, match="handle_identity_mismatch"):
        ExecutorOpenedMaterialV2(
            reference="cred://1",
            reference_kind=ReferenceKind.CREDENTIAL,
            checkout_id="chk_other",
            metadata=cred_snap,
            checkout_handle=handle,
        )


def test_task_catalog():
    cat = TaskOperationCatalog()

    id_payload = IdentityTaskPayload()
    assert id_payload.payload_kind == "identity"
    assert operation_for_payload(id_payload) == C2TaskOperationId.IDENTITY
    cat.validate(C2TaskOperationId.IDENTITY, id_payload)

    host_payload = HostInventoryTaskPayload(include_processes=True, include_services=False, max_items=100)
    assert host_payload.payload_kind == "host_inventory"
    assert operation_for_payload(host_payload) == C2TaskOperationId.HOST_INVENTORY
    cat.validate(C2TaskOperationId.HOST_INVENTORY, host_payload)

    net_payload = NetworkInventoryTaskPayload(include_routes=True, include_connections=True, max_items=50)
    assert net_payload.payload_kind == "network_inventory"
    assert operation_for_payload(net_payload) == C2TaskOperationId.NETWORK_INVENTORY
    cat.validate(C2TaskOperationId.NETWORK_INVENTORY, net_payload)

    svc_payload = ServiceInventoryTaskPayload(service_names=("sshd", "nginx"), include_status=True)
    assert svc_payload.payload_kind == "service_inventory"
    assert operation_for_payload(svc_payload) == C2TaskOperationId.SERVICE_INVENTORY
    cat.validate(C2TaskOperationId.SERVICE_INVENTORY, svc_payload)

    # Validation errors
    with pytest.raises(ValueError, match="max_items"):
        HostInventoryTaskPayload(include_processes=True, include_services=True, max_items=0)

    with pytest.raises(ValueError, match="max_items"):
        NetworkInventoryTaskPayload(include_routes=True, include_connections=True, max_items=2000)

    with pytest.raises(ValueError, match="service_names"):
        ServiceInventoryTaskPayload(service_names=(), include_status=True)

    with pytest.raises(ValueError, match="service_names must be unique"):
        ServiceInventoryTaskPayload(service_names=("ssh", "SSH"), include_status=True)

    with pytest.raises(ValueError, match="payload variant mismatch"):
        cat.validate(C2TaskOperationId.IDENTITY, host_payload)


def test_principal_and_approval_snapshots():
    p_snap = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="p1",
        revision=1,
        subject_id="sub1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("admin",),
        capabilities=("exec",),
        authenticated_at=100.0,
        expires_at=200.0,
    )
    assert p_snap.principal_ref == "p1"

    # Principal validation errors
    with pytest.raises(ValueError, match="schema version"):
        PrincipalAuthorizationSnapshot(
            schema_version="1.0",
            principal_ref="p1",
            revision=1,
            subject_id="sub1",
            subject_type=SubjectType.OPERATOR,
            active=True,
            roles=("admin",),
            capabilities=("exec",),
            authenticated_at=100.0,
            expires_at=200.0,
        )

    # Approval snapshot
    app_snap = ApprovalAuthorizationSnapshot(
        schema_version="2.0",
        approval_ref="app1",
        revision=1,
        approval_id="id1",
        mission_id="m1",
        subject_id="sub1",
        approver_subject_id="approver1",
        permitted_root_action_ids=("root1",),
        permitted_concrete_action_ids=("c2:c2_deploy",),
        permitted_capabilities=("c2",),
        permitted_killchain_stages=("command_and_control",),
        target_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
        ),
        permitted_operation_ids=("op1",),
        status=ApprovalStatus.ACTIVE,
        issued_at=100.0,
        expires_at=200.0,
        max_uses=5,
        remaining_uses=5,
    )
    assert app_snap.approval_ref == "app1"
    assert app_snap.status == ApprovalStatus.ACTIVE

    with pytest.raises(ValueError, match="schema_version"):
        ApprovalAuthorizationSnapshot(
            schema_version="1.0",
            approval_ref="app1",
            revision=1,
            approval_id="id1",
            mission_id="m1",
            subject_id="sub1",
            approver_subject_id="approver1",
            permitted_root_action_ids=("root1",),
            permitted_concrete_action_ids=("c2:c2_deploy",),
            permitted_capabilities=("c2",),
            permitted_killchain_stages=("command_and_control",),
            target_scope=TargetScopeSnapshot(schema_version="2.0", revision=1, rules=()),
            permitted_operation_ids=("op1",),
            status=ApprovalStatus.ACTIVE,
            issued_at=100.0,
            expires_at=200.0,
            max_uses=5,
            remaining_uses=5,
        )
