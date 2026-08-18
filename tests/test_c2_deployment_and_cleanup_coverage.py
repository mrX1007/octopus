"""Unit tests for C2 deployment, cleanup, enrollment, resource models, and CLI auth session."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import MagicMock
import pytest

from core.c2.artifact_bindings import (
    C2ArtifactBindingV1,
    compute_artifact_binding_digest,
)
from core.c2.cleanup_effect_models import (
    C2CleanupAttemptRecordV1,
    C2CleanupAttemptStateV1,
    C2CleanupBackendRequestV1,
    C2CleanupEffectOutcomeV1,
    C2CleanupEffectProbeV1,
    C2CleanupEffectReceiptV1,
    C2CleanupPlanV1,
)
from core.c2.cleanup_effect_participant import C2CleanupExternalEffectParticipant
from core.c2.deployment_attempts import (
    DeploymentAttemptProbe,
    DeploymentAttemptRecord,
    DeploymentAttemptState,
    DeploymentProbeOutcome,
    DeploymentStartReceipt,
)
from core.c2.deployment_cleanup import DeploymentCleanupManager, DeploymentCleanupRecipe
from core.c2.deployment_effect_participant import DeploymentEffectParticipant
from core.c2.deployment_outbox import DeploymentOutboxMessage, DeploymentOutboxStore
from core.c2.deployment_store import DeploymentRecordV1, DeploymentStore
from core.c2.enrollment_service import EnrollmentRecordV1, EnrollmentService, EnrollmentStateV1
from core.c2.enrollment_transaction_participant import C2EnrollmentTransactionParticipant
from core.c2.resource_models import ManagedC2ResourceKind, ManagedC2ResourceStateV1
from core.c2.resource_payload_registry import (
    C2DaemonResourcePayloadRegistry,
    ResourcePayloadDigestMismatchError,
    UnknownResourceSchemaError,
)
from core.cli.auth_session import CLIAuthSessionManager, get_cli_auth_manager

pytestmark = pytest.mark.unit


def test_artifact_bindings():
    binding = C2ArtifactBindingV1(
        deployment_ref="dep://1",
        enrollment_ref="enr://1",
        channel_ref="chan://1",
        target_id="target_1",
        profile_id="prof_1",
        method_id="meth_1",
        protocol_version="2.0",
        source_digest="sha256:src",
        content_digest="sha256:content",
    )
    digest = compute_artifact_binding_digest(binding)
    assert digest.startswith("sha256:")


def test_cleanup_effect_participant_and_models():
    plan = C2CleanupPlanV1(
        schema_version="1.0",
        transaction_id="tx_1",
        participant_id="part_1",
        resource_ref="res://1",
        expected_revision=1,
        resource_kind="c2_channel",
        lifecycle_owner="owner_1",
        reason="cleanup test",
        mission_id="m1",
        subject_id="s1",
        cleanup_attempt_id="att_1",
        cleanup_recipe_ref=None,
        request_digest="sha256:req",
        idempotency_digest="sha256:idem",
    )
    assert plan.resource_kind == "c2_channel"

    part = C2CleanupExternalEffectParticipant("part_1", "tx_1", "res://1")
    prep = part.prepare()
    assert prep["outcome"] == "cleaned"
    comm = part.commit()
    assert comm["outcome"] == "cleaned"
    assert part.finalize_visibility(prep, comm) == comm
    assert part.rollback("receipt") == "receipt"
    assert part.reconcile()["status"] == "cleaned"


def test_deployment_store_and_cleanup_manager():
    store = DeploymentStore()
    dep = store.allocate_deployment(
        deployment_ref="dep://1",
        mission_id="m1",
        subject_id="s1",
        channel_ref="chan://1",
        enrollment_ref="enr://1",
        target_id="target_1",
        profile_id="prof_1",
        method="ssh",
    )
    assert dep.deployment_ref == "dep://1"
    assert dep.status == "allocated"

    # Idempotent allocate
    dep2 = store.allocate_deployment(
        deployment_ref="dep://1",
        mission_id="m1",
        subject_id="s1",
        channel_ref="chan://1",
        enrollment_ref="enr://1",
        target_id="target_1",
        profile_id="prof_1",
        method="ssh",
    )
    assert dep2 == dep

    # Get & list
    assert store.get_deployment("dep://1") == dep
    assert len(store.list_deployments("m1")) == 1
    assert len(store.list_deployments("other_mission")) == 0

    # Update status
    updated = store.update_status("dep://1", "deployed", expected_revision=1)
    assert updated.status == "deployed"
    assert updated.revision == 2

    # Revision mismatch
    with pytest.raises(ValueError, match="revision mismatch"):
        store.update_status("dep://1", "deployed", expected_revision=1)

    # Missing deployment
    with pytest.raises(KeyError, match="not found"):
        store.update_status("dep://missing", "deployed")

    # Record and get attempt
    attempt = DeploymentAttemptRecord(
        transaction_id="tx_1",
        deployment_attempt_id="att_1",
        deployment_ref="dep://1",
        request_digest="sha256:req",
        state=DeploymentAttemptState.RESERVED,
        backend_probe_token=None,
        revision=1,
    )
    store.record_attempt(attempt)
    assert store.get_attempt("att_1") == attempt
    assert store.get_attempt("att_missing") is None

    # Cleanup Manager
    mgr = DeploymentCleanupManager(store)
    recipe = mgr.register_recipe(
        deployment_ref="dep://1",
        target_id="target_1",
        remote_path="/tmp/implant",
        process_id=1234,
    )
    assert recipe.recipe_id == "recipe-dep://1"
    assert mgr.get_recipe("dep://1") == recipe

    assert mgr.execute_cleanup("dep://1") is True
    assert store.get_deployment("dep://1").status == "cleaned"
    assert mgr.execute_cleanup("dep://missing") is False


def test_deployment_outbox_store():
    outbox = DeploymentOutboxStore()
    msg = outbox.enqueue(deployment_ref="dep://1", action="start", payload_digest="sha256:p1")
    assert msg.status == "pending"

    pending = outbox.list_pending()
    assert len(pending) == 1
    assert pending[0].message_id == msg.message_id

    outbox.mark_delivered(msg.message_id)
    assert len(outbox.list_pending()) == 0


def test_deployment_effect_participant():
    part = DeploymentEffectParticipant("part_1", "tx_1", "dep://1")
    prep = part.prepare()
    assert prep.state == DeploymentAttemptState.STARTED
    comm = part.commit()
    assert comm == prep
    assert part.finalize_visibility(prep, comm) == comm
    assert part.rollback("receipt") == "receipt"
    assert part.reconcile() == prep


def test_enrollment_service_and_participant():
    svc = EnrollmentService()
    rec = svc.issue(profile_id="p1", channel_ref="chan://1", target_id="target_1", max_uses=2)
    assert rec.state == EnrollmentStateV1.ISSUED
    assert svc.get(rec.enrollment_ref) == rec

    # Reserve for build
    reserved = svc.reserve_for_build(rec.enrollment_ref, expected_revision=1)
    assert reserved.state == EnrollmentStateV1.RESERVED_FOR_BUILD
    assert reserved.revision == 2

    # Revision mismatch
    with pytest.raises(ValueError, match="Revision mismatch"):
        svc.reserve_for_build(rec.enrollment_ref, expected_revision=1)

    # Mark embedded
    embedded = svc.mark_embedded(rec.enrollment_ref, expected_revision=2)
    assert embedded.state == EnrollmentStateV1.EMBEDDED_IN_ARTIFACT

    # Consume 1st time
    consumed1 = svc.consume(rec.enrollment_ref, rec.token)
    assert consumed1.used_count == 1
    assert consumed1.state == EnrollmentStateV1.EMBEDDED_IN_ARTIFACT

    # Consume 2nd time (hits max_uses)
    consumed2 = svc.consume(rec.enrollment_ref, rec.token)
    assert consumed2.used_count == 2
    assert consumed2.state == EnrollmentStateV1.CONSUMED_BY_AGENT

    # Consume with wrong token
    with pytest.raises(ValueError, match="Invalid enrollment token"):
        svc.consume(rec.enrollment_ref, "wrong_token")

    # Consume when max uses exceeded
    with pytest.raises(ValueError, match="maximum uses exceeded"):
        svc.consume(rec.enrollment_ref, rec.token)

    # 2PC Participant
    part = C2EnrollmentTransactionParticipant("part_enr", "tx_enr", rec.enrollment_ref)
    p_prep = part.prepare()
    assert p_prep.state == "prepared"
    p_comm = part.commit()
    assert p_comm == p_prep
    assert part.finalize_visibility(p_prep, p_comm) == p_comm
    assert part.rollback("receipt") == "receipt"
    assert part.reconcile() == p_prep


def test_resource_payload_registry_and_models():
    reg = C2DaemonResourcePayloadRegistry()

    # Empty schema_id
    with pytest.raises(ValueError, match="schema_id must not be empty"):
        reg.register("channel", "", lambda b: None)

    # Custom decoder
    reg.register("channel", "custom_schema", lambda b: {"decoded": b.decode("utf-8")})
    res = reg.decode("channel", "custom_schema", b"hello")
    assert res == {"decoded": "hello"}

    # Default JSON decoder
    payload_raw = b'{"key":"value"}'
    res_json = reg.decode("task", "json_schema", payload_raw)
    assert res_json == {"key": "value"}

    # Digest check success
    digest = f"sha256:{hashlib.sha256(payload_raw).hexdigest()}"
    res_digest = reg.decode("task", "json_schema", payload_raw, expected_digest=digest)
    assert res_digest == {"key": "value"}

    # Digest mismatch
    with pytest.raises(ResourcePayloadDigestMismatchError):
        reg.decode("task", "json_schema", payload_raw, expected_digest="sha256:wrong")

    # Corrupt payload without custom decoder
    with pytest.raises(UnknownResourceSchemaError):
        reg.decode("task", "json_schema", b"{bad_json")

    # Model
    model = ManagedC2ResourceStateV1(
        resource_ref="res://1",
        resource_kind=ManagedC2ResourceKind.CHANNEL,
        mission_id="m1",
        subject_id="s1",
        status="active",
        revision=1,
        metadata_digest="sha256:meta",
        created_at=100.0,
    )
    assert model.resource_kind == ManagedC2ResourceKind.CHANNEL


def test_cli_auth_session_manager():
    mgr = get_cli_auth_manager()
    assert mgr is not None
    lease = mgr.issue_command_lease("req_cli_123")
    assert lease is not None
    assert lease.lease_id is not None
    assert lease.principal_ref == "principal:cli-operator"
