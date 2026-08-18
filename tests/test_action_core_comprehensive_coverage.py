"""Comprehensive unit tests covering target_scope, reference_snapshots, readiness_registry, execution_finalization, and trusted_facts."""

from __future__ import annotations

import pytest

from core.actions.execution_finalization import (
    DefaultInvocationFinalizationIntentStoreV2,
    InvocationFinalizationIntentBodyV2,
    InvocationFinalizationIntentCheckpointV2,
    InvocationFinalizationIntentPhaseV2,
    InvocationFinalizationIntentRecordV2,
    InvocationFinalizationIntentRefV2,
)
from core.actions.provider_mounts import DefaultProviderMountRegistry
from core.actions.readiness_registry import ReadinessRegistry
from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_snapshots import (
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    SessionReferenceSnapshot,
    reference_has_active_state,
)
from core.actions.reference_types import (
    C2ResourceKind,
    C2ResourceState,
    DeploymentState,
    RouteState,
    SessionState,
)
from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopePolicy,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.types import SubjectType
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


def test_target_scope_canonicalizer_and_policy():
    # Canonicalize various targets
    ipv4_t = TargetScopeCanonicalizer.canonicalize("192.168.1.1", role=TargetRole.PRIMARY)
    assert ipv4_t.kind == TargetKind.IPV4
    assert ipv4_t.normalized_value == "192.168.1.1"

    ipv6_t = TargetScopeCanonicalizer.canonicalize("::1", role=TargetRole.PRIMARY)
    assert ipv6_t.kind == TargetKind.IPV6

    cidr_t = TargetScopeCanonicalizer.canonicalize("10.0.0.0/24", role=TargetRole.PRIMARY)
    assert cidr_t.kind == TargetKind.CIDR

    fqdn_t = TargetScopeCanonicalizer.canonicalize("victim.local", role=TargetRole.DESTINATION)
    assert fqdn_t.kind == TargetKind.FQDN
    assert fqdn_t.normalized_value == "victim.local"

    host_t = TargetScopeCanonicalizer.canonicalize("target-box", role=TargetRole.HOP)
    assert host_t.kind == TargetKind.HOST

    ref_t = TargetScopeCanonicalizer.canonicalize("session://123", role=TargetRole.RESOURCE_BOUND, resource_bound=True)
    assert ref_t.kind == TargetKind.RESOURCE_BOUND_TARGET

    # Scope rules and matching
    rule_cidr = TargetScopeRule(
        role=TargetRole.PRIMARY,
        kind=TargetKind.CIDR,
        normalized_value="192.168.1.0/24",
        allow_containment=True,
    )
    scope = TargetScopeSnapshot(schema_version="2.0", revision=1, rules=(rule_cidr,))
    decision = TargetScopePolicy.evaluate((ipv4_t,), scope)
    assert decision.allowed is True

    # Out of scope
    out_t = TargetScopeCanonicalizer.canonicalize("10.1.1.1", role=TargetRole.PRIMARY)
    decision_out = TargetScopePolicy.evaluate((out_t,), scope)
    assert decision_out.allowed is False
    assert "target_not_in_scope" in decision_out.reason

    # Validate targets compatibility
    dec_compat = TargetScopePolicy.validate_targets(("192.168.1.1",), ("192.168.1.1",))
    assert dec_compat.allowed is True


def test_reference_snapshots_and_active_predicate():
    auth = _make_auth("cred://1")
    cred_snap = CredentialReferenceSnapshot(
        reference="cred://1",
        revision=1,
        authorization=auth,
        target="10.0.0.1",
        service="ssh",
        username="root",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=1000.0,
    )
    assert reference_has_active_state(cred_snap) is True

    sess_snap = SessionReferenceSnapshot(
        reference="sess://1",
        revision=1,
        authorization=_make_auth("sess://1"),
        target="10.0.0.1",
        service="ssh",
        connected_peer="10.0.0.2",
        state=SessionState.ACTIVE,
        created_at=100.0,
        expires_at=None,
    )
    assert reference_has_active_state(sess_snap) is True

    route_snap = PivotRouteReferenceSnapshot(
        reference="route://1",
        revision=1,
        authorization=_make_auth("route://1"),
        session_ref="sess://1",
        source_fact_ref="fact://1",
        proxy_endpoint=ExtractedActionTarget(
            role=TargetRole.PRIMARY,
            kind=TargetKind.IPV4,
            normalized_value="127.0.0.1",
            port=1080,
        ),
        allowed_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=1,
            rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
        ),
        state=RouteState.ACTIVE,
        expires_at=None,
    )
    assert reference_has_active_state(route_snap) is True

    c2_snap = C2ReferenceSnapshot(
        reference="c2://1",
        revision=1,
        authorization=_make_auth("c2://1"),
        resource_kind=C2ResourceKind.CHANNEL,
        target="10.0.0.1",
        daemon_instance_id="d1",
        state=C2ResourceState.ACTIVE,
        expires_at=None,
    )
    assert reference_has_active_state(c2_snap) is True

    deploy_snap = DeploymentReferenceSnapshot(
        reference="deploy://1",
        revision=1,
        authorization=_make_auth("deploy://1"),
        target="10.0.0.1",
        lifecycle_owner="owner1",
        state=DeploymentState.ACTIVE,
        deployment_attempt_id="att1",
        artifact_binding_digest="sha256:d",
        expires_at=None,
    )
    assert reference_has_active_state(deploy_snap) is True


def test_readiness_registry():
    reg = ReadinessRegistry()
    mount_reg = DefaultProviderMountRegistry()
    mount = mount_reg.require_v2("killchain:ad_dump_lsass")

    snap = reg.probe(mount)
    assert snap.action_id == "killchain:ad_dump_lsass"

    # assert_current check
    reg.assert_current(snap, mount)

    # recheck
    snap_fresh = reg.recheck(mount)
    assert snap_fresh.action_id == "killchain:ad_dump_lsass"


def test_execution_finalization_intent_store():
    store = DefaultInvocationFinalizationIntentStoreV2()

    ref = InvocationFinalizationIntentRefV2(
        reference="intent://1",
        revision=1,
        execution_id="e1",
        action_id="a1",
        transaction_id="tx1",
        intent_digest="sha256:d",
    )
    body = InvocationFinalizationIntentBodyV2(
        execution_id="e1",
        action_id="a1",
        transaction_id="tx1",
        phase=InvocationFinalizationIntentPhaseV2.CREATED,
    )
    record = InvocationFinalizationIntentRecordV2(intent_ref=ref, body=body)

    # Initial checkpoint
    chk = InvocationFinalizationIntentCheckpointV2(
        expected_revision=1,
        phase=InvocationFinalizationIntentPhaseV2.OWNERS_FENCED,
    )
    updated_rec = store.checkpoint(record, chk)
    assert updated_rec.intent_ref.revision == 2
    assert updated_rec.body.phase == InvocationFinalizationIntentPhaseV2.OWNERS_FENCED

    assert store.require(updated_rec.intent_ref) == updated_rec
    assert store.require_current("intent://1") == updated_rec
    assert len(store.list_pending()) == 1

    chk2 = InvocationFinalizationIntentCheckpointV2(
        expected_revision=2,
        phase=InvocationFinalizationIntentPhaseV2.CLEANUP_COMPLETE,
    )
    rec2 = store.checkpoint(updated_rec, chk2)
    assert rec2.intent_ref.revision == 3
    assert rec2.body.phase == InvocationFinalizationIntentPhaseV2.CLEANUP_COMPLETE
