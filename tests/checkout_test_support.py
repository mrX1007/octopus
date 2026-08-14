"""Deterministic authorities used by the PR-4 checkout contract tests."""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace

from core.actions.checkout_models import (
    ApprovalCheckoutRequest,
    ExecutionAttemptGroup,
    ExecutorCheckoutRequestBundle,
    FactCheckoutRequest,
    IngressSessionCheckoutRequest,
    MissionCheckoutRequest,
    PrincipalCheckoutRequest,
    ReferenceAccessMode,
    ReferenceCheckout,
    ReferenceCheckoutRequest,
    ReferenceKind,
    ReferenceLeaseToken,
)
from core.actions.reference_authorization import ReferenceAuthorizationSnapshot
from core.actions.reference_checkout import ReferenceCheckoutCoordinator
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.target_scope import (
    ExtractedActionTarget,
    NetworkProtocol,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.actions.trusted_facts import (
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
    TrustedFactSnapshot,
    TrustedFactTrustLevelV2,
    TrustedFactType,
)
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.approval_store import ApprovalStore
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.ingress import IngressSessionAuthorizationSnapshot
from core.auth.missions import MissionAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot
from core.auth.types import ApprovalStatus, AuthenticationMethod, IngressKind, SubjectType
from core.credentials import CredentialAuthKind


class FakeCheckoutHandle:
    def __init__(self, checkout_id: str, secret_marker: str = "never-in-repr") -> None:
        self._checkout_id = checkout_id
        self.secret_marker = secret_marker
        self.close_count = 0

    @property
    def checkout_id(self) -> str:
        return self._checkout_id

    def close_checkout(self) -> None:
        self.close_count += 1


class FakeAuthorityStore:
    def __init__(
        self,
        *,
        ingress: IngressSessionAuthorizationSnapshot,
        principal: PrincipalAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
        facts: tuple[TrustedFactSnapshot, ...],
        events: list[str],
        approval_store: ApprovalStore | None = None,
        approval_lease: ApprovalExecutionLease | None = None,
    ) -> None:
        self.ingress = ingress
        self.principal = principal
        self.mission = mission
        self.facts = {fact.fact_ref: fact for fact in facts}
        self.events = events
        self.approval_store = approval_store
        self.approval_lease = approval_lease
        self._lock = threading.RLock()

    @property
    def checkout_lock_order_key(self) -> str:
        return "10:authority"

    def acquire_checkout_lock(self) -> None:
        self.events.append("acquire:10:authority")
        self._lock.acquire()

    def release_checkout_lock(self) -> None:
        self.events.append("release:10:authority")
        self._lock.release()

    def checkout_ingress(
        self,
        request: IngressSessionCheckoutRequest,
    ) -> IngressSessionAuthorizationSnapshot:
        if (
            request.lease_id != "lease-1"
            or request.lease_revision != 1
            or request.bound_request_id != "request-1"
            or request.transport_instance_id != "transport-1"
        ):
            raise RuntimeError("ingress_lease_binding_mismatch")
        return self.ingress

    def assert_ingress_current(
        self,
        _request: IngressSessionCheckoutRequest,
        snapshot: IngressSessionAuthorizationSnapshot,
    ) -> None:
        if snapshot != self.ingress:
            raise RuntimeError("ingress_revision_mismatch")

    def checkout_principal(
        self,
        _request: PrincipalCheckoutRequest,
        _ingress: IngressSessionAuthorizationSnapshot,
    ) -> PrincipalAuthorizationSnapshot:
        return self.principal

    def assert_principal_current(
        self,
        _request: PrincipalCheckoutRequest,
        snapshot: PrincipalAuthorizationSnapshot,
    ) -> None:
        if snapshot != self.principal:
            raise RuntimeError("principal_revision_mismatch")

    def checkout_mission(
        self,
        _request: MissionCheckoutRequest,
        _principal: PrincipalAuthorizationSnapshot,
    ) -> MissionAuthorizationSnapshot:
        return self.mission

    def assert_mission_current(
        self,
        _request: MissionCheckoutRequest,
        snapshot: MissionAuthorizationSnapshot,
    ) -> None:
        if snapshot != self.mission:
            raise RuntimeError("mission_revision_mismatch")

    def checkout_fact(
        self,
        request: FactCheckoutRequest,
        _ingress: IngressSessionAuthorizationSnapshot,
        _mission: MissionAuthorizationSnapshot,
    ) -> TrustedFactSnapshot:
        return self.facts[request.fact_ref]

    def assert_fact_current(
        self,
        request: FactCheckoutRequest,
        snapshot: TrustedFactSnapshot,
    ) -> None:
        if snapshot != self.facts[request.fact_ref]:
            raise RuntimeError("fact_revision_mismatch")

    def checkout_approval(
        self,
        request: ApprovalCheckoutRequest,
        _ingress: IngressSessionAuthorizationSnapshot,
        _principal: PrincipalAuthorizationSnapshot,
        _mission: MissionAuthorizationSnapshot,
        targets: tuple[ExtractedActionTarget, ...],
    ) -> ApprovalExecutionLease:
        lease = self.approval_lease
        if lease is None:
            raise RuntimeError("approval_lease_unavailable")
        lease.authorize_router_step(
            action_id=request.concrete_action_id,
            capability="cap:test",
            killchain_stage="test",
            operation_id=None,
            targets=targets,
            now=10.0,
        )
        return lease

    def assert_approval_current(
        self,
        request: ApprovalCheckoutRequest,
        lease: ApprovalExecutionLease,
    ) -> None:
        if lease is not self.approval_lease:
            raise RuntimeError("approval_lease_identity_mismatch")
        lease.authorize_router_step(
            action_id=request.concrete_action_id,
            capability="cap:test",
            killchain_stage="test",
            operation_id=None,
            targets=(make_target(),),
            now=10.0,
        )


class FakeReferenceStore:
    def __init__(
        self,
        snapshots: tuple[CredentialReferenceSnapshot, ...],
        *,
        checkout_id: str,
        events: list[str],
        order: int = 20,
    ) -> None:
        self.snapshots = {snapshot.reference: snapshot for snapshot in snapshots}
        self.checkout_id = checkout_id
        self.events = events
        self.order = order
        self._lock = threading.RLock()
        self.receipts: dict[str, ReferenceCheckout] = {}
        self.release_counts: dict[str, int] = {}
        self.open_calls: list[str] = []
        self.handles: list[FakeCheckoutHandle] = []
        self.fail_checkout_for: str | None = None
        self.fail_open_for: str | None = None

    @property
    def checkout_lock_order_key(self) -> str:
        return f"{self.order:02d}:reference"

    def acquire_checkout_lock(self) -> None:
        self.events.append(f"acquire:{self.checkout_lock_order_key}")
        self._lock.acquire()

    def release_checkout_lock(self) -> None:
        self.events.append(f"release:{self.checkout_lock_order_key}")
        self._lock.release()

    def checkout(
        self,
        *,
        reference: str,
        expected_metadata_revision: int,
        expected_authorization_revision: int,
        ingress_session: IngressSessionAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
        action_id: str,
        targets: tuple[ExtractedActionTarget, ...],
    ) -> ReferenceCheckout:
        del ingress_session, mission, action_id, targets
        if reference == self.fail_checkout_for:
            raise RuntimeError("test_checkout_failure")
        snapshot = self.snapshots[reference]
        if (
            snapshot.revision != expected_metadata_revision
            or snapshot.authorization.authorization_revision != expected_authorization_revision
        ):
            raise RuntimeError("reference_revision_mismatch")
        receipt = ReferenceCheckout(
            metadata=snapshot,
            lease_token=ReferenceLeaseToken(
                reference=reference,
                metadata_revision=snapshot.revision,
                authorization_revision=snapshot.authorization.authorization_revision,
                fence_generation=1,
                checkout_id=self.checkout_id,
            ),
        )
        self.receipts[reference] = receipt
        return receipt

    def assert_reference_current(self, checkout: ReferenceCheckout) -> None:
        current = self.snapshots[checkout.metadata.reference]
        if current != checkout.metadata or self.receipts.get(current.reference) is not checkout:
            raise RuntimeError("reference_fence_invalid")

    def open_material(self, checkout: ReferenceCheckout) -> FakeCheckoutHandle:
        reference = checkout.metadata.reference
        self.open_calls.append(reference)
        if reference == self.fail_open_for:
            raise RuntimeError("test_material_open_failure")
        handle = FakeCheckoutHandle(checkout.lease_token.checkout_id)
        self.handles.append(handle)
        return handle

    def release_reference_checkout(self, checkout: ReferenceCheckout) -> None:
        reference = checkout.metadata.reference
        self.release_counts[reference] = self.release_counts.get(reference, 0) + 1
        if self.receipts.get(reference) is checkout:
            del self.receipts[reference]

    def advance_metadata_revision(self, reference: str) -> None:
        self.snapshots[reference] = replace(
            self.snapshots[reference],
            revision=self.snapshots[reference].revision + 1,
        )


@dataclass(frozen=True)
class CheckoutFixture:
    coordinator: ReferenceCheckoutCoordinator
    authority: FakeAuthorityStore
    reference_store: FakeReferenceStore
    request: ExecutorCheckoutRequestBundle
    target: ExtractedActionTarget
    approval_store: ApprovalStore | None


def make_target() -> ExtractedActionTarget:
    return TargetScopeCanonicalizer.canonicalize(
        "192.0.2.10",
        role=TargetRole.PRIMARY,
        port=22,
        protocol=NetworkProtocol.SSH,
    )


def make_scope(target: ExtractedActionTarget) -> TargetScopeSnapshot:
    assert target.kind is TargetKind.IPV4
    return TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(
            TargetScopeRule(
                role=target.role,
                kind=target.kind,
                normalized_value=target.normalized_value,
                port=target.port,
                protocol=target.protocol,
            ),
        ),
    )


def make_authorization(reference: str, target: ExtractedActionTarget) -> ReferenceAuthorizationSnapshot:
    return ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference=reference,
        authorization_revision=1,
        mission_id="mission-1",
        owner_subject_id="operator-1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=(),
        permitted_action_ids=("action:test",),
        permitted_capabilities=("cap:test",),
        authorization_scope=make_scope(target),
        created_by_request_id="request-1",
        delegated_by_subject_id=None,
        expires_at=100.0,
    )


def make_credential(reference: str, target: ExtractedActionTarget) -> CredentialReferenceSnapshot:
    return CredentialReferenceSnapshot(
        reference=reference,
        revision=1,
        authorization=make_authorization(reference, target),
        target=target.normalized_value,
        service="ssh",
        username="alice",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=100.0,
    )


def make_fact(target: ExtractedActionTarget) -> TrustedFactSnapshot:
    return TrustedFactSnapshot(
        schema_version="2.0",
        fact_ref="fact://access/1",
        revision=1,
        payload_digest="sha256:fact-1",
        mission_id="mission-1",
        target=target.normalized_value,
        fact_type=TrustedFactType.CONFIRMED_SSH_ACCESS,
        assessment_status=AssessmentStatus.VERIFIED,
        trust_level=TrustedFactTrustLevelV2.TRUSTED,
        freshness_status=FactFreshnessStatus.FRESH,
        coverage_status=EvidenceCoverageStatus.COMPLETE,
        source_execution_ids=("execution-source-1",),
        expires_at=100.0,
    )


def build_fixture(
    *,
    reference_count: int = 1,
    access_modes: tuple[ReferenceAccessMode, ...] | None = None,
    include_fact: bool = False,
    include_approval: bool = False,
    events: list[str] | None = None,
) -> CheckoutFixture:
    target = make_target()
    scope = make_scope(target)
    ingress = IngressSessionAuthorizationSnapshot(
        schema_version="2.0",
        ingress_session_ref="ingress-1",
        revision=1,
        principal_ref="principal-1",
        subject_id="operator-1",
        subject_type=SubjectType.OPERATOR,
        authentication_method=AuthenticationMethod.OS_PEER_API_KEY,
        ingress_kind=IngressKind.INTERACTIVE_CLI,
        authenticated_peer_id="peer-1",
        transport_binding_digest="sha256:binding-1",
        issued_at=1.0,
        expires_at=100.0,
        revoked_at=None,
    )
    principal = PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="principal-1",
        revision=1,
        subject_id="operator-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("cap:test",),
        authenticated_at=1.0,
        expires_at=100.0,
    )
    mission = MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="mission-ref-1",
        revision=1,
        mission_id="mission-1",
        active=True,
        permitted_subject_ids=("operator-1",),
        target_scope=scope,
        permitted_capabilities=("cap:test",),
        permitted_stages=("test",),
        expires_at=100.0,
    )
    facts = (make_fact(target),) if include_fact else ()
    event_log = events if events is not None else []
    approval_store: ApprovalStore | None = None
    approval_lease: ApprovalExecutionLease | None = None
    if include_approval:
        approval_store = ApprovalStore()
        approval_snapshot = ApprovalAuthorizationSnapshot(
            schema_version="2.0",
            approval_ref="approval://test/1",
            revision=1,
            approval_id="approval-1",
            mission_id="mission-1",
            subject_id="operator-1",
            approver_subject_id="approver-1",
            permitted_root_action_ids=("action:test",),
            permitted_concrete_action_ids=("action:test",),
            permitted_capabilities=("cap:test",),
            permitted_killchain_stages=("test",),
            target_scope=scope,
            permitted_operation_ids=(),
            status=ApprovalStatus.ACTIVE,
            issued_at=1.0,
            expires_at=100.0,
            max_uses=1,
            remaining_uses=1,
        )
        approval_store.register_approval(approval_snapshot)
        approval_lease = ApprovalExecutionLease.open_graph(
            store=approval_store,
            approval_ref=approval_snapshot.approval_ref,
            approval_revision=approval_snapshot.revision,
            execution_graph_id="graph-1",
            root_action_id="action:test",
            mission_id="mission-1",
            subject_id="operator-1",
            capability="cap:test",
            killchain_stage="test",
            operation_id=None,
            targets=(target,),
            now=10.0,
        )
    authority = FakeAuthorityStore(
        ingress=ingress,
        principal=principal,
        mission=mission,
        facts=facts,
        events=event_log,
        approval_store=approval_store,
        approval_lease=approval_lease,
    )
    snapshots = tuple(make_credential(f"credential://test/{index}", target) for index in range(reference_count))
    reference_store = FakeReferenceStore(
        snapshots,
        checkout_id="checkout://test-1",
        events=event_log,
    )
    modes = access_modes or tuple(ReferenceAccessMode.MATERIAL for _ in range(reference_count))
    if len(modes) != reference_count:
        raise ValueError("one access mode is required per reference")
    reference_requests = tuple(
        ReferenceCheckoutRequest(
            reference=snapshot.reference,
            expected_kind=ReferenceKind.CREDENTIAL,
            expected_metadata_revision=snapshot.revision,
            expected_authorization_revision=snapshot.authorization.authorization_revision,
            required_action_id="action:test",
            required_capability="cap:test",
            targets=(target,),
            access_mode=mode,
        )
        for snapshot, mode in zip(snapshots, modes)
    )
    fact_requests = (
        (
            FactCheckoutRequest(
                fact_ref=facts[0].fact_ref,
                expected_revision=facts[0].revision,
                expected_payload_digest=facts[0].payload_digest,
                required_fact_type=facts[0].fact_type.value,
                target=target,
            ),
        )
        if facts
        else ()
    )
    request = ExecutorCheckoutRequestBundle(
        references=reference_requests,
        ingress_session=IngressSessionCheckoutRequest(
            lease_id="lease-1",
            lease_revision=1,
            bound_request_id="request-1",
            ingress_session_ref="ingress-1",
            expected_session_revision=1,
            principal_ref="principal-1",
            expected_principal_revision=1,
            transport_instance_id="transport-1",
            transport_binding_digest="sha256:binding-1",
        ),
        principal=PrincipalCheckoutRequest("principal-1", 1, "operator-1"),
        mission=MissionCheckoutRequest("mission-ref-1", 1, "operator-1"),
        approval=(
            ApprovalCheckoutRequest(
                approval_ref="approval://test/1",
                expected_revision=1,
                approval_graph_lease_id=approval_lease.lease_id,
                execution_graph_id="graph-1",
                root_action_id="action:test",
                concrete_action_id="action:test",
            )
            if approval_lease is not None
            else None
        ),
        facts=fact_requests,
        targets=(target,),
        attempt_group=ExecutionAttemptGroup("attempt-group-1", "execution-1", "graph-1"),
    )
    coordinator = ReferenceCheckoutCoordinator(
        ingress_store=authority,
        principal_store=authority,
        mission_store=authority,
        fact_store=authority,
        approval_store=authority if include_approval else None,
        reference_stores={ReferenceKind.CREDENTIAL: reference_store},
        clock=lambda: 10.0,
    )
    return CheckoutFixture(
        coordinator,
        authority,
        reference_store,
        request,
        target,
        approval_store,
    )
