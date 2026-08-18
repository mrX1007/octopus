"""Atomic, fenced PR-4 reference checkout coordinator.

The coordinator is deliberately dependency-injected.  There is no process
global resolver or caller-supplied material.  Participant locks are acquired in
a stable order for both snapshot checkout and the later material-open phase.
"""

from __future__ import annotations

import hmac
import math
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from core.actions.checkout_models import (
    ApprovalCheckoutRequest,
    CheckoutRecoveryRefV2,
    ExecutorCheckoutBundle,
    ExecutorCheckoutRequestBundle,
    FactCheckoutRequest,
    IngressSessionCheckoutRequest,
    MissionCheckoutRequest,
    PrincipalCheckoutRequest,
    ReferenceAccessMode,
    ReferenceCheckout,
    ReferenceCheckoutRequest,
    ReferenceKind,
)
from core.actions.materials import (
    ExecutorCheckoutHandleV2,
    ExecutorOpenedMaterialBundleV2,
    ExecutorOpenedMaterialV2,
)
from core.actions.reference_authorization import (
    ReferenceAuthorizationError,
    assert_reference_authorized,
)
from core.actions.reference_snapshots import (
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    ReferenceMetadataSnapshot,
    SensitiveArtifactReferenceSnapshot,
    SessionReferenceSnapshot,
    reference_has_active_state,
)
from core.actions.target_scope import ExtractedActionTarget, TargetScopePolicy
from core.actions.trusted_facts import TrustedFactSnapshot
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.ingress import IngressSessionAuthorizationSnapshot
from core.auth.missions import MissionAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot


class ReferenceCheckoutError(RuntimeError):
    """Stable fail-closed checkout error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@runtime_checkable
class CheckoutLockParticipantV2(Protocol):
    @property
    def checkout_lock_order_key(self) -> str: ...

    def acquire_checkout_lock(self) -> None: ...

    def release_checkout_lock(self) -> None: ...


class IngressSessionCheckoutStoreV2(CheckoutLockParticipantV2, Protocol):
    def checkout_ingress(
        self,
        request: IngressSessionCheckoutRequest,
    ) -> IngressSessionAuthorizationSnapshot: ...

    def assert_ingress_current(
        self,
        request: IngressSessionCheckoutRequest,
        snapshot: IngressSessionAuthorizationSnapshot,
    ) -> None: ...


class PrincipalCheckoutStoreV2(CheckoutLockParticipantV2, Protocol):
    def checkout_principal(
        self,
        request: PrincipalCheckoutRequest,
        ingress_session: IngressSessionAuthorizationSnapshot,
    ) -> PrincipalAuthorizationSnapshot: ...

    def assert_principal_current(
        self,
        request: PrincipalCheckoutRequest,
        snapshot: PrincipalAuthorizationSnapshot,
    ) -> None: ...


class MissionCheckoutStoreV2(CheckoutLockParticipantV2, Protocol):
    def checkout_mission(
        self,
        request: MissionCheckoutRequest,
        principal: PrincipalAuthorizationSnapshot,
    ) -> MissionAuthorizationSnapshot: ...

    def assert_mission_current(
        self,
        request: MissionCheckoutRequest,
        snapshot: MissionAuthorizationSnapshot,
    ) -> None: ...


class ApprovalCheckoutStoreV2(CheckoutLockParticipantV2, Protocol):
    def checkout_approval(
        self,
        request: ApprovalCheckoutRequest,
        ingress_session: IngressSessionAuthorizationSnapshot,
        principal: PrincipalAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
        targets: tuple[ExtractedActionTarget, ...],
    ) -> ApprovalExecutionLease: ...

    def assert_approval_current(
        self,
        request: ApprovalCheckoutRequest,
        lease: ApprovalExecutionLease,
    ) -> None: ...


class TrustedFactCheckoutStoreV2(CheckoutLockParticipantV2, Protocol):
    def checkout_fact(
        self,
        request: FactCheckoutRequest,
        ingress_session: IngressSessionAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
    ) -> TrustedFactSnapshot: ...

    def assert_fact_current(
        self,
        request: FactCheckoutRequest,
        snapshot: TrustedFactSnapshot,
    ) -> None: ...


class ReferenceStore(CheckoutLockParticipantV2, Protocol):
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
    ) -> ReferenceCheckout: ...

    def assert_reference_current(self, checkout: ReferenceCheckout) -> None: ...

    def open_material(self, checkout: ReferenceCheckout) -> ExecutorCheckoutHandleV2: ...

    def release_reference_checkout(self, checkout: ReferenceCheckout) -> None: ...


@dataclass(frozen=True)
class _ReferenceBinding:
    request: ReferenceCheckoutRequest
    store: ReferenceStore = field(repr=False, compare=False)
    checkout: ReferenceCheckout


@dataclass
class _CheckoutRecord:
    request: ExecutorCheckoutRequestBundle
    bundle: ExecutorCheckoutBundle
    participants: tuple[CheckoutLockParticipantV2, ...]
    reference_bindings: tuple[_ReferenceBinding, ...]
    material_handles: tuple[ExecutorCheckoutHandleV2, ...] = ()
    opened_bundle: ExecutorOpenedMaterialBundleV2 | None = None
    material_open_failed: bool = False
    closed: bool = False


def _require_lock_key(participant: CheckoutLockParticipantV2) -> str:
    key = participant.checkout_lock_order_key
    if type(key) is not str or not key or any(ord(character) < 32 for character in key):
        raise ReferenceCheckoutError("checkout_lock_order_key_invalid")
    return key


def _metadata_matches_kind(metadata: ReferenceMetadataSnapshot, kind: ReferenceKind) -> bool:
    if kind is ReferenceKind.CREDENTIAL:
        return type(metadata) is CredentialReferenceSnapshot
    if kind is ReferenceKind.SESSION:
        return type(metadata) is SessionReferenceSnapshot
    if kind is ReferenceKind.ARTIFACT:
        return type(metadata) in (
            NonSensitiveArtifactReferenceSnapshot,
            SensitiveArtifactReferenceSnapshot,
        )
    if kind is ReferenceKind.PIVOT_ROUTE:
        return type(metadata) is PivotRouteReferenceSnapshot
    if kind is ReferenceKind.C2_RESOURCE:
        return type(metadata) is C2ReferenceSnapshot
    if kind is ReferenceKind.DEPLOYMENT:
        return type(metadata) is DeploymentReferenceSnapshot
    # Enrollment is added atomically by PR-15. A generic C2 resource must never
    # be accepted for that distinct lifecycle.
    return False


def _is_checkout_lock_participant(store: object) -> bool:
    if isinstance(store, CheckoutLockParticipantV2):
        return True
    return (
        hasattr(store, "checkout_lock_order_key")
        and hasattr(store, "acquire_checkout_lock")
        and hasattr(store, "release_checkout_lock")
    )


class ReferenceCheckoutCoordinator:
    """Coordinate all immutable authorization snapshots and reference fences."""

    def __init__(
        self,
        *,
        ingress_store: IngressSessionCheckoutStoreV2,
        principal_store: PrincipalCheckoutStoreV2,
        mission_store: MissionCheckoutStoreV2,
        reference_stores: Mapping[ReferenceKind, ReferenceStore],
        approval_store: ApprovalCheckoutStoreV2 | None = None,
        fact_store: TrustedFactCheckoutStoreV2 | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not _is_checkout_lock_participant(ingress_store):
            raise TypeError("checkout_ingress_store_invalid")
        if not _is_checkout_lock_participant(principal_store):
            raise TypeError("checkout_principal_store_invalid")
        if not _is_checkout_lock_participant(mission_store):
            raise TypeError("checkout_mission_store_invalid")
        if approval_store is not None and not _is_checkout_lock_participant(approval_store):
            raise TypeError("checkout_approval_store_invalid")
        if fact_store is not None and not _is_checkout_lock_participant(fact_store):
            raise TypeError("checkout_fact_store_invalid")
        if not callable(clock):
            raise TypeError("checkout_clock_invalid")

        normalized_reference_stores: dict[ReferenceKind, ReferenceStore] = {}
        for kind, store in reference_stores.items():
            if type(kind) is not ReferenceKind:
                raise TypeError("checkout_reference_store_kind_invalid")
            if not _is_checkout_lock_participant(store):
                raise TypeError("checkout_reference_store_invalid")
            normalized_reference_stores[kind] = store

        self._ingress_store = ingress_store
        self._principal_store = principal_store
        self._mission_store = mission_store
        self._approval_store = approval_store
        self._fact_store = fact_store
        self._reference_stores = normalized_reference_stores
        self._clock = clock
        self._lock = threading.RLock()
        self._records: dict[str, _CheckoutRecord] = {}
        self._recovery_bindings: dict[tuple[str, str], ExecutorCheckoutBundle] = {}

    def checkout_many(
        self,
        request: ExecutorCheckoutRequestBundle,
    ) -> ExecutorCheckoutBundle:
        if type(request) is not ExecutorCheckoutRequestBundle:
            raise TypeError("checkout_request_bundle_invalid")
        reference_pairs = self._reference_store_pairs(request.references)
        participants = self._canonical_participants(request, reference_pairs)
        acquired_references: list[tuple[ReferenceStore, ReferenceCheckout]] = []

        with self._lock, self._locked(participants):
            try:
                ingress = self._ingress_store.checkout_ingress(request.ingress_session)
                self._validate_ingress(request.ingress_session, ingress)
                principal = self._principal_store.checkout_principal(request.principal, ingress)
                self._validate_principal(request.principal, principal, ingress)
                mission = self._mission_store.checkout_mission(request.mission, principal)
                self._validate_mission(request, mission, principal)
                approval = self._checkout_approval(request, ingress, principal, mission)
                facts = self._checkout_facts(request, ingress, mission)

                bindings: list[_ReferenceBinding] = []
                for reference_request, store in reference_pairs:
                    receipt = store.checkout(
                        reference=reference_request.reference,
                        expected_metadata_revision=reference_request.expected_metadata_revision,
                        expected_authorization_revision=reference_request.expected_authorization_revision,
                        ingress_session=ingress,
                        mission=mission,
                        action_id=reference_request.required_action_id,
                        targets=reference_request.targets,
                    )
                    acquired_references.append((store, receipt))
                    self._validate_reference(
                        reference_request,
                        receipt,
                        mission=mission,
                        principal=principal,
                        checkout_targets=request.targets,
                    )
                    bindings.append(_ReferenceBinding(reference_request, store, receipt))

                checkout_id, fence_generation = self._bundle_fence(bindings)
                if checkout_id in self._records:
                    raise ReferenceCheckoutError("checkout_id_already_registered")
                bundle = ExecutorCheckoutBundle._from_coordinator(
                    checkout_id=checkout_id,
                    ingress_session=ingress,
                    principal=principal,
                    mission=mission,
                    approval_graph_lease=approval,
                    facts=facts,
                    references=tuple(binding.checkout for binding in bindings),
                    targets=request.targets,
                    fence_generation=fence_generation,
                    issuer=self,
                )
                self._records[checkout_id] = _CheckoutRecord(
                    request=request,
                    bundle=bundle,
                    participants=participants,
                    reference_bindings=tuple(bindings),
                )
                return bundle
            except Exception:
                self._release_reference_receipts(acquired_references)
                raise

    def open_materials(
        self,
        checkout: ExecutorCheckoutBundle,
    ) -> ExecutorOpenedMaterialBundleV2:
        with self._lock:
            record = self._require_record(checkout)
            if record.opened_bundle is not None:
                raise ReferenceCheckoutError("checkout_materials_already_opened")
            if record.material_open_failed:
                raise ReferenceCheckoutError("checkout_material_open_previously_failed")
            with self._locked(record.participants):
                self._assert_record_current_locked(record)
                opened: list[ExecutorOpenedMaterialV2] = []
                opened_handles: list[ExecutorCheckoutHandleV2] = []
                try:
                    for binding in record.reference_bindings:
                        if binding.request.access_mode is ReferenceAccessMode.METADATA_ONLY:
                            continue
                        handle = binding.store.open_material(binding.checkout)
                        opened_handles.append(handle)
                        material = ExecutorOpenedMaterialV2(
                            reference=binding.checkout.metadata.reference,
                            reference_kind=binding.request.expected_kind,
                            checkout_id=checkout.checkout_id,
                            metadata=binding.checkout.metadata,
                            checkout_handle=handle,
                        )
                        opened.append(material)
                    opened_bundle = ExecutorOpenedMaterialBundleV2(
                        checkout_id=checkout.checkout_id,
                        materials=tuple(opened),
                    )
                except Exception:
                    record.material_open_failed = True
                    self._close_material_handles(tuple(opened_handles))
                    raise
                record.material_handles = tuple(material.checkout_handle for material in opened)
                record.opened_bundle = opened_bundle
                return opened_bundle

    def checkpoint_existing_recovery_state(
        self,
        checkout: ExecutorCheckoutBundle,
        current_ref: CheckoutRecoveryRefV2,
    ) -> CheckoutRecoveryRefV2:
        if type(current_ref) is not CheckoutRecoveryRefV2:
            raise TypeError("checkout_recovery_ref_invalid")
        with self._lock:
            record = self._require_record(checkout)
            if (
                current_ref.checkout_id != checkout.checkout_id
                or current_ref.fence_generation != checkout.fence_generation
            ):
                raise ReferenceCheckoutError("checkout_recovery_fence_mismatch")
            with self._locked(record.participants):
                self._assert_record_current_locked(record)
                key = (current_ref.journal_ref, current_ref.journal_digest)
                existing = self._recovery_bindings.get(key)
                if existing is not None and existing is not checkout:
                    raise ReferenceCheckoutError("checkout_recovery_ref_conflict")
                self._recovery_bindings[key] = checkout
                return current_ref

    def reopen_fenced(
        self,
        recovery_ref: CheckoutRecoveryRefV2,
    ) -> ExecutorCheckoutBundle:
        if type(recovery_ref) is not CheckoutRecoveryRefV2:
            raise TypeError("checkout_recovery_ref_invalid")
        with self._lock:
            bundle = self._recovery_bindings.get((recovery_ref.journal_ref, recovery_ref.journal_digest))
            if bundle is None:
                raise ReferenceCheckoutError("checkout_recovery_ref_not_found")
            if (
                bundle.checkout_id != recovery_ref.checkout_id
                or bundle.fence_generation != recovery_ref.fence_generation
            ):
                raise ReferenceCheckoutError("checkout_recovery_fence_mismatch")
            record = self._require_record(bundle)
            with self._locked(record.participants):
                self._assert_record_current_locked(record)
            return bundle

    def _assert_bundle_current(self, bundle: ExecutorCheckoutBundle) -> None:
        with self._lock:
            record = self._require_record(bundle)
            with self._locked(record.participants):
                self._assert_record_current_locked(record)

    def _close_bundle(self, bundle: ExecutorCheckoutBundle) -> None:
        with self._lock:
            record = self._require_record(bundle, allow_closed=True)
            if record.closed:
                return
            record.closed = True
            failures: list[Exception] = []
            with self._locked(record.participants):
                failures.extend(self._close_material_handles(record.material_handles))
                failures.extend(
                    self._release_reference_receipts(
                        [(binding.store, binding.checkout) for binding in record.reference_bindings],
                        suppress=True,
                    )
                )
            if failures:
                raise ReferenceCheckoutError("checkout_close_failed") from failures[0]

    def _assert_record_current_locked(self, record: _CheckoutRecord) -> None:
        request = record.request
        bundle = record.bundle
        self._ingress_store.assert_ingress_current(request.ingress_session, bundle.ingress_session)
        self._validate_ingress(request.ingress_session, bundle.ingress_session)
        self._principal_store.assert_principal_current(request.principal, bundle.principal)
        self._validate_principal(request.principal, bundle.principal, bundle.ingress_session)
        self._mission_store.assert_mission_current(request.mission, bundle.mission)
        self._validate_mission(request, bundle.mission, bundle.principal)
        if request.approval is not None:
            if self._approval_store is None or bundle.approval_graph_lease is None:
                raise ReferenceCheckoutError("checkout_approval_store_unavailable")
            self._approval_store.assert_approval_current(
                request.approval,
                bundle.approval_graph_lease,
            )
            self._validate_approval(
                request.approval,
                bundle.approval_graph_lease,
                bundle.mission,
                bundle.principal,
            )
        if len(request.facts) != len(bundle.facts):
            raise ReferenceCheckoutError("checkout_fact_bundle_length_mismatch")
        for fact_request, fact in zip(request.facts, bundle.facts):
            if self._fact_store is None:
                raise ReferenceCheckoutError("checkout_fact_store_unavailable")
            self._fact_store.assert_fact_current(fact_request, fact)
            self._validate_fact(
                fact_request,
                fact,
                bundle.mission,
                checkout_targets=request.targets,
            )
        for binding in record.reference_bindings:
            binding.store.assert_reference_current(binding.checkout)
            self._validate_reference(
                binding.request,
                binding.checkout,
                mission=bundle.mission,
                principal=bundle.principal,
                checkout_targets=request.targets,
            )

    def _checkout_approval(
        self,
        request: ExecutorCheckoutRequestBundle,
        ingress: IngressSessionAuthorizationSnapshot,
        principal: PrincipalAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
    ) -> ApprovalExecutionLease | None:
        approval_request = request.approval
        if approval_request is None:
            return None
        if self._approval_store is None:
            raise ReferenceCheckoutError("checkout_approval_store_unavailable")
        lease = self._approval_store.checkout_approval(
            approval_request,
            ingress,
            principal,
            mission,
            request.targets,
        )
        self._validate_approval(approval_request, lease, mission, principal)
        return lease

    def _checkout_facts(
        self,
        request: ExecutorCheckoutRequestBundle,
        ingress: IngressSessionAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
    ) -> tuple[TrustedFactSnapshot, ...]:
        if not request.facts:
            return ()
        if self._fact_store is None:
            raise ReferenceCheckoutError("checkout_fact_store_unavailable")
        snapshots: list[TrustedFactSnapshot] = []
        for fact_request in request.facts:
            snapshot = self._fact_store.checkout_fact(fact_request, ingress, mission)
            self._validate_fact(
                fact_request,
                snapshot,
                mission,
                checkout_targets=request.targets,
            )
            snapshots.append(snapshot)
        return tuple(snapshots)

    def _reference_store_pairs(
        self,
        requests: tuple[ReferenceCheckoutRequest, ...],
    ) -> tuple[tuple[ReferenceCheckoutRequest, ReferenceStore], ...]:
        pairs: list[tuple[ReferenceCheckoutRequest, ReferenceStore]] = []
        for request in requests:
            store = self._reference_stores.get(request.expected_kind)
            if store is None:
                raise ReferenceCheckoutError("checkout_reference_store_unavailable")
            pairs.append((request, store))
        return tuple(pairs)

    def _canonical_participants(
        self,
        request: ExecutorCheckoutRequestBundle,
        reference_pairs: tuple[tuple[ReferenceCheckoutRequest, ReferenceStore], ...],
    ) -> tuple[CheckoutLockParticipantV2, ...]:
        candidates: list[CheckoutLockParticipantV2] = [
            self._ingress_store,
            self._principal_store,
            self._mission_store,
        ]
        if request.approval is not None:
            if self._approval_store is None:
                raise ReferenceCheckoutError("checkout_approval_store_unavailable")
            candidates.append(self._approval_store)
        if request.facts:
            if self._fact_store is None:
                raise ReferenceCheckoutError("checkout_fact_store_unavailable")
            candidates.append(self._fact_store)
        candidates.extend(store for _, store in reference_pairs)

        unique: dict[int, CheckoutLockParticipantV2] = {}
        keys: dict[str, CheckoutLockParticipantV2] = {}
        for participant in candidates:
            unique[id(participant)] = participant
        for participant in unique.values():
            key = _require_lock_key(participant)
            previous = keys.get(key)
            if previous is not None and previous is not participant:
                raise ReferenceCheckoutError("checkout_lock_order_key_duplicate")
            keys[key] = participant
        return tuple(keys[key] for key in sorted(keys))

    @contextmanager
    def _locked(
        self,
        participants: tuple[CheckoutLockParticipantV2, ...],
    ) -> Iterator[None]:
        acquired: list[CheckoutLockParticipantV2] = []
        try:
            for participant in participants:
                participant.acquire_checkout_lock()
                acquired.append(participant)
            yield
        finally:
            first_failure: Exception | None = None
            for participant in reversed(acquired):
                try:
                    participant.release_checkout_lock()
                except Exception as exc:
                    if first_failure is None:
                        first_failure = exc
            if first_failure is not None:
                raise ReferenceCheckoutError("checkout_lock_release_failed") from first_failure

    def _require_record(
        self,
        bundle: ExecutorCheckoutBundle,
        *,
        allow_closed: bool = False,
    ) -> _CheckoutRecord:
        if type(bundle) is not ExecutorCheckoutBundle:
            raise TypeError("checkout_bundle_invalid")
        record = self._records.get(bundle.checkout_id)
        if record is None or record.bundle is not bundle:
            raise ReferenceCheckoutError("checkout_bundle_not_canonical")
        if record.closed and not allow_closed:
            raise ReferenceCheckoutError("checkout_bundle_closed")
        return record

    def _bundle_fence(
        self,
        bindings: list[_ReferenceBinding],
    ) -> tuple[str, int]:
        if not bindings:
            return f"checkout://{uuid.uuid4()}", 1
        checkout_ids = {binding.checkout.lease_token.checkout_id for binding in bindings}
        generations = {binding.checkout.lease_token.fence_generation for binding in bindings}
        if len(checkout_ids) != 1 or len(generations) != 1:
            raise ReferenceCheckoutError("checkout_reference_fence_group_mismatch")
        return next(iter(checkout_ids)), next(iter(generations))

    def _validate_ingress(
        self,
        request: IngressSessionCheckoutRequest,
        snapshot: IngressSessionAuthorizationSnapshot,
    ) -> None:
        if type(snapshot) is not IngressSessionAuthorizationSnapshot:
            raise ReferenceCheckoutError("checkout_ingress_snapshot_invalid")
        if (
            snapshot.ingress_session_ref != request.ingress_session_ref
            or snapshot.revision != request.expected_session_revision
            or snapshot.principal_ref != request.principal_ref
            or not hmac.compare_digest(
                snapshot.transport_binding_digest,
                request.transport_binding_digest,
            )
        ):
            raise ReferenceCheckoutError("checkout_ingress_identity_mismatch")
        now = self._now()
        if snapshot.revoked_at is not None or now < snapshot.issued_at or now >= snapshot.expires_at:
            raise ReferenceCheckoutError("checkout_ingress_inactive")

    def _validate_principal(
        self,
        request: PrincipalCheckoutRequest,
        snapshot: PrincipalAuthorizationSnapshot,
        ingress: IngressSessionAuthorizationSnapshot,
    ) -> None:
        if type(snapshot) is not PrincipalAuthorizationSnapshot:
            raise ReferenceCheckoutError("checkout_principal_snapshot_invalid")
        if (
            snapshot.principal_ref != request.principal_ref
            or snapshot.revision != request.expected_revision
            or snapshot.subject_id != request.subject_id
            or snapshot.principal_ref != ingress.principal_ref
            or snapshot.subject_id != ingress.subject_id
            or snapshot.subject_type is not ingress.subject_type
        ):
            raise ReferenceCheckoutError("checkout_ingress_principal_identity_mismatch")
        if not snapshot.active or (snapshot.expires_at is not None and snapshot.expires_at <= self._now()):
            raise ReferenceCheckoutError("checkout_principal_inactive")

    def _validate_mission(
        self,
        request: ExecutorCheckoutRequestBundle,
        snapshot: MissionAuthorizationSnapshot,
        principal: PrincipalAuthorizationSnapshot,
    ) -> None:
        mission_request = request.mission
        if type(snapshot) is not MissionAuthorizationSnapshot:
            raise ReferenceCheckoutError("checkout_mission_snapshot_invalid")
        if (
            snapshot.mission_ref != mission_request.mission_ref
            or snapshot.revision != mission_request.expected_revision
            or mission_request.subject_id != principal.subject_id
            or principal.subject_id not in snapshot.permitted_subject_ids
        ):
            raise ReferenceCheckoutError("checkout_mission_identity_mismatch")
        if not snapshot.active or (snapshot.expires_at is not None and snapshot.expires_at <= self._now()):
            raise ReferenceCheckoutError("checkout_mission_inactive")
        scope = TargetScopePolicy.evaluate(request.targets, snapshot.target_scope)
        if not scope.allowed:
            raise ReferenceCheckoutError("checkout_mission_scope_denied")
        if any(item.required_capability not in snapshot.permitted_capabilities for item in request.references):
            raise ReferenceCheckoutError("checkout_mission_capability_denied")
        if any(item.required_capability not in principal.capabilities for item in request.references):
            raise ReferenceCheckoutError("checkout_principal_capability_denied")

    @staticmethod
    def _validate_approval(
        request: ApprovalCheckoutRequest,
        lease: ApprovalExecutionLease,
        mission: MissionAuthorizationSnapshot,
        principal: PrincipalAuthorizationSnapshot,
    ) -> None:
        if type(lease) is not ApprovalExecutionLease:
            raise ReferenceCheckoutError("checkout_approval_graph_lease_invalid")
        if (
            lease.lease_id != request.approval_graph_lease_id
            or lease.approval_ref != request.approval_ref
            or lease.approval_revision != request.expected_revision
            or lease.execution_graph_id != request.execution_graph_id
            or lease.root_action_id != request.root_action_id
            or lease.mission_id != mission.mission_id
            or lease.subject_id != principal.subject_id
        ):
            raise ReferenceCheckoutError("checkout_approval_graph_identity_mismatch")

    def _validate_fact(
        self,
        request: FactCheckoutRequest,
        snapshot: TrustedFactSnapshot,
        mission: MissionAuthorizationSnapshot,
        *,
        checkout_targets: tuple[ExtractedActionTarget, ...],
    ) -> None:
        if type(snapshot) is not TrustedFactSnapshot:
            raise ReferenceCheckoutError("checkout_fact_snapshot_invalid")
        if (
            snapshot.fact_ref != request.fact_ref
            or snapshot.revision != request.expected_revision
            or not hmac.compare_digest(
                snapshot.payload_digest,
                request.expected_payload_digest,
            )
            or snapshot.fact_type.value != request.required_fact_type
            or snapshot.target != request.target.normalized_value
            or snapshot.mission_id != mission.mission_id
        ):
            raise ReferenceCheckoutError("checkout_fact_identity_mismatch")
        if request.target not in checkout_targets:
            raise ReferenceCheckoutError("checkout_fact_target_not_extracted")
        if not snapshot.satisfies_positive_precondition or (
            snapshot.expires_at is not None and snapshot.expires_at <= self._now()
        ):
            raise ReferenceCheckoutError("checkout_fact_not_trusted")

    def _validate_reference(
        self,
        request: ReferenceCheckoutRequest,
        receipt: ReferenceCheckout,
        *,
        mission: MissionAuthorizationSnapshot,
        principal: PrincipalAuthorizationSnapshot,
        checkout_targets: tuple[ExtractedActionTarget, ...],
    ) -> None:
        if type(receipt) is not ReferenceCheckout:
            raise ReferenceCheckoutError("checkout_reference_receipt_invalid")
        metadata = receipt.metadata
        token = receipt.lease_token
        if (
            metadata.reference != request.reference
            or token.reference != request.reference
            or metadata.revision != request.expected_metadata_revision
            or metadata.authorization.authorization_revision != request.expected_authorization_revision
        ):
            raise ReferenceCheckoutError("checkout_reference_identity_mismatch")
        if not _metadata_matches_kind(metadata, request.expected_kind):
            raise ReferenceCheckoutError("checkout_reference_kind_mismatch")
        if not reference_has_active_state(metadata):
            raise ReferenceCheckoutError("checkout_reference_inactive")
        if (
            principal.subject_id == metadata.authorization.owner_subject_id
            and principal.subject_type is not metadata.authorization.owner_subject_type
        ):
            raise ReferenceCheckoutError("reference_owner_subject_type_mismatch")
        if any(target not in checkout_targets for target in request.targets):
            raise ReferenceCheckoutError("checkout_reference_target_not_extracted")
        try:
            assert_reference_authorized(
                metadata,
                expected_metadata_revision=request.expected_metadata_revision,
                expected_authorization_revision=request.expected_authorization_revision,
                mission_id=mission.mission_id,
                subject_id=principal.subject_id,
                action_id=request.required_action_id,
                required_capability=request.required_capability,
                targets=request.targets,
                now=self._now(),
            )
        except ReferenceAuthorizationError as exc:
            raise ReferenceCheckoutError(exc.code) from exc

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ReferenceCheckoutError("checkout_clock_value_invalid")
        return float(value)

    @staticmethod
    def _close_material_handles(
        handles: tuple[ExecutorCheckoutHandleV2, ...],
    ) -> list[Exception]:
        failures: list[Exception] = []
        for handle in reversed(handles):
            try:
                handle.close_checkout()
            except Exception as exc:
                failures.append(exc)
        return failures

    @staticmethod
    def _release_reference_receipts(
        receipts: list[tuple[ReferenceStore, ReferenceCheckout]],
        *,
        suppress: bool = False,
    ) -> list[Exception]:
        failures: list[Exception] = []
        for store, receipt in reversed(receipts):
            try:
                store.release_reference_checkout(receipt)
            except Exception as exc:
                failures.append(exc)
        if failures and not suppress:
            raise ReferenceCheckoutError("checkout_reference_release_failed") from failures[0]
        return failures


__all__ = [
    "ApprovalCheckoutStoreV2",
    "CheckoutLockParticipantV2",
    "IngressSessionCheckoutStoreV2",
    "MissionCheckoutStoreV2",
    "PrincipalCheckoutStoreV2",
    "ReferenceCheckoutCoordinator",
    "ReferenceCheckoutError",
    "ReferenceStore",
    "TrustedFactCheckoutStoreV2",
]
