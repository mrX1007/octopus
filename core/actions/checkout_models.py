"""Closed PR-4 checkout requests, receipts, and fenced bundle models.

This module deliberately contains no resolver registry and no material handle.
The request side carries only immutable metadata expectations. Mutable lease
authority stays in :mod:`core.actions.reference_checkout` and is reachable
only through a coordinator-issued :class:`ExecutorCheckoutBundle`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, NoReturn, Protocol, SupportsIndex, cast

from core.actions.reference_snapshots import ReferenceMetadataSnapshot
from core.actions.target_scope import ExtractedActionTarget
from core.actions.trusted_facts import TrustedFactSnapshot
from core.auth.approval_leases import ApprovalExecutionLease
from core.auth.ingress import IngressSessionAuthorizationSnapshot
from core.auth.missions import MissionAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot

if TYPE_CHECKING:
    from typing_extensions import Self


def _require_non_empty(name: str, value: object) -> None:
    if type(value) is not str or not value or any(ord(character) < 32 for character in value):
        raise ValueError(f"checkout_{name}_invalid")


def _require_revision(name: str, value: object) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"checkout_{name}_invalid")


def _require_targets(name: str, values: object) -> None:
    if type(values) is not tuple or any(type(value) is not ExtractedActionTarget for value in values):
        raise ValueError(f"checkout_{name}_invalid")
    if len(values) != len(set(values)):
        raise ValueError(f"checkout_{name}_duplicate")


class ReferenceKind(str, Enum):
    CREDENTIAL = "credential"
    SESSION = "session"
    ARTIFACT = "artifact"
    PIVOT_ROUTE = "pivot_route"
    C2_RESOURCE = "c2_resource"
    C2_ENROLLMENT = "c2_enrollment"
    DEPLOYMENT = "deployment"


class ReferenceAccessMode(str, Enum):
    METADATA_ONLY = "metadata_only"
    MATERIAL = "material"


@dataclass(frozen=True)
class ReferenceCheckoutRequest:
    reference: str
    expected_kind: ReferenceKind
    expected_metadata_revision: int
    expected_authorization_revision: int
    required_action_id: str
    required_capability: str
    targets: tuple[ExtractedActionTarget, ...]
    access_mode: ReferenceAccessMode

    def __post_init__(self) -> None:
        for name in ("reference", "required_action_id", "required_capability"):
            _require_non_empty(name, getattr(self, name))
        if type(self.expected_kind) is not ReferenceKind:
            raise ValueError("checkout_reference_kind_invalid")
        _require_revision("metadata_revision", self.expected_metadata_revision)
        _require_revision("authorization_revision", self.expected_authorization_revision)
        _require_targets("reference_targets", self.targets)
        if type(self.access_mode) is not ReferenceAccessMode:
            raise ValueError("checkout_reference_access_mode_invalid")


@dataclass(frozen=True, repr=False)
class IngressSessionCheckoutRequest:
    lease_id: str
    lease_revision: int
    bound_request_id: str
    ingress_session_ref: str
    expected_session_revision: int
    principal_ref: str
    expected_principal_revision: int
    transport_instance_id: str
    transport_binding_digest: str

    def __post_init__(self) -> None:
        for name in (
            "lease_id",
            "bound_request_id",
            "ingress_session_ref",
            "principal_ref",
            "transport_instance_id",
            "transport_binding_digest",
        ):
            _require_non_empty(name, getattr(self, name))
        for name in (
            "lease_revision",
            "expected_session_revision",
            "expected_principal_revision",
        ):
            _require_revision(name, getattr(self, name))


@dataclass(frozen=True)
class PrincipalCheckoutRequest:
    principal_ref: str
    expected_revision: int
    subject_id: str

    def __post_init__(self) -> None:
        _require_non_empty("principal_ref", self.principal_ref)
        _require_revision("principal_revision", self.expected_revision)
        _require_non_empty("principal_subject_id", self.subject_id)


@dataclass(frozen=True)
class MissionCheckoutRequest:
    mission_ref: str
    expected_revision: int
    subject_id: str

    def __post_init__(self) -> None:
        _require_non_empty("mission_ref", self.mission_ref)
        _require_revision("mission_revision", self.expected_revision)
        _require_non_empty("mission_subject_id", self.subject_id)


@dataclass(frozen=True, repr=False)
class ApprovalCheckoutRequest:
    approval_ref: str
    expected_revision: int
    approval_graph_lease_id: str
    execution_graph_id: str
    root_action_id: str
    concrete_action_id: str

    def __post_init__(self) -> None:
        for name in (
            "approval_ref",
            "approval_graph_lease_id",
            "execution_graph_id",
            "root_action_id",
            "concrete_action_id",
        ):
            _require_non_empty(name, getattr(self, name))
        _require_revision("approval_revision", self.expected_revision)


@dataclass(frozen=True)
class FactCheckoutRequest:
    fact_ref: str
    expected_revision: int
    expected_payload_digest: str
    required_fact_type: str
    target: ExtractedActionTarget

    def __post_init__(self) -> None:
        for name in ("fact_ref", "expected_payload_digest", "required_fact_type"):
            _require_non_empty(name, getattr(self, name))
        _require_revision("fact_revision", self.expected_revision)
        if type(self.target) is not ExtractedActionTarget:
            raise ValueError("checkout_fact_target_invalid")


@dataclass(frozen=True)
class ExecutionAttemptGroup:
    attempt_group_id: str
    root_execution_id: str
    execution_graph_id: str

    def __post_init__(self) -> None:
        for name in ("attempt_group_id", "root_execution_id", "execution_graph_id"):
            _require_non_empty(name, getattr(self, name))


@dataclass(frozen=True, repr=False)
class ExecutorCheckoutRequestBundle:
    references: tuple[ReferenceCheckoutRequest, ...]
    ingress_session: IngressSessionCheckoutRequest
    principal: PrincipalCheckoutRequest
    mission: MissionCheckoutRequest
    approval: ApprovalCheckoutRequest | None
    facts: tuple[FactCheckoutRequest, ...]
    targets: tuple[ExtractedActionTarget, ...]
    attempt_group: ExecutionAttemptGroup

    def __post_init__(self) -> None:
        if type(self.references) is not tuple or any(
            type(item) is not ReferenceCheckoutRequest for item in self.references
        ):
            raise ValueError("checkout_references_invalid")
        references = tuple(item.reference for item in self.references)
        if len(references) != len(set(references)):
            raise ValueError("checkout_reference_duplicate")
        if type(self.ingress_session) is not IngressSessionCheckoutRequest:
            raise ValueError("checkout_ingress_request_invalid")
        if type(self.principal) is not PrincipalCheckoutRequest:
            raise ValueError("checkout_principal_request_invalid")
        if type(self.mission) is not MissionCheckoutRequest:
            raise ValueError("checkout_mission_request_invalid")
        if self.approval is not None and type(self.approval) is not ApprovalCheckoutRequest:
            raise ValueError("checkout_approval_request_invalid")
        if type(self.facts) is not tuple or any(type(item) is not FactCheckoutRequest for item in self.facts):
            raise ValueError("checkout_facts_invalid")
        fact_refs = tuple(item.fact_ref for item in self.facts)
        if len(fact_refs) != len(set(fact_refs)):
            raise ValueError("checkout_fact_duplicate")
        _require_targets("targets", self.targets)
        if type(self.attempt_group) is not ExecutionAttemptGroup:
            raise ValueError("checkout_attempt_group_invalid")

        ingress = self.ingress_session
        if (
            ingress.principal_ref != self.principal.principal_ref
            or ingress.expected_principal_revision != self.principal.expected_revision
        ):
            raise ValueError("checkout_ingress_principal_identity_mismatch")
        if self.principal.subject_id != self.mission.subject_id:
            raise ValueError("checkout_principal_mission_subject_mismatch")
        if self.approval is not None:
            if self.approval.execution_graph_id != self.attempt_group.execution_graph_id:
                raise ValueError("checkout_approval_execution_graph_mismatch")
            if any(item.required_action_id != self.approval.concrete_action_id for item in self.references):
                raise ValueError("checkout_reference_concrete_action_mismatch")


@dataclass(frozen=True)
class ReferenceLeaseToken:
    reference: str
    metadata_revision: int
    authorization_revision: int
    fence_generation: int
    checkout_id: str

    def __post_init__(self) -> None:
        _require_non_empty("lease_reference", self.reference)
        _require_revision("lease_metadata_revision", self.metadata_revision)
        _require_revision("lease_authorization_revision", self.authorization_revision)
        _require_revision("lease_fence_generation", self.fence_generation)
        _require_non_empty("lease_checkout_id", self.checkout_id)


@dataclass(frozen=True, repr=False)
class ReferenceCheckout:
    metadata: ReferenceMetadataSnapshot
    lease_token: ReferenceLeaseToken

    def __post_init__(self) -> None:
        if self.metadata.reference != self.metadata.authorization.reference:
            raise ValueError("reference_authorization_identity_mismatch")
        token = self.lease_token
        if type(token) is not ReferenceLeaseToken:
            raise ValueError("checkout_reference_lease_token_invalid")
        if (
            token.reference != self.metadata.reference
            or token.metadata_revision != self.metadata.revision
            or token.authorization_revision != self.metadata.authorization.authorization_revision
        ):
            raise ValueError("checkout_reference_lease_identity_mismatch")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ReferenceCheckout is non-serializable")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ReferenceCheckout is non-serializable")


@dataclass(frozen=True)
class CheckoutRecoveryRefV2:
    checkout_id: str
    fence_generation: int
    journal_ref: str
    journal_digest: str

    def __post_init__(self) -> None:
        _require_non_empty("recovery_checkout_id", self.checkout_id)
        _require_revision("recovery_fence_generation", self.fence_generation)
        _require_non_empty("recovery_journal_ref", self.journal_ref)
        _require_non_empty("recovery_journal_digest", self.journal_digest)


class _ExecutorCheckoutBundleIssuerV2(Protocol):
    def _assert_bundle_current(self, bundle: ExecutorCheckoutBundle) -> None: ...

    def _close_bundle(self, bundle: ExecutorCheckoutBundle) -> None: ...


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ExecutorCheckoutBundle:
    checkout_id: str
    ingress_session: IngressSessionAuthorizationSnapshot
    principal: PrincipalAuthorizationSnapshot
    mission: MissionAuthorizationSnapshot
    approval_graph_lease: ApprovalExecutionLease | None
    facts: tuple[TrustedFactSnapshot, ...]
    references: tuple[ReferenceCheckout, ...]
    targets: tuple[ExtractedActionTarget, ...]
    fence_generation: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ExecutorCheckoutBundle is coordinator-issued only")

    @classmethod
    def _from_coordinator(
        cls,
        *,
        checkout_id: str,
        ingress_session: IngressSessionAuthorizationSnapshot,
        principal: PrincipalAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
        approval_graph_lease: ApprovalExecutionLease | None,
        facts: tuple[TrustedFactSnapshot, ...],
        references: tuple[ReferenceCheckout, ...],
        targets: tuple[ExtractedActionTarget, ...],
        fence_generation: int,
        issuer: _ExecutorCheckoutBundleIssuerV2,
    ) -> Self:
        _require_non_empty("bundle_checkout_id", checkout_id)
        _require_revision("bundle_fence_generation", fence_generation)
        if type(ingress_session) is not IngressSessionAuthorizationSnapshot:
            raise ValueError("checkout_ingress_snapshot_invalid")
        if type(principal) is not PrincipalAuthorizationSnapshot:
            raise ValueError("checkout_principal_snapshot_invalid")
        if type(mission) is not MissionAuthorizationSnapshot:
            raise ValueError("checkout_mission_snapshot_invalid")
        if approval_graph_lease is not None and type(approval_graph_lease) is not ApprovalExecutionLease:
            raise ValueError("checkout_approval_graph_lease_invalid")
        if type(facts) is not tuple or any(type(item) is not TrustedFactSnapshot for item in facts):
            raise ValueError("checkout_fact_snapshots_invalid")
        if type(references) is not tuple or any(type(item) is not ReferenceCheckout for item in references):
            raise ValueError("checkout_reference_receipts_invalid")
        if any(
            item.lease_token.checkout_id != checkout_id or item.lease_token.fence_generation != fence_generation
            for item in references
        ):
            raise ValueError("checkout_reference_bundle_fence_mismatch")
        _require_targets("bundle_targets", targets)

        instance = object.__new__(cls)
        object.__setattr__(instance, "checkout_id", checkout_id)
        object.__setattr__(instance, "ingress_session", ingress_session)
        object.__setattr__(instance, "principal", principal)
        object.__setattr__(instance, "mission", mission)
        object.__setattr__(instance, "approval_graph_lease", approval_graph_lease)
        object.__setattr__(instance, "facts", facts)
        object.__setattr__(instance, "references", references)
        object.__setattr__(instance, "targets", targets)
        object.__setattr__(instance, "fence_generation", fence_generation)
        object.__setattr__(instance, "_checkout_bundle_issuer", issuer)
        return instance

    def _authority(self) -> _ExecutorCheckoutBundleIssuerV2:
        return cast(_ExecutorCheckoutBundleIssuerV2, self.__dict__["_checkout_bundle_issuer"])

    def assert_current(self) -> None:
        self._authority()._assert_bundle_current(self)

    def close(self) -> None:
        self._authority()._close_bundle(self)

    def __reduce__(self) -> NoReturn:
        raise TypeError("ExecutorCheckoutBundle is non-serializable")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ExecutorCheckoutBundle is non-serializable")


__all__ = [
    "ApprovalCheckoutRequest",
    "CheckoutRecoveryRefV2",
    "ExecutionAttemptGroup",
    "ExecutorCheckoutBundle",
    "ExecutorCheckoutRequestBundle",
    "FactCheckoutRequest",
    "IngressSessionCheckoutRequest",
    "MissionCheckoutRequest",
    "PrincipalCheckoutRequest",
    "ReferenceAccessMode",
    "ReferenceCheckout",
    "ReferenceCheckoutRequest",
    "ReferenceKind",
    "ReferenceLeaseToken",
]
