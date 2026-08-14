"""Executor-only PR-4 material checkout boundary.

Provider-facing, phase-leased views are a PR-5 modification and intentionally
do not appear here.  In particular there is no request-constructible material
view and no ``Any`` payload escape hatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn, Protocol, SupportsIndex, runtime_checkable

from core.actions.checkout_models import ReferenceKind
from core.actions.reference_snapshots import (
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    ReferenceMetadataSnapshot,
    SensitiveArtifactReferenceSnapshot,
    SessionReferenceSnapshot,
)


def _require_non_empty(name: str, value: object) -> None:
    if type(value) is not str or not value or any(ord(character) < 32 for character in value):
        raise ValueError(f"opened_material_{name}_invalid")


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
    # PR-15 modifies this closed branch when EnrollmentReferenceSnapshot is
    # introduced.  PR-4 must not accept a generic C2 snapshot as enrollment.
    return False


@runtime_checkable
class ExecutorCheckoutHandleV2(Protocol):
    @property
    def checkout_id(self) -> str: ...

    def close_checkout(self) -> None: ...


@dataclass(frozen=True, repr=False)
class ExecutorOpenedMaterialV2:
    reference: str
    reference_kind: ReferenceKind
    checkout_id: str
    metadata: ReferenceMetadataSnapshot
    checkout_handle: ExecutorCheckoutHandleV2 = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_non_empty("reference", self.reference)
        _require_non_empty("checkout_id", self.checkout_id)
        if type(self.reference_kind) is not ReferenceKind:
            raise ValueError("opened_material_reference_kind_invalid")
        if self.reference != self.metadata.reference:
            raise ValueError("opened_material_reference_identity_mismatch")
        if self.metadata.reference != self.metadata.authorization.reference:
            raise ValueError("reference_authorization_identity_mismatch")
        if not _metadata_matches_kind(self.metadata, self.reference_kind):
            raise ValueError("opened_material_reference_kind_mismatch")
        if not isinstance(self.checkout_handle, ExecutorCheckoutHandleV2):
            raise TypeError("opened_material_checkout_handle_invalid")
        if self.checkout_handle.checkout_id != self.checkout_id:
            raise ValueError("opened_material_checkout_handle_identity_mismatch")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ExecutorOpenedMaterialV2 is non-serializable")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ExecutorOpenedMaterialV2 is non-serializable")


@dataclass(frozen=True, repr=False)
class ExecutorOpenedMaterialBundleV2:
    checkout_id: str
    materials: tuple[ExecutorOpenedMaterialV2, ...]

    def __post_init__(self) -> None:
        _require_non_empty("bundle_checkout_id", self.checkout_id)
        if type(self.materials) is not tuple or any(
            type(material) is not ExecutorOpenedMaterialV2 for material in self.materials
        ):
            raise ValueError("opened_material_bundle_items_invalid")
        references = tuple(material.reference for material in self.materials)
        if len(references) != len(set(references)):
            raise ValueError("opened_material_bundle_reference_duplicate")
        if any(material.checkout_id != self.checkout_id for material in self.materials):
            raise ValueError("opened_material_bundle_checkout_identity_mismatch")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ExecutorOpenedMaterialBundleV2 is non-serializable")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ExecutorOpenedMaterialBundleV2 is non-serializable")


__all__ = [
    "ExecutorCheckoutHandleV2",
    "ExecutorOpenedMaterialBundleV2",
    "ExecutorOpenedMaterialV2",
]
