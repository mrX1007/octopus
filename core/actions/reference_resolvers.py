"""Metadata-only resolvers for opaque PR-4 references.

Resolution returns immutable metadata and ACL snapshots only.  No resolver in
this module has a material/open/reveal API.
"""

from __future__ import annotations

import threading
from typing import Generic, Protocol, TypeVar, cast, runtime_checkable

from core.actions.reference_authorization import assert_reference_authorized
from core.actions.reference_snapshots import (
    REFERENCE_METADATA_SNAPSHOT_TYPES,
    C2ReferenceSnapshot,
    CredentialReferenceSnapshot,
    DeploymentReferenceSnapshot,
    NonSensitiveArtifactReferenceSnapshot,
    PivotRouteReferenceSnapshot,
    ReferenceMetadataSnapshot,
    SensitiveArtifactReferenceSnapshot,
    SessionReferenceSnapshot,
)
from core.actions.target_scope import ExtractedActionTarget
from core.credentials import CredentialStore

SnapshotT = TypeVar("SnapshotT", bound=ReferenceMetadataSnapshot)


@runtime_checkable
class ReferenceMetadataResolver(Protocol):
    def resolve_metadata(self, reference: str) -> ReferenceMetadataSnapshot: ...


def _require_reference(reference: object) -> str:
    if type(reference) is not str or not reference or any(ord(character) < 32 for character in reference):
        raise ValueError("reference_invalid")
    return reference


class _MetadataSnapshotStore(Generic[SnapshotT]):
    """Small monotonic store shared by metadata-only domain facades."""

    _snapshot_types: tuple[type[object], ...] = ()

    def __init__(self) -> None:
        self._metadata_lock = threading.RLock()
        self._metadata_snapshots: dict[str, SnapshotT] = {}

    def register_metadata(self, snapshot: SnapshotT) -> None:
        if type(snapshot) not in self._snapshot_types:
            raise TypeError("reference_metadata_type_mismatch")
        _require_reference(snapshot.reference)
        if snapshot.reference != snapshot.authorization.reference:
            raise ValueError("reference_authorization_identity_mismatch")
        with self._metadata_lock:
            current = self._metadata_snapshots.get(snapshot.reference)
            if current is not None:
                if snapshot.revision < current.revision:
                    raise ValueError("reference_metadata_revision_rollback")
                if snapshot.authorization.authorization_revision < current.authorization.authorization_revision:
                    raise ValueError("reference_authorization_revision_rollback")
                if (
                    snapshot.revision == current.revision
                    and snapshot.authorization.authorization_revision == current.authorization.authorization_revision
                    and snapshot != current
                ):
                    raise ValueError("reference_metadata_revision_conflict")
            self._metadata_snapshots[snapshot.reference] = snapshot

    def resolve_metadata(self, reference: str) -> SnapshotT:
        normalized_reference = _require_reference(reference)
        with self._metadata_lock:
            snapshot = self._metadata_snapshots.get(normalized_reference)
        if snapshot is None:
            raise KeyError("reference_not_found")
        if snapshot.reference != snapshot.authorization.reference:
            raise ValueError("reference_authorization_identity_mismatch")
        return snapshot

    def assert_current(
        self,
        *,
        reference: str,
        expected_metadata_revision: int,
        expected_authorization_revision: int,
    ) -> SnapshotT:
        with self._metadata_lock:
            snapshot = self.resolve_metadata(reference)
            if type(expected_metadata_revision) is not int or snapshot.revision != expected_metadata_revision:
                raise ValueError("reference_metadata_revision_mismatch")
            if (
                type(expected_authorization_revision) is not int
                or snapshot.authorization.authorization_revision != expected_authorization_revision
            ):
                raise ValueError("reference_authorization_revision_mismatch")
            return snapshot


class CredentialMetadataStore(_MetadataSnapshotStore[CredentialReferenceSnapshot]):
    _snapshot_types = (CredentialReferenceSnapshot,)


class CredentialReferenceResolver:
    """Metadata adapter over the existing reference-only CredentialStore."""

    def __init__(
        self,
        credential_store: CredentialStore,
        metadata_store: CredentialMetadataStore | None = None,
    ) -> None:
        self._credential_store = credential_store
        self._metadata_store = metadata_store or CredentialMetadataStore()

    def register_metadata(self, snapshot: CredentialReferenceSnapshot) -> None:
        credential = self._credential_store.resolve(snapshot.reference)
        if credential is None:
            raise KeyError("credential_reference_not_found")
        normalized_port = credential.port or None
        if (
            credential.target != snapshot.target
            or credential.service != snapshot.service
            or credential.username != snapshot.username
            or credential.auth_kind is not snapshot.auth_kind
            or normalized_port != snapshot.port
            or credential.verified is not snapshot.verified
        ):
            raise ValueError("credential_reference_metadata_mismatch")
        self._metadata_store.register_metadata(snapshot)

    def resolve_metadata(self, reference: str) -> CredentialReferenceSnapshot:
        snapshot = self._metadata_store.resolve_metadata(reference)
        credential = self._credential_store.resolve(reference)
        if credential is None:
            raise KeyError("credential_reference_not_found")
        normalized_port = credential.port or None
        if (
            credential.target != snapshot.target
            or credential.service != snapshot.service
            or credential.username != snapshot.username
            or credential.auth_kind is not snapshot.auth_kind
            or normalized_port != snapshot.port
            or credential.verified is not snapshot.verified
        ):
            raise ValueError("credential_reference_metadata_mismatch")
        return snapshot


class SessionReferenceResolver:
    def __init__(self, store: ReferenceMetadataResolver) -> None:
        self._store = store

    def resolve_metadata(self, reference: str) -> SessionReferenceSnapshot:
        snapshot = self._store.resolve_metadata(reference)
        if type(snapshot) is not SessionReferenceSnapshot:
            raise TypeError("reference_metadata_type_mismatch")
        return snapshot


class ArtifactReferenceResolver:
    def __init__(self, store: ReferenceMetadataResolver) -> None:
        self._store = store

    def resolve_metadata(
        self,
        reference: str,
    ) -> NonSensitiveArtifactReferenceSnapshot | SensitiveArtifactReferenceSnapshot:
        snapshot = self._store.resolve_metadata(reference)
        if type(snapshot) not in (NonSensitiveArtifactReferenceSnapshot, SensitiveArtifactReferenceSnapshot):
            raise TypeError("reference_metadata_type_mismatch")
        return cast(
            "NonSensitiveArtifactReferenceSnapshot | SensitiveArtifactReferenceSnapshot",
            snapshot,
        )


class PivotRouteReferenceResolver:
    def __init__(self, store: ReferenceMetadataResolver) -> None:
        self._store = store

    def resolve_metadata(self, reference: str) -> PivotRouteReferenceSnapshot:
        snapshot = self._store.resolve_metadata(reference)
        if type(snapshot) is not PivotRouteReferenceSnapshot:
            raise TypeError("reference_metadata_type_mismatch")
        return snapshot


class C2ReferenceResolver:
    def __init__(self, store: ReferenceMetadataResolver) -> None:
        self._store = store

    def resolve_metadata(self, reference: str) -> C2ReferenceSnapshot:
        snapshot = self._store.resolve_metadata(reference)
        if type(snapshot) is not C2ReferenceSnapshot:
            raise TypeError("reference_metadata_type_mismatch")
        return snapshot


class DeploymentReferenceResolver:
    def __init__(self, store: ReferenceMetadataResolver) -> None:
        self._store = store

    def resolve_metadata(self, reference: str) -> DeploymentReferenceSnapshot:
        snapshot = self._store.resolve_metadata(reference)
        if type(snapshot) is not DeploymentReferenceSnapshot:
            raise TypeError("reference_metadata_type_mismatch")
        return snapshot


class _DirectReferenceMetadataStore(_MetadataSnapshotStore[ReferenceMetadataSnapshot]):
    _snapshot_types = REFERENCE_METADATA_SNAPSHOT_TYPES


def _is_reference_metadata_resolver(resolver: object) -> bool:
    if isinstance(resolver, ReferenceMetadataResolver):
        return True
    return hasattr(resolver, "resolve_metadata") and callable(getattr(resolver, "resolve_metadata", None))


class ReferenceResolverRegistry:
    """Routes opaque namespaces to metadata-only resolvers, fail-closed."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._direct = _DirectReferenceMetadataStore()
        self._resolvers: dict[str, ReferenceMetadataResolver] = {}

    def register(self, snapshot: ReferenceMetadataSnapshot) -> None:
        """Compatibility helper for immutable metadata-only registrations."""

        self._direct.register_metadata(snapshot)

    def register_resolver(self, reference_prefix: str, resolver: ReferenceMetadataResolver) -> None:
        if type(reference_prefix) is not str or not reference_prefix.endswith("://"):
            raise ValueError("reference_prefix_invalid")
        if not _is_reference_metadata_resolver(resolver):
            raise TypeError("reference_resolver_invalid")
        with self._lock:
            if reference_prefix in self._resolvers:
                raise ValueError("reference_resolver_duplicate")
            self._resolvers[reference_prefix] = resolver

    def resolve(self, reference: str) -> ReferenceMetadataSnapshot:
        normalized_reference = _require_reference(reference)
        try:
            return self._direct.resolve_metadata(normalized_reference)
        except KeyError:
            pass
        with self._lock:
            matches = tuple(
                resolver for prefix, resolver in self._resolvers.items() if normalized_reference.startswith(prefix)
            )
        if len(matches) != 1:
            raise KeyError("reference_not_found" if not matches else "reference_resolver_ambiguous")
        snapshot = matches[0].resolve_metadata(normalized_reference)
        if type(snapshot) not in REFERENCE_METADATA_SNAPSHOT_TYPES:
            raise TypeError("reference_metadata_type_mismatch")
        if snapshot.reference != normalized_reference:
            raise ValueError("reference_resolver_identity_mismatch")
        if snapshot.reference != snapshot.authorization.reference:
            raise ValueError("reference_authorization_identity_mismatch")
        return snapshot

    def resolve_authorized(
        self,
        reference: str,
        *,
        expected_metadata_revision: int,
        expected_authorization_revision: int,
        mission_id: str,
        subject_id: str,
        action_id: str,
        required_capability: str,
        targets: tuple[ExtractedActionTarget, ...],
        now: float | None = None,
    ) -> ReferenceMetadataSnapshot:
        snapshot = self.resolve(reference)
        assert_reference_authorized(
            snapshot,
            expected_metadata_revision=expected_metadata_revision,
            expected_authorization_revision=expected_authorization_revision,
            mission_id=mission_id,
            subject_id=subject_id,
            action_id=action_id,
            required_capability=required_capability,
            targets=targets,
            now=now,
        )
        return snapshot


__all__ = [
    "ArtifactReferenceResolver",
    "C2ReferenceResolver",
    "CredentialMetadataStore",
    "CredentialReferenceResolver",
    "DeploymentReferenceResolver",
    "PivotRouteReferenceResolver",
    "ReferenceMetadataResolver",
    "ReferenceResolverRegistry",
    "SessionReferenceResolver",
]
