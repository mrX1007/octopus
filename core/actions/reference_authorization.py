"""Frozen reference ACL snapshots and the fail-closed PR-4 policy."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.actions.target_scope import ExtractedActionTarget, TargetScopePolicy, TargetScopeSnapshot
from core.auth.types import SubjectType

if TYPE_CHECKING:
    from core.actions.reference_snapshots import ReferenceMetadataSnapshot


def _require_non_empty(name: str, value: object) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"reference_authorization_{name}_invalid")


def _require_unique_strings(name: str, values: object) -> None:
    if type(values) is not tuple or any(type(value) is not str or not value for value in values):
        raise ValueError(f"reference_authorization_{name}_invalid")
    if len(values) != len(set(values)):
        raise ValueError(f"reference_authorization_{name}_duplicate")


@dataclass(frozen=True)
class ReferenceAuthorizationSnapshot:
    schema_version: str
    reference: str
    authorization_revision: int

    mission_id: str
    owner_subject_id: str
    owner_subject_type: SubjectType

    permitted_subject_ids: tuple[str, ...]
    permitted_action_ids: tuple[str, ...]
    permitted_capabilities: tuple[str, ...]
    authorization_scope: TargetScopeSnapshot

    created_by_request_id: str
    delegated_by_subject_id: str | None
    expires_at: float | None

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("reference_authorization_schema_version_unsupported")
        for name in ("reference", "mission_id", "owner_subject_id", "created_by_request_id"):
            _require_non_empty(name, getattr(self, name))
        if type(self.authorization_revision) is not int or self.authorization_revision < 1:
            raise ValueError("reference_authorization_revision_invalid")
        if type(self.owner_subject_type) is not SubjectType:
            raise ValueError("reference_authorization_owner_subject_type_invalid")
        for name in ("permitted_subject_ids", "permitted_action_ids", "permitted_capabilities"):
            _require_unique_strings(name, getattr(self, name))
        if type(self.authorization_scope) is not TargetScopeSnapshot:
            raise ValueError("reference_authorization_scope_invalid")
        if self.delegated_by_subject_id is not None:
            _require_non_empty("delegated_by_subject_id", self.delegated_by_subject_id)
        if self.expires_at is not None and (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, (int, float))
            or not math.isfinite(self.expires_at)
        ):
            raise ValueError("reference_authorization_expiry_invalid")


class ReferenceAuthorizationError(PermissionError):
    """One stable fail-closed reference authorization reason."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def assert_reference_authorized(
    metadata: ReferenceMetadataSnapshot,
    *,
    expected_metadata_revision: int,
    expected_authorization_revision: int,
    mission_id: str,
    subject_id: str,
    action_id: str,
    required_capability: str,
    targets: tuple[ExtractedActionTarget, ...],
    now: float | None = None,
) -> None:
    """Validate every PR-4 metadata/ACL fence or raise one closed error.

    The policy consumes immutable snapshots only. It never resolves or opens
    material, and callers cannot override the authorization scope matcher.
    """

    authorization = metadata.authorization
    if metadata.reference != authorization.reference:
        raise ReferenceAuthorizationError("reference_authorization_identity_mismatch")
    if type(expected_metadata_revision) is not int or metadata.revision != expected_metadata_revision:
        raise ReferenceAuthorizationError("reference_metadata_revision_mismatch")
    if (
        type(expected_authorization_revision) is not int
        or authorization.authorization_revision != expected_authorization_revision
    ):
        raise ReferenceAuthorizationError("reference_authorization_revision_mismatch")

    for name, value in (
        ("mission_id", mission_id),
        ("subject_id", subject_id),
        ("action_id", action_id),
        ("required_capability", required_capability),
    ):
        if type(value) is not str or not value:
            raise ReferenceAuthorizationError(f"reference_{name}_invalid")
    if type(targets) is not tuple or any(type(target) is not ExtractedActionTarget for target in targets):
        raise ReferenceAuthorizationError("reference_targets_invalid")

    evaluated_at = time.time() if now is None else now
    if (
        isinstance(evaluated_at, bool)
        or not isinstance(evaluated_at, (int, float))
        or not math.isfinite(evaluated_at)
    ):
        raise ReferenceAuthorizationError("reference_authorization_time_invalid")
    if authorization.expires_at is not None and authorization.expires_at <= evaluated_at:
        raise ReferenceAuthorizationError("reference_authorization_expired")
    metadata_expiry = metadata.expires_at
    if metadata_expiry is not None and metadata_expiry <= evaluated_at:
        raise ReferenceAuthorizationError("reference_metadata_expired")

    if authorization.mission_id != mission_id:
        raise ReferenceAuthorizationError("reference_mission_mismatch")
    if subject_id != authorization.owner_subject_id and subject_id not in authorization.permitted_subject_ids:
        raise ReferenceAuthorizationError("reference_subject_denied")
    if action_id not in authorization.permitted_action_ids:
        raise ReferenceAuthorizationError("reference_action_denied")
    if required_capability not in authorization.permitted_capabilities:
        raise ReferenceAuthorizationError("reference_capability_denied")

    scope_decision = TargetScopePolicy.evaluate(targets, authorization.authorization_scope)
    if not scope_decision.allowed:
        raise ReferenceAuthorizationError("reference_scope_denied")


__all__ = [
    "ReferenceAuthorizationError",
    "ReferenceAuthorizationSnapshot",
    "assert_reference_authorized",
]
