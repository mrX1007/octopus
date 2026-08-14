"""Immutable approval authorization snapshots resolved by the executor."""

from __future__ import annotations

import math
from dataclasses import dataclass

from core.actions.target_scope import TargetScopeSnapshot
from core.auth.types import ApprovalStatus


@dataclass(frozen=True)
class ApprovalAuthorizationSnapshot:
    """Exact, non-authoritative projection of one approval revision.

    The caller supplies only ``approval_ref``. An :class:`ApprovalStore`
    resolves this snapshot and remains the authority for graph and attempt
    state. In particular, copying this value cannot reserve or consume uses.
    """

    schema_version: str
    approval_ref: str
    revision: int
    approval_id: str
    mission_id: str
    subject_id: str
    approver_subject_id: str
    permitted_root_action_ids: tuple[str, ...]
    permitted_concrete_action_ids: tuple[str, ...]
    permitted_capabilities: tuple[str, ...]
    permitted_killchain_stages: tuple[str, ...]
    target_scope: TargetScopeSnapshot
    permitted_operation_ids: tuple[str, ...]
    status: ApprovalStatus
    issued_at: float
    expires_at: float
    max_uses: int
    remaining_uses: int

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("approval_schema_version_unsupported")
        for field_name in (
            "approval_ref",
            "approval_id",
            "mission_id",
            "subject_id",
            "approver_subject_id",
        ):
            value = getattr(self, field_name)
            if type(value) is not str or not value:
                raise ValueError(f"{field_name}_missing")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("approval_revision_invalid")
        for field_name in (
            "permitted_root_action_ids",
            "permitted_concrete_action_ids",
            "permitted_capabilities",
            "permitted_killchain_stages",
            "permitted_operation_ids",
        ):
            values = getattr(self, field_name)
            if type(values) is not tuple or any(type(value) is not str or not value for value in values):
                raise ValueError(f"{field_name}_invalid")
            if len(set(values)) != len(values):
                raise ValueError(f"{field_name}_contains_duplicates")
        if type(self.target_scope) is not TargetScopeSnapshot:
            raise ValueError("approval_target_scope_invalid")
        if type(self.status) is not ApprovalStatus:
            raise ValueError("approval_status_invalid")
        if (
            type(self.issued_at) not in (int, float)
            or type(self.expires_at) not in (int, float)
            or not math.isfinite(self.issued_at)
            or not math.isfinite(self.expires_at)
            or self.expires_at <= self.issued_at
        ):
            raise ValueError("approval_lifetime_invalid")
        if type(self.max_uses) is not int or self.max_uses < 1:
            raise ValueError("approval_max_uses_invalid")
        if type(self.remaining_uses) is not int or self.remaining_uses < 0 or self.remaining_uses > self.max_uses:
            raise ValueError("approval_remaining_uses_invalid")


__all__ = ["ApprovalAuthorizationSnapshot"]
