"""Policy request snapshots composing headers, authorization, facts, and references."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from core.actions.canonical_state import CanonicalActionStaticState
from core.actions.child_execution import ChildExecutionBridge, RootExecutionBridge
from core.actions.reference_snapshots import ReferenceMetadataSnapshot
from core.actions.target_scope import ExtractedActionTarget
from core.actions.trusted_facts import TrustedFactSnapshot
from core.auth.approvals import ApprovalAuthorizationSnapshot
from core.auth.missions import MissionAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot


@dataclass(frozen=True)
class ActionPolicyRequestHeaderV2:
    schema_version: str
    request_id: str
    action_id: str
    root_action_id: str
    parent_action_id: str | None
    execution_graph_id: str
    capability_class: str
    killchain_stage: str | None
    operation_id: str | None

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("policy header schema version is unsupported")
        for name in (
            "request_id",
            "action_id",
            "root_action_id",
            "execution_graph_id",
            "capability_class",
        ):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        for name in ("parent_action_id", "killchain_stage", "operation_id"):
            value = getattr(self, name)
            if value is not None and (type(value) is not str or not value):
                raise ValueError(f"{name} must be None or a non-empty string")


@dataclass(frozen=True)
class ActionPolicyRequestSnapshot:
    header: ActionPolicyRequestHeaderV2
    targets: tuple[ExtractedActionTarget, ...]
    principal: PrincipalAuthorizationSnapshot
    mission: MissionAuthorizationSnapshot
    approval: ApprovalAuthorizationSnapshot | None
    facts: tuple[TrustedFactSnapshot, ...]
    references: tuple[ReferenceMetadataSnapshot, ...]


@runtime_checkable
class ActionPolicyRequestSnapshotFactoryV2(Protocol):
    def build(
        self,
        *,
        static_state: CanonicalActionStaticState,
        bridge: RootExecutionBridge | ChildExecutionBridge,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        principal: PrincipalAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
        approval: ApprovalAuthorizationSnapshot | None,
        facts: tuple[TrustedFactSnapshot, ...],
        references: tuple[ReferenceMetadataSnapshot, ...],
    ) -> ActionPolicyRequestSnapshot: ...


__all__ = [
    "ActionPolicyRequestHeaderV2",
    "ActionPolicyRequestSnapshot",
    "ActionPolicyRequestSnapshotFactoryV2",
]
