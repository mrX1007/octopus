"""PR-5 Module: Provider call recovery models and managers (§8.6)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from core.actions.provider_call_types import ProviderCallPhaseV2
from core.actions.provider_mounts import ProviderExecutionModeV2


class ProviderCallRecoveryStateV2(str, Enum):
    RESERVED = "reserved"
    RUNNING = "running"
    QUIESCED = "quiesced"
    IPC_CLOSED = "ipc_closed"
    CHILD_COMPLETED = "child_completed"
    DETACHED_FENCED = "detached_fenced"


@dataclass(frozen=True)
class ProviderBoundaryClosureReceiptV2:
    call_id: str
    phase: ProviderCallPhaseV2
    closure_digest: str


@dataclass(frozen=True)
class DetachedProviderCallRefV2:
    call_id: str
    revision: int
    detached_digest: str


@dataclass(frozen=True)
class ProviderCallRecoveryRefV2:
    call_id: str
    call_revision: int
    execution_mode: ProviderExecutionModeV2
    state: ProviderCallRecoveryStateV2
    runner_handle_ref: str | None
    record_digest: str


@dataclass(frozen=True)
class ProviderCallRecoveryRecordV2:
    recovery_ref: ProviderCallRecoveryRefV2
    execution_id: str
    action_id: str
    phase: ProviderCallPhaseV2
    provider_id: str
    mount_revision: int
    mount_digest: str
    provider_generation: str
    snapshot_digest: str
    call_plan_digest: str
    runner_handle_ref: str | None
    closure_receipt: ProviderBoundaryClosureReceiptV2 | None
    detached_record_ref: DetachedProviderCallRefV2 | None


class ProviderCallRecoveryManager:
    """Manager for recovering in-flight provider calls across host restarts."""

    def __init__(self) -> None:
        self._records: dict[str, ProviderCallRecoveryRecordV2] = {}

    def register(self, record: ProviderCallRecoveryRecordV2) -> None:
        self._records[record.recovery_ref.call_id] = record

    def get(self, call_id: str) -> Optional[ProviderCallRecoveryRecordV2]:
        return self._records.get(call_id)


class DetachedCallClaimStore:
    """Store for managing claims on detached provider executions."""

    def __init__(self) -> None:
        self._claims: dict[str, str] = {}

    def claim(self, call_id: str, claimant_id: str) -> bool:
        if call_id in self._claims:
            return False
        self._claims[call_id] = claimant_id
        return True


__all__ = [
    "DetachedCallClaimStore",
    "DetachedProviderCallRefV2",
    "ProviderBoundaryClosureReceiptV2",
    "ProviderCallRecoveryManager",
    "ProviderCallRecoveryRecordV2",
    "ProviderCallRecoveryRefV2",
    "ProviderCallRecoveryStateV2",
]
