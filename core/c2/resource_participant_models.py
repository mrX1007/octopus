"""Resource participant models."""
from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field
from typing import Literal

class C2DaemonResourceKindV1(str, Enum):
    ENROLLMENT = "enrollment"
    TASK = "task"
    DNS_CHANNEL = "dns_channel"

class C2DaemonResourceStateV1(str, Enum):
    PENDING = "pending"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED_VISIBLE = "finalized_visible"
    ABORTED = "aborted"
    FAILED = "failed"

@dataclass(frozen=True)
class C2DaemonResourceControlPayloadV1:
    resource_kind: C2DaemonResourceKindV1
    payload_schema_id: str
    payload_digest: str
    canonical_payload: bytes = field(repr=False, compare=False)

@dataclass(frozen=True)
class C2DaemonResourcePrepareReceiptV1:
    transaction_id: str
    participant_id: str
    daemon_instance_id: str
    resource_ref: str
    resource_revision: int
    resource_kind: C2DaemonResourceKindV1
    payload_digest: str
    receipt_digest: str
    state: Literal[C2DaemonResourceStateV1.PENDING]

@dataclass(frozen=True)
class C2DaemonResourceCommitReceiptV1:
    transaction_id: str
    participant_id: str
    resource_ref: str
    resource_revision: int
    commit_digest: str
    state: Literal[C2DaemonResourceStateV1.COMMITTED_HIDDEN]

@dataclass(frozen=True)
class C2DaemonResourceFinalizeReceiptV1:
    transaction_id: str
    participant_id: str
    resource_ref: str
    resource_revision: int
    visibility_digest: str
    finalized_at: float
    state: Literal[C2DaemonResourceStateV1.FINALIZED_VISIBLE]
