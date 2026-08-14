"""Execution commit store protocols, marker models, and canonical implementations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class CommittedExecutionMarkerV2:
    marker_id: str
    transaction_id: str
    execution_id: str
    finalization_ref: str
    fence_ref: str
    marker_digest: str


def canonical_committed_execution_marker_digest(marker: CommittedExecutionMarkerV2) -> str:
    payload = {
        "marker_id": marker.marker_id,
        "transaction_id": marker.transaction_id,
        "execution_id": marker.execution_id,
        "finalization_ref": marker.finalization_ref,
        "fence_ref": marker.fence_ref,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@runtime_checkable
class ExecutionCommitStoreV2(Protocol):
    def persist_committed_marker(
        self,
        transaction_id: str,
        execution_id: str,
        finalization_ref: str,
        fence_ref: str,
    ) -> CommittedExecutionMarkerV2: ...

    def require_current_marker(
        self,
        marker: CommittedExecutionMarkerV2,
    ) -> CommittedExecutionMarkerV2: ...


class DefaultExecutionCommitStoreV2:
    """In-memory production implementation of ExecutionCommitStoreV2."""

    def __init__(self) -> None:
        self._markers: dict[str, CommittedExecutionMarkerV2] = {}

    def persist_committed_marker(
        self,
        transaction_id: str,
        execution_id: str,
        finalization_ref: str,
        fence_ref: str,
    ) -> CommittedExecutionMarkerV2:
        marker_id = f"marker:{transaction_id}"
        dummy = CommittedExecutionMarkerV2(
            marker_id=marker_id,
            transaction_id=transaction_id,
            execution_id=execution_id,
            finalization_ref=finalization_ref,
            fence_ref=fence_ref,
            marker_digest="",
        )
        digest = canonical_committed_execution_marker_digest(dummy)
        marker = CommittedExecutionMarkerV2(
            marker_id=marker_id,
            transaction_id=transaction_id,
            execution_id=execution_id,
            finalization_ref=finalization_ref,
            fence_ref=fence_ref,
            marker_digest=digest,
        )
        self._markers[marker_id] = marker
        return marker

    def require_current_marker(
        self,
        marker: CommittedExecutionMarkerV2,
    ) -> CommittedExecutionMarkerV2:
        if marker.marker_id not in self._markers:
            raise KeyError(f"CommittedExecutionMarker '{marker.marker_id}' not found")
        return self._markers[marker.marker_id]
