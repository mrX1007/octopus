"""Evaluated-snapshot and state-replan persistence repository."""

from __future__ import annotations

import json
import time

from core.ai.evaluated_facts import EvaluatedFactSnapshot
from core.ai.mission_store_models import (
    _MAX_EVALUATED_SNAPSHOT_BYTES,
    _MAX_STATE_REPLAN_SIGNATURE_BYTES,
    _MAX_STATE_REPLANS,
    MissionStoreError,
    StateReplanResult,
)

# mypy: disable-error-code="attr-defined"


class MissionStoreReplanRepositoryMixin:
    def store_evaluated_fact_snapshot(
        self,
        mission_id: str,
        snapshot: EvaluatedFactSnapshot,
    ) -> str:
        """Persist one complete content-addressed decision snapshot.

        Task rows keep the compact reference, while this mission-owned table
        makes that reference resolvable after process restart. A conflicting
        payload for the same content address is treated as corruption.
        """

        if not isinstance(snapshot, EvaluatedFactSnapshot):
            raise MissionStoreError("evaluated snapshot must be an EvaluatedFactSnapshot")
        payload_json = json.dumps(
            snapshot.to_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if len(payload_json.encode("utf-8", "replace")) > _MAX_EVALUATED_SNAPSHOT_BYTES:
            raise MissionStoreError("evaluated fact snapshot is too large")
        with self._transaction() as conn:
            mission = self._require_mutable_mission(conn, mission_id)
            if snapshot.scan_id != str(mission["scan_id"]):
                raise MissionStoreError("evaluated fact snapshot belongs to a different scan")
            existing = conn.execute(
                """
                SELECT payload_json FROM mission_evaluated_fact_snapshots
                WHERE mission_id = ? AND snapshot_ref = ?
                """,
                (mission_id, snapshot.snapshot_ref),
            ).fetchone()
            if existing is not None:
                if str(existing["payload_json"]) != payload_json:
                    raise MissionStoreError("evaluated fact snapshot reference has conflicting content")
                return snapshot.snapshot_ref
            conn.execute(
                """
                INSERT INTO mission_evaluated_fact_snapshots(
                    mission_id, snapshot_ref, payload_json, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (mission_id, snapshot.snapshot_ref, payload_json, time.time()),
            )
        return snapshot.snapshot_ref

    def resolve_evaluated_fact_snapshot(
        self,
        mission_id: str,
        snapshot_ref: str,
    ) -> EvaluatedFactSnapshot | None:
        """Resolve and integrity-check a mission-owned snapshot reference."""

        reference = str(snapshot_ref or "").strip()
        if not reference:
            return None
        with self._connection() as conn:
            self._require_mission(conn, mission_id)
            row = conn.execute(
                """
                SELECT payload_json FROM mission_evaluated_fact_snapshots
                WHERE mission_id = ? AND snapshot_ref = ?
                """,
                (mission_id, reference),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row["payload_json"]))
            snapshot = EvaluatedFactSnapshot.from_payload(payload)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("invalid persisted evaluated fact snapshot") from exc
        if snapshot.snapshot_ref != reference:
            raise MissionStoreError("evaluated fact snapshot reference mismatch")
        return snapshot

    def record_state_replan(
        self,
        mission_id: str,
        transition_signature: str,
        max_replans: int,
    ) -> StateReplanResult:
        """Atomically deduplicate a transition and reserve its replan budget."""

        signature = str(transition_signature or "")
        if not signature:
            raise MissionStoreError("state replan transition signature is required")
        if len(signature.encode("utf-8", "replace")) > _MAX_STATE_REPLAN_SIGNATURE_BYTES:
            raise MissionStoreError("state replan transition signature is too large")
        if isinstance(max_replans, bool) or not isinstance(max_replans, int):
            raise MissionStoreError("max_replans must be an integer")
        if not 0 <= max_replans <= _MAX_STATE_REPLANS:
            raise MissionStoreError(f"max_replans must be between 0 and {_MAX_STATE_REPLANS}")

        with self._transaction() as conn:
            row = self._require_mutable_mission(conn, mission_id)
            count = self._state_replan_count_from_row(row)
            signatures = self._state_replan_signatures_from_row(row)
            if signature in signatures:
                return StateReplanResult(
                    requested=False,
                    reason="duplicate_transition",
                    count=count,
                    signatures=signatures,
                )
            if count >= max_replans:
                signatures = (*signatures, signature)
                conn.execute(
                    """
                    UPDATE missions
                    SET state_replan_signatures_json = ?, updated_at = ?
                    WHERE mission_id = ?
                    """,
                    (
                        self._encode_state_replan_signatures(signatures),
                        time.time(),
                        mission_id,
                    ),
                )
                return StateReplanResult(
                    requested=False,
                    reason="budget_exhausted",
                    count=count,
                    signatures=signatures,
                )

            signatures = (*signatures, signature)
            count += 1
            now = time.time()
            conn.execute(
                """
                UPDATE missions
                SET state_replan_count = ?, state_replan_signatures_json = ?,
                    updated_at = ?
                WHERE mission_id = ?
                """,
                (
                    count,
                    self._encode_state_replan_signatures(signatures),
                    now,
                    mission_id,
                ),
            )
            return StateReplanResult(
                requested=True,
                reason="requested",
                count=count,
                signatures=signatures,
            )
