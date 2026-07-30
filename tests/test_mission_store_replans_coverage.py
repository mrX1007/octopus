"""Boundary coverage for persisted decision snapshots and replan budgets."""

from __future__ import annotations

import json
import sqlite3

import pytest

import core.ai.mission_store_replans as replans_module
from core.ai.evaluated_facts import EvaluatedFactSnapshot
from core.ai.mission_store import MissionStore
from core.ai.mission_store_models import MissionStoreError

pytestmark = pytest.mark.contract


def _snapshot(scan_id: str, *, marker: str = "one") -> EvaluatedFactSnapshot:
    return EvaluatedFactSnapshot.build(
        scan_id,
        "host.example",
        [{"id": marker, "coverage_status": "complete"}],
        evaluated_at=12,
    )


def test_snapshot_store_validates_type_size_and_scan(tmp_path, monkeypatch):
    store = MissionStore(str(tmp_path / "missions.db"))
    mission = store.open_mission("scan-one", "host.example")

    with pytest.raises(MissionStoreError, match="EvaluatedFactSnapshot"):
        store.store_evaluated_fact_snapshot(mission.mission_id, object())

    monkeypatch.setattr(replans_module, "_MAX_EVALUATED_SNAPSHOT_BYTES", 1)
    with pytest.raises(MissionStoreError, match="too large"):
        store.store_evaluated_fact_snapshot(
            mission.mission_id,
            _snapshot("scan-one"),
        )
    monkeypatch.setattr(replans_module, "_MAX_EVALUATED_SNAPSHOT_BYTES", 1_000_000)

    with pytest.raises(MissionStoreError, match="different scan"):
        store.store_evaluated_fact_snapshot(
            mission.mission_id,
            _snapshot("scan-two"),
        )


def test_snapshot_store_is_idempotent_and_rejects_conflicting_content(tmp_path):
    db_path = tmp_path / "missions.db"
    store = MissionStore(str(db_path))
    mission = store.open_mission("scan-one", "host.example")
    snapshot = _snapshot("scan-one")

    assert store.store_evaluated_fact_snapshot(mission.mission_id, snapshot) == snapshot.snapshot_ref
    assert store.store_evaluated_fact_snapshot(mission.mission_id, snapshot) == snapshot.snapshot_ref

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE mission_evaluated_fact_snapshots
            SET payload_json = '{}'
            WHERE mission_id = ? AND snapshot_ref = ?
            """,
            (mission.mission_id, snapshot.snapshot_ref),
        )

    with pytest.raises(MissionStoreError, match="conflicting content"):
        store.store_evaluated_fact_snapshot(mission.mission_id, snapshot)


def test_snapshot_resolution_handles_empty_missing_and_corrupt_rows(tmp_path):
    db_path = tmp_path / "missions.db"
    store = MissionStore(str(db_path))
    mission = store.open_mission("scan-one", "host.example")
    snapshot = _snapshot("scan-one")

    assert store.resolve_evaluated_fact_snapshot(mission.mission_id, "") is None
    assert store.resolve_evaluated_fact_snapshot(mission.mission_id, "missing") is None
    store.store_evaluated_fact_snapshot(mission.mission_id, snapshot)
    assert (
        store.resolve_evaluated_fact_snapshot(
            mission.mission_id,
            f"  {snapshot.snapshot_ref}  ",
        )
        == snapshot
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE mission_evaluated_fact_snapshots
            SET payload_json = '{'
            WHERE mission_id = ? AND snapshot_ref = ?
            """,
            (mission.mission_id, snapshot.snapshot_ref),
        )
    with pytest.raises(MissionStoreError, match="invalid persisted"):
        store.resolve_evaluated_fact_snapshot(
            mission.mission_id,
            snapshot.snapshot_ref,
        )


def test_snapshot_resolution_rejects_reference_mismatch(tmp_path):
    db_path = tmp_path / "missions.db"
    store = MissionStore(str(db_path))
    mission = store.open_mission("scan-one", "host.example")
    first = _snapshot("scan-one", marker="one")
    second = _snapshot("scan-one", marker="two")
    store.store_evaluated_fact_snapshot(mission.mission_id, first)
    second_payload = json.dumps(
        second.to_payload(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE mission_evaluated_fact_snapshots
            SET payload_json = ?
            WHERE mission_id = ? AND snapshot_ref = ?
            """,
            (second_payload, mission.mission_id, first.snapshot_ref),
        )

    with pytest.raises(MissionStoreError, match="reference mismatch"):
        store.resolve_evaluated_fact_snapshot(mission.mission_id, first.snapshot_ref)


@pytest.mark.parametrize(
    ("signature", "maximum", "message"),
    [
        ("", 1, "signature is required"),
        ("x", True, "must be an integer"),
        ("x", 1.5, "must be an integer"),
        ("x", -1, "must be between"),
        ("x", replans_module._MAX_STATE_REPLANS + 1, "must be between"),
    ],
)
def test_state_replan_rejects_invalid_inputs(
    tmp_path,
    signature,
    maximum,
    message,
):
    store = MissionStore(str(tmp_path / "missions.db"))
    mission = store.open_mission("scan-one", "host.example")

    with pytest.raises(MissionStoreError, match=message):
        store.record_state_replan(mission.mission_id, signature, maximum)


def test_state_replan_rejects_oversized_signature(tmp_path, monkeypatch):
    store = MissionStore(str(tmp_path / "missions.db"))
    mission = store.open_mission("scan-one", "host.example")
    monkeypatch.setattr(replans_module, "_MAX_STATE_REPLAN_SIGNATURE_BYTES", 1)

    with pytest.raises(MissionStoreError, match="signature is too large"):
        store.record_state_replan(mission.mission_id, "xx", 1)
