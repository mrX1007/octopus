"""Remaining public MissionStore lifecycle boundary coverage."""

from __future__ import annotations

import pytest

import core.ai.mission_store as mission_store_module
from core.ai.mission_store import MissionStore, MissionStoreError

pytestmark = pytest.mark.contract


def test_default_facts_path_uses_default_secret_store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    secret_path = tmp_path / "default-secrets.db"
    monkeypatch.setattr(mission_store_module, "default_secret_store_path", lambda: str(secret_path))
    store = MissionStore("data/facts.db")
    assert store._owned_secret_store is not None
    assert secret_path.exists()
    store.close()


def test_open_mission_requires_scan_and_target():
    store = MissionStore(":memory:")
    for scan_id, target in (("", "target"), ("scan", "")):
        with pytest.raises(MissionStoreError, match="scan_id and target are required"):
            store.open_mission(scan_id, target)


def test_completed_mission_reopens_as_same_terminal_record():
    store = MissionStore(":memory:")
    mission = store.open_mission("scan", "target")
    completed = store.complete_mission(mission.mission_id, "done")
    reopened = store.open_mission("scan", "target")
    assert reopened == completed


def test_interrupt_requires_reason_and_rejects_a_different_terminal_reason():
    store = MissionStore(":memory:")
    mission = store.open_mission("scan", "target")
    with pytest.raises(MissionStoreError, match="interrupt reason is required"):
        store.interrupt_mission(mission.mission_id, "")
    store.interrupt_mission(mission.mission_id, "first")
    with pytest.raises(MissionStoreError, match="another reason"):
        store.interrupt_mission(mission.mission_id, "second")


def test_complete_requires_reason_and_running_state():
    store = MissionStore(":memory:")
    mission = store.open_mission("scan", "target")
    with pytest.raises(MissionStoreError, match="completion reason is required"):
        store.complete_mission(mission.mission_id, "")
    store.interrupt_mission(mission.mission_id, "stop")
    with pytest.raises(MissionStoreError, match="cannot complete from interrupted"):
        store.complete_mission(mission.mission_id, "done")
