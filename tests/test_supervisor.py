#!/usr/bin/env python3
"""Regression tests for Supervisor health and lifecycle persistence."""

import errno
import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.contract


@pytest.fixture
def supervisor_paths(monkeypatch, tmp_path):
    import core.supervisor as supervisor

    monkeypatch.setattr(supervisor, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(supervisor, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(supervisor, "PID_FILE", str(tmp_path / "octopus.pid"))
    monkeypatch.setattr(supervisor, "LOCK_FILE", str(tmp_path / "octopus.lock"))
    return supervisor


def test_required_stopped_subsystem_is_unhealthy():
    from core.supervisor import Supervisor

    checks = []
    sv = Supervisor()
    sv.register("required", lambda: checks.append(True) or True)
    sv._running = True
    sv._subsystems["required"].status = "stopped"

    assert sv.is_healthy() is False
    assert checks == []
    assert sv.health_report()["status"] == "unhealthy"


def test_health_checks_are_eager_even_after_failure():
    from core.supervisor import Supervisor

    checks = []
    sv = Supervisor()
    sv.register("first", lambda: checks.append("first") or False)
    sv.register("second", lambda: checks.append("second") or True)
    sv._running = True

    assert sv.is_healthy() is False
    assert checks == ["first", "second"]
    assert sv._subsystems["first"].status == "crashed"
    assert sv._subsystems["second"].status == "running"


def test_start_checks_subsystems_and_clean_stop_is_not_a_crash(
        supervisor_paths, monkeypatch):
    supervisor = supervisor_paths
    checks = []
    sv = supervisor.Supervisor()
    sv.register("required", lambda: checks.append(True) or True)
    monkeypatch.setattr(sv, "_watchdog_loop", lambda: None)
    monkeypatch.setattr(sv, "_emit_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(supervisor.atexit, "register", lambda *_args: None)
    monkeypatch.setattr(supervisor.signal, "signal", lambda *_args: None)

    sv.start()

    assert checks
    assert sv._subsystems["required"].last_check > 0
    running_state = json.loads(Path(supervisor.STATE_FILE).read_text(encoding="utf-8"))
    assert running_state["lifecycle"] == "running"
    assert running_state["clean_shutdown"] is False

    assert sv.stop() is True
    stopped_state = json.loads(Path(supervisor.STATE_FILE).read_text(encoding="utf-8"))
    assert stopped_state["lifecycle"] == "stopped"
    assert stopped_state["clean_shutdown"] is True
    assert not os.path.exists(supervisor.PID_FILE)
    assert os.path.exists(supervisor.LOCK_FILE)

    monkeypatch.setattr(sv, "_is_pid_alive", lambda _pid: False)
    assert sv.get_crash_info() is None


def test_dead_running_and_legacy_states_are_crashes(supervisor_paths, monkeypatch):
    supervisor = supervisor_paths
    sv = supervisor.Supervisor()
    monkeypatch.setattr(sv, "_is_pid_alive", lambda _pid: False)

    supervisor._atomic_write_json(supervisor.STATE_FILE, {
        "pid": 123, "lifecycle": "running", "clean_shutdown": False,
        "started_at": 1, "saved_at": 2, "subsystems": {},
    })
    assert sv.get_crash_info()["previous_pid"] == 123

    supervisor._atomic_write_json(supervisor.STATE_FILE, {
        "pid": 456, "started_at": 1, "saved_at": 2, "subsystems": {},
    })
    assert sv.get_crash_info()["previous_pid"] == 456


def test_atomic_state_failure_preserves_previous_file(supervisor_paths, monkeypatch):
    supervisor = supervisor_paths
    path = supervisor.STATE_FILE
    supervisor._atomic_write_json(path, {"generation": 1})

    def fail_replace(_source, _destination):
        raise OSError("replace failed")

    monkeypatch.setattr(supervisor.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        supervisor._atomic_write_json(path, {"generation": 2})

    assert json.loads(Path(path).read_text(encoding="utf-8")) == {"generation": 1}
    assert not list(Path(path).parent.glob(".state.json.*.tmp"))


def test_database_health_uses_cursor_and_always_closes(monkeypatch):
    import core.supervisor as supervisor

    connection = MagicMock()
    cursor = MagicMock()
    connection.cursor.return_value = cursor
    fake_db = types.ModuleType("db")
    fake_db.get_connection = lambda: connection
    monkeypatch.setitem(sys.modules, "db", fake_db)

    assert supervisor._check_database() is True
    cursor.execute.assert_called_once_with("SELECT 1")
    cursor.close.assert_called_once()
    connection.close.assert_called_once()

    connection.reset_mock()
    cursor.reset_mock()
    cursor.execute.side_effect = RuntimeError("query failed")
    assert supervisor._check_database() is False
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_missing_required_event_store_is_unhealthy(supervisor_paths, monkeypatch):
    supervisor = supervisor_paths
    fake_module = types.ModuleType("core.c2.event_store")
    fake_module.EventStore = object
    monkeypatch.setitem(sys.modules, "core.c2.event_store", fake_module)

    assert supervisor._check_event_store() is False


def test_stop_joins_watchdog_before_teardown(supervisor_paths, monkeypatch):
    supervisor = supervisor_paths
    order = []

    class Watchdog:
        alive = True

        def is_alive(self):
            return self.alive

        def join(self, timeout):
            order.append("join")
            self.alive = False

    sv = supervisor.Supervisor()
    sv.register("component", lambda: True, stop_fn=lambda: order.append("stop"))
    sv._subsystems["component"].status = "crashed"
    sv._running = True
    sv._lifecycle = "running"
    sv._clean_shutdown = False
    sv._start_time = 1.0
    sv._watchdog_thread = Watchdog()
    monkeypatch.setattr(sv, "_emit_event", lambda *_args, **_kwargs: None)

    assert sv.stop() is True
    assert order == ["join", "stop"]


def test_shutdown_failure_is_persisted_as_unclean(supervisor_paths, monkeypatch):
    supervisor = supervisor_paths
    sv = supervisor.Supervisor()

    def fail_stop():
        raise RuntimeError("cannot stop")

    sv.register("component", lambda: True, stop_fn=fail_stop)
    sv._subsystems["component"].status = "crashed"
    sv._running = True
    sv._lifecycle = "running"
    sv._clean_shutdown = False
    sv._start_time = 1.0
    monkeypatch.setattr(sv, "_emit_event", lambda *_args, **_kwargs: None)

    assert sv.stop() is False
    state = json.loads(Path(supervisor.STATE_FILE).read_text(encoding="utf-8"))
    assert state["lifecycle"] == "shutdown_failed"
    assert state["clean_shutdown"] is False


def test_lock_contention_does_not_unlink_lock_file(supervisor_paths, monkeypatch):
    supervisor = supervisor_paths
    sv = supervisor.Supervisor()

    def busy_lock(_fd, _operation):
        raise BlockingIOError(errno.EAGAIN, "busy")

    monkeypatch.setattr(supervisor.fcntl, "flock", busy_lock)
    with pytest.raises(supervisor.AlreadyRunningError):
        sv._acquire_lock()

    assert os.path.exists(supervisor.LOCK_FILE)
