"""Hermetic lifecycle and CLI boundary coverage for the process supervisor."""

from __future__ import annotations

import errno
import json
import signal
import sqlite3
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import core.supervisor as supervisor

pytestmark = [pytest.mark.unit, pytest.mark.contract]


@pytest.fixture
def paths(monkeypatch, tmp_path):
    monkeypatch.setattr(supervisor, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(supervisor, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(supervisor, "PID_FILE", str(tmp_path / "octopus.pid"))
    monkeypatch.setattr(supervisor, "LOCK_FILE", str(tmp_path / "octopus.lock"))
    return tmp_path


def test_atomic_json_success_and_each_cleanup_suppression(monkeypatch, tmp_path) -> None:
    path = tmp_path / "state" / "state.json"
    supervisor._atomic_write_json(str(path), {"generation": 1})
    assert json.loads(path.read_text(encoding="utf-8")) == {"generation": 1}
    assert path.stat().st_mode & 0o777 == 0o600

    closed = []
    unlinked = []
    monkeypatch.setattr(supervisor.tempfile, "mkstemp", lambda **_kwargs: (99, str(tmp_path / "temp")))
    monkeypatch.setattr(
        supervisor.os,
        "fchmod",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("chmod failed")),
    )
    monkeypatch.setattr(supervisor.os, "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(supervisor.os, "unlink", lambda name: unlinked.append(name))
    with pytest.raises(RuntimeError, match="chmod failed"):
        supervisor._atomic_write_json(str(path), {})
    assert closed == [99] and unlinked == [str(tmp_path / "temp")]

    monkeypatch.setattr(
        supervisor.os,
        "close",
        lambda _fd: (_ for _ in ()).throw(OSError("already closed")),
    )
    monkeypatch.setattr(
        supervisor.os,
        "unlink",
        lambda _name: (_ for _ in ()).throw(FileNotFoundError()),
    )
    with pytest.raises(RuntimeError, match="chmod failed"):
        supervisor._atomic_write_json(str(path), {})


def test_subsystem_check_restart_limits_and_serialization(monkeypatch, caplog) -> None:
    times = iter((1.0, 2.0, 3.0, 4.0, 5.0))
    monkeypatch.setattr(supervisor.time, "time", lambda: next(times, 5.0))
    healthy = supervisor.Subsystem("healthy", lambda: 1)
    assert healthy.check() is True
    assert healthy.status == "running" and healthy.last_healthy == 2.0

    unhealthy = supervisor.Subsystem("bad", lambda: False)
    assert unhealthy.check() is False
    assert unhealthy.check() is False
    assert unhealthy.crash_count == 1

    exploding = supervisor.Subsystem("explode", lambda: (_ for _ in ()).throw(ValueError("boom")))
    with caplog.at_level("ERROR"):
        assert exploding.check() is False
        assert exploding.check() is False
    assert exploding.crash_count == 1
    assert exploding.to_dict()["status"] == "crashed"

    limited = supervisor.Subsystem("limited", lambda: True, max_restarts=0)
    limited.crash_count = 1
    assert limited.restart() is False

    calls = []
    restarted = supervisor.Subsystem(
        "service",
        lambda: True,
        start_fn=lambda: calls.append("start"),
        stop_fn=lambda: calls.append("stop"),
    )
    monkeypatch.setattr(supervisor.time, "time", lambda: 10.0)
    assert restarted.restart() is True
    assert calls == ["stop", "start"]

    stop_error = supervisor.Subsystem(
        "stop-error",
        lambda: True,
        start_fn=lambda: calls.append("started-after-error"),
        stop_fn=lambda: (_ for _ in ()).throw(RuntimeError("stop failed")),
    )
    assert stop_error.restart() is True

    no_callbacks = supervisor.Subsystem("none", lambda: True)
    assert no_callbacks.restart() is True

    start_error = supervisor.Subsystem(
        "start-error",
        lambda: True,
        start_fn=lambda: (_ for _ in ()).throw(RuntimeError("start failed")),
    )
    assert start_error.restart() is False
    assert start_error.status == "crashed"


def test_lock_pid_and_stale_cleanup_paths(monkeypatch, paths) -> None:
    instance = supervisor.Supervisor()
    flock_calls = []
    monkeypatch.setattr(
        supervisor.fcntl,
        "flock",
        lambda fd, operation: flock_calls.append((fd, operation)),
    )
    instance._acquire_lock()
    assert instance._lock_fd is not None
    instance._release_lock()
    assert instance._lock_fd is None
    instance._release_lock()

    instance._lock_fd = 123
    monkeypatch.setattr(
        supervisor.fcntl,
        "flock",
        lambda *_args: (_ for _ in ()).throw(OSError("unlock failed")),
    )
    instance._release_lock()
    assert instance._lock_fd is None

    monkeypatch.setattr(
        supervisor.fcntl,
        "flock",
        lambda *_args: (_ for _ in ()).throw(OSError(errno.EIO, "io")),
    )
    with pytest.raises(OSError):
        instance._acquire_lock()

    Path(supervisor.PID_FILE).write_text('{"pid": 321}', encoding="utf-8")
    monkeypatch.setattr(
        supervisor.fcntl,
        "flock",
        lambda *_args: (_ for _ in ()).throw(OSError(errno.EAGAIN, "busy")),
    )
    with pytest.raises(supervisor.AlreadyRunningError, match="PID 321"):
        instance._acquire_lock()

    instance._write_pid()
    payload = json.loads(Path(supervisor.PID_FILE).read_text(encoding="utf-8"))
    assert payload["pid"] == instance._pid
    assert instance._read_pid() == instance._pid
    Path(supervisor.PID_FILE).write_text("4321", encoding="utf-8")
    assert instance._read_pid() == 4321
    Path(supervisor.PID_FILE).write_text("invalid", encoding="utf-8")
    assert instance._read_pid() is None

    instance._remove_pid()
    instance._remove_pid()
    Path(supervisor.PID_FILE).write_text("stale", encoding="utf-8")
    instance._force_cleanup()
    instance._force_cleanup()

    monkeypatch.setattr(supervisor.os, "kill", lambda *_args: None)
    assert instance._is_pid_alive(1) is True
    monkeypatch.setattr(
        supervisor.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    assert instance._is_pid_alive(1) is False


def test_state_load_save_and_crash_info_boundaries(monkeypatch, paths) -> None:
    instance = supervisor.Supervisor()
    instance.register("component", lambda: True)
    assert instance._save_state() is True
    assert instance._load_state()["subsystems"]["component"]["name"] == "component"

    Path(supervisor.STATE_FILE).write_text("[]", encoding="utf-8")
    assert instance._load_state() is None
    Path(supervisor.STATE_FILE).write_text("not json", encoding="utf-8")
    assert instance._load_state() is None
    Path(supervisor.STATE_FILE).unlink()
    assert instance._load_state() is None

    monkeypatch.setattr(
        supervisor,
        "_atomic_write_json",
        lambda *_args: (_ for _ in ()).throw(OSError("disk full")),
    )
    assert instance._save_state() is False

    monkeypatch.setattr(instance, "_load_state", lambda: None)
    assert instance.get_crash_info() is None
    monkeypatch.setattr(
        instance,
        "_load_state",
        lambda: {"clean_shutdown": True, "lifecycle": "stopped", "pid": 1},
    )
    assert instance.get_crash_info() is None
    monkeypatch.setattr(instance, "_load_state", lambda: {"pid": None})
    assert instance.get_crash_info() is None
    monkeypatch.setattr(instance, "_load_state", lambda: {"pid": 2})
    monkeypatch.setattr(instance, "_is_pid_alive", lambda _pid: True)
    assert instance.get_crash_info() is None
    monkeypatch.setattr(instance, "_is_pid_alive", lambda _pid: False)
    assert instance.get_crash_info() == {
        "previous_pid": 2,
        "started_at": 0,
        "crashed_at": 0,
        "subsystems": {},
    }


def test_register_while_running_and_unregister(monkeypatch) -> None:
    instance = supervisor.Supervisor()
    instance.register("idle", lambda: True)
    instance._running = True
    instance.register("healthy", lambda: True)
    instance.register("broken", lambda: False)
    assert instance._metrics["crashes"] == 1
    instance.unregister("idle")
    instance.unregister("missing")
    assert "idle" not in instance._subsystems


def test_watchdog_restart_skip_stop_and_sleep_paths(monkeypatch) -> None:
    instance = supervisor.Supervisor()
    starts = []
    instance.register("stopped", lambda: True)
    instance._subsystems["stopped"].status = "stopped"
    instance.register("restart", lambda: False, start_fn=lambda: starts.append("restart"))
    instance.register("healthy", lambda: True)
    instance.register("over-limit", lambda: False, start_fn=lambda: starts.append("never"), max_restarts=1)
    instance._subsystems["over-limit"].status = "crashed"
    instance._subsystems["over-limit"].crash_count = 2
    instance.register(
        "restart-fails",
        lambda: False,
        start_fn=lambda: (_ for _ in ()).throw(RuntimeError("start failed")),
    )
    instance.register("no-start", lambda: False)
    instance._running = True
    saves = []

    def save_once():
        saves.append(True)
        instance._running = False
        return True

    monkeypatch.setattr(instance, "_save_state", save_once)
    instance._watchdog_loop()
    assert starts == ["restart"]
    assert instance._metrics == {
        "starts": 0,
        "crashes": 3,
        "restarts": 1,
        "uptime_total": 0.0,
    }
    assert saves == [True]

    break_instance = supervisor.Supervisor()

    def stop_during_check():
        break_instance._running = False
        return True

    break_instance.register("first", stop_during_check)
    break_instance.register("never", lambda: True)
    break_instance._running = True
    break_instance._watchdog_loop()
    assert break_instance._subsystems["never"].status == "unknown"

    continue_instance = supervisor.Supervisor()

    class StopOnStatus:
        @property
        def status(self):
            continue_instance._running = False
            return "stopped"

    continue_instance._subsystems = {
        "stop": StopOnStatus(),
        "break": supervisor.Subsystem("break", lambda: True),
    }
    continue_instance._running = True
    continue_instance._watchdog_loop()
    assert continue_instance._subsystems["break"].status == "unknown"

    sleep_instance = supervisor.Supervisor()
    sleep_instance._running = True
    monkeypatch.setattr(supervisor, "HEALTH_INTERVAL", 1)
    monkeypatch.setattr(sleep_instance, "_save_state", lambda: True)
    sleeps = []

    def sleep(_seconds):
        sleeps.append(True)
        if len(sleeps) == 2:
            sleep_instance._running = False

    monkeypatch.setattr(supervisor.time, "sleep", sleep)
    sleep_instance._watchdog_loop()
    assert len(sleeps) == 2


class Watchdog:
    def __init__(self, *, alive=True, stays_alive=False) -> None:
        self.alive = alive
        self.stays_alive = stays_alive
        self.started = False
        self.joins = []

    def start(self) -> None:
        self.started = True

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout=None) -> None:
        self.joins.append(timeout)
        if not self.stays_alive:
            self.alive = False


def configure_lifecycle(monkeypatch, instance, *, watchdog=None) -> None:
    monkeypatch.setattr(instance, "_acquire_lock", lambda: None)
    monkeypatch.setattr(instance, "_release_lock", lambda: None)
    monkeypatch.setattr(instance, "_write_pid", lambda: None)
    monkeypatch.setattr(instance, "_remove_pid", lambda: None)
    monkeypatch.setattr(instance, "_save_state", lambda: True)
    monkeypatch.setattr(instance, "_emit_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(supervisor.atexit, "register", lambda *_args: None)
    monkeypatch.setattr(supervisor.signal, "signal", lambda *_args: None)
    if watchdog is not None:
        monkeypatch.setattr(supervisor.threading, "Thread", lambda **_kwargs: watchdog)


def test_start_crash_warning_eager_failure_and_success(monkeypatch, capsys) -> None:
    instance = supervisor.Supervisor()
    instance.register("bad", lambda: False)
    watchdog = Watchdog(alive=False)
    configure_lifecycle(monkeypatch, instance, watchdog=watchdog)
    monkeypatch.setattr(instance, "get_crash_info", lambda: {"previous_pid": 321})
    instance.start()
    assert instance._running is True
    assert instance._metrics["starts"] == 1
    assert instance._metrics["crashes"] == 1
    assert watchdog.started is True
    assert "PID 321" in capsys.readouterr().out


def test_start_failure_unwinds_with_live_or_absent_watchdog(monkeypatch) -> None:
    instance = supervisor.Supervisor()
    watchdog = Watchdog(alive=True)
    configure_lifecycle(monkeypatch, instance, watchdog=watchdog)
    monkeypatch.setattr(
        supervisor.signal,
        "signal",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("signal failed")),
    )
    with pytest.raises(RuntimeError, match="signal failed"):
        instance.start()
    assert watchdog.joins == [2.0]
    assert instance._lifecycle == "startup_failed"

    early = supervisor.Supervisor()
    configure_lifecycle(monkeypatch, early)
    monkeypatch.setattr(
        early,
        "_write_pid",
        lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        early.start()
    assert early._watchdog_thread is None

    dead = supervisor.Supervisor()
    dead_watchdog = Watchdog(alive=False)
    configure_lifecycle(monkeypatch, dead, watchdog=dead_watchdog)
    monkeypatch.setattr(
        supervisor.signal,
        "signal",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("signal failed")),
    )
    with pytest.raises(RuntimeError):
        dead.start()
    assert dead_watchdog.joins == []


def test_stop_boundaries_hooks_watchdog_save_failure_and_zero_uptime(monkeypatch) -> None:
    instance = supervisor.Supervisor()
    assert instance.stop() is True
    instance._clean_shutdown = False
    assert instance.stop() is False

    errors = supervisor.Supervisor()
    errors._running = True
    errors._start_time = 0.0
    errors._watchdog_thread = Watchdog(alive=True, stays_alive=True)
    errors.on_shutdown(lambda: None)
    errors.on_shutdown(lambda: (_ for _ in ()).throw(RuntimeError("hook failed")))
    errors.register("stopped", lambda: True, stop_fn=lambda: None)
    errors._subsystems["stopped"].status = "stopped"
    errors.register("active", lambda: True, stop_fn=lambda: None)
    errors._subsystems["active"].status = "running"
    configure_lifecycle(monkeypatch, errors)
    monkeypatch.setattr(errors, "_save_state", lambda: False)
    assert errors.stop() is False
    assert errors._lifecycle == "shutdown_failed"
    assert errors._metrics["uptime_total"] == 0.0

    current = supervisor.Supervisor()
    current._running = True
    current._watchdog_thread = supervisor.threading.current_thread()
    configure_lifecycle(monkeypatch, current)
    assert current.stop() is True


def test_signal_health_and_reports(monkeypatch) -> None:
    instance = supervisor.Supervisor()
    with pytest.raises(SystemExit) as exc_info:
        instance._signal_handler(signal.SIGTERM, None)
    assert exc_info.value.code == 0
    assert instance.is_healthy() is False

    instance._running = True
    instance.register("ok", lambda: True)
    assert instance.is_healthy() is True
    stopped = supervisor.Subsystem("stopped", lambda: True)
    stopped.status = "stopped"
    instance._subsystems["stopped"] = stopped
    assert instance.is_healthy() is False

    monkeypatch.setattr(supervisor.time, "time", lambda: 20.0)
    instance._start_time = 10.0
    assert instance.health_report()["status"] == "unhealthy"
    instance.unregister("stopped")
    instance._subsystems["ok"].status = "running"
    assert instance.health_report()["status"] == "running"
    instance._running = False
    instance._start_time = 0.0
    report = instance.health_report()
    assert report["status"] == "stopped" and report["uptime_seconds"] == 0


def event_module(event_store):
    module = ModuleType("core.c2.event_store")
    module.EventStore = event_store
    return module


def test_event_emission_absent_success_and_allowed_errors(monkeypatch, paths, caplog) -> None:
    instance = supervisor.Supervisor()
    calls = []

    class Store:
        def __init__(self, **kwargs) -> None:
            calls.append(kwargs)

        def append(self, *args) -> None:
            calls.append(args)

    monkeypatch.setitem(sys.modules, "core.c2.event_store", event_module(Store))
    monkeypatch.setattr(supervisor.os.path, "exists", lambda _path: False)
    instance._emit_event("absent", {})
    assert calls == []
    monkeypatch.setattr(supervisor.os.path, "exists", lambda _path: True)
    instance._emit_event("started", {"x": 1})
    assert calls[-1][2] == "started"

    for error in (
        ImportError("missing"),
        OSError("disk"),
        sqlite3.Error("sqlite"),
        TypeError("type"),
        ValueError("value"),
    ):
        class BrokenStore:
            def __init__(self, selected_error=error, **_kwargs) -> None:
                raise selected_error

        monkeypatch.setitem(sys.modules, "core.c2.event_store", event_module(BrokenStore))
        with caplog.at_level("DEBUG"):
            instance._emit_event("failure", {})
    assert "event emission failed" in caplog.text


def test_pid_class_methods_and_kill_paths(monkeypatch, paths) -> None:
    Path(supervisor.PID_FILE).write_text('{"pid": 10}', encoding="utf-8")
    monkeypatch.setattr(supervisor.Supervisor, "_is_pid_alive", staticmethod(lambda _pid: True))
    assert supervisor.Supervisor.is_running() is True
    assert supervisor.Supervisor.get_pid() == 10
    Path(supervisor.PID_FILE).write_text("11", encoding="utf-8")
    assert supervisor.Supervisor.is_running() is True
    assert supervisor.Supervisor.get_pid() == 11
    Path(supervisor.PID_FILE).write_text("bad", encoding="utf-8")
    assert supervisor.Supervisor.is_running() is False
    assert supervisor.Supervisor.get_pid() is None

    monkeypatch.setattr(supervisor.Supervisor, "get_pid", classmethod(lambda _cls: None))
    assert supervisor.Supervisor.kill_running() is False
    monkeypatch.setattr(supervisor.Supervisor, "get_pid", classmethod(lambda _cls: 9))
    monkeypatch.setattr(supervisor.Supervisor, "_is_pid_alive", staticmethod(lambda _pid: False))
    assert supervisor.Supervisor.kill_running() is False

    alive = iter((True, False))
    monkeypatch.setattr(supervisor.Supervisor, "_is_pid_alive", staticmethod(lambda _pid: next(alive)))
    kills = []
    monkeypatch.setattr(supervisor.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    assert supervisor.Supervisor.kill_running() is True
    assert kills == [(9, signal.SIGTERM)]

    monkeypatch.setattr(supervisor.Supervisor, "_is_pid_alive", staticmethod(lambda _pid: True))
    sleeps = []
    monkeypatch.setattr(supervisor.time, "sleep", lambda value: sleeps.append(value))
    assert supervisor.Supervisor.kill_running() is True
    assert kills[-2:] == [(9, signal.SIGTERM), (9, signal.SIGKILL)]
    assert len(sleeps) == 50

    monkeypatch.setattr(
        supervisor.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    assert supervisor.Supervisor.kill_running() is True


class Response:
    def __init__(self, status) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None


def test_default_health_checks_success_failure_and_cleanup(monkeypatch, paths) -> None:
    import urllib.request

    requests = []
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, **kwargs: requests.append((request, kwargs)) or Response(200),
    )
    assert supervisor._check_ollama() is True
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_args, **_kwargs: Response(503))
    assert supervisor._check_ollama() is False
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    assert supervisor._check_ollama() is False

    connection = SimpleNamespace(
        cursor=lambda: (_ for _ in ()).throw(RuntimeError("cursor failed")),
        close=lambda: (_ for _ in ()).throw(RuntimeError("close failed")),
    )
    db_module = ModuleType("db")
    db_module.get_connection = lambda: connection
    monkeypatch.setitem(sys.modules, "db", db_module)
    assert supervisor._check_database() is False
    db_module.get_connection = lambda: (_ for _ in ()).throw(RuntimeError("connect failed"))
    assert supervisor._check_database() is False

    reads = []

    class Store:
        def __init__(self, **_kwargs) -> None:
            pass

        def read_stream(self, **kwargs) -> None:
            reads.append(kwargs)

    monkeypatch.setitem(sys.modules, "core.c2.event_store", event_module(Store))
    event_path = paths / "c2.db"
    event_path.write_text("db", encoding="utf-8")
    assert supervisor._check_event_store() is True
    assert reads == [{"limit": 1}]

    class BrokenStore:
        def __init__(self, **_kwargs) -> None:
            raise RuntimeError("broken")

    monkeypatch.setitem(sys.modules, "core.c2.event_store", event_module(BrokenStore))
    assert supervisor._check_event_store() is False


def test_factory_all_flags_and_no_flags() -> None:
    populated = supervisor.create_supervisor()
    assert set(populated._subsystems) == {"ollama", "database", "event_store"}
    assert supervisor.create_supervisor(False, False, False)._subsystems == {}


def run_cli(monkeypatch, action: str, *, pid=None, alive=True, kill_result=False):
    monkeypatch.setattr(sys, "argv", ["supervisor", action])
    monkeypatch.setattr(supervisor.Supervisor, "get_pid", classmethod(lambda _cls: pid))
    monkeypatch.setattr(
        supervisor.Supervisor,
        "_is_pid_alive",
        staticmethod(lambda _pid: alive),
    )
    monkeypatch.setattr(
        supervisor.Supervisor,
        "kill_running",
        classmethod(lambda _cls: kill_result),
    )
    return supervisor.cli()


def test_cli_pid_status_and_stop_variants(monkeypatch, paths, capsys) -> None:
    run_cli(monkeypatch, "pid", pid=12)
    assert "PID 12" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="1"):
        run_cli(monkeypatch, "pid", pid=None)

    state = {
        "started_at": 1,
        "subsystems": {
            "ok": {"status": "running", "crash_count": 0},
            "bad": {},
        },
    }
    Path(supervisor.STATE_FILE).write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(supervisor.time, "time", lambda: 11)
    run_cli(monkeypatch, "status", pid=12)
    output = capsys.readouterr().out
    assert "Status:     RUNNING" in output and "✅" in output and "❌" in output
    Path(supervisor.STATE_FILE).unlink()
    run_cli(monkeypatch, "status", pid=12)
    assert "no state file" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="1"):
        run_cli(monkeypatch, "status", pid=12, alive=False)

    run_cli(monkeypatch, "stop", kill_result=True)
    assert "stopped" in capsys.readouterr().out
    run_cli(monkeypatch, "stop", kill_result=False)
    assert "not running" in capsys.readouterr().out


def test_cli_health_all_empty_unhealthy_missing_and_invalid_state(monkeypatch, paths, capsys) -> None:
    with pytest.raises(SystemExit, match="1"):
        run_cli(monkeypatch, "health", pid=None)
    with pytest.raises(SystemExit, match="1"):
        run_cli(monkeypatch, "health", pid=2, alive=False)

    Path(supervisor.STATE_FILE).write_text(
        json.dumps({"subsystems": {"ok": {"status": "running"}}}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="0"):
        run_cli(monkeypatch, "health", pid=2)
    Path(supervisor.STATE_FILE).write_text(json.dumps({"subsystems": {}}), encoding="utf-8")
    with pytest.raises(SystemExit, match="0"):
        run_cli(monkeypatch, "health", pid=2)
    Path(supervisor.STATE_FILE).write_text(
        json.dumps({"subsystems": {"bad": {}}}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="1"):
        run_cli(monkeypatch, "health", pid=2)
    Path(supervisor.STATE_FILE).write_text("bad json", encoding="utf-8")
    with pytest.raises(SystemExit, match="1"):
        run_cli(monkeypatch, "health", pid=2)
    assert "No health data" in capsys.readouterr().out


def test_main_entrypoint_dispatches_cli(monkeypatch, tmp_path, capsys) -> None:
    source = Path(supervisor.__file__).read_text(encoding="utf-8")
    monkeypatch.setenv("OCTOPUS_PID", str(tmp_path / "missing.pid"))
    monkeypatch.setattr(sys, "argv", ["supervisor.py", "stop"])
    exec(
        compile(source, supervisor.__file__, "exec"),
        {"__name__": "__main__", "__file__": supervisor.__file__},
    )
    assert "not running" in capsys.readouterr().out
