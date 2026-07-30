"""Hermetic async-boundary coverage for the reconnaissance engine."""

from __future__ import annotations

import asyncio
import runpy
import sys

import pytest

import core.recon.recon_engine as recon_module
from core.recon.recon_engine import ReconEngine, ReconTask

pytestmark = [pytest.mark.contract, pytest.mark.security]


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data

    async def read(self, _size: int) -> bytes:
        return self.data


class Writer:
    def __init__(self, *, wait_error: Exception | None = None) -> None:
        self.wait_error = wait_error
        self.writes: list[bytes] = []
        self.closed = False
        self.drained = False
        self.waited = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        self.drained = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True
        if self.wait_error is not None:
            raise self.wait_error


def _initialized_engine(target: str = "target") -> ReconEngine:
    engine = object.__new__(ReconEngine)
    engine.concurrency = 1
    engine.queue = None
    engine.results = {}
    engine.state = {}
    engine.completed_tasks = 0
    engine.results[target] = {}
    engine.state[target] = {"open_ports": [], "services": {}}
    return engine


def test_recon_task_ordering_and_default_metadata() -> None:
    lower = ReconTask("a", "first", priority=0)
    higher = ReconTask("b", "second", priority=2, meta={"port": 80})

    assert lower < higher
    assert lower.meta == {}
    assert higher.meta == {"port": 80}


def test_worker_contains_queue_and_task_failures_and_acknowledges_cancellation() -> None:
    error_task = ReconTask("target", "error")
    cancel_task = ReconTask("target", "cancel")

    class Queue:
        def __init__(self) -> None:
            self.actions = [RuntimeError("queue fixture"), error_task, cancel_task]
            self.done = 0

        async def get(self):
            action = self.actions.pop(0)
            if isinstance(action, BaseException):
                raise action
            return action

        def task_done(self) -> None:
            self.done += 1

    queue = Queue()
    engine = _initialized_engine()
    engine.queue = queue

    async def process(task: ReconTask, _worker_id: int) -> None:
        if task.task_type == "error":
            raise ValueError("task fixture")
        raise asyncio.CancelledError

    engine._process_task = process
    asyncio.run(engine._worker(7))

    assert queue.done == 2
    assert engine.completed_tasks == 2


def test_process_task_dispatches_every_handler_and_unknown_type(capsys) -> None:
    engine = _initialized_engine()
    engine.results.clear()
    engine.state.clear()
    calls = []

    def handler(name: str):
        async def record(*args) -> None:
            calls.append((name, args))

        return record

    engine._run_nmap_fast = handler("nmap")
    engine._grab_banner = handler("banner")
    engine._tls_fingerprint = handler("tls")
    engine._http_probe = handler("http")
    engine._run_enum4linux = handler("enum")

    async def scenario() -> None:
        await engine._process_task(ReconTask("target", "nmap_fast"), 1)
        await engine._process_task(
            ReconTask("target", "banner_grab", meta={"port": 22}),
            1,
        )
        await engine._process_task(
            ReconTask("target", "tls_fingerprint", meta={"port": 443}),
            1,
        )
        await engine._process_task(
            ReconTask("target", "http_probe", meta={"port": 80}),
            1,
        )
        await engine._process_task(
            ReconTask(
                "target",
                "http_probe",
                meta={"port": 443, "is_tls": True},
            ),
            1,
        )
        await engine._process_task(ReconTask("target", "enum4linux"), 1)
        await engine._process_task(ReconTask("target", "unknown"), 1)

    asyncio.run(scenario())

    assert engine.state["target"] == {"open_ports": [], "services": {}}
    assert calls == [
        ("nmap", ("target",)),
        ("banner", ("target", 22)),
        ("tls", ("target", 443)),
        ("http", ("target", 80, False)),
        ("http", ("target", 443, True)),
        ("enum", ("target",)),
    ]
    assert "Unknown task type" in capsys.readouterr().out


def test_nmap_parser_and_adaptive_queue_use_only_mocked_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = b"""80/tcp open http
443/tcp open https
445/tcp open microsoft-ds
9999/tcp open unknown
bad/tcp open malformed
22/tcp closed ssh
"""
    calls = []

    class Process:
        async def communicate(self):
            return output, b""

    async def create_process(*command, **kwargs):
        calls.append((command, kwargs))
        return Process()

    monkeypatch.setattr(
        recon_module.asyncio,
        "create_subprocess_exec",
        create_process,
    )
    engine = _initialized_engine()

    async def scenario() -> list[ReconTask]:
        engine.queue = asyncio.PriorityQueue()
        await engine._run_nmap_fast("target")
        queued = []
        while not engine.queue.empty():
            queued.append(engine.queue.get_nowait())
        return queued

    queued = asyncio.run(scenario())

    assert calls[0][0] == (
        "nmap",
        "-T4",
        "-F",
        "--open",
        "-n",
        "target",
    )
    assert engine.state["target"]["open_ports"] == [80, 443, 445, 9999]
    assert [task.task_type for task in queued].count("banner_grab") == 4
    assert [task.task_type for task in queued].count("http_probe") == 2
    assert [task.task_type for task in queued].count("tls_fingerprint") == 1
    assert [task.task_type for task in queued].count("enum4linux") == 1


def test_banner_probe_success_empty_failure_and_cleanup_are_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writers = [
        Writer(),
        Writer(wait_error=OSError("cleanup fixture")),
        Writer(),
    ]
    actions = [
        (Reader(b"SSH-2.0 fixture"), writers[0]),
        (Reader(b"HTTP/1.1 200 OK\r\n\r\n<html>"), writers[1]),
        (Reader(b""), writers[2]),
        OSError("connect fixture"),
    ]

    async def open_connection(*_args, **_kwargs):
        action = actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return action

    monkeypatch.setattr(recon_module.asyncio, "open_connection", open_connection)
    engine = _initialized_engine()

    async def scenario() -> None:
        for port in (22, 80, 81, 82):
            await engine._grab_banner("target", port)

    asyncio.run(scenario())

    assert engine.state["target"]["services"] == {22: "ssh", 80: "http"}
    assert engine.results["target"]["banners"].count("[Port") == 2
    assert all(writer.closed for writer in writers)
    assert all(writer.waited for writer in writers)


@pytest.mark.parametrize(
    ("port", "banner", "expected"),
    [
        (22, "SSH-2.0", "ssh"),
        (80, "HTTP/1.1 200", "http"),
        (8080, "<html>", "http"),
        (21, "FTP ready", "ftp"),
        (21, "220 ready", "ftp"),
        (3306, "MySQL handshake", "mysql"),
        (1234, "opaque", "unknown"),
    ],
)
def test_service_heuristic_covers_every_protocol_branch(
    port: int,
    banner: str,
    expected: str,
) -> None:
    assert _initialized_engine()._heuristic_service_detect(port, banner) == expected


def test_tls_fingerprint_success_append_and_failure_use_mocked_thread_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actions = ["CERTIFICATE-ONE", "CERTIFICATE-TWO", OSError("tls fixture")]
    calls = []

    async def to_thread(function, address, **kwargs):
        calls.append((function, address, kwargs))
        action = actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return action

    monkeypatch.setattr(recon_module.asyncio, "to_thread", to_thread)
    engine = _initialized_engine()

    async def scenario() -> None:
        await engine._tls_fingerprint("target", 443)
        await engine._tls_fingerprint("target", 8443)
        await engine._tls_fingerprint("target", 9443)

    asyncio.run(scenario())

    assert "CERTIFICATE-ONE" in engine.results["target"]["tls"]
    assert "CERTIFICATE-TWO" in engine.results["target"]["tls"]
    assert [call[1] for call in calls] == [
        ("target", 443),
        ("target", 8443),
        ("target", 9443),
    ]
    assert all(call[2] == {"timeout": 5} for call in calls)


def test_http_probe_title_server_plain_response_and_errors_are_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writers = [
        Writer(),
        Writer(wait_error=OSError("cleanup fixture")),
        Writer(),
    ]
    actions = [
        (
            Reader(
                b"HTTP/1.1 200 OK\r\nServer: Fixture\r\n\r\n"
                b"<TITLE> Example </TITLE>"
            ),
            writers[0],
        ),
        (Reader(b"HTTP/1.1 200 OK\r\n\r\n<title>broken"), writers[1]),
        (Reader(b"HTTP/1.1 204 No Content\r\n\r\n"), writers[2]),
        OSError("connect fixture"),
    ]
    ssl_values = []

    async def open_connection(*_args, **kwargs):
        ssl_values.append(kwargs.get("ssl"))
        action = actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return action

    monkeypatch.setattr(recon_module.asyncio, "open_connection", open_connection)
    engine = _initialized_engine()

    async def scenario() -> None:
        await engine._http_probe("target", 443, True)
        await engine._http_probe("target", 80, False)
        await engine._http_probe("target", 8080, False)
        await engine._http_probe("target", 81, False)

    asyncio.run(scenario())

    http_output = engine.results["target"]["http_enum"]
    assert "https://target:443/ | Server: Fixture | Title: Example" in http_output
    assert "http://target:80/ | Server: Unknown | Title: None" in http_output
    assert "http://target:8080/ | Server: Unknown | Title: None" in http_output
    assert ssl_values == [True, None, None, None]
    assert all(writer.closed for writer in writers)


def test_enum4linux_success_timeout_kill_race_and_spawn_error_are_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        def __init__(self, *, timeout: bool = False, kill_error: bool = False) -> None:
            self.timeout = timeout
            self.kill_error = kill_error
            self.calls = 0
            self.killed = False

        async def communicate(self):
            self.calls += 1
            if self.timeout and self.calls == 1:
                raise asyncio.TimeoutError
            return b"enum output", b""

        def kill(self) -> None:
            self.killed = True
            if self.kill_error:
                raise ProcessLookupError

    success = Process()
    timed_out = Process(timeout=True)
    raced = Process(timeout=True, kill_error=True)
    actions = [
        success,
        timed_out,
        raced,
        asyncio.TimeoutError(),
        OSError("spawn fixture"),
    ]

    async def create_process(*_args, **_kwargs):
        action = actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return action

    monkeypatch.setattr(
        recon_module.asyncio,
        "create_subprocess_exec",
        create_process,
    )
    engine = _initialized_engine("success")
    for target in ("timeout", "race", "no-proc", "error"):
        engine.results[target] = {}
        engine.state[target] = {"open_ports": [], "services": {}}

    async def scenario() -> None:
        for target in ("success", "timeout", "race", "no-proc", "error"):
            await engine._run_enum4linux(target)

    asyncio.run(scenario())

    assert engine.results["success"]["enum4linux"] == "enum output"
    assert engine.results["timeout"]["enum4linux"] == "[!] enum4linux timed out."
    assert engine.results["race"]["enum4linux"] == "[!] enum4linux timed out."
    assert engine.results["no-proc"]["enum4linux"] == "[!] enum4linux timed out."
    assert engine.results["error"]["enum4linux"] == "[!] enum4linux error: OSError"
    assert timed_out.killed is True
    assert raced.killed is True
    assert timed_out.calls == raced.calls == 2


def test_run_scan_drains_mocked_tasks_cancels_workers_and_formats_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = iter((10.0, 12.5))
    monkeypatch.setattr(recon_module.time, "time", lambda: next(clock, 12.5))

    async def scenario():
        engine = ReconEngine(concurrency=2)

        async def process(task: ReconTask, _worker_id: int) -> None:
            engine.results[task.target] = {
                "fixture": f" result for {task.target} ",
                "empty": "   ",
            }
            engine.state[task.target] = {"open_ports": [], "services": {}}

        engine._process_task = process
        result = await engine.run_scan(["one", "two"])
        return engine, result

    engine, result = asyncio.run(scenario())

    assert result == {
        "one": "[FIXTURE]\nresult for one\n\n",
        "two": "[FIXTURE]\nresult for two\n\n",
    }
    assert engine.completed_tasks == 2


def test_sync_adapter_and_script_entrypoint_use_mocked_async_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    seen = []

    class Engine:
        def __init__(self, concurrency: int) -> None:
            seen.append(concurrency)

        async def run_scan(self, targets):
            return {targets[0]: "direct result"}

    monkeypatch.setattr(recon_module, "ReconEngine", Engine)
    assert recon_module.run_async_recon(["direct"], concurrency=3) == {
        "direct": "direct result"
    }
    assert seen == [3]

    def fake_run(coroutine):
        coroutine.close()
        return {"script-target": "script result"}

    monkeypatch.setattr(asyncio, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["recon_engine.py", "script-target"])
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        runpy.run_path(recon_module.__file__, run_name="__main__")
    finally:
        asyncio.set_event_loop(None)
        loop.close()

    output = capsys.readouterr().out
    assert "RESULTS FOR script-target" in output
    assert "script result" in output
