"""Hermetic branch coverage for the bounded competitor command runner."""

from __future__ import annotations

import io
import json
import os
import signal
import stat
import subprocess
from collections import deque
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks import load_scenario
from core.benchmarks.competitors import runner as runner_module
from core.benchmarks.competitors.schema import SystemManifest

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


SCENARIO_PATH = Path(__file__).parents[2] / "benchmarks" / "scenarios" / "01-service-discovery-verification.json"


def _manifest(
    tmp_path: Path,
    *,
    argv: list[str] | None = None,
    source_path: bool = True,
) -> SystemManifest:
    payload = {
        "schema_version": "1.0",
        "system_id": "example-system",
        "name": "Example System",
        "version": "2.1.0",
        "source_revision": "abc123",
        "track": "framework_only",
        "execution_mode": "replay",
        "fairness_profile": {
            "profile_id": "shared-replay-v1",
            "same_model": True,
            "same_tool_versions": True,
            "same_hardware": True,
            "same_budgets": True,
        },
        "model": {
            "provider": "deterministic",
            "name": "fixture",
            "parameters": {"temperature": 0},
        },
        "tool_versions": {"adapter": "1.0"},
        "adapter": {
            "kind": "command",
            "argv": argv
            or [
                "adapter",
                "{scenario_path}",
                "{output_path}",
                "{repetition}",
                "{seed}",
                "{system_id}",
            ],
            "working_directory": ".",
            "environment_passthrough": ["RUNNER_ALLOWED", "RUNNER_MISSING"],
        },
        "metadata": {"publisher": "test"},
    }
    return SystemManifest.from_dict(
        payload,
        source_path=tmp_path / "system.json" if source_path else None,
    )


@pytest.fixture
def scenario():
    return load_scenario(SCENARIO_PATH)


class _FakeProcess:
    def __init__(
        self,
        *,
        stdout: Any = None,
        polls: list[int | None] | None = None,
        returncode: int | None = 0,
        waits: list[Any] | None = None,
    ) -> None:
        self.stdout = stdout
        self.pid = 31415
        self.returncode = returncode
        self._polls = deque(polls or [])
        self._waits = deque(waits or [])
        self.calls: list[Any] = []

    def poll(self):
        self.calls.append("poll")
        if self._polls:
            return self._polls.popleft()
        return self.returncode

    def terminate(self) -> None:
        self.calls.append("terminate")

    def kill(self) -> None:
        self.calls.append("kill")

    def wait(self, *, timeout: float):
        self.calls.append(("wait", timeout))
        if self._waits:
            outcome = self._waits.popleft()
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return self.returncode


class _FakePipe:
    def __init__(self, fd: int = 73) -> None:
        self.fd = fd
        self.closed = False

    def fileno(self) -> int:
        return self.fd

    def close(self) -> None:
        self.closed = True


class _FakeKey:
    def __init__(self, pipe: _FakePipe) -> None:
        self.fd = pipe.fd
        self.fileobj = pipe


class _FakeSelector:
    def __init__(
        self,
        *,
        events: list[list[tuple[_FakeKey, int]]] | None = None,
        keep_registered: bool = True,
        unregister_error: BaseException | None = None,
    ) -> None:
        self._events = deque(events or [])
        self._key: _FakeKey | None = None
        self.keep_registered = keep_registered
        self.unregister_error = unregister_error
        self.closed = False
        self.waits: list[float] = []

    def register(self, pipe: _FakePipe, _event: int) -> None:
        self._key = _FakeKey(pipe)

    def select(self, timeout: float):
        self.waits.append(timeout)
        if self._events:
            return self._events.popleft()
        return []

    def unregister(self, _pipe: _FakePipe) -> None:
        if self.unregister_error is not None:
            raise self.unregister_error
        self.keep_registered = False

    def get_map(self):
        if self.keep_registered and self._key is not None:
            return {self._key.fd: self._key}
        return {}

    def close(self) -> None:
        self.closed = True


def _patch_monitor_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    selector: _FakeSelector,
    times: list[float],
    reads: list[bytes | BaseException] | None = None,
) -> list[_FakeProcess]:
    cleaned: list[_FakeProcess] = []
    clock = iter(times)
    read_values = deque(reads or [])

    monkeypatch.setattr(
        runner_module.selectors,
        "DefaultSelector",
        lambda: selector,
    )
    monkeypatch.setattr(runner_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(runner_module.os, "set_blocking", lambda *_args: None)

    def fake_read(_fd: int, _limit: int) -> bytes:
        outcome = read_values.popleft() if read_values else b""
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(runner_module.os, "read", fake_read)
    monkeypatch.setattr(
        runner_module,
        "_cleanup_process_tree",
        lambda process: cleaned.append(process),
    )
    return cleaned


def test_error_codes_and_constructor_variants(
    tmp_path: Path,
) -> None:
    assert str(runner_module.SystemRunnerError()) == "system_runner_error"
    assert str(runner_module.SystemUnavailableError()) == "system_unavailable"
    assert str(runner_module.SystemProtocolError()) == "system_protocol_error"

    default = runner_module.CommandSystemRunner(_manifest(tmp_path))
    configured = runner_module.CommandSystemRunner(
        _manifest(tmp_path),
        timeout_seconds=12.5,
        max_output_bytes=99,
        temporary_directory=tmp_path,
        private_log_path=tmp_path / "private.log",
    )

    assert default.timeout_seconds is None
    assert default.max_output_bytes is None
    assert default.temporary_directory is None
    assert default.private_log_path is None
    assert configured.timeout_seconds == 12.5
    assert configured.max_output_bytes == 99
    assert configured.temporary_directory == tmp_path
    assert configured.private_log_path == tmp_path / "private.log"


def test_call_success_is_shell_free_bounded_and_closes_private_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
) -> None:
    manifest = _manifest(tmp_path)
    command_runner = runner_module.CommandSystemRunner(
        manifest,
        timeout_seconds=10,
        max_output_bytes=1_000,
        temporary_directory=tmp_path,
        private_log_path=tmp_path / "private.log",
    )
    popen_calls: list[tuple[list[str], dict[str, Any]]] = []
    private_log = io.BytesIO()

    def fake_popen(argv: list[str], **kwargs: Any):
        popen_calls.append((argv, kwargs))
        Path(argv[2]).write_text(
            json.dumps(
                {
                    "status": "SUCCEEDED",
                    "actions": ["Scan.Action"],
                    "reported_claims": [" claim "],
                    "reported_findings": ["Finding.One"],
                    "verified_findings": ["finding.one"],
                    "coverage_gaps": ["gap.one"],
                    "metrics": {"Score.One": 2},
                    "artifact_refs": [" artifact://one "],
                    "error_class": "AdapterNote",
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(name="fake-process")

    monotonic_values = iter([100.0, 104.0])
    monkeypatch.setenv("RUNNER_ALLOWED", "available")
    monkeypatch.setattr(
        runner_module.time,
        "monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr(runner_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        runner_module,
        "_monitor_process",
        lambda *_args, **_kwargs: (0, 20, False, False, False),
    )
    monkeypatch.setattr(
        runner_module,
        "_open_private_log",
        lambda _path: private_log,
    )

    result = command_runner(scenario, repetition=2, seed=101)

    argv, kwargs = popen_calls[0]
    assert argv[0] == "adapter"
    assert argv[3:] == ["2", "101", "example-system"]
    assert kwargs["cwd"] == str(tmp_path.resolve())
    assert kwargs["env"]["RUNNER_ALLOWED"] == "available"
    assert "RUNNER_MISSING" not in kwargs["env"]
    assert kwargs["env"]["OCTOPUS_BENCHMARK_SEED"] == "101"
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.STDOUT
    assert kwargs["shell"] is False
    assert kwargs["start_new_session"] is (os.name == "posix")
    assert result == {
        "status": "succeeded",
        "actions": ["scan.action"],
        "reported_claims": ["claim"],
        "reported_findings": ["finding.one"],
        "verified_findings": ["finding.one"],
        "coverage_gaps": ["gap.one"],
        "metrics": {"score.one": 2.0},
        "artifact_refs": ["artifact://one"],
        "duration_seconds": 4.0,
        "error_class": "AdapterNote",
    }
    assert private_log.closed
    assert command_runner.public_metadata() == manifest.to_public_dict()


@pytest.mark.parametrize(
    ("monitor_result", "payload", "expected_status", "expected_error"),
    [
        ((0, 0, True, False, False), None, "timeout", "AdapterWallTimeout"),
        ((7, 0, False, False, False), None, "failed", "AdapterExitCode7"),
        ((-9, 0, False, False, False), None, "failed", "AdapterSignal9"),
        (
            (0, 0, False, False, True),
            {"status": "succeeded"},
            "timeout",
            "AdapterExecutionDeadlineExceeded",
        ),
        ((0, 0, False, False, True), {"status": "partial"}, "partial", ""),
        ((0, 0, False, False, True), {"status": "timeout"}, "timeout", ""),
    ],
)
def test_call_maps_monitor_outcomes_without_processes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
    monitor_result: tuple[int, int, bool, bool, bool],
    payload: dict[str, Any] | None,
    expected_status: str,
    expected_error: str,
) -> None:
    def fake_popen(argv: list[str], **_kwargs: Any):
        if payload is not None:
            Path(argv[2]).write_text(json.dumps(payload), encoding="utf-8")
        return SimpleNamespace(name="fake-process")

    monkeypatch.setattr(runner_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        runner_module,
        "_monitor_process",
        lambda *_args, **_kwargs: monitor_result,
    )
    monkeypatch.setattr(runner_module.time, "monotonic", lambda: 10.0)

    result = runner_module.CommandSystemRunner(_manifest(tmp_path))(
        scenario,
        repetition=1,
        seed=2,
    )

    assert result["status"] == expected_status
    assert result["error_class"] == expected_error


def test_call_v3_blinds_seed_and_uses_generated_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
) -> None:
    scenario = replace(scenario, lab={**scenario.lab, "version": "discovery-lab-v3"})
    manifest = _manifest(
        tmp_path,
        argv=["adapter", "{scenario_path}", "{output_path}"],
    )
    observed: dict[str, Any] = {}

    def fake_popen(argv: list[str], **kwargs: Any):
        observed.update(kwargs)
        Path(argv[2]).write_text("{}", encoding="utf-8")
        return SimpleNamespace(name="fake-process")

    monkeypatch.setattr(runner_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        runner_module,
        "_monitor_process",
        lambda *_args, **_kwargs: (0, 0, False, False, False),
    )
    monkeypatch.setattr(runner_module.time, "monotonic", lambda: 10.0)

    result = runner_module.CommandSystemRunner(
        manifest,
        temporary_directory=tmp_path,
    )(scenario, 1, 999)

    assert result["status"] == "succeeded"
    assert "OCTOPUS_BENCHMARK_SEED" not in observed["env"]
    assert Path(observed["cwd"]).parent == tmp_path
    assert Path(observed["cwd"]).name.startswith("octopus-benchmark-adapter-")


@pytest.mark.parametrize("exception", [OSError("missing"), ValueError("bad argv")])
def test_call_wraps_popen_failures_and_closes_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
    exception: BaseException,
) -> None:
    private_log = io.BytesIO()
    monkeypatch.setattr(
        runner_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(exception),
    )
    monkeypatch.setattr(
        runner_module,
        "_open_private_log",
        lambda _path: private_log,
    )

    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module.CommandSystemRunner(
            _manifest(tmp_path),
            private_log_path=tmp_path / "log",
        )(scenario, 1, 2)

    assert private_log.closed


def test_call_rejects_output_overflow_and_preserves_runner_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
) -> None:
    monkeypatch.setattr(
        runner_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: SimpleNamespace(name="fake-process"),
    )
    monkeypatch.setattr(
        runner_module,
        "_monitor_process",
        lambda *_args, **_kwargs: (0, 11, False, True, False),
    )
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module.CommandSystemRunner(_manifest(tmp_path))(scenario, 1, 2)

    monkeypatch.setattr(
        runner_module,
        "_write_scenario",
        lambda *_args: (_ for _ in ()).throw(runner_module.SystemProtocolError()),
    )
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module.CommandSystemRunner(_manifest(tmp_path))(scenario, 1, 2)


@pytest.mark.parametrize("exception", [OSError("disk"), ValueError("path")])
def test_call_wraps_outer_platform_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
    exception: BaseException,
) -> None:
    monkeypatch.setattr(
        runner_module,
        "_write_scenario",
        lambda *_args: (_ for _ in ()).throw(exception),
    )

    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module.CommandSystemRunner(_manifest(tmp_path))(scenario, 1, 2)


def test_effective_limits_working_directory_argv_and_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
) -> None:
    default = runner_module.CommandSystemRunner(_manifest(tmp_path))
    limited = runner_module.CommandSystemRunner(
        _manifest(tmp_path),
        timeout_seconds=2,
        max_output_bytes=3,
    )

    assert default._effective_timeout(scenario) == scenario.budgets["max_seconds"]
    assert default._effective_wall_timeout(4) == 9
    assert default._effective_output_limit(scenario) == scenario.budgets["max_output_bytes"]
    assert limited._effective_timeout(scenario) == 2
    assert limited._effective_wall_timeout(4) == 2
    assert limited._effective_output_limit(scenario) == 3
    assert default._working_directory() == tmp_path.resolve()
    assert (
        runner_module.CommandSystemRunner(_manifest(tmp_path, source_path=False))._working_directory()
        == Path.cwd().resolve()
    )

    outside = replace(
        default.manifest,
        adapter=replace(default.manifest.adapter, cwd=".."),
    )
    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module.CommandSystemRunner(outside)._working_directory()

    missing = replace(
        default.manifest,
        adapter=replace(default.manifest.adapter, cwd="missing"),
    )
    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module.CommandSystemRunner(missing)._working_directory()

    paths = {"scenario_path": tmp_path / "s", "output_path": tmp_path / "o"}
    assert default._argv(**paths, repetition=4, seed=5) == [
        "adapter",
        str(tmp_path / "s"),
        str(tmp_path / "o"),
        "4",
        "5",
        "example-system",
    ]
    with pytest.raises(runner_module.SystemProtocolError):
        default._argv(**paths, repetition=4, seed=5, blinded_v3=True)

    bad_format = replace(
        default.manifest,
        adapter=replace(default.manifest.adapter, argv=("{missing}",)),
    )
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module.CommandSystemRunner(bad_format)._argv(
            **paths,
            repetition=4,
            seed=5,
        )

    bad_brace = replace(
        default.manifest,
        adapter=replace(default.manifest.adapter, argv=("{",)),
    )
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module.CommandSystemRunner(bad_brace)._argv(
            **paths,
            repetition=4,
            seed=5,
        )

    huge = replace(
        default.manifest,
        adapter=replace(default.manifest.adapter, argv=("x" * 16_385,)),
    )
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module.CommandSystemRunner(huge)._argv(
            **paths,
            repetition=4,
            seed=5,
        )

    monkeypatch.setenv("RUNNER_ALLOWED", "yes")
    environment = default._environment(
        scenario=scenario,
        scenario_path=paths["scenario_path"],
        output_path=paths["output_path"],
        repetition=4,
        seed=5,
    )
    assert environment["RUNNER_ALLOWED"] == "yes"
    assert "RUNNER_MISSING" not in environment
    assert environment["OCTOPUS_BENCHMARK_SEED"] == "5"
    v3 = replace(scenario, lab={"version": "discovery-lab-v3"})
    assert "OCTOPUS_BENCHMARK_SEED" not in default._environment(
        scenario=v3,
        scenario_path=paths["scenario_path"],
        output_path=paths["output_path"],
        repetition=4,
        seed=5,
    )


def test_write_scenario_is_canonical_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario,
) -> None:
    destination = tmp_path / "scenario.json"
    runner_module._write_scenario(scenario, destination)
    payload = destination.read_bytes()
    assert payload.endswith(b"\n")
    assert json.loads(payload) == scenario.to_dict()

    monkeypatch.setattr(runner_module, "MAX_SCENARIO_BYTES", 1)
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._write_scenario(scenario, destination)


def test_monitor_rejects_missing_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(stdout=None)
    cleaned: list[_FakeProcess] = []
    monkeypatch.setattr(
        runner_module,
        "_cleanup_process_tree",
        lambda item: cleaned.append(item),
    )

    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module._monitor_process(
            process,
            timeout_seconds=1,
            execution_timeout_seconds=1,
            output_limit=1,
        )

    assert cleaned == [process]


def test_monitor_wall_timeout_is_hermetic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = _FakePipe()
    selector = _FakeSelector()
    process = _FakeProcess(stdout=pipe, polls=[None], returncode=-9)
    cleaned = _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 2],
    )

    assert runner_module._monitor_process(
        process,
        timeout_seconds=1,
        execution_timeout_seconds=10,
        output_limit=8,
    ) == (-9, 0, True, False, False)
    assert selector.closed and pipe.closed
    assert cleaned == [process]


def test_monitor_execution_deadline_then_clean_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = _FakePipe()
    selector = _FakeSelector(keep_registered=False)
    process = _FakeProcess(stdout=pipe, polls=[None, 0], returncode=0)
    _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 2],
    )

    assert runner_module._monitor_process(
        process,
        timeout_seconds=5,
        execution_timeout_seconds=1,
        output_limit=8,
    ) == (0, 0, False, False, True)
    assert selector.waits == [0.05]


def test_monitor_continues_while_process_remains_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = _FakePipe()
    selector = _FakeSelector(events=[[], []], keep_registered=False)
    process = _FakeProcess(
        stdout=pipe,
        polls=[None, None, 0, 0],
        returncode=0,
    )
    _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 0, 0],
    )

    assert runner_module._monitor_process(
        process,
        timeout_seconds=5,
        execution_timeout_seconds=2,
        output_limit=8,
    ) == (0, 0, False, False, False)
    assert len(selector.waits) == 2


def test_monitor_captures_event_and_drains_after_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = _FakePipe()
    key = _FakeKey(pipe)
    selector = _FakeSelector(events=[[(key, 1)]])
    process = _FakeProcess(stdout=pipe, polls=[None, 0], returncode=0)
    private_log = io.BytesIO()
    _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 0],
        reads=[b"ab", b"cd"],
    )

    assert runner_module._monitor_process(
        process,
        timeout_seconds=5,
        execution_timeout_seconds=2,
        output_limit=10,
        private_log=private_log,
    ) == (0, 4, False, False, False)
    assert private_log.getvalue() == b"abcd"


def test_monitor_event_overflow_stops_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = _FakePipe()
    key = _FakeKey(pipe)
    selector = _FakeSelector(events=[[(key, 1)]])
    process = _FakeProcess(stdout=pipe, polls=[None], returncode=0)
    private_log = io.BytesIO()
    _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 0],
        reads=[b"xx"],
    )

    assert runner_module._monitor_process(
        process,
        timeout_seconds=5,
        execution_timeout_seconds=2,
        output_limit=1,
        private_log=private_log,
    ) == (0, 2, False, True, False)
    assert private_log.getvalue() == b"x"


@pytest.mark.parametrize("unregister_error", [None, KeyError("gone")])
def test_monitor_empty_or_failed_event_read_unregisters_safely(
    monkeypatch: pytest.MonkeyPatch,
    unregister_error: BaseException | None,
) -> None:
    pipe = _FakePipe()
    key = _FakeKey(pipe)
    selector = _FakeSelector(
        events=[[(key, 1)]],
        unregister_error=unregister_error,
    )
    process = _FakeProcess(stdout=pipe, polls=[None, 0], returncode=0)
    _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 0],
        reads=[OSError("closed")],
    )

    assert runner_module._monitor_process(
        process,
        timeout_seconds=5,
        execution_timeout_seconds=2,
        output_limit=10,
    ) == (0, 0, False, False, False)


@pytest.mark.parametrize(
    ("read_value", "limit", "expected"),
    [
        (OSError("closed"), 10, (0, 0, False, False, False)),
        (b"xx", 1, (0, 2, False, True, False)),
    ],
)
def test_monitor_drains_terminated_process_without_waiting(
    monkeypatch: pytest.MonkeyPatch,
    read_value: bytes | BaseException,
    limit: int,
    expected: tuple[int, int, bool, bool, bool],
) -> None:
    pipe = _FakePipe()
    selector = _FakeSelector()
    process = _FakeProcess(stdout=pipe, polls=[0, 0], returncode=0)
    _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 0],
        reads=[read_value],
    )

    assert (
        runner_module._monitor_process(
            process,
            timeout_seconds=5,
            execution_timeout_seconds=2,
            output_limit=limit,
        )
        == expected
    )


def test_monitor_ignores_set_blocking_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe = _FakePipe()
    selector = _FakeSelector(keep_registered=False)
    process = _FakeProcess(stdout=pipe, polls=[0, 0], returncode=0)
    _patch_monitor_dependencies(
        monkeypatch,
        selector=selector,
        times=[0, 0],
    )
    monkeypatch.setattr(
        runner_module.os,
        "set_blocking",
        lambda *_args: (_ for _ in ()).throw(OSError("unsupported")),
    )

    assert runner_module._monitor_process(
        process,
        timeout_seconds=5,
        execution_timeout_seconds=2,
        output_limit=10,
    ) == (0, 0, False, False, False)


def test_open_private_log_real_success_and_input_failures(tmp_path: Path) -> None:
    assert runner_module._open_private_log(None) is None
    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module._open_private_log(Path("relative.log"))

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    destination = private / "adapter.log"
    stream = runner_module._open_private_log(destination)
    assert stream is not None
    stream.write(b"safe")
    stream.close()
    assert destination.read_bytes() == b"safe"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600

    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module._open_private_log(destination)

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o755)
    with pytest.raises(runner_module.SystemUnavailableError):
        runner_module._open_private_log(unsafe / "adapter.log")


def test_open_private_log_portable_flags_and_descriptor_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[tuple[Any, ...]] = []
    closed: list[int] = []
    fstats = deque(
        [
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o700),
            SimpleNamespace(st_mode=stat.S_IFREG | 0o600),
        ]
    )

    with monkeypatch.context() as patcher:
        patcher.delattr(runner_module.os, "O_DIRECTORY")
        patcher.delattr(runner_module.os, "O_NOFOLLOW")

        def fake_open(*args: Any, **kwargs: Any) -> int:
            opened.append((*args, kwargs))
            return 10 if len(opened) == 1 else 11

        patcher.setattr(runner_module.os, "open", fake_open)
        patcher.setattr(runner_module.os, "fstat", lambda _fd: fstats.popleft())
        patcher.setattr(runner_module.os, "fchmod", lambda *_args: None)
        patcher.setattr(runner_module.os, "close", closed.append)
        patcher.setattr(runner_module.os, "fdopen", lambda *_args: io.BytesIO())

        stream = runner_module._open_private_log(Path("/safe/adapter.log"))

    assert stream is not None
    assert opened[0][1] == os.O_RDONLY
    assert closed == [10]


@pytest.mark.parametrize(
    ("modes", "failure", "expected_closed"),
    [
        ([stat.S_IFREG | 0o600], None, [10]),
        ([stat.S_IFDIR | 0o700, stat.S_IFDIR | 0o700], None, [11, 10]),
        ([stat.S_IFDIR | 0o700], OSError("chmod"), [11, 10]),
    ],
)
def test_open_private_log_rejects_bad_metadata_and_closes_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    modes: list[int],
    failure: BaseException | None,
    expected_closed: list[int],
) -> None:
    descriptors = iter([10, 11])
    metadata = iter(SimpleNamespace(st_mode=mode) for mode in modes)
    closed: list[int] = []

    with monkeypatch.context() as patcher:
        patcher.setattr(runner_module.os, "open", lambda *_args, **_kwargs: next(descriptors))
        patcher.setattr(runner_module.os, "fstat", lambda _fd: next(metadata))
        patcher.setattr(runner_module.os, "close", closed.append)

        def fake_fchmod(*_args: Any) -> None:
            if failure is not None:
                raise failure

        patcher.setattr(runner_module.os, "fchmod", fake_fchmod)
        with pytest.raises(runner_module.SystemUnavailableError):
            runner_module._open_private_log(Path("/safe/adapter.log"))

    assert closed == expected_closed


def test_capture_private_chunk_handles_optional_empty_truncated_and_full() -> None:
    destination = io.BytesIO()
    runner_module._capture_private_chunk(None, b"abc", captured=0, output_limit=3)
    runner_module._capture_private_chunk(destination, b"", captured=0, output_limit=3)
    runner_module._capture_private_chunk(destination, b"abc", captured=3, output_limit=3)
    runner_module._capture_private_chunk(destination, b"abcd", captured=1, output_limit=3)
    assert destination.getvalue() == b"ab"


def test_cleanup_process_tree_posix_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, signal.Signals]] = []
    process = _FakeProcess(returncode=0)
    monkeypatch.setattr(runner_module.os, "name", "posix")
    monkeypatch.setattr(runner_module.time, "sleep", lambda value: calls.append((-1, value)))

    def killpg(pid: int, sig: signal.Signals) -> None:
        calls.append((pid, sig))
        if sig == runner_module.signal.SIGKILL:
            raise PermissionError

    monkeypatch.setattr(runner_module.os, "killpg", killpg)
    runner_module._cleanup_process_tree(process)
    assert calls[0] == (process.pid, runner_module.signal.SIGTERM)
    assert calls[-1] == (process.pid, runner_module.signal.SIGKILL)

    waits = [
        subprocess.TimeoutExpired("adapter", 0.2),
        subprocess.TimeoutExpired("adapter", 0.2),
    ]
    missing = _FakeProcess(returncode=None, waits=waits)
    monkeypatch.setattr(
        runner_module.os,
        "killpg",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    runner_module._cleanup_process_tree(missing)
    assert "kill" in missing.calls


@pytest.mark.parametrize(
    ("poll", "waits", "expected_calls"),
    [
        (None, [None, None], ["terminate"]),
        (None, [subprocess.TimeoutExpired("adapter", 0.1), None], ["terminate", "kill"]),
        (
            0,
            [
                subprocess.TimeoutExpired("adapter", 0.2),
                subprocess.TimeoutExpired("adapter", 0.2),
            ],
            ["kill"],
        ),
    ],
)
def test_cleanup_process_tree_non_posix_paths(
    monkeypatch: pytest.MonkeyPatch,
    poll: int | None,
    waits: list[Any],
    expected_calls: list[str],
) -> None:
    process = _FakeProcess(polls=[poll], returncode=poll, waits=waits)
    monkeypatch.setattr(runner_module.os, "name", "nt")
    runner_module._cleanup_process_tree(process)
    for call in expected_calls:
        assert call in process.calls


def test_read_result_accepts_mapping_and_rejects_bounds_and_shapes(tmp_path: Path) -> None:
    valid = tmp_path / "valid.json"
    valid.write_text('{"status":"succeeded"}', encoding="utf-8")
    assert runner_module._read_result(valid, 100) == {"status": "succeeded"}

    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(valid, 0)
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(tmp_path / "missing.json", 100)
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(tmp_path, 100)

    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(empty, 100)
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(valid, 1)

    invalid_utf8 = tmp_path / "utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(invalid_utf8, 100)
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(invalid_json, 100)
    sequence = tmp_path / "sequence.json"
    sequence.write_text("[]", encoding="utf-8")
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(sequence, 100)


def test_read_result_detects_read_race_and_recursion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GrowingPath:
        def lstat(self):
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=1)

        def open(self, _mode: str):
            return io.BytesIO(b"{}")

    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(GrowingPath(), 1)

    source = tmp_path / "result.json"
    source.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        runner_module.json,
        "loads",
        lambda _payload: (_ for _ in ()).throw(RecursionError()),
    )
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._read_result(source, 10)


def test_normalize_result_defaults_and_complete_payload() -> None:
    assert runner_module._normalize_result({}, max_tools=1, duration_seconds=1.5) == {
        "status": "succeeded",
        "actions": [],
        "reported_claims": [],
        "reported_findings": [],
        "verified_findings": [],
        "coverage_gaps": [],
        "metrics": {},
        "artifact_refs": [],
        "duration_seconds": 1.5,
        "error_class": "",
    }
    assert runner_module._normalize_result(
        {
            "status": " FAILED ",
            "actions": [" Action.One "],
            "reported_claims": [" claim "],
            "reported_findings": [" Finding.One "],
            "verified_findings": [" Finding.One "],
            "coverage_gaps": [" Gap.One "],
            "metrics": {" Score.One ": "1.25"},
            "artifact_refs": [" artifact://one "],
            "error_class": " AdapterError ",
        },
        max_tools=1,
        duration_seconds=2,
    )["metrics"] == {"score.one": 1.25}


@pytest.mark.parametrize(
    ("payload", "max_tools"),
    [
        ({"status": "unknown"}, 1),
        ({"actions": ["one", "two"]}, 1),
        ({"error_class": "not allowed"}, 1),
    ],
)
def test_normalize_result_rejects_protocol_violations(
    payload: dict[str, Any],
    max_tools: int,
) -> None:
    with pytest.raises(runner_module.SystemProtocolError):
        runner_module._normalize_result(
            payload,
            max_tools=max_tools,
            duration_seconds=0,
        )


@pytest.mark.parametrize(
    ("function", "value"),
    [
        (runner_module._identifier_list, "string"),
        (runner_module._identifier_list, ["x"] * 513),
        (runner_module._identifier_list, [""]),
        (runner_module._identifier_list, ["bad value"]),
        (runner_module._text_list, "string"),
        (runner_module._text_list, ["x"] * 513),
        (runner_module._text_list, [""]),
        (runner_module._text_list, ["nul\x00value"]),
        (runner_module._text_list, ["x" * 4_097]),
        (runner_module._metrics, []),
        (runner_module._metrics, {str(index): 1 for index in range(513)}),
        (runner_module._metrics, {"bad key": 1}),
        (runner_module._metrics, {"score": True}),
        (runner_module._metrics, {"score": object()}),
        (runner_module._metrics, {"score": "not-a-number"}),
        (runner_module._metrics, {"score": float("inf")}),
        (runner_module._metrics, {"score": -1}),
    ],
)
def test_result_value_validators_reject_bad_values(function, value: Any) -> None:
    with pytest.raises(runner_module.SystemProtocolError):
        function(value)


def test_result_value_validators_accept_and_normalize_values() -> None:
    assert runner_module._identifier_list([" One.Two ", 3]) == ["one.two", "3"]
    assert runner_module._text_list([" one ", 2]) == ["one", "2"]
    assert runner_module._metrics({" One.Two ": 0, "three": "2.5"}) == {
        "one.two": 0.0,
        "three": 2.5,
    }
    assert runner_module._sequence((1, 2)) == (1, 2)
    assert runner_module._optional_error_class(None) == ""
    assert runner_module._optional_error_class(" Adapter.Error ") == "Adapter.Error"


def test_empty_result_and_exit_error_class() -> None:
    assert runner_module._empty_result("failed", 1.0) == {
        "status": "failed",
        "actions": [],
        "reported_claims": [],
        "reported_findings": [],
        "verified_findings": [],
        "coverage_gaps": [],
        "metrics": {},
        "artifact_refs": [],
        "duration_seconds": 1.0,
        "error_class": "",
    }
    assert runner_module._adapter_exit_error_class(-3) == "AdapterSignal3"
    assert runner_module._adapter_exit_error_class(4) == "AdapterExitCode4"


@pytest.mark.parametrize(
    ("function", "value"),
    [
        (runner_module._positive_number, True),
        (runner_module._positive_number, object()),
        (runner_module._positive_number, "bad"),
        (runner_module._positive_number, float("nan")),
        (runner_module._positive_number, float("inf")),
        (runner_module._positive_number, 0),
        (runner_module._positive_number, -1),
        (runner_module._positive_integer, True),
        (runner_module._positive_integer, object()),
        (runner_module._positive_integer, "bad"),
        (runner_module._positive_integer, 0),
        (runner_module._positive_integer, -1),
    ],
)
def test_positive_validators_reject_invalid_values(function, value: Any) -> None:
    with pytest.raises(runner_module.SystemProtocolError):
        function(value)


def test_positive_validators_accept_and_optional_values() -> None:
    assert runner_module._positive_number("2.5") == 2.5
    assert runner_module._positive_integer("2") == 2
    assert runner_module._positive_optional_number(None) is None
    assert runner_module._positive_optional_number("3") == 3.0
    assert runner_module._positive_optional_integer(None) is None
    assert runner_module._positive_optional_integer("4") == 4
