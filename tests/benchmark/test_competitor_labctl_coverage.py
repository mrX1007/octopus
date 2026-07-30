"""Hermetic branch coverage for the competitor lab controller."""

from __future__ import annotations

import io
import ipaddress
import json
import runpy
import signal
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks.competitors import labctl

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _raises(error: BaseException):
    def raise_error(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return raise_error


class _Headers:
    def __init__(self, content_type: str = "application/json") -> None:
        self.content_type = content_type

    def get_content_type(self) -> str:
        return self.content_type


class _Response:
    def __init__(self, payload: bytes, *, content_type: str = "application/json") -> None:
        self.payload = payload
        self.headers = _Headers(content_type)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def read(self, count: int) -> bytes:
        return self.payload[:count]


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, *_args: Any, **_kwargs: Any) -> _Response:
        return self.response


def _definition(path: Path, *, v3: bool = False) -> labctl._LabDefinition:
    return labctl._LabDefinition(
        definition_id=labctl.V3_LAB_VERSION if v3 else labctl.LAB_VERSION,
        project_name="coverage-lab",
        compose_path=path,
        lab_version=labctl.V3_LAB_VERSION if v3 else labctl.LAB_VERSION,
        health_evidence=(labctl.V3_LAB_HEALTH_EVIDENCE if v3 else labctl.LAB_HEALTH_EVIDENCE),
        scenario_ids=frozenset({"scenario-v3"}) if v3 else frozenset(),
    )


def test_redirect_and_unreachable_cli_fallback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = labctl.urllib.request.Request("http://127.0.0.1/source")
    assert (
        labctl._NoRedirectHandler().redirect_request(
            request,
            None,
            302,
            "redirected",
            {},
            "http://127.0.0.1/destination",
        )
        is None
    )

    parser = SimpleNamespace(parse_args=lambda _argv: SimpleNamespace(command="not-a-parser-command"))
    monkeypatch.setattr(labctl, "_argument_parser", lambda: parser)
    assert labctl.main([]) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "health_invalid"}


def test_main_v3_prepare_failure_is_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        labctl,
        "prepare_fixture_run",
        _raises(ValueError("private fixture detail")),
    )
    result = labctl.main(
        [
            "reset",
            "--lab-definition",
            labctl.V3_LAB_VERSION,
            "--scenario-id",
            "deep-navigation-v3",
            "--target",
            "http://127.0.0.1:8080",
            "--campaign-id",
            "campaign",
            "--system-id",
            "system",
            "--repetition",
            "1",
            "--matched-fixture-seed",
            "2",
            "--state-directory",
            str(tmp_path),
        ]
    )
    assert result == 2
    assert json.loads(capsys.readouterr().err) == {"error": "v3_fixture_prepare_failed"}


def test_main_health_success_with_and_without_scenario(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        labctl,
        "_health",
        lambda *_args, lab_definition=None, **_kwargs: {"lab_version": lab_definition.lab_version},
    )
    assert (
        labctl.main(
            [
                "health",
                "--target",
                "http://127.0.0.1:8080",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "command": "health",
        "healthy": True,
        "lab_version": labctl.LAB_VERSION,
        "target": "http://127.0.0.1:8080",
    }

    scenario = "authorized-linked-navigation-small-model-v2"
    assert (
        labctl.main(
            [
                "health",
                "--lab-definition",
                labctl.V2_LAB_VERSION,
                "--scenario-id",
                scenario,
                "--target",
                "http://127.0.0.1:8080",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["scenario_id"] == scenario


def test_run_compose_preflight_and_spawn_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = _definition(tmp_path / "missing.yaml")
    with pytest.raises(labctl.LabControlError, match="compose_file_missing"):
        labctl._run_compose(
            ("down",),
            failure_code="cleanup_failed",
            environment={},
            lab_definition=missing,
        )

    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    with pytest.raises(labctl.LabControlError, match="invalid_v3_context"):
        labctl._run_compose(
            ("up",),
            failure_code="reset_failed",
            environment={},
            lab_definition=_definition(compose, v3=True),
            scenario_id="scenario-v3",
        )

    capture = io.BytesIO()
    with monkeypatch.context() as patch:
        patch.setattr(labctl, "_compose_output_capture", lambda _environment: capture)
        patch.setattr(labctl.subprocess, "Popen", _raises(OSError("no docker")))
        with pytest.raises(labctl.LabControlError, match="compose_unavailable"):
            labctl._run_compose(
                ("down",),
                failure_code="cleanup_failed",
                environment={},
                lab_definition=_definition(compose),
            )
    assert capture.closed


@pytest.mark.parametrize(
    ("error", "expected"),
    (
        (subprocess.TimeoutExpired("docker", 1), "compose_timeout"),
        (OSError("wait failed"), "reset_failed"),
    ),
)
def test_run_compose_wait_failures_are_terminated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
    expected: str,
) -> None:
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    capture = io.BytesIO(b"private diagnostic")
    terminated: list[Any] = []

    class Process:
        pid = 123

        def wait(self, *, timeout: float) -> int:
            assert timeout == labctl.COMPOSE_TIMEOUT_SECONDS
            raise error

    monkeypatch.setattr(labctl, "_compose_output_capture", lambda _environment: capture)
    monkeypatch.setattr(labctl.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(labctl, "_terminate_process_group", terminated.append)
    with pytest.raises(labctl.LabControlError, match=expected) as captured:
        labctl._run_compose(
            ("up",),
            failure_code="reset_failed",
            environment={},
            lab_definition=_definition(compose),
        )
    assert captured.value.diagnostic_output == b"private diagnostic"
    assert len(terminated) == 1
    assert capture.closed


def test_compose_capture_read_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        labctl,
        "_private_diagnostic_directory",
        lambda _raw_path: tmp_path,
    )
    monkeypatch.setattr(
        labctl.tempfile,
        "TemporaryFile",
        _raises(OSError("capture unavailable")),
    )
    assert labctl._compose_output_capture({}) is None
    assert labctl._read_compose_output(None) == b""

    class BrokenCapture:
        def flush(self) -> None:
            raise OSError("broken")

    assert labctl._read_compose_output(BrokenCapture()) == b""


def test_collect_compose_state_handles_all_stubbed_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = _definition(tmp_path / "compose.yaml")
    monkeypatch.setattr(labctl, "_compose_output_capture", lambda _environment: None)
    unavailable = labctl._collect_compose_state(
        environment={},
        lab_definition=definition,
        scenario_id=None,
        v3_run_directory=None,
    )
    assert unavailable.count(b"unavailable") == 2

    captures = iter((io.BytesIO(b"first"), io.BytesIO(b"second")))
    calls = iter(("timeout", "spawn-error"))

    class TimeoutProcess:
        pid = 123

        def wait(self, *, timeout: float) -> int:
            assert timeout == labctl.COMPOSE_DIAGNOSTIC_TIMEOUT_SECONDS
            raise subprocess.TimeoutExpired("docker", timeout)

    def popen(*_args: Any, **_kwargs: Any) -> TimeoutProcess:
        if next(calls) == "timeout":
            return TimeoutProcess()
        raise OSError("unavailable")

    terminated: list[Any] = []
    monkeypatch.setattr(
        labctl,
        "_compose_output_capture",
        lambda _environment: next(captures),
    )
    monkeypatch.setattr(labctl.subprocess, "Popen", popen)
    monkeypatch.setattr(labctl, "_terminate_process_group", terminated.append)
    output = labctl._collect_compose_state(
        environment={},
        lab_definition=definition,
        scenario_id=None,
        v3_run_directory=None,
    )
    assert b"exit -1" in output
    assert b"unavailable" in output
    assert len(terminated) == 1


def _diagnostic_destination(tmp_path: Path, name: str) -> Path:
    directory = tmp_path / name
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory / "diagnostic.log"


def test_private_diagnostic_fallback_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = _diagnostic_destination(tmp_path, "large-header")
    labctl._write_private_diagnostic(
        str(destination),
        command="reset",
        error=labctl.LabControlError(
            "reset_failed",
            diagnostic_metadata={"oversized": "x" * labctl.MAX_PRIVATE_DIAGNOSTIC_BYTES},
        ),
    )
    assert json.loads(destination.read_text(encoding="utf-8"))["error"] == "reset_failed"

    failed_destination = _diagnostic_destination(tmp_path, "failed-write")
    with monkeypatch.context() as patch:
        patch.setattr(labctl.os, "replace", _raises(OSError("replace failed")))
        labctl._write_private_diagnostic(
            str(failed_destination),
            command="reset",
            error=labctl.LabControlError("reset_failed"),
        )
    assert not failed_destination.exists()
    assert list(failed_destination.parent.iterdir()) == []

    assert labctl._private_diagnostic_directory("relative.log") is None
    assert labctl._private_diagnostic_directory(str(tmp_path / "missing-directory" / "diagnostic.log")) is None


def test_process_group_termination_is_fully_stubbed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Stopped:
        pid = 1

        @staticmethod
        def poll() -> int:
            return 0

    labctl._terminate_process_group(Stopped())

    signals: list[int] = []

    class Running:
        pid = 2

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(*, timeout: float) -> int:
            assert timeout == 1.0
            return 0

    monkeypatch.setattr(
        labctl.os,
        "killpg",
        lambda _pid, selected_signal: signals.append(selected_signal),
    )
    labctl._terminate_process_group(Running())
    assert signals == [signal.SIGTERM]

    events: list[str] = []

    class Resistant:
        pid = 3

        @staticmethod
        def poll() -> None:
            raise OSError("poll failed")

        @staticmethod
        def terminate() -> None:
            events.append("terminate")
            raise OSError("terminate failed")

        @staticmethod
        def kill() -> None:
            events.append("kill")
            raise OSError("kill failed")

        @staticmethod
        def wait(*, timeout: float) -> int:
            events.append("wait")
            raise subprocess.TimeoutExpired("process", timeout)

    def denied_killpg(_pid: int, selected_signal: int) -> None:
        if selected_signal == signal.SIGTERM:
            raise ProcessLookupError
        raise PermissionError

    monkeypatch.setattr(labctl.os, "killpg", denied_killpg)
    labctl._terminate_process_group(Resistant())
    assert events == ["terminate", "wait", "kill", "wait"]


def test_wait_for_health_timeout_retry_and_unexpected_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monotonic = iter((0.0, 2.0))
    monkeypatch.setattr(labctl.time, "monotonic", lambda: next(monotonic))
    with pytest.raises(labctl.LabControlError, match="health_timeout"):
        labctl._wait_for_health("http://127.0.0.1", timeout_seconds=1)

    monkeypatch.setattr(labctl.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        labctl,
        "_health",
        _raises(labctl.LabControlError("invalid_target")),
    )
    with pytest.raises(labctl.LabControlError, match="invalid_target"):
        labctl._wait_for_health("http://127.0.0.1", timeout_seconds=1)

    responses: Iterator[dict[str, Any] | BaseException] = iter(
        (
            labctl.LabControlError("health_unreachable"),
            {"healthy": True, "lab_version": labctl.LAB_VERSION},
        )
    )

    def health(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        response = next(responses)
        if isinstance(response, BaseException):
            raise response
        return response

    sleeps: list[float] = []
    monkeypatch.setattr(labctl, "_health", health)
    monkeypatch.setattr(labctl.time, "sleep", sleeps.append)
    assert labctl._wait_for_health(
        "http://127.0.0.1",
        timeout_seconds=1,
    )["healthy"]
    assert sleeps == [0.25]


@pytest.mark.parametrize(
    ("response", "expected"),
    (
        (_Response(b"{}", content_type="text/plain"), "health_invalid"),
        (_Response(b"not-json"), "health_invalid"),
    ),
)
def test_health_rejects_content_and_decoding_failures(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
    expected: str,
) -> None:
    monkeypatch.setattr(
        labctl.urllib.request,
        "build_opener",
        lambda *_handlers: _Opener(response),
    )
    with pytest.raises(labctl.LabControlError, match=expected):
        labctl._health("http://127.0.0.1:8080", timeout_seconds=1)


def test_numeric_target_and_address_parse_failures() -> None:
    for value in ("not-an-integer", 0):
        with pytest.raises(labctl.LabControlError, match="invalid_v3_context"):
            labctl._v3_positive_integer(value)
    for value in ("not-a-seed", -1):
        with pytest.raises(labctl.LabControlError, match="invalid_v3_context"):
            labctl._v3_seed(value)

    with pytest.raises(labctl.LabControlError, match="target_required"):
        labctl._target_url(None, {})
    with pytest.raises(labctl.LabControlError, match="invalid_target"):
        labctl._canonical_target("x" * 2_049)
    with pytest.raises(labctl.LabControlError, match="invalid_target"):
        labctl._canonical_target("http://127.0.0.1:not-a-port")
    with pytest.raises(labctl.LabControlError, match="invalid_host_ip"):
        labctl._lab_address(
            {"OCTOBENCH_HOST_IP": "not-an-ip"},
            port=8080,
        )
    with pytest.raises(labctl.LabControlError, match="invalid_timeout"):
        labctl._health_timeout("not-a-timeout")
    with pytest.raises(labctl.LabControlError, match="invalid_port"):
        labctl._port("not-a-port")


def test_detect_private_host_ip_without_real_sockets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(labctl.socket, "socket", _raises(OSError("socket unavailable")))
        patch.setattr(labctl.socket, "gethostname", lambda: "host")
        patch.setattr(
            labctl.socket,
            "getaddrinfo",
            _raises(OSError("lookup unavailable")),
        )
        with pytest.raises(labctl.LabControlError, match="address_unavailable"):
            labctl._detect_private_host_ip()

    class PublicProbe:
        @staticmethod
        def connect(_target: tuple[str, int]) -> None:
            return None

        @staticmethod
        def getsockname() -> tuple[str, int]:
            return ("8.8.8.8", 1234)

        @staticmethod
        def close() -> None:
            return None

    with monkeypatch.context() as patch:
        patch.setattr(labctl.socket, "socket", lambda *_args: PublicProbe())
        patch.setattr(labctl.socket, "gethostname", lambda: "host")
        patch.setattr(
            labctl.socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [
                (0, 0, 0, "", ("not-an-ip", 0)),
                (0, 0, 0, "", ("127.0.0.1", 0)),
            ],
        )
        assert labctl._detect_private_host_ip() == ipaddress.ip_address("127.0.0.1")

    class FailedProbe:
        @staticmethod
        def connect(_target: tuple[str, int]) -> None:
            raise OSError("no route")

        @staticmethod
        def close() -> None:
            return None

    with monkeypatch.context() as patch:
        patch.setattr(labctl.socket, "socket", lambda *_args: FailedProbe())
        patch.setattr(labctl.socket, "gethostname", lambda: "host")
        patch.setattr(
            labctl.socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [(0, 0, 0, "", ("10.20.30.40", 0))],
        )
        assert labctl._detect_private_host_ip() == ipaddress.ip_address("10.20.30.40")


def test_module_entrypoint_uses_main_guard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OCTOBENCH_HOST_IP", "127.0.0.1")
    monkeypatch.setattr(sys, "argv", ["labctl", "address", "--port", "invalid"])
    with pytest.warns(RuntimeWarning, match="found in sys.modules"), pytest.raises(SystemExit) as captured:
        runpy.run_module(
            "core.benchmarks.competitors.labctl",
            run_name="__main__",
            alter_sys=True,
        )
    assert captured.value.code == 2
    assert json.loads(capsys.readouterr().err) == {"error": "invalid_port"}
