"""Hermetic branch coverage for benchmark lab controls."""

from __future__ import annotations

import signal
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.benchmarks.competitors import lab

pytestmark = [pytest.mark.unit, pytest.mark.benchmark]


def context() -> lab.LabRunContext:
    return lab.LabRunContext(
        campaign_id="campaign",
        system_id="system",
        scenario_id="scenario",
        repetition=1,
        seed=10,
        lab_version="lab-v1",
        snapshot_ref="snapshot-v1",
    )


def command(tmp_path: Path, **overrides) -> lab.LabCommand:
    payload = {
        "argv": ["fixture", "{scenario_id}"],
        "working_directory": ".",
    }
    payload.update(overrides)
    return lab.LabCommand.from_dict(payload, base_directory=tmp_path)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({"argv": ["fixture"], "unknown": True}, "unknown_lab_command_key"),
        ({"argv": "fixture"}, "invalid_lab_command_argv"),
        ({"argv": []}, "invalid_lab_command_argv"),
        ({"argv": ["fixture", ""]}, "invalid_lab_command_argv"),
        ({"argv": ["fixture\x00value"]}, "invalid_lab_command_argv"),
        ({"argv": ["fixture"], "timeout_seconds": "bad"}, "invalid_lab_command_timeout"),
        ({"argv": ["fixture"], "timeout_seconds": 0}, "invalid_lab_command_timeout"),
        (
            {"argv": ["fixture"], "environment_passthrough": "PATH"},
            "invalid_lab_environment_passthrough",
        ),
        (
            {"argv": ["fixture"], "environment_passthrough": [None]},
            "invalid_lab_environment_passthrough",
        ),
        (
            {
                "argv": ["fixture"],
                "environment_passthrough": ["OCTOPUS_BENCHMARK_SEED"],
            },
            "reserved_lab_environment_name",
        ),
    ],
)
def test_lab_command_rejects_invalid_contracts(tmp_path, payload, error) -> None:
    with pytest.raises(lab.LabControlError, match=error):
        lab.LabCommand.from_dict(payload, base_directory=tmp_path)


def test_lab_command_bounds_argument_count_and_deduplicates_environment(tmp_path) -> None:
    with pytest.raises(lab.LabControlError, match="invalid_lab_command_argv"):
        lab.LabCommand.from_dict(
            {"argv": ["fixture"] * 65},
            base_directory=tmp_path,
        )

    configured = command(
        tmp_path,
        timeout_seconds=3600,
        environment_passthrough=["PATH", "PATH"],
    )
    assert configured.environment_passthrough == ("PATH",)
    assert configured.timeout_seconds == 3600


def test_attestation_serialization_and_cleanup_optional_paths(tmp_path) -> None:
    configured = command(tmp_path)
    attestation = lab.ResetAttestation(
        context=context(),
        reset_duration_seconds=1.1234567,
        health_duration_seconds=2.7654321,
        reset_command_sha256="reset-digest",
        health_command_sha256="health-digest",
        observed_at=3.0,
    )
    assert attestation.to_dict()["reset_duration_seconds"] == 1.123457

    without_cleanup = lab.CommandLabController(configured, configured)
    without_cleanup._run = MagicMock()
    without_cleanup.cleanup(context())
    without_cleanup._run.assert_not_called()

    with_cleanup = lab.CommandLabController(
        configured,
        configured,
        cleanup=configured,
    )
    with_cleanup._run = MagicMock()
    with_cleanup.cleanup(context())
    with_cleanup._run.assert_called_once_with(configured, context(), phase="cleanup")


def test_diagnostic_path_handles_filesystem_errors(tmp_path, monkeypatch) -> None:
    configured = command(tmp_path)
    controller = lab.CommandLabController(
        configured,
        configured,
        diagnostics_directory=tmp_path / "diagnostics",
    )
    monkeypatch.setattr(lab.os, "lstat", MagicMock(side_effect=OSError("unavailable")))
    assert controller._diagnostic_path(context(), phase="reset") is None


def test_lab_reset_error_exposes_only_existing_regular_diagnostics(tmp_path) -> None:
    assert lab._lab_reset_error("code", None).diagnostic_path is None

    directory = tmp_path / "directory"
    directory.mkdir()
    assert lab._lab_reset_error("code", directory).diagnostic_path is None

    missing = tmp_path / "missing.log"
    assert lab._lab_reset_error("code", missing).diagnostic_path is None


def executable_command(working_directory: Path, executable: str) -> lab.LabCommand:
    return lab.LabCommand(argv=(executable,), working_directory=working_directory)


def test_command_executable_availability_paths(tmp_path, monkeypatch) -> None:
    missing_directory = tmp_path / "missing-directory"
    assert not lab.command_executable_available(
        executable_command(missing_directory, "fixture"),
        {},
    )
    assert not lab.command_executable_available(
        executable_command(tmp_path, "{system_id}"),
        {},
    )

    absolute = tmp_path / "absolute-tool"
    absolute.write_text("fixture", encoding="utf-8")
    absolute.chmod(0o700)
    assert lab.command_executable_available(
        executable_command(tmp_path, str(absolute)),
        {},
    )

    nested = tmp_path / "bin"
    nested.mkdir()
    relative = nested / "relative-tool"
    relative.write_text("fixture", encoding="utf-8")
    relative.chmod(0o700)
    assert lab.command_executable_available(
        executable_command(tmp_path, "bin/relative-tool"),
        {},
    )

    which = MagicMock(side_effect=["/fixture/tool", None])
    monkeypatch.setattr(lab.shutil, "which", which)
    simple = executable_command(tmp_path, "fixture-tool")
    assert lab.command_executable_available(simple, {"PATH": "/fixture"})
    assert not lab.command_executable_available(simple, {})


def test_format_and_placeholder_validation_edges() -> None:
    assert lab._format_argv(("{system_id}",), {"system_id": "fixture"}) == [
        "fixture"
    ]
    with pytest.raises(lab.LabResetError, match="lab_command_placeholder_error"):
        lab._format_argv(("{missing}",), {})

    lab._validate_placeholders(("{system_id}",))
    with pytest.raises(lab.LabControlError, match="invalid_lab_command_placeholder"):
        lab._validate_placeholders(("{unknown}",))
    with pytest.raises(lab.LabControlError, match="invalid_lab_command_placeholder"):
        lab._validate_placeholders(("{broken",))


class FakeProcess:
    def __init__(self, *, poll_result=None, timeout_once=False):
        self.pid = 12345
        self.poll_result = poll_result
        self.timeout_once = timeout_once
        self.wait_calls = 0
        self.terminate = MagicMock()
        self.kill = MagicMock()

    def poll(self):
        return self.poll_result

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.timeout_once and self.wait_calls == 1:
            raise lab.subprocess.TimeoutExpired("fixture", timeout)
        return 0


def test_terminate_process_posix_graceful_and_forced(monkeypatch) -> None:
    monkeypatch.setattr(lab.os, "name", "posix")
    killpg = MagicMock()
    monkeypatch.setattr(lab.os, "killpg", killpg)

    graceful = FakeProcess()
    lab._terminate_process(graceful)
    killpg.assert_called_once_with(graceful.pid, signal.SIGTERM)

    killpg.reset_mock()
    forced = FakeProcess(timeout_once=True)
    lab._terminate_process(forced)
    assert killpg.call_args_list == [
        ((forced.pid, signal.SIGTERM),),
        ((forced.pid, signal.SIGKILL),),
    ]
    assert forced.wait_calls == 2


def test_terminate_process_non_posix_running_finished_and_forced(monkeypatch) -> None:
    monkeypatch.setattr(lab.os, "name", "nt")

    running = FakeProcess()
    lab._terminate_process(running)
    running.terminate.assert_called_once_with()

    finished = FakeProcess(poll_result=0)
    lab._terminate_process(finished)
    finished.terminate.assert_not_called()

    forced = FakeProcess(timeout_once=True)
    lab._terminate_process(forced)
    forced.terminate.assert_called_once_with()
    forced.kill.assert_called_once_with()
    assert forced.wait_calls == 2


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("PATH", True),
        ("_FIXTURE_1", True),
        ("", False),
        ("1INVALID", False),
        ("NON-ASCII-ø", False),
        ("INVALID-NAME", False),
    ],
)
def test_environment_name_validation(value, expected) -> None:
    assert lab._valid_environment_name(value) is expected
