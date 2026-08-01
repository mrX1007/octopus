"""Complete process-free coverage for the Metasploit command wrapper."""

from __future__ import annotations

import builtins
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import msf
from core.execution import ExecutionCancelled

pytestmark = [pytest.mark.unit, pytest.mark.security]


class Cancellation:
    def __init__(self, *, cancelled=False, reason_code="") -> None:
        self.cancelled = cancelled
        self.reason_code = reason_code


def context(*, output=100_000, runtime=300, cancelled=False, reason=""):
    return SimpleNamespace(
        max_output_bytes=output,
        max_runtime_seconds=runtime,
        cancellation=Cancellation(cancelled=cancelled, reason_code=reason),
    )


class Stdout:
    def __init__(self, lines=(), *, iteration_error=None, close_error=None) -> None:
        self.lines = list(lines)
        self.iteration_error = iteration_error
        self.close_error = close_error
        self.closed = False

    def __iter__(self):
        yield from self.lines
        if self.iteration_error:
            raise self.iteration_error

    def close(self) -> None:
        self.closed = True
        if self.close_error:
            raise self.close_error


class Proc:
    def __init__(self, lines=(), *, wait_effects=(), stdout=None) -> None:
        self.stdout = stdout or Stdout(lines)
        self.wait_effects = list(wait_effects)
        self.returncode = 0
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.wait_effects:
            effect = self.wait_effects.pop(0)
            if isinstance(effect, Exception):
                raise effect
            return effect
        return 0


def configure(monkeypatch, proc: Proc, *, selected_context=None, scripts=None):
    scripts = [] if scripts is None else scripts
    monkeypatch.setattr(msf.shutil, "which", lambda executable: "/usr/bin/msfconsole")
    monkeypatch.setattr(
        msf,
        "current_execution_context",
        lambda: selected_context or context(),
    )
    monkeypatch.setattr(msf, "redact_sensitive_command", lambda value: str(value))
    monkeypatch.setattr(msf, "_terminate_process_tree", lambda selected: None)

    def popen(command, **kwargs):
        scripts.append((command[-1], kwargs))
        return proc

    monkeypatch.setattr(msf.subprocess, "Popen", popen)
    return scripts


def test_option_parser_and_case_insensitive_defaults() -> None:
    assert msf._parse_msf_options("") == {}
    assert msf._parse_msf_options(" RHOSTS = 10.0.0.5, RPORT=22 | USER_FILE=/tmp/users, ") == {
        "RHOSTS": "10.0.0.5",
        "RPORT": "22",
        "USER_FILE": "/tmp/users",
    }
    options = {"verbose": "true"}
    msf._setdefault_option_ci(options, "VERBOSE", "false")
    msf._setdefault_option_ci(options, "STOP_ON_SUCCESS", "true")
    assert options == {"verbose": "true", "STOP_ON_SUCCESS": "true"}


def test_import_fallback_exposes_empty_tool_config(monkeypatch) -> None:
    original_import = builtins.__import__

    def import_without_core_execution(name, *args, **kwargs):
        if name == "core.execution":
            raise ImportError("core execution unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_core_execution)
    namespace = {"__name__": "msf_import_fallback"}
    source = Path(msf.__file__).read_text(encoding="utf-8")
    exec(compile(source, msf.__file__, "exec"), namespace)
    assert namespace["get_tool_config"]("msfconsole") == {}


def test_msf_validates_binary_module_options_and_mode(monkeypatch) -> None:
    monkeypatch.setattr(msf.shutil, "which", lambda executable: None)
    assert "not installed" in msf.run_msf_module("auxiliary/test", "RHOSTS=host")

    monkeypatch.setattr(msf.shutil, "which", lambda executable: "/usr/bin/msfconsole")
    assert "does NOT EXIST" in msf.run_msf_module(
        "exploit/linux/ssh/openssh_rce",
        "RHOSTS=host",
    )
    assert "Invalid MSF module format" in msf.run_msf_module("single", "RHOSTS=host")
    assert "Invalid MSF module format" in msf.run_msf_module(" '' ", "RHOSTS=host")
    assert "requires RHOSTS" in msf.run_msf_module("auxiliary/scanner/test", "RPORT=22")
    assert "Invalid MSF mode" in msf.run_msf_module(
        "auxiliary/scanner/test",
        "RHOSTS=host",
        mode="invalid",
    )


def test_timeout_config_correction_and_login_defaults(monkeypatch, capsys) -> None:
    proc = Proc(["[+] host - Success: 'user:password'\n"])
    scripts = configure(monkeypatch, proc)
    monkeypatch.setattr(msf, "get_tool_config", lambda name: {"timeout": 17})

    result = msf.run_msf_module(
        ' "exploit/ssh/ssh_login" ',
        "RHOSTS=host USERNAME=user PASSWORD=password verbose=true",
        timeout=None,
        mode=" CHECK ",
    )

    script = scripts[0][0]
    assert script.startswith("use auxiliary/scanner/ssh/ssh_login")
    assert "set STOP_ON_SUCCESS true" in script
    assert "set CreateSession false" in script
    assert script.count("set verbose true") == 1
    assert script.endswith("run; exit -y")
    assert "Success: 'user:password'" in result
    assert "MSF module corrected" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("module", "options", "mode", "needles", "terminator"),
    [
        (
            "exploit/unix/test/module",
            "RHOSTS=host",
            "run",
            ("cmd/unix/bind_netcat", "LPORT 4444"),
            "exploit -z; exit -y",
        ),
        (
            "exploit/windows/test/module",
            "RHOSTS=host LPORT=5555",
            "run",
            (
                "windows/meterpreter/bind_tcp",
                "set LPORT 5555",
            ),
            "exploit -z; exit -y",
        ),
        (
            "exploit/multi/test/module",
            "RHOSTS=host",
            "run",
            ("generic/shell_bind_tcp",),
            "exploit -z; exit -y",
        ),
        (
            "exploit/multi/test/module",
            "RHOSTS=host",
            "check",
            ("generic/shell_bind_tcp",),
            "check; exit -y",
        ),
        (
            "auxiliary/scanner/test",
            "RHOSTS=host",
            None,
            (),
            "run; exit -y",
        ),
    ],
)
def test_script_building_for_each_module_family(
    monkeypatch,
    module: str,
    options: str,
    mode: str | None,
    needles: tuple[str, ...],
    terminator: str,
) -> None:
    scripts = configure(monkeypatch, Proc())
    result = msf.run_msf_module(module, options, timeout=30, mode=mode)
    script = scripts[0][0]
    assert all(needle in script for needle in needles)
    assert script.endswith(terminator)
    assert "No MSF Output" in result


def test_reader_filters_noise_reports_important_lines_and_tolerates_closed_stdout(
    monkeypatch,
    capsys,
) -> None:
    proc = Proc(
        [
            "\n",
            "[*] Starting framework\n",
            "msf6 banner\n",
            "regular result\n",
            "[+] session opened\n",
        ]
    )
    configure(monkeypatch, proc)
    result = msf.run_msf_module("auxiliary/scanner/test", "RHOSTS=host", timeout=30)
    assert "regular result" in result
    assert "session opened" in result
    assert "Starting framework" not in result
    assert "msf6 banner" not in result
    assert "[MSF" in capsys.readouterr().out

    broken = Proc(stdout=Stdout(iteration_error=ValueError("closed")))
    configure(monkeypatch, broken)
    assert "No MSF Output" in msf.run_msf_module(
        "auxiliary/scanner/test",
        "RHOSTS=host",
        timeout=30,
    )


@pytest.mark.parametrize("limit", [0, 4])
def test_output_limit_stops_process_with_and_without_remaining_capacity(
    monkeypatch,
    limit: int,
) -> None:
    terminations = []
    proc = Proc(["long output line\n"])
    configure(monkeypatch, proc, selected_context=context(output=limit))
    monkeypatch.setattr(msf, "_terminate_process_tree", lambda selected: terminations.append(selected))
    monkeypatch.setattr(msf, "_bounded_process_output", lambda value, maximum: value)

    result = msf.run_msf_module("auxiliary/scanner/test", "RHOSTS=host", timeout=30)

    assert terminations == [proc]
    assert f"process killed at {limit} bytes" in result


class ControlledThread:
    target = None
    alive_values = ()
    run_target = False

    def __init__(self, *, target, daemon) -> None:
        type(self).target = target
        self.values = list(type(self).alive_values)

    def start(self) -> None:
        if type(self).run_target:
            type(self).target()

    def is_alive(self) -> bool:
        return self.values.pop(0) if self.values else False

    def join(self, timeout=None) -> None:
        return None


class Clock:
    """Return scripted timestamps and then keep returning the final value."""

    def __init__(self, *values: float) -> None:
        self.values = list(values)
        self.current = self.values[0]

    def __call__(self) -> float:
        if self.values:
            self.current = self.values.pop(0)
        return self.current


def test_cancellation_terminates_and_reraises_typed_partial_result(monkeypatch) -> None:
    proc = Proc()
    configure(
        monkeypatch,
        proc,
        selected_context=context(cancelled=True, reason="operator_cancelled"),
    )
    ControlledThread.alive_values = [True]
    ControlledThread.run_target = False
    monkeypatch.setattr(threading, "Thread", ControlledThread)
    terminations = []
    monkeypatch.setattr(msf, "_terminate_process_tree", lambda selected: terminations.append(selected))

    with pytest.raises(ExecutionCancelled) as exc_info:
        msf.run_msf_module("auxiliary/scanner/test", "RHOSTS=host", timeout=30)
    assert exc_info.value.reason_code == "operator_cancelled"
    assert "[CANCELLED] operator_cancelled" in exc_info.value.stdout
    assert terminations == [proc]


@pytest.mark.parametrize("close_error", [None, RuntimeError("close failed")])
def test_login_success_stops_check_and_contains_close_errors(
    monkeypatch,
    close_error,
    caplog,
) -> None:
    proc = Proc(
        stdout=Stdout(
            ["[+] host - Success: 'user:password'\n"],
            close_error=close_error,
        )
    )
    configure(monkeypatch, proc)
    ControlledThread.alive_values = [True]
    ControlledThread.run_target = True
    monkeypatch.setattr(threading, "Thread", ControlledThread)
    terminations = []
    monkeypatch.setattr(msf, "_terminate_process_tree", terminations.append)
    import time

    monkeypatch.setattr(time, "time", Clock(0.0, 6.0))
    with caplog.at_level("DEBUG"):
        result = msf.run_msf_module(
            "auxiliary/scanner/ssh/ssh_login",
            "RHOSTS=host",
            timeout=30,
            mode="check",
        )
    assert "Success: 'user:password'" in result
    assert proc.stdout.closed
    assert terminations == [proc]
    if close_error:
        assert "close failed" in caplog.text


@pytest.mark.parametrize("close_error", [None, RuntimeError("timeout close failed")])
def test_runtime_timeout_and_heartbeat_paths(monkeypatch, close_error, caplog, capsys) -> None:
    proc = Proc(stdout=Stdout(close_error=close_error))
    configure(monkeypatch, proc)
    ControlledThread.alive_values = [True]
    ControlledThread.run_target = False
    monkeypatch.setattr(threading, "Thread", ControlledThread)
    import time

    monkeypatch.setattr(time, "time", Clock(0.0, 61.0))
    with caplog.at_level("DEBUG"):
        result = msf.run_msf_module("auxiliary/scanner/test", "RHOSTS=host", timeout=60)
    assert "No MSF Output" in result
    assert proc.stdout.closed
    assert "[TIMEOUT]" in capsys.readouterr().out
    if close_error:
        assert "timeout close failed" in caplog.text

    heartbeat_proc = Proc()
    configure(monkeypatch, heartbeat_proc)
    ControlledThread.alive_values = [True, True, False]
    monkeypatch.setattr(threading, "Thread", ControlledThread)
    monkeypatch.setattr(time, "time", Clock(0.0, 15.0))
    result = msf.run_msf_module("auxiliary/scanner/test", "RHOSTS=host", timeout=60)
    assert "No MSF Output" in result
    assert "MSF running" in capsys.readouterr().out


def test_running_reader_below_heartbeat_threshold_rechecks_loop(monkeypatch, capsys) -> None:
    configure(monkeypatch, Proc())
    ControlledThread.alive_values = [True, True, False]
    ControlledThread.run_target = False
    monkeypatch.setattr(threading, "Thread", ControlledThread)
    import time

    monkeypatch.setattr(time, "time", Clock(0.0, 1.0))
    result = msf.run_msf_module("auxiliary/scanner/test", "RHOSTS=host", timeout=60)
    assert "No MSF Output" in result
    assert "MSF running" not in capsys.readouterr().out


@pytest.mark.parametrize("second_wait_error", [None, RuntimeError("still running")])
def test_wait_timeout_forces_cleanup_and_contains_secondary_failures(
    monkeypatch,
    second_wait_error,
    caplog,
) -> None:
    effects = [subprocess.TimeoutExpired("msf", 10)]
    effects.append(second_wait_error if second_wait_error else 0)
    close_error = RuntimeError("wait close failed") if second_wait_error else None
    proc = Proc(wait_effects=effects, stdout=Stdout(close_error=close_error))
    configure(monkeypatch, proc)
    with caplog.at_level("DEBUG"):
        result = msf.run_msf_module("auxiliary/scanner/test", "RHOSTS=host", timeout=30)
    assert "No MSF Output" in result
    assert proc.waits == [10, 5]
    if second_wait_error:
        assert "wait close failed" in caplog.text
        assert "still running" in caplog.text


@pytest.mark.parametrize(
    ("line", "needle"),
    [
        ("unknown command", "does NOT EXIST"),
        ("invalid module selected", "does NOT EXIST"),
        ("failed to load module", "FAILED TO LOAD"),
        ("optionvalidateerror", "INVALID OPTIONS"),
        ("failed to validate options", "INVALID OPTIONS"),
    ],
)
def test_output_error_classification(monkeypatch, line: str, needle: str) -> None:
    configure(monkeypatch, Proc([line + "\n"]))
    assert needle in msf.run_msf_module(
        "auxiliary/scanner/test",
        "RHOSTS=host",
        timeout=30,
    )


def test_outer_timeout_generic_error_and_cancel_passthrough(monkeypatch) -> None:
    monkeypatch.setattr(msf.shutil, "which", lambda executable: "/usr/bin/msfconsole")
    monkeypatch.setattr(msf, "current_execution_context", lambda: context())
    monkeypatch.setattr(msf, "redact_sensitive_command", lambda value: str(value).replace("secret", "[redacted]"))
    monkeypatch.setattr(
        msf.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("msf", 9)),
    )
    assert "execution timed out after 9 seconds" in msf.run_msf_module(
        "auxiliary/scanner/test",
        "RHOSTS=host",
        timeout=9,
    )

    monkeypatch.setattr(
        msf.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret failure")),
    )
    assert "RuntimeError: [redacted] failure" in msf.run_msf_module(
        "auxiliary/scanner/test",
        "RHOSTS=host",
        timeout=9,
    )
