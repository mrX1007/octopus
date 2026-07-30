"""Hermetic statement and branch coverage for shared tool utilities."""

from __future__ import annotations

import builtins
import subprocess
from types import SimpleNamespace

import pytest

import core.execution as execution
from core.execution import ExecutionCancelled
from core.tools import base

pytestmark = [pytest.mark.unit, pytest.mark.security]


class Cancellation:
    def __init__(self, *, cancelled: bool = False, reason_code: str = "") -> None:
        self.cancelled = cancelled
        self.reason_code = reason_code
        self.cancel_calls: list[str] = []

    def cancel(self, reason: str) -> bool:
        self.cancel_calls.append(reason)
        self.cancelled = True
        self.reason_code = reason
        return True


def context(
    *,
    runtime: int = 120,
    output: int = 4096,
    cancellation: Cancellation | None = None,
):
    return SimpleNamespace(
        max_runtime_seconds=runtime,
        max_output_bytes=output,
        cancellation=cancellation or Cancellation(),
    )


class Clock:
    def __init__(self, *values: float) -> None:
        self.values = list(values)
        self.current = self.values[0] if self.values else 0.0

    def __call__(self) -> float:
        if self.values:
            self.current = self.values.pop(0)
        return self.current


class Stdout:
    def __init__(
        self,
        lines=(),
        *,
        iteration_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.lines = list(lines)
        self.iteration_error = iteration_error
        self.close_error = close_error
        self.closed = False

    def __iter__(self):
        yield from self.lines
        if self.iteration_error is not None:
            raise self.iteration_error

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class Proc:
    def __init__(
        self,
        lines=(),
        *,
        stdout=...,
        returncode: int = 0,
        wait_effects=(),
    ) -> None:
        self.stdout = Stdout(lines) if stdout is ... else stdout
        self.returncode = returncode
        self.wait_effects = list(wait_effects)
        self.waits: list[float | None] = []
        self.pid = 4321

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.wait_effects:
            effect = self.wait_effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            return effect
        return self.returncode


def thread_class(
    *,
    run_target: bool = True,
    alive_values=(),
    start_error: BaseException | None = None,
    joins: list[float | None] | None = None,
):
    class Thread:
        def __init__(self, *, target, daemon) -> None:
            self.target = target
            self.values = list(alive_values)

        def start(self) -> None:
            if start_error is not None:
                raise start_error
            if run_target:
                self.target()

        def is_alive(self) -> bool:
            return self.values.pop(0) if self.values else False

        def join(self, timeout=None) -> None:
            if joins is not None:
                joins.append(timeout)

    return Thread


def configure_run(
    monkeypatch,
    proc: Proc,
    *,
    selected_context=None,
    selected_thread=None,
    times=(0.0,),
    os_name: str = "posix",
    terminations: list[Proc] | None = None,
    popen_error: BaseException | None = None,
):
    selected_context = selected_context or context()
    selected_thread = selected_thread or thread_class()
    terminations = [] if terminations is None else terminations
    popen_calls = []
    monkeypatch.setattr(execution, "current_execution_context", lambda: selected_context)
    monkeypatch.setattr(
        execution,
        "redact_sensitive_command",
        lambda value: str(value).replace("secret", "[redacted]"),
    )
    monkeypatch.setattr(base.shutil, "which", lambda _name: "/usr/bin/tool")
    monkeypatch.setattr(base.threading, "Thread", selected_thread)
    monkeypatch.setattr(base.time, "monotonic", Clock(*times))
    monkeypatch.setattr(base, "os", SimpleNamespace(name=os_name))
    monkeypatch.setattr(base, "_terminate_process_tree", terminations.append)

    def popen(command, **kwargs):
        popen_calls.append((command, kwargs))
        if popen_error is not None:
            raise popen_error
        return proc

    monkeypatch.setattr(base.subprocess, "Popen", popen)
    return popen_calls, terminations


def test_availability_cache_and_tool_result_string_protocol(monkeypatch) -> None:
    calls: list[str] = []
    base._TOOL_AVAILABLE.clear()
    monkeypatch.setattr(
        base.shutil,
        "which",
        lambda name: calls.append(name) or ("/bin/tool" if name == "present" else None),
    )
    assert base.is_tool_available("present") is True
    assert base.is_tool_available("present") is True
    assert base.is_tool_available("missing") is False
    assert calls == ["present", "missing"]

    result = base.ToolResult(
        tool_name="scanner",
        command="scan",
        stdout="Alpha",
        stderr="warning",
        exit_code=2,
        duration=1.5,
    )
    same = base.ToolResult(
        tool_name="scanner",
        command="scan",
        stdout="Alpha",
        stderr="warning",
        exit_code=2,
        duration=1.5,
        timestamp="different",
    )
    assert str(result) == "Alpha"
    assert repr(result) == "ToolResult('scanner', len=5)"
    assert result == "Alpha"
    assert result == same
    assert result != base.ToolResult(stdout="different")
    assert result != object()
    assert "ph" in result
    assert len(result) == 5
    assert bool(result) is True
    assert bool(base.ToolResult(stdout="  ")) is False
    assert "".join(result) == "Alpha"
    assert result[1:3] == "lp"
    assert result + 7 == "Alpha7"
    assert 7 + result == "7Alpha"
    assert result.lower() == "alpha"
    assert result.startswith("Al") is True
    with pytest.raises(AttributeError, match="_private"):
        _ = result._private


def test_config_import_fallback_and_elapsed_boundaries(monkeypatch) -> None:
    import config

    monkeypatch.setattr(config, "CFG", {"tools": {"nmap": {"timeout": 5}}})
    assert base.get_tool_config("nmap") == {"timeout": 5}
    assert base.get_tool_config("missing") == {}

    original_import = builtins.__import__

    def without_config(name, *args, **kwargs):
        if name == "config":
            raise ImportError("config unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_config)
    assert base.get_tool_config("nmap") == {}
    assert base._fmt_elapsed(119) == "119s"
    assert base._fmt_elapsed(120) == "2m00s"
    assert base._fmt_elapsed(3599) == "59m59s"
    assert base._fmt_elapsed(3600) == "1h00m"
    assert base._fmt_elapsed(7261) == "2h01m"


class TerminationProc:
    def __init__(
        self,
        *,
        poll_result=None,
        wait_effects=(),
        terminate_effects=(),
        kill_effects=(),
    ) -> None:
        self.pid = 99
        self.poll_result = poll_result
        self.wait_effects = list(wait_effects)
        self.terminate_effects = list(terminate_effects)
        self.kill_effects = list(kill_effects)
        self.calls = []

    @staticmethod
    def _effect(effects):
        if effects:
            effect = effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            return effect
        return None

    def poll(self):
        self.calls.append(("poll", None))
        return self.poll_result

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        return self._effect(self.wait_effects)

    def terminate(self):
        self.calls.append(("terminate", None))
        return self._effect(self.terminate_effects)

    def kill(self):
        self.calls.append(("kill", None))
        return self._effect(self.kill_effects)


class TerminationOS:
    def __init__(self, name: str, effects=()) -> None:
        self.name = name
        self.effects = list(effects)
        self.calls = []

    def killpg(self, pid, selected_signal) -> None:
        self.calls.append((pid, selected_signal))
        if self.effects:
            effect = self.effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect


def test_terminate_process_tree_platform_and_fallback_paths(monkeypatch) -> None:
    finished = TerminationProc(poll_result=0)
    base._terminate_process_tree(finished)
    assert finished.calls == [("poll", None)]

    posix_os = TerminationOS("posix")
    monkeypatch.setattr(base, "os", posix_os)
    graceful = TerminationProc()
    base._terminate_process_tree(graceful, grace_seconds=-2)
    assert graceful.calls[-1] == ("wait", 0.0)
    assert posix_os.calls == [(99, base.signal.SIGTERM)]

    nt_os = TerminationOS("nt")
    monkeypatch.setattr(base, "os", nt_os)
    windows = TerminationProc()
    base._terminate_process_tree(windows)
    assert ("terminate", None) in windows.calls

    fallback_os = TerminationOS("posix", [PermissionError("denied")])
    monkeypatch.setattr(base, "os", fallback_os)
    fallback = TerminationProc()
    base._terminate_process_tree(fallback)
    assert ("terminate", None) in fallback.calls

    suppressed = TerminationProc(terminate_effects=[OSError("gone")])
    monkeypatch.setattr(
        base,
        "os",
        TerminationOS("posix", [ProcessLookupError("gone")]),
    )
    base._terminate_process_tree(suppressed)

    timeout = subprocess.TimeoutExpired("tool", 1)
    kill_os = TerminationOS("posix")
    monkeypatch.setattr(base, "os", kill_os)
    force_posix = TerminationProc(wait_effects=[timeout])
    base._terminate_process_tree(force_posix)
    assert kill_os.calls[-1] == (99, base.signal.SIGKILL)

    monkeypatch.setattr(base, "os", TerminationOS("nt"))
    force_windows = TerminationProc(wait_effects=[timeout])
    base._terminate_process_tree(force_windows)
    assert ("kill", None) in force_windows.calls

    kill_fallback_os = TerminationOS("posix", [None, OSError("killpg failed")])
    monkeypatch.setattr(base, "os", kill_fallback_os)
    kill_fallback = TerminationProc(wait_effects=[timeout])
    base._terminate_process_tree(kill_fallback)
    assert ("kill", None) in kill_fallback.calls

    kill_suppressed_os = TerminationOS("posix", [None, OSError("killpg failed")])
    monkeypatch.setattr(base, "os", kill_suppressed_os)
    kill_suppressed = TerminationProc(
        wait_effects=[timeout],
        kill_effects=[OSError("already gone")],
    )
    base._terminate_process_tree(kill_suppressed)


def test_bounded_output_and_nuclei_summary_variants() -> None:
    assert base._bounded_process_output(None, 10) == ""
    assert base._bounded_process_output("abc", 3) == "abc"
    assert "truncated at 2 bytes" in base._bounded_process_output("abcdef", 2)
    assert "truncated at 50 bytes" in base._bounded_process_output("é" * 100, 50)

    assert base._nuclei_live_summary(None) == ""
    assert base._nuclei_live_summary("ordinary output") == ""
    assert base._nuclei_live_summary("warning: template failed") == "warning: template failed"
    assert base._nuclei_live_summary("{}") == ""
    assert (
        base._nuclei_live_summary(
            '{"info":{"severity":"HIGH","name":"Finding"},"template-id":"tpl","matched-at":"https://host"}'
        )
        == "nuclei high tpl https://host"
    )
    assert base._nuclei_live_summary('{"severity":"low","template":"legacy","host":"h"}') == ("nuclei low legacy h")
    assert base._nuclei_live_summary('{"info":{"name":"Named"},"ip":"127.0.0.1"}') == ("nuclei info Named 127.0.0.1")
    assert base._nuclei_live_summary('{"template-id":"only-template"}') == ("nuclei info only-template")


def test_run_tool_empty_missing_and_regular_output(monkeypatch, capsys) -> None:
    assert base.run_tool([]) == "[!] Empty command."

    proc = Proc(["ordinary\n", "22/tcp open ssh secret\n"])
    calls, _ = configure_run(monkeypatch, proc, times=(0.0, 3.0))
    monkeypatch.setattr(base.shutil, "which", lambda name: None if name == "missing" else "/bin/tool")
    assert "Tool not found: missing" in base.run_tool(["missing"])
    output = base.run_tool(["nmap", "host"], timeout="invalid")
    assert output == "ordinary\n22/tcp open ssh secret"
    assert "[redacted]" in capsys.readouterr().out
    assert proc.stdout.closed
    assert calls[-1][1]["start_new_session"] is True


def test_run_tool_windows_stdout_none_and_nonpositive_timeout(monkeypatch) -> None:
    proc = Proc(stdout=None)
    calls, _ = configure_run(
        monkeypatch,
        proc,
        selected_context=context(runtime=0, output=1),
        os_name="nt",
    )
    result = base.run_tool(["custom"], timeout=0)
    assert "returned no output" in result
    assert calls[0][1]["start_new_session"] is False


def test_run_tool_hydra_status_and_long_heartbeat(monkeypatch, capsys) -> None:
    proc = Proc(["[STATUS] 1 try secret\n"])
    controlled = thread_class(run_target=True, alive_values=(True, True, False))
    configure_run(
        monkeypatch,
        proc,
        selected_context=context(runtime=600),
        selected_thread=controlled,
        times=(0.0, 61.0),
    )
    result = base.run_tool(["hydra"], timeout=600)
    rendered = capsys.readouterr().out
    assert "[STATUS]" in result
    assert "♻ hydra 61s / 10m00s max" in rendered
    assert "secret" not in rendered


@pytest.mark.parametrize(
    ("alive_values", "elapsed", "expect_heartbeat"),
    [
        ((True, True, False), 30.0, True),
        ((True, True, False), 1.0, False),
        ((True, False, False), 30.0, False),
    ],
)
def test_run_tool_generic_heartbeat_and_loop_recheck(
    monkeypatch,
    capsys,
    alive_values,
    elapsed,
    expect_heartbeat,
) -> None:
    proc = Proc()
    configure_run(
        monkeypatch,
        proc,
        selected_context=context(runtime=60),
        selected_thread=thread_class(run_target=False, alive_values=alive_values),
        times=(0.0, elapsed),
    )
    assert "returned no output" in base.run_tool(["custom"], timeout=60)
    assert ("custom running" in capsys.readouterr().out) is expect_heartbeat


def test_run_tool_cancellation_and_runtime_timeout(monkeypatch, capsys) -> None:
    cancellation = Cancellation(cancelled=True, reason_code="operator")
    cancelled_proc = Proc(returncode=-15)
    terminations: list[Proc] = []
    configure_run(
        monkeypatch,
        cancelled_proc,
        selected_context=context(cancellation=cancellation),
        selected_thread=thread_class(run_target=False, alive_values=(True,)),
        times=(0.0, 1.0),
        terminations=terminations,
    )
    with pytest.raises(ExecutionCancelled) as exc_info:
        base.run_tool(["custom"], timeout=60)
    assert exc_info.value.reason_code == "operator"
    assert "[CANCELLED] operator" in exc_info.value.stdout
    assert terminations == [cancelled_proc]

    timeout_proc = Proc()
    timeout_terminations: list[Proc] = []
    configure_run(
        monkeypatch,
        timeout_proc,
        selected_context=context(runtime=1),
        selected_thread=thread_class(run_target=False, alive_values=(True,)),
        times=(0.0, 2.0),
        terminations=timeout_terminations,
    )
    result = base.run_tool(["custom"], timeout=50)
    assert "[PARTIAL OUTPUT" in result
    assert "[TIMEOUT] custom killed after 1s" in result
    assert timeout_terminations == [timeout_proc]
    assert "[TIMEOUT]" in capsys.readouterr().out


@pytest.mark.parametrize(
    "lines",
    [
        ("x" * 2000 + "\n",),
        ("x" * 1023 + "\n", "second line\n"),
    ],
)
def test_run_tool_output_limit_with_partial_or_zero_capacity(monkeypatch, lines) -> None:
    proc = Proc(lines)
    terminations: list[Proc] = []
    configure_run(
        monkeypatch,
        proc,
        selected_context=context(output=1024),
        terminations=terminations,
    )
    output = base.run_tool(["custom"])
    assert "[OUTPUT LIMIT]" in output
    assert terminations == [proc]


def test_run_tool_nuclei_rendering_and_wait_timeout(monkeypatch, capsys) -> None:
    proc = Proc(
        [
            "quiet text\n",
            "warning from nuclei\n",
            '{"info":{"severity":"high"},"host":"example"}\n',
        ],
        wait_effects=(subprocess.TimeoutExpired("nuclei", 5), 0),
    )
    terminations: list[Proc] = []
    configure_run(monkeypatch, proc, times=(0.0, 2.0, 3.0), terminations=terminations)
    result = base.run_tool(["nuclei"])
    live = capsys.readouterr().out
    assert "quiet text" in result
    assert "warning from nuclei" in live
    assert "nuclei high" in live
    assert proc.waits == [5, 5]
    assert terminations == [proc]


def test_run_tool_keyboard_interrupt_with_and_without_started_process(monkeypatch) -> None:
    before_start = context()
    configure_run(
        monkeypatch,
        Proc(),
        selected_context=before_start,
        popen_error=KeyboardInterrupt(),
    )
    with pytest.raises(ExecutionCancelled) as before_exc:
        base.run_tool(["custom"])
    assert before_exc.value.returncode is None
    assert before_start.cancellation.cancel_calls == ["keyboard_interrupt"]

    joins: list[float | None] = []
    after_start = context()
    proc = Proc(returncode=-2)
    terminations: list[Proc] = []
    configure_run(
        monkeypatch,
        proc,
        selected_context=after_start,
        selected_thread=thread_class(start_error=KeyboardInterrupt(), joins=joins),
        terminations=terminations,
    )
    with pytest.raises(ExecutionCancelled) as after_exc:
        base.run_tool(["custom"])
    assert after_exc.value.returncode == -2
    assert joins == [2]
    assert terminations == [proc]


@pytest.mark.parametrize(
    ("proc", "popen_error", "needle", "expect_termination"),
    [
        (Proc(), RuntimeError("secret popen"), "[redacted] popen", False),
        (
            Proc(),
            None,
            "thread failed",
            True,
        ),
        (
            Proc(stdout=Stdout(close_error=RuntimeError("close failed"))),
            None,
            "close failed",
            True,
        ),
        (
            Proc(stdout=Stdout(iteration_error=RuntimeError("reader failed"))),
            None,
            "reader failed",
            True,
        ),
    ],
)
def test_run_tool_unexpected_errors_are_sanitized(
    monkeypatch,
    proc,
    popen_error,
    needle,
    expect_termination,
) -> None:
    terminations: list[Proc] = []
    selected_thread = (
        thread_class(start_error=RuntimeError("thread failed")) if needle == "thread failed" else thread_class()
    )
    configure_run(
        monkeypatch,
        proc,
        selected_thread=selected_thread,
        terminations=terminations,
        popen_error=popen_error,
    )
    result = base.run_tool(["custom"])
    assert "Unexpected error" in result
    assert needle in result
    assert (terminations == [proc]) is expect_termination
