from __future__ import annotations

import sys
import pytest

from core.execution.processes import ProcessRunnerV1, ProcessExecutionModel, ProcessExecutionResult

pytestmark = pytest.mark.unit


def test_process_runner_execute_success() -> None:
    runner = ProcessRunnerV1()
    model = ProcessExecutionModel(
        command=[sys.executable, "-c", "print('hello octopus')"],
        timeout_seconds=5.0,
    )
    result = runner.execute(model)

    assert isinstance(result, ProcessExecutionResult)
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello octopus"
    assert result.stderr == ""
    assert result.duration_seconds > 0.0


def test_process_runner_execute_stderr_and_exit_code() -> None:
    runner = ProcessRunnerV1()
    model = ProcessExecutionModel(
        command=[sys.executable, "-c", "import sys; sys.stderr.write('custom_error'); sys.exit(7)"],
        timeout_seconds=5.0,
    )
    result = runner.execute(model)

    assert result.exit_code == 7
    assert result.stderr == "custom_error"


def test_process_runner_stdin_input() -> None:
    runner = ProcessRunnerV1()
    model = ProcessExecutionModel(
        command=[sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"],
        timeout_seconds=5.0,
        input="hello octopus execution",
    )
    result = runner.execute(model)

    assert result.exit_code == 0
    assert result.stdout == "HELLO OCTOPUS EXECUTION"


def test_process_runner_timeout() -> None:
    runner = ProcessRunnerV1()
    model = ProcessExecutionModel(
        command=[sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_seconds=0.1,
    )
    result = runner.execute(model)

    assert result.exit_code == 124
    assert "timed out" in result.stderr


def test_process_runner_validation_errors() -> None:
    runner = ProcessRunnerV1()

    with pytest.raises(ValueError, match="command list cannot be empty"):
        runner.execute(ProcessExecutionModel(command=[], timeout_seconds=5.0))

    with pytest.raises(ValueError, match="Timeout must be greater than zero"):
        runner.execute(ProcessExecutionModel(command=["echo", "test"], timeout_seconds=0.0))


def test_process_runner_nonexistent_command() -> None:
    runner = ProcessRunnerV1()
    model = ProcessExecutionModel(
        command=["invalid_command_binary_12345"],
        timeout_seconds=5.0,
    )
    result = runner.execute(model)

    assert result.exit_code == 127
    assert "Command not found" in result.stderr
