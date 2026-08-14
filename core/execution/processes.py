from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ProcessExecutionModel:
    """Model for process execution."""

    command: list[str]
    timeout_seconds: float
    cwd: str | None = None
    env: dict | None = None
    input: str | None = None


@dataclass
class ProcessExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float


class ProcessRunnerV1:
    def execute(self, model: ProcessExecutionModel) -> ProcessExecutionResult:
        if not model.command:
            raise ValueError("Process command list cannot be empty")
        if model.timeout_seconds <= 0:
            raise ValueError("Timeout must be greater than zero")

        start_time = time.monotonic()

        try:
            result = subprocess.run(
                model.command,
                cwd=model.cwd,
                env=model.env,
                input=model.input,
                capture_output=True,
                text=True,
                timeout=model.timeout_seconds,
                check=False,
            )
            exit_code = result.returncode
            stdout = result.stdout or ""
            stderr = result.stderr or ""
        except subprocess.TimeoutExpired as e:
            exit_code = 124  # Standard timeout exit code
            stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else e.stdout or ""
            if isinstance(e.stderr, bytes):
                stderr = e.stderr.decode("utf-8", errors="replace")
            else:
                stderr = e.stderr or f"Command timed out after {model.timeout_seconds}s"
        except FileNotFoundError as e:
            exit_code = 127
            stdout = ""
            stderr = f"Command not found: {e!s}"
        except Exception as e:
            exit_code = 1
            stdout = ""
            stderr = f"Execution failed: {e!s}"

        duration = time.monotonic() - start_time

        return ProcessExecutionResult(stdout=stdout, stderr=stderr, exit_code=exit_code, duration_seconds=duration)
